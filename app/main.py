import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, conlist

BASE_DIR = Path(__file__).resolve().parent.parent
LANDING_DIR = BASE_DIR / "landing"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "spend_guard.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)

APP_NAME = "Agent Spend Guard"
APP_SLUG = "spendguard"
DEFAULT_BASE_URL = "https://spendguard.dataweaveai.com"

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
FOLLOWUP_INBOX_EMAIL = os.getenv("FOLLOWUP_INBOX_EMAIL", "joseph@dataweaveai.com").strip()
FOLLOWUP_FROM_EMAIL = os.getenv("FOLLOWUP_FROM_EMAIL", "SpendGuard <noreply@dataweaveai.com>").strip()
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()

DATAWEAVE_HOME_URL = os.getenv("DATAWEAVE_HOME_URL", "https://dataweaveai.com").strip()
AGENT_ROUTER_URL = os.getenv("AGENT_ROUTER_URL", "https://get-agent-router.com").strip()

CHECKOUT_LINK_STARTER = os.getenv("CHECKOUT_LINK_STARTER", "https://buy.stripe.com/cNidR9bpT0284Or8nf3Je04").strip()
CHECKOUT_LINK_DFY = os.getenv("CHECKOUT_LINK_DFY", "https://buy.stripe.com/cNi14n0Lf8yEep1dHz3Je05").strip()

API_RATE_WINDOW_SECONDS = int(os.getenv("API_RATE_WINDOW_SECONDS", "60"))
LEAD_RATE_LIMIT_PER_MINUTE = int(os.getenv("LEAD_RATE_LIMIT_PER_MINUTE", "15"))
SCAN_RATE_LIMIT_PER_MINUTE = int(os.getenv("SCAN_RATE_LIMIT_PER_MINUTE", "60"))

CORS_ALLOW_ORIGINS = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",") if o.strip()]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

KEY_PATTERNS = [
    ("openai", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("anthropic", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    ("stripe", re.compile(r"sk_(live|test)_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
]


class LeadRequest(BaseModel):
    email: str
    company: str = Field(min_length=2, max_length=120)
    team_size: Optional[int] = Field(default=None, ge=1, le=50000)
    main_risk: str = Field(min_length=4, max_length=280)
    plan: str = Field(default="starter", pattern="^(starter|dfy)$")
    source: Optional[str] = Field(default="site", max_length=80)


class LeakScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=40000)
    source: Optional[str] = Field(default="unknown", max_length=80)


class SpendAnalyzeRequest(BaseModel):
    provider: str = Field(min_length=2, max_length=40)
    hourly_cost_usd: conlist(float, min_length=6, max_length=336)
    hourly_requests: conlist(int, min_length=6, max_length=336)
    threshold_multiplier: float = Field(default=2.5, ge=1.2, le=8.0)


app = FastAPI(title=APP_NAME, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS if CORS_ALLOW_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

_rate_lock = threading.Lock()
_rate_state: dict[str, list[float]] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leads (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                email TEXT NOT NULL,
                company TEXT NOT NULL,
                team_size INTEGER,
                main_risk TEXT NOT NULL,
                plan TEXT NOT NULL,
                source TEXT,
                ip_hash TEXT,
                checkout_url TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                source TEXT,
                ip_hash TEXT,
                findings_json TEXT NOT NULL,
                risk_score INTEGER NOT NULL
            )
            """
        )


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:24]


def check_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    cutoff = time.time() - window_seconds
    with _rate_lock:
        bucket = _rate_state.get(key, [])
        bucket = [ts for ts in bucket if ts >= cutoff]
        if len(bucket) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        bucket.append(time.time())
        _rate_state[key] = bucket


def checkout_link_for_plan(plan: str) -> str:
    return {
        "starter": CHECKOUT_LINK_STARTER,
        "dfy": CHECKOUT_LINK_DFY,
    }.get(plan, CHECKOUT_LINK_STARTER)


def render_template(name: str) -> str:
    raw = (LANDING_DIR / name).read_text(encoding="utf-8")
    return (
        raw.replace("{{BASE_URL}}", PUBLIC_BASE_URL)
        .replace("{{DATAWEAVE_HOME_URL}}", DATAWEAVE_HOME_URL)
        .replace("{{AGENT_ROUTER_URL}}", AGENT_ROUTER_URL)
        .replace("{{CHECKOUT_LINK_STARTER}}", CHECKOUT_LINK_STARTER)
        .replace("{{CHECKOUT_LINK_DFY}}", CHECKOUT_LINK_DFY)
    )


def send_resend_email(subject: str, html: str) -> None:
    if not RESEND_API_KEY:
        return
    payload = {
        "from": FOLLOWUP_FROM_EMAIL,
        "to": [FOLLOWUP_INBOX_EMAIL],
        "subject": subject,
        "html": html,
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8):
            pass
    except urllib.error.URLError:
        return


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "upgrade-insecure-requests"
    return response


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": APP_SLUG, "time": now_iso()}


@app.get("/", response_class=HTMLResponse)
def home() -> HTMLResponse:
    return HTMLResponse(render_template("index.html"))


@app.get("/docs-page", response_class=HTMLResponse)
def docs_page() -> HTMLResponse:
    return HTMLResponse(render_template("docs.html"))


@app.get("/privacy", response_class=HTMLResponse)
def privacy() -> HTMLResponse:
    return HTMLResponse(render_template("privacy.html"))


@app.get("/terms", response_class=HTMLResponse)
def terms() -> HTMLResponse:
    return HTMLResponse(render_template("terms.html"))


@app.get("/llms.txt", response_class=PlainTextResponse)
def llms() -> PlainTextResponse:
    content = (LANDING_DIR / "llms.txt").read_text(encoding="utf-8")
    content = (
        content.replace("{{BASE_URL}}", PUBLIC_BASE_URL)
        .replace("{{CHECKOUT_LINK_STARTER}}", CHECKOUT_LINK_STARTER)
        .replace("{{CHECKOUT_LINK_DFY}}", CHECKOUT_LINK_DFY)
    )
    return PlainTextResponse(content)


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots() -> PlainTextResponse:
    return PlainTextResponse(
        f"""User-agent: *
Allow: /
Disallow: /v1/admin

User-agent: GPTBot
Allow: /
User-agent: OAI-SearchBot
Allow: /
User-agent: ClaudeBot
Allow: /
User-agent: PerplexityBot
Allow: /

Sitemap: {PUBLIC_BASE_URL}/sitemap.xml
"""
    )


@app.get("/sitemap.xml", response_class=PlainTextResponse)
def sitemap() -> PlainTextResponse:
    today = datetime.now(timezone.utc).date().isoformat()
    return PlainTextResponse(
        f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">
  <url><loc>{PUBLIC_BASE_URL}/</loc><lastmod>{today}</lastmod></url>
  <url><loc>{PUBLIC_BASE_URL}/docs-page</loc><lastmod>{today}</lastmod></url>
  <url><loc>{PUBLIC_BASE_URL}/llms.txt</loc><lastmod>{today}</lastmod></url>
</urlset>""",
        media_type="application/xml",
    )


@app.get("/.well-known/agent-offer.json", response_class=JSONResponse)
def agent_offer() -> JSONResponse:
    return JSONResponse(
        {
            "name": APP_NAME,
            "url": PUBLIC_BASE_URL,
            "type": "agent_spend_protection",
            "checkout_endpoint": f"{PUBLIC_BASE_URL}/api/public/lead",
            "api_endpoints": [
                f"{PUBLIC_BASE_URL}/v1/leak-scan",
                f"{PUBLIC_BASE_URL}/v1/spend/analyze",
            ],
        }
    )


@app.get("/.well-known/ai-plugin.json", response_class=JSONResponse)
def ai_plugin() -> JSONResponse:
    return JSONResponse(
        {
            "schema_version": "v1",
            "name_for_human": APP_NAME,
            "name_for_model": "agent_spend_guard",
            "description_for_human": "Detect API key leaks and spend anomalies for AI agent workloads.",
            "description_for_model": "Scan text/logs for leaked keys and score usage anomalies.",
            "auth": {"type": "none"},
            "api": {"type": "openapi", "url": f"{PUBLIC_BASE_URL}/openapi.json", "is_user_authenticated": False},
            "logo_url": f"{PUBLIC_BASE_URL}/logo-192.png",
            "contact_email": FOLLOWUP_INBOX_EMAIL,
            "legal_info_url": f"{PUBLIC_BASE_URL}/terms",
        }
    )


@app.post("/api/public/lead")
def create_lead(payload: LeadRequest, request: Request) -> dict[str, Any]:
    ip = client_ip(request)
    check_rate_limit(f"lead:{ip}", LEAD_RATE_LIMIT_PER_MINUTE, API_RATE_WINDOW_SECONDS)
    if not EMAIL_RE.match(payload.email.strip()):
        raise HTTPException(status_code=400, detail="Invalid email")

    lead_id = f"lead_{secrets.token_hex(8)}"
    checkout_url = checkout_link_for_plan(payload.plan)

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO leads (id, created_at, email, company, team_size, main_risk, plan, source, ip_hash, checkout_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                lead_id,
                now_iso(),
                payload.email.lower().strip(),
                payload.company.strip(),
                payload.team_size,
                payload.main_risk.strip(),
                payload.plan,
                (payload.source or "site").strip(),
                ip_hash(ip),
                checkout_url,
            ),
        )

    send_resend_email(
        subject=f"SpendGuard lead: {payload.plan}",
        html=(
            f"<p><strong>New SpendGuard lead</strong></p>"
            f"<p>Email: {payload.email}<br>Company: {payload.company}<br>Plan: {payload.plan}<br>"
            f"Checkout: <a href='{checkout_url}'>{checkout_url}</a></p>"
        ),
    )

    return {"ok": True, "lead_id": lead_id, "checkout_url": checkout_url, "plan": payload.plan}


@app.post("/v1/leak-scan")
def leak_scan(payload: LeakScanRequest, request: Request) -> dict[str, Any]:
    ip = client_ip(request)
    check_rate_limit(f"scan:{ip}", SCAN_RATE_LIMIT_PER_MINUTE, API_RATE_WINDOW_SECONDS)

    findings: list[dict[str, Any]] = []
    for provider, pattern in KEY_PATTERNS:
        for match in pattern.finditer(payload.text):
            token = match.group(0)
            findings.append(
                {
                    "provider": provider,
                    "preview": token[:6] + "..." + token[-4:],
                    "position": match.start(),
                    "severity": "critical" if provider in {"openai", "anthropic", "stripe"} else "high",
                }
            )

    risk_score = min(100, len(findings) * 22)
    actions = []
    if findings:
        actions.extend(
            [
                "Revoke exposed keys immediately.",
                "Rotate credentials and audit usage in provider dashboard.",
                "Block future commits containing secrets with pre-commit scanning.",
            ]
        )
    else:
        actions.append("No known key patterns found. Continue monitoring with anomaly alerts.")

    scan_id = f"scan_{secrets.token_hex(8)}"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (id, created_at, source, ip_hash, findings_json, risk_score) VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                now_iso(),
                (payload.source or "unknown").strip(),
                ip_hash(ip),
                json.dumps(findings),
                risk_score,
            ),
        )

    return {"ok": True, "scan_id": scan_id, "risk_score": risk_score, "findings": findings, "actions": actions}


@app.post("/v1/spend/analyze")
def spend_analyze(payload: SpendAnalyzeRequest, request: Request) -> dict[str, Any]:
    ip = client_ip(request)
    check_rate_limit(f"scan:{ip}", SCAN_RATE_LIMIT_PER_MINUTE, API_RATE_WINDOW_SECONDS)

    costs = payload.hourly_cost_usd
    reqs = payload.hourly_requests

    baseline = sum(costs[:-1]) / max(1, len(costs) - 1)
    latest = costs[-1]
    ratio = (latest / baseline) if baseline > 0 else 0

    req_baseline = sum(reqs[:-1]) / max(1, len(reqs) - 1)
    req_latest = reqs[-1]
    req_ratio = (req_latest / req_baseline) if req_baseline > 0 else 0

    alerts = []
    if ratio >= payload.threshold_multiplier:
        alerts.append("Cost spike exceeds configured threshold")
    if req_ratio >= payload.threshold_multiplier:
        alerts.append("Request volume spike exceeds configured threshold")
    if latest > (req_latest * 0.25) and req_latest > 0:
        alerts.append("High cost-per-request detected in latest hour")

    severity = "low"
    if len(alerts) >= 2:
        severity = "high"
    elif len(alerts) == 1:
        severity = "medium"

    response = {
        "ok": True,
        "provider": payload.provider,
        "baseline_cost": round(baseline, 4),
        "latest_cost": round(latest, 4),
        "cost_ratio": round(ratio, 3),
        "baseline_requests": round(req_baseline, 2),
        "latest_requests": req_latest,
        "request_ratio": round(req_ratio, 3),
        "severity": severity,
        "alerts": alerts,
        "recommended_actions": [
            "Apply temporary request caps for high-risk endpoints.",
            "Rotate keys if anomaly correlates with leaked credentials.",
            "Require signed requests from approved agents only.",
        ],
    }
    return response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
