# Agent Spend Guard

FastAPI product for preventing AI agent cost blowups and key leakage.

## Core Endpoints
- `POST /v1/leak-scan`
- `POST /v1/spend/analyze`
- `POST /api/public/lead`

## Local run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Stripe
Use DataWeave INC payment links via `CHECKOUT_LINK_*` variables.

## Security defaults
- IP-based rate limiting
- strict response headers
- no plain-text secret storage in DB
