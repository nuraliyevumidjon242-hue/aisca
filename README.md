# AISCA — Infrastructure Security Assessment Platform

AISCA is a portfolio-stage security assessment platform that combines network
service discovery, basic TLS and HTTP-header checks, heuristic log analysis,
and bilingual PDF reporting in a web dashboard.

[Download the English project presentation](./AISCA_Project_Overview.pptx).

> **Scope and safety:** Use only against systems you own or are explicitly
> authorized to assess. AISCA is an MVP, not a penetration-testing suite,
> compliance certification, or production-ready security product.

## What is implemented

- **Network scans:** Nmap TCP connect and service/version detection, with a
  simple port-based risk classification.
- **Web/TLS checks:** Certificate verification, supported TLS versions, and a
  small set of HTTP security headers.
- **Log analysis:** Deterministic keyword/rule matching for suspicious log
  entries. This is not a trained AI/ML model and can produce false positives
  or miss attacks.
- **Dashboard and alerts:** Next.js interface, scan history, summary charts,
  and authenticated live alerts.
- **Reports:** English and German PDF output with heuristic BSI/GDPR mapping.
  Findings are informational and do not establish legal or standards compliance.
- **Authentication:** FastAPI bearer tokens and Argon2 password hashing.

## Stack

- Python 3.11+, FastAPI, SQLite, optional Redis cache
- Nmap and `python-nmap`
- Next.js 13, React 18, Chart.js
- WeasyPrint/Jinja2 for PDF generation
- Docker Compose for local development

The current application stores scan and user records in SQLite. The Compose
file includes a PostgreSQL service for experimentation, but the application
does not currently use PostgreSQL as its scan database.

## Run locally with Docker

1. Copy `.env.example` to `.env`.
2. Set the blank password and signing-key values to unique secrets. Generate a
   long random value for `AISCA_SECRET_KEY`; do not commit `.env`.
3. Start the stack:

   ```sh
   docker compose up --build
   ```

4. Open the dashboard at <http://localhost:3000>. Sign in using the admin
   username and password configured in `.env`.
5. API documentation is available at <http://localhost:8000/docs>.

The Compose ports are bound to loopback for local use. Do not expose this
development configuration directly to the public internet.

## Run without Docker

Backend (Nmap must be installed on the host):

```sh
cd backend
python -m venv .venv
# Activate the virtual environment for your shell, then:
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

For native PDF generation outside Docker, install WeasyPrint's platform
dependencies (including Pango and Cairo); the Docker image provides them.

Set `AISCA_ADMIN_USER`, `AISCA_ADMIN_PASS`, and a stable, random
`AISCA_SECRET_KEY` in the environment before starting the backend. The frontend
can be started with:

```sh
cd frontend
npm ci
npm run dev
```

## API overview

- `POST /token` — obtain a bearer token
- `POST /scan` — run an authorized Nmap scan
- `POST /audit` — run network, TLS, and HTTP-header checks
- `POST /analyze-logs` — apply heuristic rules to supplied logs
- `GET /scans`, `GET /stats`, `GET /alerts` — authenticated dashboard data
- `GET /report/{scan_id}?lang=en|de` — download a PDF report
- `WS /ws/alerts?token=<access-token>` — authenticated live alerts

## Known limitations and next steps

- Log detection and risk scoring are rule-based, not machine-learning based.
- Scan execution is synchronous; there is no queue or multi-tenant isolation.
- The compliance mapping is illustrative and should be validated by qualified
  security and legal professionals.
- Add PostgreSQL-backed persistence, background scan jobs, tenant-scoped
  records, broader test coverage, and deployment-grade secret management before
  production use.
