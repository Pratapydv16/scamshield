# ScamShield AI

A responsive security-awareness site and API for reviewing suspicious URLs, email, SMS, and payment requests. The detector combines transparent local heuristics with an optional Google Web Risk Lookup API check for URLs. It does not include a trained model, domain-age lookup, or page-content analysis; a low score is not a safety guarantee.

## What is included

- React + TypeScript + Vite + Tailwind CSS responsive single-page checker.
- Four input types, client validation, loading/error states, and a clearly labeled simulated demo option.
- FastAPI validation, HTTP API documentation, CORS allowlist, rate limits, secure password hashing, JWT authentication, API-key authentication, and safe structured logs.
- Optional Google Web Risk checks for website links, with explicit per-scan consent and an honest unavailable state when the provider is not configured.
- Heuristic checks for URL structure, tokenized language/phrase patterns, payment/credential requests, and email header mismatches when headers are supplied.
- PostgreSQL schema migration and SQLite local-development default.
- Scan history and API-key management endpoints remain available through the API. The simplified web interface has no login or pricing pages. No payment processing or paid billing is enabled.

The web interface sends scans to the FastAPI service unless **Use simulated demo result** is selected. A user must explicitly opt in before a website URL is sent to Google Web Risk; other text types are never sent to Google. Authentication and account management are API-only; they are not exposed in the simplified interface.

## Requirements

- Node.js 20+ and npm
- Python 3.11+
- PostgreSQL 14+ for a persistent deployment (SQLite is used locally)

## Local setup

1. Copy `.env.example` to `.env`. Set `JWT_SECRET` to a new random value (for example `python -c "import secrets; print(secrets.token_urlsafe(48))"`). To enable live URL lookups locally, set `GOOGLE_WEB_RISK_API_KEY` in this server-side `.env`; never put it in a `VITE_` variable. Google Cloud must have Web Risk enabled and billing/quota configured.
2. From the project root, start the API:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r backend\requirements.txt
   uvicorn backend.app.main:app --reload --env-file .env
   ```

   Set `JWT_SECRET` in `.env` to a generated secret before starting. API docs are available at `http://localhost:8000/docs`; readiness is `http://localhost:8000/health`.
3. In a separate terminal, install and start the frontend:

   ```powershell
   npm install
   npm run dev
   ```

4. Open the Vite URL (typically `http://localhost:5173`). Choose **Use simulated demo result** for clearly labeled sample output. For live URL lookups, leave demo mode off and explicitly select the Google Web Risk consent checkbox. Without a configured key, scans still return local heuristic results and clearly report that the provider is unavailable.

For PostgreSQL, configure `DATABASE_URL` for SQLAlchemy and your usual `PGHOST`/`PGDATABASE`/`PGUSER`/`PGPASSWORD` variables, then apply `backend/migrations/001_initial.sql` with `psql -f backend\migrations\001_initial.sql` in PowerShell before deploying. Local startup creates missing tables for convenience; use migrations as the production schema source.

## API

- `GET /health` — reports configured detection capabilities.
- `POST /api/v1/scans` — public, rate-limited scan; optional bearer JWT or `ss_live_` API key associates scan with a user. Body: `{"scan_type":"url|email|sms|payment","input":"...","share_with_google":false}`. Set `share_with_google` to `true` only with the submitter's consent; this is supported for URL scans only.
- `POST /api/v1/auth/register` — create an account (password minimum 12 characters).
- `POST /api/v1/auth/login` — obtain a short-lived JWT.
- `GET /api/v1/auth/me` — authenticated account information.
- `GET /api/v1/scans` — authenticated scan history.
- `POST /api/v1/api-keys` — authenticated API key issuance; raw key is returned once.
- `GET /api/v1/api-keys` / `DELETE /api/v1/api-keys/{key_id}` — authenticated key management.
- OpenAPI UI: `/docs`; OpenAPI JSON: `/openapi.json`.

The database stores a keyed HMAC digest of submitted content, not the submitted content itself. With consent, a URL scan sends the full URL (including its path and query) to Google Web Risk for list matching. The API response contains scan findings and should be handled as sensitive data by clients. Logs do not include scan content or credentials.

## Detection and safety limits

The scanner never opens or fetches a user-provided website. If the submitter opts in and `GOOGLE_WEB_RISK_API_KEY` is configured, the backend sends the URL to Google's Web Risk Lookup API and combines any listed threat match with local heuristic findings. A no-match result only means the URL was not found on the queried lists; it is not a guarantee of safety. Provider errors and missing configuration are shown explicitly. URL checks do not validate live DNS, certificate chains, redirects, domain registration age, or page contents. HTTPS indicates the URL scheme only; it is not a certificate check. Email authentication checks only examine headers the user supplied; a text-only paste cannot establish SPF/DKIM/DMARC validity. Text processing uses token and phrase rules, not a trained NLP/ML model; the ML integration is an unconfigured interface (`detection_engine/models.py`). Heuristic scores are not fraud probabilities.

## Netlify + Render deployment

The project includes `netlify.toml` for the static frontend and `render.yaml` for a small Render API service. These files prepare deployment; they do not publish the site by themselves.

1. Push the project to a Git provider and connect that repository to Netlify and Render.
2. Deploy the Render Blueprint. Set `GOOGLE_WEB_RISK_API_KEY` as a secret in the Render dashboard and set `CORS_ORIGINS` to the exact deployed Netlify origin (for example, `https://your-site.netlify.app`).
3. In Netlify, set `VITE_API_URL` to the Render API base, ending in `/api/v1` (for example, `https://your-api.onrender.com/api/v1`), then redeploy.
4. Enable Google Web Risk in a Google Cloud project, create an API key restricted to the Web Risk API, and set billing and quotas there. Never put this key in Netlify or client-side code.

The Render Blueprint uses a free web service and local SQLite for initial testing; its local database is not durable across service replacement. Configure PostgreSQL via `DATABASE_URL` for durable deployment. Public deployments should review provider costs and quotas, abuse controls, data retention, and proxy-aware rate limiting before sharing the site broadly.

Before production, configure HTTPS and a strong secret, restrict CORS to deployed origins, deploy PostgreSQL backups, run the migration, set proxy-aware rate-limit identity handling, add monitoring/retention policy, review jurisdiction-specific privacy obligations, and connect only vetted optional reputation/model providers. Billing tiers are display examples with configurable free limits; payment collection and subscription billing are not implemented.

## Tests

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
$env:JWT_SECRET = "test-only-secret-that-is-never-used-outside-tests"
python -m pytest backend\tests
```

Frontend production build:

```powershell
npm install
npm run build
```
