# Security Policy

## Supported versions

EvoNIDS is pre-1.0 software. Security fixes target the latest 0.1.x line only.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1.0 | No        |

## Reporting a vulnerability

Use GitHub **Private Vulnerability Reporting** (Security tab -> "Report a vulnerability").

Do not open a public GitHub issue, and never paste tokens, API keys or raw authenticated responses into issues.

Please include:

- Affected version or commit
- Environment (mock vs real mode, Docker Compose or local processes)
- Reproduction steps or a minimal proof of concept
- Your assessment of the impact
- Whether you would like credit

We handle reports on a best-effort basis and aim to acknowledge new reports within 72 hours. There is no guaranteed fix timeline for a 0.1.x project; we will coordinate disclosure with you and credit reporters who ask for it.

## Areas we especially care about

- **Sensor and admin token handling.** `EVONIDS_ADMIN_API_TOKEN` and `EVONIDS_SENSOR_INGEST_TOKEN` are service-to-service secrets. They must stay server-side; the browser must never receive or hold the admin token.
- **EVE ingestion limits.** The EVE ingestion endpoint must enforce authentication (`EVONIDS_SENSOR_INGEST_TOKEN`, required outside development) and bounded request/file sizes so ingestion cannot become an unauthenticated or unbounded write path.
- **RAG prompt-injection isolation.** Knowledge evidence carries source, authorization, agent-use permission and prompt-injection risk fields. Evidence marked blocked or prompt-injection-like, or without agent-use permission, must never be passed into the Agent context.
- **DeepSeek key handling.** `NUXT_DEEPSEEK_API_KEY` must remain in the Nuxt server runtime config only. It must never reach the browser, logs, error responses, or the upstream response body relayed back to the client.

## Known limitations (please read before reporting)

- The admin token is a service-to-service control, not an end-user authentication system. There is no RBAC, SSO, session management or tenant isolation yet.
- The Nuxt console ships with **optional password authentication** (`NUXT_CONSOLE_PASSWORD`), disabled by default to keep local development and demos friction-free. Once a password is set, login (a signed HttpOnly session cookie issued by `POST /api/auth/login`, with `NUXT_CONSOLE_SESSION_HOURS` controlling the session lifetime, default 24) guards every console page and `/api/**` BFF route. Production deployments must set this password and place the console behind a TLS-terminating reverse proxy.
- Prompt-injection detection is heuristic substring matching over a fixed marker list; crafted variants (Unicode homoglyphs, token splitting, other languages) can evade it. Structured schema validation, evidence-ID whitelisting and the human approval gate are the remaining layers — do not treat the marker filter as a complete defense.
- "Rule deployment" closes the database and audit loop only; no configuration is pushed to real Suricata probes.
- Development defaults (SQLite, localhost CORS, auto-created tables, empty tokens in dev) are conveniences, not production hardening. Production use requires PostgreSQL, secret management, TLS/reverse proxy, backups and monitoring.

Console authentication scope: the optional console password protects only the Nuxt console pages and their server-side BFF routes (`/api/**`). It does **not** protect the FastAPI service — a client connecting directly to a FastAPI endpoint bypasses the console login entirely and remains subject to the admin/sensor token enforcement (`EVONIDS_ADMIN_API_TOKEN` / `EVONIDS_SENSOR_INGEST_TOKEN`, mandatory outside development).

These limitations are documented in the READMEs; reports that only restate them will not be treated as vulnerabilities.

## Secrets hygiene

Never commit `.env`, API keys or tokens to the repository. If you accidentally leak a credential in an issue, screenshot or log, rotate it immediately and notify us through the private reporting channel.
