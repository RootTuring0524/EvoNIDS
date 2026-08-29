# Contributing to EvoNIDS

Thanks for your interest in improving EvoNIDS. This document covers the local development setup, repository layout, commit conventions and pull request expectations.

## Prerequisites

- Python 3.11+ (the `py` launcher on Windows)
- Node.js >= 22 with Corepack enabled (`packageManager` pins pnpm 11.13.1)
- Docker Desktop (optional, for the container stack)
- The command examples below use PowerShell; translate to your shell as needed

## Development setup

### Backend (`backend/`)

```powershell
Set-Location "<your clone>\backend"
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,ml]"
Copy-Item .env.example .env   # then edit backend/.env
alembic upgrade head
uvicorn app.main:app --reload # API docs at http://127.0.0.1:8000/docs
pytest
```

The `dev` extra installs pytest, httpx and ruff; the `ml` extra installs numpy, pandas, scikit-learn and torch for the CPU training pipelines.

### Frontend (`project/`)

```powershell
Set-Location "<your clone>\project"
corepack pnpm install
pnpm hooks:install            # optional: prepare husky git hooks (the repo ships without active hooks)
pnpm dev                      # console at http://localhost:3000/overview
```

Quality commands (actual script names from `project/package.json`):

| Command | Purpose |
| --- | --- |
| `pnpm lint` / `pnpm lint:fix` | ESLint |
| `pnpm format` | Prettier |
| `pnpm typecheck` | Nuxt/vue-tsc type checking |
| `pnpm test` (alias `pnpm test:unit`) | Vitest unit tests |
| `pnpm test:e2e` | Playwright end-to-end tests |
| `pnpm validate` | typecheck + lint + unit tests in one command |
| `pnpm build` / `pnpm preview` | production build / serve it |

### Mock vs real mode

`NUXT_PUBLIC_USE_MOCK_API=true` runs the deterministic UI demo with no backend. Setting it to `false` plus `NUXT_BACKEND_API_BASE` and matching admin/sensor token pairs proxies through the Nuxt BFF to FastAPI. See the root `README.md` and `.env.example`; never commit a real `.env`.

## Repository tour

```
backend/
  app/
    api/        FastAPI routers (routes/), router.py and token security
    core/       pydantic-settings configuration
    db/         SQLAlchemy models, session handling
    domain/     feature building and structured rule interpretation
    ingestion/  Suricata EVE JSON/NDJSON parsing
    schemas/    Pydantic request/response schemas
    services/   sensor ops, alert ops, EVE ingestion, dataset catalog,
                training, autoencoder, model registry, rule lifecycle,
                knowledge retrieval
    main.py     FastAPI application
  alembic/      database migrations
  scripts/      dataset extraction, baseline bootstrap, replay import,
                dual-channel inference backfill, demo seed
  tests/        pytest suite

project/
  app/
    pages/      11 console pages: overview, traffic, sensors, alerts,
                alerts/[id], rules, rules/[id], knowledge, models, audit,
                settings (index.vue only redirects)
    components/ console UI: tables, charts, lifecycle dialogs, agent panel,
                evidence views
    composables/ stores/ (Pinia) layouts/ middleware/ plugins/ types/ utils/
  server/       Nuxt BFF (Nitro)
    api/        server routes proxying FastAPI: alerts, datasets, flows,
                ingestion, models, overview, rag, rules, sensors, audit,
                settings, training, agent/analyze
    services/   server-only clients (DeepSeek lives here; the API key never
                leaves the server runtime)
    utils/
  shared/       contract layer shared by app and server:
    schemas/    zod schemas
    types/      TypeScript types
```

## Commit conventions

The repository uses [Conventional Commits](https://www.conventionalcommits.org/). The `project/.husky/` directory intentionally ships without active hook scripts, so the convention is currently a guideline rather than an enforced gate; `pnpm commitlint` and lint-staged are wired up and can be enabled locally via `pnpm hooks:install`. lint-staged runs ESLint + Prettier on staged `ts`/`vue` files and Prettier on `css`/`md`/`json`.

```
feat(ingestion): bound EVE file import size
fix(rules): keep deprecated rules out of candidate validation
docs: clarify dataset registry workflow
```

Use types `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`. Breaking changes require `!` or a `BREAKING CHANGE:` footer.

## Code style

- Backend: ruff (line length 120, target py311). Run `python -m ruff check app tests` from `backend/`.
- Frontend: ESLint (`@nuxt/eslint`) plus Prettier. Run `pnpm lint` and `pnpm format` from `project/`.

## Pull requests

1. Branch from the default branch and keep the diff focused on one change.
2. Follow the commit conventions above; PR titles follow the same rules.
3. Before opening the PR:
   - backend changes: `pytest` and `python -m ruff check app tests` pass;
   - frontend changes: `pnpm validate` passes;
   - no secrets, tokens, `.env` files or real dataset files are committed.
4. Describe what changed, why, how to test it, and any behavior changes. Link related issues.

## Test requirements

- Changes to the shared contract layer (`project/shared/`) must come with tests: Vitest on the BFF/consumer side, and pytest when the FastAPI schemas change too.
- Changes to the rule lifecycle (state transitions, replay validation) must include tests covering the new transitions and their audit behavior.
- Changes to EVE ingestion, dataset profiling or knowledge-evidence filtering should include regression tests for idempotency and filtering behavior.

## Security issues

Do not open public issues for security problems. See [SECURITY.md](SECURITY.md).
