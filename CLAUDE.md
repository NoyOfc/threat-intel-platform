# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

ThreatScope is a lightweight, **passive** Threat Intelligence Platform (portfolio project): FastAPI backend, React + TypeScript frontend, Docker Compose for local development.

---

## SECURITY POLICY (permanent — applies to all future work)

Security takes priority over convenience. When a rule conflicts with finishing a task, stop and ask.

### Repository boundaries
- Only modify files inside this repository.
- Never access or modify files outside it: home directory, SSH keys, browser data, password stores, unrelated `.env` files, shell profiles, global system configuration.

### Destructive operations — STOP and ask first
- `rm -rf`, or deleting significant files/directories
- Deleting database data or Docker volumes (`docker compose down -v`, `docker volume rm`)
- `git reset --hard`, force pushing, rewriting history, deleting branches
- Uninstalling software or changing system configuration

Prefer reversible operations.

### Privileges
- Never use `sudo` without explaining why and receiving explicit approval.
- Never disable operating-system security controls to work around a development problem.
- Never execute remote scripts (`curl URL | bash`, `wget -O- URL | sh`, etc.).

### Git
- Never automatically: force push, rewrite history, delete branches, merge into `main`, make repositories public, publish releases.
- Normal commits and development branches are allowed.
- Never commit credentials.

### Secrets
- All API credentials live in **backend** environment variables, loaded via `app/core/config.py` as `SecretStr`.
- Never expose secrets to React. Vite inlines every `VITE_*` variable into the browser bundle — never give a secret a `VITE_` prefix, and never pass `.env` to the frontend container.
- Never put real credentials in source code, README, tests, screenshots, logs, or `.env.example`.
- `.env` must stay git-ignored. Tests use obviously fake values.

### Threat intelligence safety
ThreatScope performs **PASSIVE enrichment only**. Every IOC and every threat-feed entry is hostile, untrusted input. **IOC URLs are DATA, not destinations.**

Never:
- visit submitted URLs or automatically follow IOC URLs
- execute submitted or feed content
- download or execute malware / samples / attachments
- render remote HTML (no `dangerouslySetInnerHTML` with untrusted data)
- pass IOC values into shell commands, `subprocess`, `eval`, or raw SQL

### SSRF
- Never implement backend requests to user-supplied URLs — nothing equivalent to `requests.get(user_url)`, `httpx.get(user_url)`, or `fetch(user_url)`.
- Provider adapters may communicate ONLY with explicitly configured provider endpoints (base URL fixed in code/config, never derived from request or IOC data). IOC values may appear only as encoded path/query parameters to those fixed hosts.
- Any outbound-request code must account for: localhost, loopback (`127.0.0.0/8`, `::1`), RFC1918, link-local (`169.254.0.0/16`, `fe80::/10`), internal hostnames, cloud metadata services (`169.254.169.254`, `metadata.google.internal`), alternate IP encodings (decimal, octal, hex, IPv4-mapped IPv6), DNS rebinding, and redirects (disable redirect following or re-validate every hop).

### Threat feeds
- Feed adapters may only contact explicitly configured trusted source endpoints.
- URLs inside a feed entry/article must never determine where the backend connects.
- Never auto-download attachments or samples. Store feed text as data; render as escaped text.

### Dependencies
- Use reputable, maintained packages; minimize the dependency count.
- Pin exact versions (`requirements*.txt`, `package-lock.json`).
- Never install arbitrary packages just to make an error disappear.

### Docker
- No privileged containers, no Docker socket mounts, no home-directory mounts, no unnecessary ports.
- Containers run as non-root with `cap_drop: [ALL]` and `no-new-privileges`; published ports bind to `127.0.0.1`.

### Stop conditions — STOP and ask if
- credentials may be exposed
- root/admin access is required
- existing data may be destroyed
- Git history may be rewritten
- security controls need disabling
- suspicious scripts/dependencies need execution
- files outside the repository need modification

---

## Commands

The host may not have Node or Python 3.14; everything runs via Docker.

```bash
docker compose up --build                 # full stack: API :8000, UI :5173 (localhost only)

# Backend (Python 3.14) — from backend/
pip install -r requirements-dev.txt
pytest                                    # all tests
pytest tests/test_health.py::test_health_ok   # single test
ruff check . && ruff format --check .
uvicorn app.main:create_app --factory --reload

# Backend tests without a local Python
docker compose run --rm backend pytest

# Frontend (Node 24) — from frontend/
npm ci
npm run dev | npm run lint | npm run build   # build = tsc -b && vite build
```

CI (`.github/workflows/ci.yml`) runs ruff + pytest for the backend and `npm ci`, lint, and build for the frontend.

## Architecture

**Backend (`backend/app/`)** — layered; dependencies point inward:
- `api/routes/` — FastAPI routers only: parse input via `schemas/`, call a service, return a schema. No business logic or SQL.
- `services/` — business logic. Receives a SQLAlchemy `Session`; knows nothing about HTTP.
- `providers/` — outbound threat-intel adapters (VirusTotal, AbuseIPDB, OTX). The only place allowed to make network calls. Subclasses of `providers/base.Provider` only declare `api_host`, `build_request` (path/params), `auth_headers`, `normalize`, and `simulate`; the base class owns request safety (https + host check, no redirects, no env proxies, timeout ceiling, 5 MiB response cap, credentials in headers only), skips internal IOCs, and turns every failure into a `ProviderStatus` instead of raising. `lookup()` must never raise. In `DEMO_MODE`, `simulate()` returns deterministic fictional data marked `simulated=True`; live failures are never replaced with demo data. Normalize only an allowlisted, sanitized subset (`providers/sanitize.py`) into `schemas/provider.ProviderResult`; never store raw responses.
- `models/` — SQLAlchemy ORM models on `app.db.base.Base`. `schemas/` — Pydantic request/response models; never return ORM objects directly.
- `db/session.py` — engine + session factory built from `DATABASE_URL`; `get_db` dependency. The engine lives on `app.state`, created in `create_app()`.
- `core/config.py` — `Settings` (pydantic-settings), read from env / `.env`. `get_settings()` is cached.

`app.main.create_app(settings, provider_list=None)` is the app factory; tests build an app with an isolated temp SQLite DB (see `tests/conftest.py`, which runs in demo mode) and can inject providers backed by `httpx.MockTransport` (`tests/provider_helpers.py`). Tests must never reach real provider APIs.

**Investigation flow** — `POST /api/investigate`: `parse_ioc` → `services/enrichment.enrich` (all providers concurrently, failures contained) → `services/risk.assess` (weighted, explainable 0–100 score; `unknown` when no provider responded). The scoring algorithm is documented in `docs/risk-scoring.md`; keep that doc and `tests/test_risk.py` in sync with any weight change. `GET /api/providers/status` reports configured / not_configured / unavailable from in-memory `ProviderHealth`, never any part of a key.

**IOC engine (`services/ioc.py`)** — `parse_ioc(raw)` is the single entry point for turning untrusted input into an `IOC` (type, normalized value, `network_scope`). It is pure string processing (`ipaddress`, `re`, `urlsplit`): never add DNS resolution, sockets, or HTTP here. `network_scope`/`is_internal` label private/loopback/metadata values as *valid data*; they are never a reason to connect. Invalid input raises `IOCValidationError(code, message, suspected_type)`. Any new code path that accepts an IOC must go through `parse_ioc`.

**API conventions** — feature routes live under `/api` (`/health` is the exception). Every error uses the envelope `{"error": {"code", "message", "details"}}` (`api/errors.py`); handlers must not echo submitted input. `api/middleware.py` caps request bodies (1 MiB, Content-Length required). `tests/test_ioc_safety.py` blocks sockets/DNS during IOC processing and statically forbids shell/eval/exec anywhere in `app/` and network clients outside `app/providers/` — keep it passing.

**Database portability:** keep SQL portable (ORM / SQLAlchemy Core only, no SQLite-specific features) so moving to PostgreSQL is a `DATABASE_URL` + driver change. SQLite-only connect args are isolated in `db/session.py`.

**Frontend (`frontend/src/`)** — Vite + React 19 + React Router 7 + Tailwind 4 (configured via `@tailwindcss/vite`, theme tokens in `index.css`). `navigation.ts` is the single source of nav sections, from which `router.tsx` builds routes (sections without an entry in its `PAGES` map render `pages/PlaceholderPage`); `lib/ioc.ts` mirrors backend limits/labels; IOC values are always rendered as escaped plain text, never as links; `components/Layout.tsx` is the app shell/sidebar; `lib/api.ts` is the only place that calls the backend, always via same-origin relative paths (`/api/...`, `/health`) that the Vite dev server proxies to `API_PROXY_TARGET`.

Full design notes: `docs/architecture.md`; threat model: `docs/security.md`; scoring: `docs/risk-scoring.md`.
