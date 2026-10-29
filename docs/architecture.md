# Architecture

## Components

| Component | Tech | Responsibility |
|-----------|------|----------------|
| Frontend | React 19, TypeScript, Vite 7, Tailwind 4, React Router 7 | Analyst UI. Holds no secrets; talks only to the ThreatScope backend over same-origin paths. |
| Backend | FastAPI, Pydantic 2, SQLAlchemy 2 | API, enrichment orchestration, persistence, and all provider communication. |
| Database | SQLite (dev) → PostgreSQL (planned) | Investigations, watchlist, cached enrichment results. |

## Backend layers

```
api/routes  →  services  →  providers   (outbound, allowlisted hosts only)
     │             │
  schemas        models  →  db/session  →  DATABASE_URL
     └──── core/config (Settings) ────┘
```

- **Routes** parse and validate input with Pydantic schemas, call one service, and return a schema. No SQL and no business logic.
- **Services** hold the business logic. They take a `Session` and `Settings` as arguments, which keeps them testable without HTTP.
- **Providers** are the only code allowed to make network calls. Each adapter targets one fixed, configured endpoint (see `docs/security.md`).
- **Models / schemas** are kept separate. ORM objects are never returned directly from routes.
- **App factory**: `create_app(settings)` builds the engine and session factory and stores them on `app.state`. Tests pass an isolated `Settings` that points at a temporary SQLite file.

## IOC pipeline

```
raw string ─► length cap ─► strip ─► reject whitespace/control chars ─► refang
          ─► detect: URL (has "://") → hash (hex length 32/40/64) → IP → domain
          ─► IOC(type, normalized value, original, refanged, network_scope)
```

- **Strict parsing:** IPv4 must use dotted decimal. Integer, hex, octal, and shortened forms (`2130706433`, `0x7f.0.0.1`, `127.1`) are rejected, because they are common obfuscations. IPv6 is compressed and lowercased, and IPv4-mapped addresses are scoped by the IPv4 they embed. Domains are lowercased, have any trailing dot removed, and are IDNA-encoded. URLs only allow `http`, `https`, and `ftp`; the scheme and host are lowercased, while the path and query are kept exactly as given.
- **Scope is informational:** `network_scope` (public, private, loopback, link_local, internal_hostname, …) tells analysts what a value is. Hostname scope comes from the name alone, since names are never resolved.
- **Endpoints:** `POST /api/investigate` returns `201` with an investigation object (not persisted yet; enrichment `not_started`). `POST /api/investigate/bulk` validates up to 500 IOCs, reports a result for each one, and returns a summary.

## Providers and risk

```
IOC ─► enrich(): VirusTotal ┐
                 AbuseIPDB  ├─ concurrent, each → ProviderResult (never raises)
                 OTX        ┘
    ─► assess(): weighted signals → score 0-100, level, factors
```

- `providers/base.Provider` implements request safety and failure handling once. Adapters only map an IOC to a path and params, and map the response JSON to `ProviderResult`.
- **Statuses:** `ok`, `not_found` (provider answered), `not_supported`, `skipped` (internal IOC), `not_configured` (not attempted), and `rate_limited`, `auth_error`, `timeout`, `unavailable`, `error` (attempted and failed). After a 429, a provider is paused for `Retry-After` seconds (default 60).
- **Enrichment status:** `completed`, `partial` (some providers failed), `failed`, or `no_providers`.
- **Risk:** see [`risk-scoring.md`](risk-scoring.md).
- `ProviderHealth` (in memory) records the latest live outcome per provider for `GET /api/providers/status`.
- Bulk analysis remains validation-only, because provider quotas make bulk enrichment a separate design problem.

## Database portability

All database access goes through the SQLAlchemy ORM or Core with no SQLite-specific SQL. SQLite connect arguments are isolated in `db/session.py`. Moving to PostgreSQL means:

1. Add a driver such as `psycopg[binary]` to `requirements.txt`.
2. Set `DATABASE_URL=postgresql+psycopg://...`.
3. Add a `db` service to `docker-compose.yml` that is not published to the host.

Schema migrations (Alembic) will be introduced together with the first ORM models.

## Frontend ↔ backend

The browser only ever requests same-origin paths (`/health`, `/api/...`). In development, the Vite dev server proxies these to `API_PROXY_TARGET`. That variable is server-side only and is never bundled. As a result, no CORS configuration is needed, and the backend origin and keys are never exposed to the client.
