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

## Database portability

All database access goes through the SQLAlchemy ORM or Core with no SQLite-specific SQL. SQLite connect arguments are isolated in `db/session.py`. Moving to PostgreSQL means:

1. Add a driver such as `psycopg[binary]` to `requirements.txt`.
2. Set `DATABASE_URL=postgresql+psycopg://...`.
3. Add a `db` service to `docker-compose.yml` that is not published to the host.

Schema migrations (Alembic) will be introduced together with the first ORM models.

## Frontend ↔ backend

The browser only ever requests same-origin paths (`/health`, `/api/v1/...`). In development, the Vite dev server proxies these to `API_PROXY_TARGET`. That variable is server-side only and is never bundled. As a result, no CORS configuration is needed, and the backend origin and keys are never exposed to the client.
