# TraceLock

Context-Enriched Tamper-Evident Audit Logging with Provenance Verification. This is a research prototype implementing the method described in `docs/research-paper.pdf`.

**Status:** Phase 1 (development environment) is complete. No audit-logging features are implemented yet. See `docs/PROJECT_PLAN.md`.

## Quick start

Requires Docker Desktop.

```bash
cp .env.example .env          # then set POSTGRES_PASSWORD (URL-safe characters only)
docker compose up --build
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:5173 |
| API health | http://localhost:8000/api/v1/health |
| API docs | http://localhost:8000/docs |

Run the tests with `docker compose run --rm backend pytest`. More commands are in `docs/TESTING.md`.

## Repository layout

| Path | Purpose |
|---|---|
| `backend/` | FastAPI application, Alembic migrations, pytest suite |
| `frontend/` | React + Vite + TypeScript dashboard |
| `db/init/` | One-time PostgreSQL initialisation (creates the test database) |
| `docs/` | Plan, architecture, database, API, verification, experiments, security, testing |
