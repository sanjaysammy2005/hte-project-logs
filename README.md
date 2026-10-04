# TraceLock

Context-Enriched Tamper-Evident Audit Logging with Provenance Verification. This is a research prototype implementing the method described in `docs/research-paper.pdf`.

**Status:** Phases 1–5 are complete: environment, hash chain, Merkle trees, provenance checks, persistence, ingestion API and operator authentication. See `docs/PROJECT_PLAN.md`.

## Quick start

Requires Docker Desktop.

```bash
cp .env.example .env          # then set POSTGRES_PASSWORD (URL-safe characters) and JWT_SECRET (32+ chars)
docker compose up --build
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:5173 |
| API health | http://localhost:8000/api/v1/health |
| API docs | http://localhost:8000/docs |

Create the first admin account (password read from `TRACELOCK_OPERATOR_PASSWORD`, otherwise prompted):

```bash
docker compose run --rm backend alembic upgrade head
docker compose run --rm backend python -m app.cli create-operator --username admin --role admin
```

To use the tamper lab (it only ever modifies cloned `lab` streams), set `TRACELOCK_LAB_ENABLED=true` in `.env` and restart the backend.

Run the tests with `docker compose run --rm backend pytest`. More commands are in `docs/TESTING.md`.

## Repository layout

| Path | Purpose |
|---|---|
| `backend/` | FastAPI application, Alembic migrations, pytest suite |
| `frontend/` | React + Vite + TypeScript dashboard |
| `db/init/` | One-time PostgreSQL initialisation (creates the test database) |
| `docs/` | Plan, architecture, database, API, verification, experiments, security, testing |
