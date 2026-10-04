# TraceLock

**Context-Enriched Tamper-Evident Audit Logging with Provenance Verification.** This is a research prototype that implements and evaluates the method in *"Provenance-Based Context-Enriched Hash Chaining for Secure Audit Logging"* (`docs/research-paper.pdf`).

Every audit event is stored with its **context**: who did it, in which session, after which event, at which position and when. It is hashed with SHA-256 and **chained** to the previous record. The chain is grouped into **Merkle batches**. A verifier recomputes every hash, re-applies five **provenance checks** and rebuilds every batch root. It reports **VALID**, or **TAMPERING DETECTED** with the record, the batch and the check that failed.

> TraceLock is **tamper-evident, not tamper-proof**. Someone who can rewrite *all* records, hashes and batch roots in the database is not detected, and nor is deleting the newest records. The paper states the first limitation itself; the second is noted in `docs/SECURITY_LIMITATIONS.md`, and the tamper lab demonstrates both.

## Features

- **Capture:** hash-chained, context-enriched capture (paper Eq. 1) with an unambiguous, length-prefixed encoding and published test vectors.
- **Provenance:** five checks (who, session, previous event, sequence number, allowed transition) plus timestamp order. Session-rule violations are rejected at capture and logged as `SECURITY_VIOLATION`.
- **Merkle batches:** automatic sealing, O(log m) membership proofs, and leaf-count checks.
- **Verification engine:** reports that name the first failing record, its batch and the check; runs are stored.
- **Operator accounts:** Argon2id passwords, JWT tokens, and three roles (admin, auditor, ingestor). Every sign-in, sign-out and failed attempt is itself a chained audit event.
- **Tamper lab:** 11 controlled scenarios (modification, context forgery, deletion, insertion, reordering, batch deletion, the paper's worked example, tail truncation, full rewrite). Scenarios only ever tamper with cloned lab streams.
- **Experiment harness:** detection rate, false-positive rate, localization accuracy, verification time and storage overhead, computed from stored raw data.
- **React dashboard:** events, hash relationships, proofs, batches, verification, lab and experiment charts.

## Quick start

Requires Docker Desktop.

```bash
cp .env.example .env        # set POSTGRES_PASSWORD (URL-safe characters) and JWT_SECRET (32+ chars)
docker compose up -d --build
docker compose run --rm backend alembic upgrade head
docker compose run --rm backend python -m app.cli create-operator --username admin --role admin
```

Open **http://localhost:5173** and sign in with the admin account you just created. There are no default accounts.

| Service | URL |
|---|---|
| Dashboard | http://localhost:5173 |
| API docs (Swagger) | http://localhost:8000/docs |
| API health | http://localhost:8000/api/v1/health |

**Tamper lab:** it only modifies cloned `lab` streams. To use it, set `TRACELOCK_LAB_ENABLED=true` in `.env`, then run `docker compose up -d backend`.

**More accounts:** use the same CLI with `--role auditor` (can view and verify) or `--role ingestor` (API-only event submission).

## Demo

`docs/DEMO.md` is a 12–15 minute presenter script. To seed and rehearse the demo through the real API:

```bash
export DEMO_ADMIN_PASSWORD='<admin password>'      # PowerShell: $env:DEMO_ADMIN_PASSWORD = "..."
docker compose run --rm -e DEMO_ADMIN_PASSWORD backend python scripts/demo_walkthrough.py
```

## Tests

```bash
docker compose run --rm backend pytest                       # ~300 tests (unit + DB-backed)
docker compose run --rm backend pytest tests/unit            # pure tests, no database needed
docker compose run --rm backend pytest --cov=app --cov-report=term-missing
docker compose run --rm backend ruff check .
docker compose run --rm --no-deps frontend npm run build     # metrics guard + type-check + build
```

More commands are in `docs/TESTING.md`.

## Experiments

```bash
docker compose run --rm backend python -m app.experiments experiments/smoke.json --git-commit "$(git rev-parse --short HEAD)"
docker compose run --rm backend python -m app.experiments experiments/full.json  --git-commit "$(git rev-parse --short HEAD)"   # about an hour
```

- **Where results go:** they are stored in the database and shown on the dashboard's Experiments page.
- **What has been measured:** only the **smoke run** so far (`docs/EXPERIMENTS.md` §6.1). The full matrix has **not** been run yet.

## Documentation

| Document | Contents |
|---|---|
| `docs/PROJECT_PLAN.md` | Phases, acceptance criteria, decisions (Q1–Q16), progress log, known issues |
| `docs/ARCHITECTURE.md` | End-to-end flow, modules, technology stack |
| `docs/VERIFICATION.md` | Encoding, hash chain, provenance checks, Merkle procedure, verification algorithm, test vectors |
| `docs/DATABASE.md` | PostgreSQL schema |
| `docs/API_SPEC.md` | REST API |
| `docs/EXPERIMENTS.md` | Evaluation plan, metric formulas, measured results |
| `docs/SECURITY_LIMITATIONS.md` | Threat model, what is and isn't detected, tested protections |
| `docs/TESTING.md` | Test strategy and results log |
| `docs/DEMO.md` | Presentation demo script and likely questions |

Every requirement in these documents is tagged **[Paper]** (from the paper), **[Rec]** (an implementation choice) or **[Gap]** (where the paper is silent or ambiguous).

## Repository layout

| Path | Purpose |
|---|---|
| `backend/` | FastAPI application, Alembic migrations, experiment harness, pytest suite |
| `frontend/` | React + Vite + TypeScript dashboard |
| `db/init/` | One-time PostgreSQL initialisation (creates the test database) |
| `docs/` | Research paper and project documentation |

## Status

- **Done:** Phases 1–10 (core method, persistence, API, dashboard, tamper lab, experiment harness, final documentation).
- **Not yet done:**
  - the full experiment matrix;
  - a production deployment setup (production images, HTTPS, database privilege separation);
  - keyed hashing, signatures or external anchoring of roots (the paper's future work).

See `docs/PROJECT_PLAN.md` for details.
