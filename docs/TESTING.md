# TraceLock — Testing Strategy

Tags: **[Paper]** · **[Rec]**.

**Status:** the Phase 1 tooling is in place. The commands in §2 work. Run them from the repository root after creating `.env` from `.env.example`.

## 1. Approach [Rec]

| Layer | What | Needs DB? | Tools |
|---|---|---|---|
| Unit | `crypto/` (canonical, chain, merkle) and `provenance/` pure functions | No | pytest |
| Integration | ingestion service, batching, verification engine on PostgreSQL | Yes (`tracelock_test` DB) | pytest, SQLAlchemy |
| API | endpoints, auth, roles, error shapes | Yes | pytest + HTTPX (`ASGITransport`) |
| Scenario | tamper lab end-to-end, expected vs actual | Yes | pytest |
| Frontend | build + type-check; component tests optional | No | `tsc`, `vite build` (Vitest only if approved) |

Rules:
- Security-relevant code is tested **before** moving to the next phase (CLAUDE.md rule 11).
- **Independent oracles.** Hash and Merkle tests compare against a separate minimal reference written directly with `hashlib` in the test file, not against the production code's own output.
- **Fixed seeds** for anything randomised. Property-style tests loop over seeded random inputs, so no extra library is required.
- **Isolation.** Every integration test runs inside a transaction that is rolled back, or on a freshly created stream.
- **No hard-coded expected metrics.** Experiment code is tested for correct *formulas* on small hand-computed fixtures, never against target numbers.

## 2. Commands

`docker compose run --rm backend …` starts the `db` service automatically. Tests use the `tracelock_test` database, which is created on the first start of the DB volume by `db/init/01-create-test-database.sql`.

```bash
docker compose run --rm backend pytest                         # all tests
docker compose run --rm backend pytest tests/unit              # unit tests only
docker compose run --rm backend pytest tests/api/test_health.py::test_health_503_when_database_unreachable   # single test
docker compose run --rm backend pytest --cov=app --cov-report=term-missing
docker compose run --rm backend ruff check .                   # lint
docker compose run --rm backend ruff format --check .          # formatting
docker compose run --rm --no-deps frontend npm run build       # metrics guard + type-check + production build
```

## 3. Required test cases by phase

### Phase 1
- T1.1 Health endpoint returns 200 with the DB up and 503 with the DB down.
- T1.2 Settings load from the environment, and missing required secrets fail at startup.

### Phase 2 — canonical serialization and chain
- T2.1 The same record with permuted payload key order gives identical bytes.
- T2.2 NFC/NFD forms of the same text give identical bytes (after normalisation).
- T2.3 Field-boundary ambiguity: ("U1","0S") ≠ ("U10","S"); null ≠ empty string.
- T2.4 Floats in the payload are rejected, and the timestamp is formatted with microseconds and the `Z` suffix.
- T2.5 A valid chain of 1, 2 and 100 records verifies as VALID.
- T2.6 Modified event (type and payload) → CHAIN_HASH fails at k.
- T2.7 Modified context (user, session, prev_event, seq, timestamp, each separately) → CHAIN_HASH fails at k.
- T2.8 Deleted record → CHAIN_INDEX_CONTINUITY and CHAIN_LINK fail at the successor.
- T2.9 Inserted record (with a correctly self-computed hash) → CHAIN_LINK fails at the successor.
- T2.10 Reordered records → CHAIN_LINK fails at the first swapped position.
- T2.11 The published test vector matches the independent `hashlib` reference.

Implemented in `tests/unit/crypto/`:
- `test_canonical.py` covers T2.1–T2.4.
- `test_chain.py` covers T2.5–T2.10. It also documents two limitations: tail truncation and the A2 full rewrite.
- `test_vectors.py` covers T2.11, plus a differential test of production vs reference on 1,000 random records.

The independent oracle is `tests/reference_tl_v1.py`.

### Phase 3 — Merkle
- T3.1 A single-event batch has root = leaf.
- T3.2 Even-sized batches (2, 4, 8) match the reference.
- T3.3 Odd-sized batches (3, 5, 7, 9) match the reference with last-node duplication.
- T3.4 Every leaf's proof verifies, and the proof length is ⌈log₂ m⌉.
- T3.5 Altering any one leaf changes the root and invalidates the proofs.
- T3.6 A proof with a tampered sibling or a wrong position fails.
- T3.7 [a,b,c] vs [a,b,c,c] has the same root (documents the weakness) and is caught by the `leaf_count` check.

### Phase 4 — provenance
- T4.1 PROV_WHO: the actor differs from the session owner → fail. A matching actor passes.
- T4.2 PROV_SESSION: an event after LOGOUT, a reused session ID, or a timestamp before session start → fail.
- T4.3 PROV_PREV_EVENT: the stored previous type differs from the actual predecessor → fail.
- T4.4 PROV_SEQUENCE: a gap or a duplicate → fail.
- T4.5 PROV_TRANSITION: a disallowed pair → fail. Every allowed pair in `transitions.v1` → pass.
- T4.6 **Paper worked example (§VI-F):** deleting AUTHENTICATION gives exactly the predicted findings.
- T4.7 Interleaved concurrent sessions and sessionless events → VALID. The session checks are N/A for sessionless events.
- T4.8 PROV_TIMESTAMP_ORDER: a decreasing timestamp → fail.

### Phase 5 — persistence, ingestion, auth
- T5.1 Migrations go up and down cleanly.
- T5.2 Server-only fields in a request → 422.
- T5.3 Records re-hash correctly after a DB round-trip (timestamp, jsonb payload).
- T5.4 Concurrency: 20 × 50 parallel ingests → gapless, unique, valid chain.
- T5.5 The ingestion policy for session violations (Q6) works as decided.
- T5.6 Unauthenticated → 401; wrong role → 403 for every protected endpoint (parametrised).
- T5.7 Passwords are stored as Argon2 hashes, and do not appear in logs (log capture assertion).
- T5.8 An expired or tampered JWT is rejected.

### Phase 6 — batching and verification
- T6.1 Sealing produces contiguous, non-overlapping batches with correct leaf counts.
- T6.2 An untampered stream → VALID with zero findings.
- T6.3 Each of T2.6–T2.10 repeated on DB rows → TAMPERING_DETECTED with the correct first index and batch ID.
- T6.4 An altered `merkle_root` or `leaf_count` → MERKLE_ROOT / MERKLE_RANGE fails.
- T6.5 Unbatched records are counted correctly.
- T6.6 The API proof verifies with `verify_proof()`.

### Phase 7 — lab
- T7.1 The lab is disabled by default (404).
- T7.2 Mutation of a `primary` stream is refused at the service layer.
- T7.3 The same seed produces an identical synthetic stream.
- T7.4 Each scenario S1–S11 stores its expected outcome before verification, and the actual outcome after.
- T7.5 The negative controls S10 and S11 report "not detected".

### Phase 8 — dashboard
- T8.1 The frontend builds and type-checks.
- T8.2 A grep check finds no hard-coded metric values in the frontend source.

### Phase 9 — experiments
- T9.1 Metric formulas are correct on small hand-computed fixtures.
- T9.2 The environment metadata is captured.
- T9.3 Re-running with the same seed reproduces the detection outcomes.

## 4. Test results log

| Date | Phase | Command | Result |
|---|---|---|---|
| 2026-10-04 | 1 | `pytest -v --cov=app` | 6 passed (T1.1 ×2, T1.2 ×4), 1 deprecation warning (see PROJECT_PLAN known issues); coverage 89% overall. `db/base.py` has no models to exercise yet. |
| 2026-10-04 | 1 | `ruff check .`, `ruff format --check .` | clean |
| 2026-10-04 | 1 | `npm run build` | type-check + build OK |
| 2026-10-04 | 1 | manual: stop `db` → `GET /api/v1/health` | 503 `{"status":"degraded","database":"unavailable"}` in about 3.9 s (connect timeout); 200 again after restart |
| 2026-10-04 | 1 | manual: `alembic upgrade head` | OK (no revisions yet) |
| 2026-10-04 | 2 | `pytest --cov=app.crypto` | 82 passed (76 crypto + 6 Phase 1); `canonical.py` and `chain.py` 100% line coverage |
| 2026-10-04 | 2 | `pytest tests/unit` with no DB env vars, `--no-deps` | 80 passed (unit tests are DB-independent) |
| 2026-10-04 | 10 | `pytest --cov=app` | 295 passed; 97% coverage. Lab and experiment tests now force the lab setting explicitly (they previously failed when a developer's `.env` enabled the lab) |
| 2026-10-04 | 10 | `scripts/demo_walkthrough.py` against the live stack | all six demo sections completed; S1/S3/S5/S9 detected, S10/S11 not detected, as expected |
| 2026-10-04 | 9 | `pytest --cov=app` | 294 passed; 97% coverage. T9.1 Wilson intervals, quartiles, DR/FPR/LA/storage on hand-computed fixtures; T9.2 environment captured (CPU, memory, PostgreSQL, packages, commit, timer); T9.3 the same configuration reproduces identical detection outcomes; tiny end-to-end run leaves no lab streams; API background run, CSV/JSON export |
| 2026-10-04 | 9 | `python -m app.experiments experiments/smoke.json` | completed in about 18 s; results in EXPERIMENTS §6.1 |
| 2026-10-04 | 8 | `npm run build` in the frontend container | T8.1 type-check + production build OK; T8.2 `check:metrics` OK on `src/`, and it fails (exit 1) on a planted `y: [0.97, 1]` and a planted `detectionRate = 98.5`. A manual browser walkthrough is still pending. |
| 2026-10-04 | 7 | `pytest --cov=app` | 276 passed; 98% coverage. T7.1 lab 404 by default and admin-only; T7.2 `apply_tampering` refuses system and synthetic streams; source rows unchanged after scenarios; lab clones cannot be sources; T7.3 identical rows and hashes for the same seed, different for another seed; generated streams verify VALID with interleaving; T7.4 S1–S11 each match the stored expectation, and the expectation is stored before verification; S1/S3/S6/S7 located at the true record; S9 shows the paper's provenance findings; T7.5 S10 and S11 reported as not detected |
| 2026-10-04 | 6 | `pytest --cov=app` (×3) | 242 passed each run; 99% coverage. T6.1 auto + manual sealing, single-leaf root = leaf, sealing refuses gaps; T6.2 untampered → VALID, run persisted, last status in stream list, system stream verifies; T6.3 SQL tampering: payload, context, deletion, reorder, insertion; T6.4 altered root, shrunk range; T6.5 unbatched count; T6.6 API proof verifies locally and via `/proofs/verify`; engine unit tests (gaps, whole-batch deletion, explained-batch rule); JWT clock-skew regression tests |
| 2026-10-04 | 5 | `pytest --cov=app` | 212 passed; 99% total coverage. T5.1 migrations down/up + DB constraints; T5.2 server-only fields → 422; T5.3 round-trip re-hash (11 records incl. Unicode/nested payload); T5.4 20×50 parallel appends → gapless valid chain with interleaving; T5.5 four violation cases → 409 + SECURITY_VIOLATION, stream still valid; T5.6 401 on 10 endpoints, 403 on 6 role cases; T5.7 Argon2id, no password in DB/logs/422 bodies; T5.8 expired, bad signature, alg=none, garbage and role-escalation tokens rejected; logout revokes token; clock step-back clamp |
| 2026-10-04 | 4 | `pytest tests/unit --cov=app.crypto --cov=app.provenance` | 151 passed, 100% coverage. Deliberate breaks: transition checked against stored instead of actual predecessor (3 failed), closed session ignored (2 failed), owner never established (initially **survived**; test T4.1 tightened, now 1 failed) |
| 2026-10-04 | 3 | `pytest tests/unit --cov=app.crypto` | 118 passed; `merkle.py` 100%. Deliberate breaks caught: odd node promoted instead of duplicated (10 failed), proof sides swapped (7 failed) |
| 2026-10-04 | 2 | Mutation check (throwaway copy in the container) | Each deliberate break caught: no length prefix (3 failed), no NFC (4), null ≡ empty (6), unsorted keys (5), time zone ignored (4), link check removed (11), continuity check removed (7), context order swapped (3) |
