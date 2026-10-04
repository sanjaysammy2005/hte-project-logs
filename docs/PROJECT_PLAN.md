# TraceLock — Project Plan

**Status:** Phase 0 (planning). No application code exists yet.
**Primary reference:** `docs/research-paper.pdf` — *Provenance-Based Context-Enriched Hash Chaining for Secure Audit Logging*.

## How to read these documents

Every requirement in the `docs/` files is tagged with its source:

| Tag | Meaning |
|---|---|
| **[Paper]** | Stated in the research paper (section/table/equation cited). |
| **[Rec]** | Our recommendation for a practical implementation. Not in the paper; can be changed. |
| **[Gap]** | The paper is missing, ambiguous, or inconsistent here. Needs a decision (see *Open Questions*). |

Related documents:

| File | Contents |
|---|---|
| `ARCHITECTURE.md` | End-to-end flow, layers, modules, technology stack, Docker setup |
| `DATABASE.md` | PostgreSQL schema, constraints, what is and is not hashed |
| `API_SPEC.md` | FastAPI endpoints, roles, request/response shapes |
| `VERIFICATION.md` | Canonical serialization, hash chain, provenance checks, Merkle procedure, verification algorithm |
| `EXPERIMENTS.md` | Evaluation scenarios, metric formulas, dataset sizes, measurement procedure |
| `SECURITY_LIMITATIONS.md` | Threat model, trust assumptions, what is and is not detected |
| `TESTING.md` | Test strategy, required test cases per phase |

---

## 1. Goal

Build a working research prototype that implements the paper's pipeline. The pipeline is: capture → enrich → hash → chain → batch → Merkle root → store → verify provenance → report tampering. The prototype must then **evaluate** the pipeline honestly using controlled tampering experiments. **[Paper §IV, §VII]**

The paper states that the hash chain, provenance verification and Merkle batching were "under integration" and that **no measured results exist yet** (§VI, §VIII). TraceLock is therefore the first implementation of the method. It must not assume the method works; the experiments decide that.

## 2. Scope

**In scope**
- Ingestion of security audit events (login, authentication, file open/edit, database access, logout, IP-related security events). **[Paper §VI-A]**
- Context enrichment, canonical serialization, SHA-256 hash chain. **[Paper §V-B, §VI-B]**
- Five provenance checks. **[Paper §VI-C]**
- Merkle batching, root storage, membership proofs. **[Paper §VI-D]**
- Local verification engine with a Valid / Tampering Detected report that names the batch ID, the first failing record and the failed check. **[Paper §VI-E]**
- Controlled tampering lab covering modification, deletion, insertion, reordering and context forgery. **[Paper Table IV, §VII]**
- React dashboard. **[Paper §V-E]**
- An experiment harness measuring the paper's metrics. **[Paper §VII]**

**Out of scope** (unless you approve otherwise)
- Blockchain, machine learning, eBPF/kernel monitoring, special hardware. The paper explicitly excludes these. **[Paper Abstract, §IX-A]**
- HMAC, digital signatures and external anchoring. The paper lists these as **future work** (§IX-B, §X). They are documented as limitations, not implemented. See Q11.
- Multi-host aggregation and anomaly detection (future work in §X).

## 3. Decisions already fixed by CLAUDE.md

These come from CLAUDE.md:
- **Backend:** Python + FastAPI, with SQLAlchemy + Alembic, Pydantic and hashlib SHA-256.
- **Database:** PostgreSQL.
- **Frontend:** React + Vite + TypeScript, with Plotly for charts.
- **Testing:** pytest + HTTPX.
- **Environment:** Docker Compose.

---

## 4. Phased implementation plan

Each phase ends with passing tests, a summary of changed files, and your approval before the next phase starts.

The core logic (serialization, chain, Merkle, provenance) is built and tested as **pure Python with no database** (Phases 2–4) before any persistence is added. This keeps the cryptography easy to test and easy to defend in a presentation.

### Phase 0 — Planning and decisions (current)
**Deliverables:** the 8 documents in `docs/`.
**Acceptance criteria**
- [x] All 8 documents exist and every requirement is tagged [Paper], [Rec] or [Gap].
- [x] You have answered or explicitly deferred every open question in §5. *(Phase 1 was approved on 2026-10-04. Q1–Q16 do not affect Phase 1 and are deferred; Q1–Q4 must be decided before Phase 2 starts.)*
- [x] You approve this plan. *(Phase 1 start approved 2026-10-04.)*

### Phase 1 — Repository scaffold and development environment
**Deliverables:**
- `docker-compose.yml` with the services `db` (PostgreSQL), `backend` (FastAPI) and `frontend` (Vite).
- `.env.example`.
- A backend package skeleton with `GET /api/v1/health`.
- Baseline Alembic configuration (no tables yet).
- pytest configuration.
- A Vite React-TS skeleton page that calls the health endpoint.
- A ruff lint configuration.

**Acceptance criteria**
- [x] `docker compose up --build` starts all three services and all of them report healthy.
- [x] `GET /api/v1/health` returns `200` with `{"status":"ok","database":"ok"}`. With the DB stopped it returns `503` and `"database":"unavailable"`.
- [x] `docker compose run --rm backend pytest` runs and passes, with at least the health test.
- [x] `alembic upgrade head` runs without error against the compose database.
- [~] The frontend at `http://localhost:5173` displays the backend health status. *(Verified: the page is served, the `/api` proxy returns the health JSON, and the build type-checks. Not yet checked visually in a browser.)*
- [x] The repo contains no secrets. `.env` is git-ignored and `.env.example` holds placeholders only.

### Phase 2 — Canonical serialization and hash chain (pure, no DB)
**Deliverables:**
- `canonical` module: the byte encoding of E_n and C_n.
- `chain` module: the genesis value, `compute_entry_hash()` and `verify_chain()` over in-memory records.
- Published test vectors.

**Acceptance criteria**
- [x] The same logical record always produces identical bytes across 1,000 randomized round-trips. This includes different dict key orders, Unicode normalisation forms and timestamp inputs. *(Also covers time-zone offsets, tuple vs list, and a jsonb-style JSON round-trip.)*
- [x] Field-boundary ambiguity is impossible. For example, user `"U1"` with session `"0S"` hashes differently from user `"U10"` with session `"S"`. *(Also proven by decoding 1,000 random encodings back to their fields.)*
- [x] A documented test vector (fixed inputs → expected hex digest) is reproduced by an independent script that uses only `hashlib`. *(See `tests/reference_tl_v1.py` and `tests/vectors/tl-v1.json`. The script is standard library only; `hashlib` does the hashing.)*
- [x] `verify_chain()` returns VALID for a correct chain. For each case below it returns a failure at the expected position: modified event, modified context, deleted record, inserted record, reordered records (see `TESTING.md` T2.x).
- [x] 100% line coverage on the `canonical` and `chain` modules.

### Phase 3 — Merkle tree module (pure, no DB)
**Deliverables:** `merkle` module containing `merkle_root()`, `membership_proof()` and `verify_proof()`.

**Acceptance criteria**
- [x] Roots for batch sizes 1, 2, 3, 4, 5, 7, 8 and 9 match roots computed by an independent reference implementation in the test suite.
- [x] Odd levels duplicate the last node, as in the paper (Eq. 2).
- [x] For every leaf in every tested batch size, a membership proof verifies and has ⌈log₂ m⌉ siblings.
- [x] Altering any single leaf changes the root, and the old proof then fails.
- [x] The duplicated-last-leaf ambiguity ([a,b,c] vs [a,b,c,c]) is detected when the stored `leaf_count` is checked (see `VERIFICATION.md` §5.4).

### Phase 4 — Provenance rules engine (pure, no DB)
**Deliverables:**
- `provenance` module with the five checks.
- An allowed-transition configuration file (versioned).

**Acceptance criteria**
- [x] Each of the five checks (Who, Session, Previous Event, Sequence, Transition) has at least one passing and one failing test. The failure must be reported with the correct record and check name.
- [x] The paper's worked example (§VI-F) produces exactly the failures the paper predicts: deleting "Authentication" from Login → Authentication → Open File → Edit File → Logout gives a sequence gap 1→3, a previous-event mismatch and a disallowed Login→Open File transition.
- [x] The transition rules are loaded from a file, and the version/hash of the rule set is included in every report.
- [x] Interleaved concurrent sessions in one global stream verify as VALID.

### Phase 5 — Persistence, ingestion API and operator authentication
**Deliverables:**
- SQLAlchemy models and Alembic migrations (`DATABASE.md`).
- The ingestion/enrichment service.
- Operator login with roles.
- Event ingest and query endpoints (`API_SPEC.md`).

**Acceptance criteria**
- [ ] Migrations create the schema from empty, and `alembic downgrade base` removes it.
- [ ] Ingested events get server-assigned `chain_index`, `session_seq`, `prev_event_type`, `event_timestamp`, `prev_hash` and `entry_hash`. Clients cannot set these fields.
- [ ] A concurrency test sends 20 parallel clients × 50 events, then verifies the chain. It must be gapless, with no duplicate `chain_index` and every link valid.
- [ ] Events read back from PostgreSQL re-hash to their stored `entry_hash`, including the timestamp round-trip.
- [ ] Unauthenticated requests get `401`. Insufficient role gets `403`. Passwords are stored only as Argon2 hashes and never logged.
- [ ] The ingestion rejection policy (Q6) is implemented as decided and tested.

### Phase 6 — Batching and verification engine (DB-backed)
**Deliverables:**
- Batch sealing.
- Merkle root storage.
- Membership-proof endpoint.
- Verification runs stored with full reports.
- Verification API.

**Acceptance criteria**
- [ ] Sealing creates batches with correct `first_chain_index`, `last_chain_index`, `leaf_count` and `merkle_root`.
- [ ] Verifying an untampered stream returns `VALID` with zero findings.
- [ ] The report names the status, the first failing `chain_index`, its batch ID, the failed check(s), the rule-set version and the number of records checked. It also lists records not yet covered by a sealed batch.
- [ ] Verification runs are persisted and retrievable by ID.
- [ ] The membership proof returned by the API verifies with the Phase 3 `verify_proof()`.

### Phase 7 — Tampering lab and synthetic workload generator
**Deliverables:**
- A seeded workload generator.
- A stream-cloning mechanism.
- Tamper scenarios (see `EXPERIMENTS.md` §3) applied to clones only.
- An expected-vs-actual report for each scenario.

**Acceptance criteria**
- [ ] The lab refuses to run unless `TRACELOCK_LAB_ENABLED=true` and the caller is admin.
- [ ] The lab never mutates a stream whose `kind` is `primary`. A test proves this.
- [ ] The generator is deterministic: the same seed produces an identical event sequence.
- [ ] Every scenario stores its expected outcome **before** verification runs, plus the actual outcome and the located record.
- [ ] Scenarios in the "expected undetected" class (full rewrite, tail truncation) are run and reported honestly, not hidden.

### Phase 8 — React dashboard
**Deliverables:**
- Pages: Login, Streams, Event Explorer, Event Detail (context + hash links), Batches/Merkle, Verification, Tamper Lab, Experiments (Plotly).

**Acceptance criteria**
- [ ] Every page in `ARCHITECTURE.md` §6 is reachable and works against the live backend.
- [ ] Synthetic, lab and demo streams always show a visible "SYNTHETIC / LAB DATA" badge.
- [ ] The Event Detail page shows the stored previous hash, the actual predecessor hash and the recomputed hash, with a match/mismatch indicator.
- [ ] Charts read only persisted experiment results. The frontend contains no hard-coded metric values (enforced by code review and a grep test).
- [ ] Role-restricted actions (seal, verify, lab) are hidden or disabled for roles that cannot perform them, and the backend still enforces them.

### Phase 9 — Experiment harness and evaluation
**Deliverables:**
- A CLI/endpoint that runs the experiment matrix in `EXPERIMENTS.md`.
- Raw results stored in the DB and exported as CSV/JSON.
- The results section of `EXPERIMENTS.md`, filled with measured values.

**Acceptance criteria**
- [ ] Each experiment records its machine specification, software versions, seed, dataset size, batch size and repetition count.
- [ ] The detection rate, false-positive rate, localization accuracy, verification time and storage overhead are computed with the formulas in `EXPERIMENTS.md` §4 from raw stored data.
- [ ] Re-running an experiment with the same seed reproduces the same detection outcomes. Timings vary, and the variation is reported.
- [ ] Results that do not support the paper's expectations are reported unchanged.

### Phase 10 — Hardening and final documentation
**Deliverables:**
- A review of the security limitations.
- Optional database privilege separation (Q12).
- Final updates to all docs and the README.
- A demo script for the presentation.

**Acceptance criteria**
- [ ] `SECURITY_LIMITATIONS.md` §5 lists exactly which protections are implemented **and tested**, with test IDs.
- [ ] A fresh clone followed by `docker compose up` and the README steps reproduces the demo.
- [ ] All tests pass. A coverage report is generated.

---

## 5. Open questions (need your decision)

Each question lists our recommendation. Details are in the referenced document.

| # | Question | Recommendation | Ref |
|---|---|---|---|
| — | **Q1–Q4 decided 2026-10-04: approved as recommended.** | | |
| — | **Q10, Q14 decided 2026-10-04: approved as recommended.** | | |
| — | **Q5–Q9, Q15 and transitions.v1 decided 2026-10-04: approved as recommended.** | | |
| Q1 | The paper's hash formula uses "byte concatenation" of E, C and H but does not define how fields are encoded. Plain concatenation is ambiguous ("U1"+"0S" = "U10"+"S"). | **Length-prefixed concatenation in the paper's order (E ‖ C ‖ H_{n-1}).** This keeps the paper's structure and removes the ambiguity. Alternative: canonical JSON. | VERIFICATION §2 |
| Q2 | What exactly is "the event" E_n? Only the type ("Open File"), or also details like the filename, IP and outcome? If details are not hashed, they can be changed undetected. | E_n = event type **plus** a canonical payload (resource, IP, outcome). | VERIFICATION §2.2 |
| Q3 | The context set is inconsistent. The abstract and §IV list (user, session, previous event, sequence). Eq. 1 adds the timestamp. | Follow Eq. 1: include the timestamp in C_n. | VERIFICATION §2.3 |
| Q4 | The genesis value H₀ is "fixed" but not given. | 32 zero bytes, documented. | VERIFICATION §3 |
| Q5 | Is "previous event" the event type ("Authentication") or a reference to a specific record? A type name cannot tell apart two identical consecutive events. | Store the type (as the paper does) and keep `session_seq` as the unambiguous position. Optionally also store `prev_event_id` (not hashed). | VERIFICATION §4 |
| Q6 | If an incoming event already violates session rules (for example, Open File with no authenticated session), should ingestion reject it or record it? If recorded, verification would later call it "Tampering Detected" even though nothing was tampered with. | **Reject session-violating events at ingestion (HTTP 409) and record a sessionless `SECURITY_VIOLATION` event instead.** Any provenance failure found later then means the record changed after capture. | VERIFICATION §4.3 |
| Q7 | How do sessionless events (failed logins, IP alerts) fit the per-session checks? | Put them in the global chain and Merkle batches; mark the session checks N/A for them. | VERIFICATION §4.2 |
| Q8 | Login vs Authentication: the paper says the session owner is "established by the authentication event", but Login comes first. | LOGIN claims a user; AUTHENTICATION must name the same user and confirms ownership. Every later event must match. | VERIFICATION §4.1 |
| Q9 | Session lifetime is not defined (timeout? Logout only?). | From the first event (LOGIN) to LOGOUT. No timeout in v1. | VERIFICATION §4.1 |
| Q10 | The batch formation policy (size? time?) is not specified. A Merkle root with one leaf is not described. | Fixed configurable batch size (default 64) plus manual "seal now". For a one-leaf batch the root equals the leaf. | VERIFICATION §5 |
| Q11 | Should keyed hashing, signatures or external anchoring be implemented? The paper defers them to future work. | Not in v1. Optionally, add an "export chain-head checkpoint" feature in Phase 10 if time allows, clearly labelled as an extension beyond the paper. | SECURITY §6 |
| Q12 | Should the database be hardened with privilege separation (app role cannot UPDATE/DELETE events)? Not in the paper. | Yes, in Phase 10, as a documented extension. The tamper lab uses a separate role. | DATABASE §6 |
| Q13 | The paper's prototype (auth, roles, dashboard, IP monitoring) is not in this repo. Do you have it, and should TraceLock integrate with it? | Build TraceLock standalone with an ingestion API that the old prototype could call later. Log TraceLock's own operator logins into a `system` stream. | ARCHITECTURE §2 |
| Q14 | The Merkle procedure duplicates the last node and has no leaf/node domain separation. This is a known weakness (two different leaf lists can give the same root). | Implement the paper's procedure exactly, and add a `leaf_count` + range check that closes the gap in practice. Document RFC 6962-style domain separation as an alternative. | VERIFICATION §5.4 |
| Q15 | Ordering by timestamp: the paper uses "timestamps out of order" as reordering evidence, but clock adjustments could cause false alarms. | Check that timestamps are non-decreasing along the chain (they are server-assigned under a lock). Report a violation as a provenance failure. | VERIFICATION §4.2 |
| Q16 | Tail truncation (deleting the newest records) and rollback to an older consistent copy are not discussed in the paper, and local verification cannot detect them. | Document them as limitations and include them as "expected undetected" lab scenarios. | SECURITY §4 |

## 6. Progress log

| Date | Phase | Summary | Tests |
|---|---|---|---|
| 2026-10-04 | 0 | Planning documents created. | n/a |
| 2026-10-04 | 1 | Docker Compose (db/backend/frontend), FastAPI health endpoint, settings, Alembic baseline (no tables), pytest + ruff, Vite React-TS status page. Dependencies pinned (backend `requirements*.txt`, frontend `package-lock.json`). Fixed the frontend healthcheck (Alpine `localhost` → `::1`). | 6 passed; ruff clean; frontend build OK |

| 2026-10-04 | 2 | `app/crypto/canonical.py` (tl-v1 encoding), `app/crypto/chain.py` (genesis, hashing, `build_chain`, `rehash`, `verify_chain` with stored-link localization + cascade count), reference implementation and published vectors. DB fixtures moved to `tests/api/conftest.py`, so unit tests need no DB. | 82 passed; `app/crypto` 100% line coverage; 8/8 deliberate code breaks caught |
| 2026-10-04 | 3 | `app/crypto/merkle.py`: `merkle_root`, `membership_proof`, `verify_proof`, `check_batch` (leaf-count + root). | 118 unit tests passed; `app/crypto` 100% coverage; 2/2 deliberate breaks caught |
| 2026-10-04 | 4 | `app/provenance/rules.py` (versioned JSON rules + SHA-256, consistency validation), `app/provenance/checks.py` (P1–P5 + timestamp order, session replay from chained records only), `config/transitions.v1.json`. | 151 unit + 2 API passed; crypto + provenance 100% coverage; 3/3 deliberate breaks caught (after tightening one test) |

### Known issues
- pytest emits a `StarletteDeprecationWarning`: Starlette's TestClient now prefers `httpx2` over `httpx`. Tests pass. Revisit in Phase 5 when the API tests grow; switching would change the CLAUDE.md "HTTPX" stack item, so it needs your approval.
- The pinned frontend toolchain is new (TypeScript 7.0.2, Vite 8.3.2, React 19.3.0). It builds and type-checks cleanly now. If a later library (e.g. `react-plotly.js`) is incompatible, versions may need adjusting.
