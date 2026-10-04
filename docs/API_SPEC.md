# TraceLock — API Specification (FastAPI, planned)

Tags: **[Paper]** · **[Rec]** · **[Gap]**.

**Status:** design only. The paper defines no API. Everything here is **[Rec]** unless marked otherwise. Endpoints are introduced in the phases shown in brackets.

## 1. Conventions

- **Base path:** `/api/v1`. JSON only. FastAPI serves interactive docs at `/docs` in development.
- **Hashes:** lowercase hex strings (64 chars).
- **Timestamps:** ISO 8601 UTC with microseconds (`2026-10-04T10:15:32.123456Z`).
- **Authentication:** `Authorization: Bearer <JWT>`. Tokens are short-lived (default 30 min). Tokens and passwords are never logged.
- **Error shape:** `{"error": {"code": "STRING_CODE", "message": "human text", "details": {}}}`.
- **Pagination:** `?limit=` (max 500, default 50) and `?cursor=` (opaque, based on `chain_index`).
- **Server-only fields:** clients **cannot** set `chain_index`, `session_seq`, `prev_event_type`, `event_timestamp`, `prev_hash` or `entry_hash`. Requests that include them are rejected with `422`.

## 2. Roles

| Role | Can |
|---|---|
| `admin` | everything, including operator management, sealing, lab and experiments |
| `auditor` | read streams/events/batches, run verification, read reports and experiment results |
| `ingestor` | `POST` events only (service account for an external application) |

The paper mentions "user and administrator roles" in its prototype (§VI). **[Rec]** We split these into three roles to separate ingestion from auditing.

## 3. Endpoints

### Health [Phase 1]
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/health` | none | `{"status":"ok","database":"ok"}`; `503` if the DB is unreachable |

### Authentication [Phase 5]
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/auth/login` | none | `{username, password}` → `{access_token, token_type, expires_in, role}`; also appends LOGIN/AUTHENTICATION events to the `system` stream (Q13) |
| POST | `/auth/logout` | any | appends a LOGOUT event to the `system` stream |
| GET | `/auth/me` | any | the current operator |
| POST | `/operators` | admin | create an operator `{username, password, role}` |

Failed logins return `401` with a generic message and append a sessionless `LOGIN_FAILED` event.

### Streams [Phase 5]
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/streams` | auditor | list with `kind`, record count, sealed batch count, last verification status |
| POST | `/streams` | admin | create a `primary` stream `{name, batch_size?, description?}` |
| GET | `/streams/{stream_id}` | auditor | details, including `genesis_hash`, `hash_scheme`, `merkle_scheme` |

### Events [Phase 5]
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/streams/{id}/events` | ingestor, admin | ingest one event (below) |
| GET | `/streams/{id}/events` | auditor | filters: `actor_user_id`, `session_id`, `event_type`, `from`, `to`, `batch_index` |
| GET | `/streams/{id}/events/{chain_index}` | auditor | full record and hash relationships (below) |
| GET | `/streams/{id}/sessions/{session_id}` | auditor | the session's events in `session_seq` order |

**Ingest request**
```json
{ "actor_user_id": "U101", "session_id": "S5001",
  "event_type": "FILE_OPEN",
  "payload": {"resource": "/reports/q3.xlsx", "ip_address": "10.0.0.12", "outcome": "success"} }
```

**Ingest response `201`**
```json
{ "chain_index": 1043, "actor_user_id": "U101", "session_id": "S5001",
  "event_type": "FILE_OPEN", "prev_event_type": "AUTHENTICATION", "session_seq": 3,
  "event_timestamp": "2026-10-04T10:15:32.123456Z",
  "prev_hash": "…", "entry_hash": "…" }
```

**Ingest errors**
- `422`: validation (unknown type, float in payload, server-only field supplied).
- `409 PROVENANCE_VIOLATION`: the event would break session rules. The response includes the failing check. This applies only if Q6 is approved as recommended; a `SECURITY_VIOLATION` event is then appended.

**Event detail response** (adds verification context for the UI)
```json
{ "record": { "…all stored fields…" },
  "predecessor": {"chain_index": 1042, "entry_hash": "…"},
  "recomputed_hash": "…", "hash_matches": true, "link_matches": true,
  "batch": {"batch_id": "…", "batch_index": 17, "sealed": true} }
```

### Batches and proofs [Phase 6]
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/streams/{id}/batches` | auditor | list of `{batch_id, batch_index, first_chain_index, last_chain_index, leaf_count, merkle_root, sealed_at}` |
| POST | `/streams/{id}/batches/seal` | admin | seal all full batches; `{"include_partial": true}` also seals the remainder |
| GET | `/streams/{id}/events/{chain_index}/proof` | auditor | `{leaf, batch_id, merkle_root, proof:[{sibling, position}]}` |
| POST | `/proofs/verify` | auditor | stateless: `{leaf, proof, merkle_root}` → `{valid}` |

### Verification [Phase 6] — **[Paper §VI-E]** report content
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/streams/{id}/verify` | auditor | runs synchronously in v1; returns the report (VERIFICATION §6.5) |
| GET | `/streams/{id}/verification-runs` | auditor | history |
| GET | `/verification-runs/{run_id}` | auditor | report plus paginated findings |

**[Paper §V-E]** says verification runs "periodically". **[Rec]** v1 runs on demand. An optional periodic background task can be added in Phase 10. Synchronous runs are acceptable up to roughly 100k records; this will be measured, not assumed.

### Provenance rules [Phase 4/6]
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/config/transitions` | auditor | the active rule set, its version and SHA-256 |

### Tamper lab [Phase 7] — enabled only if `TRACELOCK_LAB_ENABLED=true`
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/lab/workloads` | admin | `{users, sessions_per_user, events_per_session, seed, batch_size}` → a new `synthetic` stream |
| POST | `/lab/scenarios` | admin | `{source_stream_id, scenario_type, target_chain_index?, attacker_model, seed}` → clones into a `lab` stream, records the expected outcome, applies the tampering, runs verification, returns expected vs actual |
| GET | `/lab/scenarios` | admin | list |
| GET | `/lab/scenarios/{id}` | admin | detail |

Safeguards:
- `400` if the source stream is a lab stream that has already been tampered with (chained tampering is out of scope in v1).
- Any mutation of a `primary` stream is refused at the service layer, not only in the API.
- With the lab disabled, every `/lab/*` endpoint returns `404`.

### Experiments [Phase 9]
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/experiments` | admin | start an experiment from a config (EXPERIMENTS §5) |
| GET | `/experiments` | auditor | list |
| GET | `/experiments/{id}` | auditor | config, environment, status, summary (null until measured) |
| GET | `/experiments/{id}/raw?format=csv\|json` | auditor | raw per-trial data |

## 4. Not specified by the paper [Gap]

- **Ingestion transport.** The paper's events are captured "at application level" (§V-A), with no transport defined. **[Rec]** Use HTTP POST with an `ingestor` token.
- **Batch ingest.** Out of scope for v1. The workload generator writes through the same service layer in-process, which is faster but uses identical enrichment and hashing code.
