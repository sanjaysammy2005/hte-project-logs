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

## 3a. Implementation notes (Phase 5)

- **Implemented:** health, auth (login, logout, me), `POST /operators`, streams (list, create, detail), and events (ingest, list with filters and cursor, detail, session).
- **Error codes:**
  - 401: `NOT_AUTHENTICATED`, `INVALID_TOKEN`, `SESSION_ENDED` (the token's system-stream session has a LOGOUT), `INVALID_CREDENTIALS`.
  - 403: `FORBIDDEN`, `STREAM_NOT_WRITABLE`.
  - 404: `STREAM_NOT_FOUND`, `EVENT_NOT_FOUND`.
  - 409: `USERNAME_TAKEN`, `STREAM_NAME_TAKEN`, `PROVENANCE_VIOLATION` (with `failed_checks` and `security_event_chain_index`).
  - 422: `VALIDATION_ERROR`, `UNKNOWN_EVENT_TYPE`, `INVALID_EVENT`.
- **Writable streams:** ingestion is accepted only into `primary` streams other than `system`. The `system` stream is written only by login and logout. `SECURITY_VIOLATION` is reserved for the server.
- **No echoed values:** validation errors return only the location, message and type, never the submitted values (which could be passwords).
- **Event detail** does not include batch information yet; that comes in Phase 6.

## 3b. Implementation notes (Phase 6)

- **Implemented:** `GET /streams/{id}/batches`, `POST /streams/{id}/batches/seal`, `GET /streams/{id}/events/{n}/proof`, `POST /proofs/verify`, `POST /streams/{id}/verify` (201, with the first 100 findings), `GET /streams/{id}/verification-runs`, and `GET /verification-runs/{id}?limit=&offset=`.
- **Sealing:** full batches are sealed automatically inside the ingesting transaction.
- **Errors:** `409 STREAM_INCONSISTENT` when sealing or proving over non-contiguous records; `404 EVENT_NOT_BATCHED`; `404 RUN_NOT_FOUND`.
- **Report fields:** `failed_by_check` gives per-check failure counts, alongside `findings_total` and `findings_stored` (capped at 1,000).
- **`duration_ms`** includes reading from the database. The engine-only time is stored in `report.check_duration_ms`.

## 3c. Implementation notes (Phase 7)

- **Endpoints:** `POST /lab/workloads` (synchronous, limited to about 50,000 events) and `POST /lab/scenarios` with `{source_stream_id, scenario_type, seed, target_chain_index?, j?, t?, batch_index?}`, plus `GET /lab/scenarios`, `GET /lab/scenarios/{id}` and `GET /lab/scenario-types`.
- **Scenario responses** include `expected_detected`, `true_first_index`, `actual_detected`, `first_failure_index`, `first_failure_check`, `located_correctly` and `outcome` (`AS_EXPECTED` or `UNEXPECTED`).
- **Errors:** `400 SCENARIO_NOT_APPLICABLE` (bad parameters, or the source is a lab clone); `422 WORKLOAD_TOO_LARGE`.
- **Disabled lab:** every `/lab/*` path returns 404 unless `TRACELOCK_LAB_ENABLED=true`, and all of them require the admin role.

## 3d. Implementation notes (Phase 9)

- **`POST /experiments`** (admin, lab enabled) returns 202 and runs as a background task. It validates the config and returns `422 INVALID_EXPERIMENT` if invalid.
- **`GET /experiments`** lists runs (no summaries). **`GET /experiments/{id}`** returns the config, environment, status, summary (null until measured) and any error.
- **`GET /experiments/{id}/raw?section=detection|false_positive|timing|proofs|storage|base_streams&format=json|csv`** returns raw data. CSV columns are sorted alphabetically, because jsonb does not keep key order.
- **Large runs** should use the CLI: `python -m app.experiments <config.json> --git-commit <sha>`.

## 3e. File module (2026-10-05) [Eng — not from the paper]

The design is in `ZERO_TRUST_FILE_MODULE.md` §14. Every file endpoint requires a signed-in user. Every decision is made server-side by `app/access/policy.py` and appended to the `system` stream inside the caller's chained session.

| Method | Path | Permission | Chained event |
|---|---|---|---|
| POST | `/auth/reauthenticate` `{password}` | any signed-in user | `REAUTHENTICATION` / `REAUTHENTICATION_FAILED` (403) |
| POST | `/files` multipart: `file`, `classification`, `description?` | CREATE (workspace) | `FILE_UPLOAD` |
| GET | `/files?scope=all\|mine\|shared\|recent\|trash&q=&classification=&type=&owner=&uploader=&created_from=&created_to=&sort=name\|created_at\|updated_at\|size\|classification\|last_accessed&order=&limit=&offset=` | discoverable files only | — (not chained) |
| GET | `/files/{id}` | discoverable | `FILE_VIEW` (`scope: metadata`) for RESTRICTED+ |
| GET | `/files/{id}/content?disposition=attachment\|inline&version=` | DOWNLOAD / READ (inline: PNG, JPEG, PDF only) | `FILE_DOWNLOAD` / `FILE_VIEW`; `FILE_INTEGRITY_FAILURE` if the bytes no longer match |
| PATCH | `/files/{id}` `{display_name?, description?, classification?, reason?}` | RENAME / UPDATE / MANAGE_PERMISSIONS (downgrade) | `FILE_RENAME`, `FILE_UPDATE` |
| DELETE | `/files/{id}` | DELETE | `FILE_DELETE` (soft delete) |
| GET | `/files/{id}/versions` | discoverable | `FILE_VIEW` (`scope: versions`) for RESTRICTED+ |
| POST | `/files/{id}/versions` multipart: `file`, `base_version`, `change_reason?` | UPLOAD | `FILE_VERSION_CREATED` |
| POST | `/files/{id}/versions/{n}/restore` `{base_version, reason?}` | RESTORE | `FILE_VERSION_RESTORED` |
| POST | `/files/{id}/integrity?version=` | VERIFY | `FILE_INTEGRITY_CHECK` / `FILE_INTEGRITY_FAILURE` |

**Every denial is chained as `FILE_ACCESS_DENIED`.**
- If the file is discoverable to the caller, the answer is **403** `ACCESS_DENIED` or `STEP_UP_REQUIRED`, with `details`:
  - `action`, `reason_code`, `reasons`;
  - `required_permission`, `classification`;
  - `your_role`, `your_permissions`;
  - `audit {stream_id, chain_index}`.
- Otherwise it is **404** `FILE_NOT_FOUND`, byte-identical to the answer for a non-existent file.

**Other error codes:**
- 409: `VERSION_CONFLICT`, `ALREADY_CURRENT`, `INTEGRITY_FAILURE`, `AUDIT_REJECTED`;
- 411: `LENGTH_REQUIRED`;
- 413: `FILE_TOO_LARGE`;
- 415: `UNSUPPORTED_FILE_TYPE`, `FILE_TYPE_MISMATCH`, `MACROS_NOT_ALLOWED`, `EXTENSION_MISMATCH`, `INLINE_NOT_SUPPORTED`;
- 422: `INVALID_FILENAME`, `MISSING_EXTENSION`, `EMPTY_FILE`, `EXTENSION_CHANGE_NOT_ALLOWED`, `REASON_REQUIRED`, `VALIDATION_ERROR`;
- 404: `VERSION_NOT_FOUND`;
- 503: `STORAGE_UNAVAILABLE`.

**Response headers for content:**
- `Content-Type`: the server's type for the validated format;
- `Content-Disposition`: RFC 6266 (ASCII fallback plus `filename*`);
- `X-Content-Type-Options: nosniff`;
- `Content-Security-Policy: default-src 'none'; …; sandbox`;
- `Cache-Control: no-store`;
- `X-TraceLock-Audit-Index`: the chain index of the access event.

**Ingestion change:** event types listed in the rule file's `server_only_events` (all file-module types) are rejected by `POST /streams/{id}/events` with `422 UNKNOWN_EVENT_TYPE`. Clients therefore cannot forge file-governance evidence.

## 3f. Access Control phase (2026-10-05) [Eng]

| Method | Path | Permission | Chained event |
|---|---|---|---|
| GET | `/files/{id}/permissions` | Discoverable. Owners and permission managers see all grants (with history); others see only grants they issued or received | `FILE_VIEW` (`scope: permissions`) for RESTRICTED+ |
| POST | `/files/{id}/permissions` `{grantee_id, permissions[], expires_at?, reason?}` | SHARE (subset of own) or MANAGE_PERMISSIONS | `FILE_SHARE` |
| DELETE | `/files/{id}/permissions/{grant_id}` | Permission manager, owner, or grantor | `FILE_PERMISSION_CHANGE` (`change: REVOKE`) |
| PUT | `/files/{id}/owner` `{owner_id, reason}` | MANAGE_PERMISSIONS | `FILE_PERMISSION_CHANGE` (`change: OWNER_TRANSFER`) |

**Error codes:**
- 409: `GRANT_EXISTS`, `GRANT_ALREADY_REVOKED`;
- 404: `GRANT_NOT_FOUND` (only after authorization);
- 422: `REASON_REQUIRED` (HIGHLY_RESTRICTED shares).

**Other changes:**
- **403 bodies** now include `rule`, `rules`, `policy` and `evaluated_at`.
- **Every 401 on a file endpoint** is chained as a sessionless `UNAUTHENTICATED_ACCESS` event (`ZERO_TRUST_FILE_MODULE.md` §27.5).
- **`FileOut`** now includes `department`.

## 3g. File sharing phase (2026-10-05) [Eng]

- **`POST /files/{id}/permissions`:**
  - takes **either** `grantee_id` **or** `grantee_role` (422 otherwise);
  - re-granting the same target replaces the grant instead of returning `409 GRANT_EXISTS`, which no longer exists.
- **`GET /files/{id}/permissions/history`** is new: owner or MANAGE_PERMISSIONS.
- **`GrantOut`** gained `grantee_role`, `revoked_by`, `audit_chain_index` and `revoked_audit_chain_index`.
- **Event names:** `FILE_SHARED`, `FILE_SHARE_REVOKED`, `FILE_PERMISSION_GRANTED`, `FILE_PERMISSION_REVOKED`, `FILE_ACCESS_POLICY_CHANGED` (`ZERO_TRUST_FILE_MODULE.md` §28).

## 3h. Security investigation (2026-10-05) [Eng]

Admin and auditor only; read-only. Endpoints:
- `GET /security/events`
- `GET /security/events/{chain_index}`
- `POST /security/events/{chain_index}/verify`
- `GET /security/files/{file_id}/timeline`
- `GET /security/files/{file_id}/integrity`
- `GET /security/findings`

Details and the distinction between FILE INTEGRITY FAILURE and AUDIT LOG INTEGRITY FAILURE are in `ZERO_TRUST_FILE_MODULE.md` §29.

Errors: `404 EVENT_NOT_FOUND`, `404 FILE_NOT_FOUND`, `422 INVALID_WINDOW`.

## 4. Not specified by the paper [Gap]

- **Ingestion transport.** The paper's events are captured "at application level" (§V-A), with no transport defined. **[Rec]** Use HTTP POST with an `ingestor` token.
- **Batch ingest.** Out of scope for v1. The workload generator writes through the same service layer in-process, which is faster but uses identical enrichment and hashing code.
