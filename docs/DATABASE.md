# TraceLock — Database Design (PostgreSQL)

Tags: **[Paper]** · **[Rec]** · **[Gap]** (see `PROJECT_PLAN.md` §5).

**Status:** design only. No tables exist yet. Migrations will be created with Alembic in Phase 5.

## 1. What the paper requires

**[Paper Table III, §VI-B, §VI-D]** Each audit record must hold:

| Paper field | Purpose (paper) | Example (paper) |
|---|---|---|
| User ID | who performed the event | U101 |
| Session ID | session the event belongs to | S5001 |
| Current Event | what happened | Open File |
| Previous Event | what happened before | Authentication |
| Sequence No. | position within the session | 3 |
| Timestamp | when it happened | 10:15:32 |
| Previous Hash | link to preceding chain value | abc123… |

The paper also requires:
- each record's own hash H_n (Eq. 1);
- for every batch: the **batch identifier, the range of entries covered, a timestamp and the Merkle root** (§VI-D).

**[Paper §IV]** Everything is stored in a local database. We use PostgreSQL, running locally in Docker.

## 2. Design principles [Rec]

1. **Audit records are append-only by design.** The application never UPDATEs or DELETEs `audit_events` rows. Batch membership is therefore **derived from index ranges** (`batches.first_chain_index`–`last_chain_index`), not stored as a `batch_id` column on events. Storing it on events would require an UPDATE after sealing.
2. **The verifier does not trust anything mutable outside the chain.** Session ownership and lifetime are *replayed from the chained events*, not read from a separate `sessions` table. A sessions table could be altered without breaking any hash.
3. **The order of records is defined by `chain_index`**, never by insertion time or physical row order.
4. Integrity metadata (hashes, roots) lives in the **same database** as the records, as in the paper. This is a known limitation: see `SECURITY_LIMITATIONS.md` §4.

## 3. Tables

### 3.1 `operators` — TraceLock dashboard/API accounts [Rec]

These accounts are separate from the *audited* user IDs that appear inside events.

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| username | text UNIQUE NOT NULL | |
| password_hash | text NOT NULL | Argon2id; never logged |
| role | text NOT NULL | `admin`, `auditor`, `ingestor` (CHECK) |
| is_active | boolean NOT NULL default true | |
| created_at | timestamptz NOT NULL default now() | |

### 3.2 `log_streams` [Rec]

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| name | text UNIQUE NOT NULL | |
| kind | text NOT NULL | `primary`, `synthetic`, `lab` (CHECK) |
| source_stream_id | uuid NULL FK → log_streams | set when cloned (lab) |
| genesis_hash | bytea(32) NOT NULL | H₀ (Q4: default 32 zero bytes) |
| hash_scheme | text NOT NULL | e.g. `tl-v1` (see VERIFICATION §2) |
| merkle_scheme | text NOT NULL | e.g. `paper-dup-v1` |
| batch_size | integer NOT NULL | Q10, default 64 |
| generator_seed | bigint NULL | for synthetic streams (reproducibility) |
| created_at | timestamptz NOT NULL | |
| description | text NULL | |

### 3.3 `audit_events` — the context-enriched, hash-chained records

| Column | Type | Hashed? | Source |
|---|---|---|---|
| id | bigserial PK | no | [Rec] surrogate key |
| stream_id | uuid NOT NULL FK | no | [Rec] |
| chain_index | bigint NOT NULL | no (see note) | [Rec] global position *n*, starts at 1 |
| event_type | text NOT NULL | **yes (E_n)** | [Paper] Current Event |
| event_payload | jsonb NOT NULL default '{}' | **yes (E_n)** | [Gap Q2] resource, ip, outcome… |
| actor_user_id | text NULL | **yes (C_n: u)** | [Paper] User ID |
| session_id | text NULL | **yes (C_n: s)** | [Paper] Session ID; NULL for sessionless events (Q7) |
| prev_event_type | text NULL | **yes (C_n: e_{n-1})** | [Paper] Previous Event; `__START__` for first in session |
| session_seq | integer NULL | **yes (C_n: q)** | [Paper] Sequence No.; starts at 1 per session |
| event_timestamp | timestamptz NOT NULL | **yes (C_n: t)** | [Paper] Timestamp; server-assigned UTC, µs |
| prev_hash | bytea(32) NOT NULL | **yes (H_{n-1})** | [Paper] Previous Hash |
| entry_hash | bytea(32) NOT NULL | — (output) | [Paper] H_n |
| prev_event_id | bigint NULL | no | [Rec, optional, Q5] convenience link for the UI |
| ingested_at | timestamptz NOT NULL default now() | no | [Rec] DB clock; diagnostic only |

Constraints and indexes:
- `UNIQUE (stream_id, chain_index)`
- `UNIQUE (stream_id, session_id, session_seq)`, partial index `WHERE session_id IS NOT NULL`
- `INDEX (stream_id, session_id, session_seq DESC)` for fast "latest event in session" lookups at ingestion
- `INDEX (stream_id, actor_user_id)`, `INDEX (stream_id, event_timestamp)` for dashboard filters
- `CHECK (octet_length(prev_hash) = 32 AND octet_length(entry_hash) = 32)`
- `CHECK ((session_id IS NULL) = (session_seq IS NULL))`

Note on `chain_index`: the paper does not include the global position in the hashed input, so we do not hash it. Gaps, duplicates and reordering in `chain_index` are still detected by the previous-hash links and an explicit continuity check (VERIFICATION §6).

Note on `jsonb`: PostgreSQL normalises jsonb key order and whitespace. That is harmless, because the canonical serializer re-sorts keys before hashing. Floats are disallowed in payloads to avoid number-formatting differences.

### 3.4 `batches` — Merkle batch summaries [Paper §VI-D]

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | [Paper] batch identifier |
| stream_id | uuid NOT NULL FK | |
| batch_index | integer NOT NULL | 1, 2, 3… per stream |
| first_chain_index | bigint NOT NULL | [Paper] range covered |
| last_chain_index | bigint NOT NULL | [Paper] range covered |
| leaf_count | integer NOT NULL | [Rec] must equal last − first + 1; closes the duplication ambiguity (Q14) |
| merkle_root | bytea(32) NOT NULL | [Paper] M₀,₀ |
| sealed_at | timestamptz NOT NULL | [Paper] timestamp |

Constraints:
- `UNIQUE (stream_id, batch_index)`
- `CHECK (leaf_count = last_chain_index - first_chain_index + 1)`
- Ranges are contiguous and non-overlapping. This is enforced by the sealing service and re-checked by the verifier.

### 3.5 `verification_runs` [Paper §VI-E report] + [Rec persistence]

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| stream_id | uuid FK | |
| started_at / finished_at | timestamptz | |
| duration_ms | double precision | measured with `time.perf_counter` |
| status | text | `VALID`, `TAMPERING_DETECTED`, `ERROR` |
| first_failing_chain_index | bigint NULL | [Paper] index of first failing record |
| first_failing_batch_id | uuid NULL | [Paper] batch identifier |
| first_failed_check | text NULL | [Paper] the check that failed |
| records_checked | bigint | |
| unbatched_records | bigint | records not covered by any sealed batch |
| rules_version | text | transition rule-set id + SHA-256 of the file |
| triggered_by | uuid FK operators NULL | |
| report | jsonb | full per-check summary |

### 3.6 `verification_findings`

| Column | Type | Notes |
|---|---|---|
| id | bigserial PK | |
| run_id | uuid FK | |
| chain_index | bigint NULL | |
| batch_id | uuid NULL | |
| check_name | text | e.g. `CHAIN_LINK`, `PROV_SEQUENCE` (VERIFICATION §6) |
| expected / actual | text | human-readable values (hashes in hex) |

### 3.7 `tamper_scenarios` [Rec, Phase 7]

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| scenario_type | text | see EXPERIMENTS §3 |
| source_stream_id / lab_stream_id | uuid FK | |
| parameters | jsonb | target index, attacker model, seed |
| expected_detected | boolean | **recorded before verification** |
| expected_first_index | bigint NULL | ground-truth locus |
| verification_run_id | uuid FK NULL | |
| actual_detected | boolean NULL | |
| located_correctly | boolean NULL | |
| created_at | timestamptz | |

### 3.8 `experiment_runs` [Rec, Phase 9]

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| name | text | |
| config | jsonb | dataset size, batch size, seeds, repetitions |
| environment | jsonb | CPU, RAM, OS, Python/PostgreSQL versions (captured automatically) |
| started_at / finished_at | timestamptz | |
| raw_results | jsonb | per-trial measurements |
| summary | jsonb | computed metrics; **NULL until measured** |

### 3.9 Implementation status (Phase 5)

- `operators`, `log_streams` and `audit_events` were created by migration `0001`, which also seeds the `system` stream with the fixed id `00000000-0000-4000-8000-000000000001`. `alembic check` confirms the migration matches the models.
- `prev_event_id` (optional under Q5) is **not** implemented. The UI can find the predecessor through `session_id` and `session_seq`.
- The extra session index from §3.3 was dropped as redundant: the partial unique index on `(stream_id, session_id, session_seq)` already serves lookups of the latest event in a session.
- The remaining tables are created in their own phases: `batches` (6), `verification_runs` and `verification_findings` (6), `tamper_scenarios` (7) and `experiment_runs` (9).

### 3.10 File module tables (migrations `0005`, `0006`, 2026-10-05) [Eng]

These are engineering additions for the Zero-Trust file module. They are **not** from the paper. The full design, with every constraint and the reasons for it, is in `ZERO_TRUST_FILE_MODULE.md` §5.

**`operators` changes (`0005`):**
- `role` now allows `admin`, `auditor`, `manager`, `employee` and `ingestor`.
- New columns: `display_name` and `department` (each 1–128 characters, nullable), and `updated_at`.
- This is still the only user table. "Operator" = platform user account.

**`audit_events` changes (`0005`): indexes only.** The hashed columns are unchanged, so existing chains and test vectors are unaffected.
- `ix_audit_events_file_id` on `(stream_id, event_payload->>'file_id')`, partial on that key being present.
- `ix_audit_events_type_time` on `(stream_id, event_type, event_timestamp)`.

**New tables (`0006`):**

| Table | Purpose | Key constraints |
|---|---|---|
| `files` | Current state of a logical document | 5 classifications; origin `user`/`demo`/`lab`; name 1–255 bytes; lowercase extension; `current_version ≥ 1`; soft-delete and purge consistency; owner/uploader FK → `operators` (RESTRICT) |
| `file_versions` | Immutable content versions | `UNIQUE(file_id, version_number)`; storage key `^[0-9a-f]{32}$`; SHA-256 exactly 32 bytes; size ≥ 0; restore only from an earlier version; audit reference `(audit_stream_id, audit_chain_index)` **without FK**; integrity status from a fixed list |
| `file_permissions` | Explicit grants (shares) | Permissions non-empty, known, never `CREATE`/`MANAGE_PERMISSIONS`; expiry after creation; revoke fields paired; **one active grant per user per file** (partial unique index); audit reference |

**What is not in the database:**
- **File contents.** These are in the storage volume (`file_versions.storage_key`).
- **Tables the design rules out:** `file_shares`, `file_access_events`, `file_integrity_records` and policy tables (`ZERO_TRUST_FILE_MODULE.md` §5.4).

### 3.11 Role grants (migration `0008`, 2026-10-05) [Eng]

**Changes to `file_permissions`:**
- `grantee_id` is now nullable;
- new column `grantee_role` (CHECK: a known role);
- new column `revoked_audit_chain_index` (the event that revoked or superseded the grant);
- CHECK `num_nonnulls(grantee_id, grantee_role) = 1` (exactly one target);
- partial unique index on `(file_id, grantee_role) WHERE revoked_at IS NULL AND grantee_role IS NOT NULL`.

The downgrade deletes role grants before restoring `grantee_id NOT NULL`.

## 4. Allowed-transition rules

**[Paper §VI-C]** These are "defined per application". **[Rec]** They are stored as a versioned file (`backend/config/transitions.v1.json`), not in the database. The file's SHA-256 is recorded in each verification run, so every report states exactly which rules it used. See VERIFICATION §4.4.

## 5. Storage overhead accounting

The extra data per record compared with a plain log line:
- 2 × 32 bytes for the hashes;
- the sequence number (4 bytes);
- the previous event type (short text);
- plus index overhead.

`EXPERIMENTS.md` §4.5 describes how this is measured with `pg_total_relation_size` against a baseline table. No numbers are claimed here.

## 6. Optional hardening (Phase 10, Q12) [Rec, not in paper]

Database privilege separation:
- The `tracelock_app` role gets `INSERT, SELECT` on `audit_events` and `batches`, but not `UPDATE` or `DELETE`.
- The `tracelock_lab` role is used only by the tamper lab, and only on lab streams. Because PostgreSQL privileges apply per table, this means either row-level security on `stream_id`, or a separate lab schema with the same table layout.
- This raises the attacker's cost. It does **not** stop a database superuser, so it does not change the paper's threat model. See SECURITY §4.
