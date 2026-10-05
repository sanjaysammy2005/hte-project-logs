# TraceLock — Secure File Governance & Zero-Trust Access Module

**Status:**
- **Design approved 2026-10-05**, with decisions Z1–Z19 accepted as recommended.
- **Foundation phase implemented 2026-10-05** (see §26.1).
- **Secure File Management phase implemented 2026-10-05** (see §26.4): the decision engine, the policy file, `transitions.v2`, chained file events, and the lifecycle endpoints.

Nothing in this document is measured; every number below is a **configurable default**, not a result.

**Primary reference:** `docs/research-paper.pdf`. The paper does **not** propose this module. See §0.2 for what comes from the paper and what does not.

---

## 0. How to read this document

### 0.1 Tags

The existing documents use **[Paper]**, **[Rec]** and **[Gap]**. This document adds three tags that answer the question "where does this come from?":

| Tag | Meaning |
|---|---|
| **[Paper]** | Stated in the research paper (section cited). |
| **[Reuse]** | Already implemented in TraceLock (Phases 1–10). It is reused unchanged or extended without changing its semantics. |
| **[Eng]** | An engineering addition for the Zero-Trust file platform. **Not** in the paper. It can be changed. |
| **[Future]** | A future research or engineering opportunity. Not planned for implementation in this module. |
| **Z*n*** | An open decision that needs your approval (listed in §24). |

### 0.2 Relationship to the research paper

| The paper says | Source |
|---|---|
| Events of interest include "login, authentication, file access, file edits, database access, logout and IP-related security events". | §VI-A |
| The surrounding prototype "provides user authentication, security event logging, user and administrator roles, a dashboard, and monitoring of IP addresses and security events". | §VI |
| Every event is enriched with user, session, previous event, sequence number and timestamp, then hash-chained and Merkle-batched. | §V, §VI-B, §VI-D |
| Events are assumed to be captured faithfully (T1), and context is only as reliable as the application that supplies it (T3). | §II, §IX-B |

The paper does **not** propose:
- Zero-Trust access control, file classification or a permission model;
- file storage, versioning or file content integrity;
- any access-decision logic.

This module is an **application** that *produces* security events. TraceLock's paper-derived pipeline then protects those events. The module makes the paper's method demonstrable on realistic activity; it does not extend the method itself.

In a presentation the claim should be:

> "We built a Zero-Trust file platform whose every access decision is captured as a context-enriched, hash-chained, Merkle-batched audit event, using the paper's method unchanged."

It should **not** be: "The paper proposes Zero-Trust file governance."

---

## 1. Architecture

### 1.1 Current architecture (as built, Phases 1–10) [Reuse]

```
Browser (React/Vite)  ──JWT──►  FastAPI /api/v1
                                 ├── auth        Argon2id + JWT; login/logout chained in `system` stream
                                 ├── streams     ingest / list / detail / session
                                 ├── verification batches, proofs, verify, runs
                                 ├── lab         workload generator, tamper scenarios S1–S11 (lab clones only)
                                 └── experiments harness, metrics, raw export
                                         │
            pure core (no DB) ───────────┤  crypto/ (canonical tl-v1, chain, merkle)
                                         │  provenance/ (P1–P5 + timestamp order, transitions.v1.json)
                                         ▼
                                 PostgreSQL: operators, log_streams, audit_events, batches,
                                 verification_runs/findings, tamper_scenarios, experiment_runs
```

Key properties the new module must respect:
- **Single append path.** Every event goes through `ingestion.service.append_event()`. It takes a per-stream advisory lock, enriches the event, enforces provenance at capture (Q6), hashes it, inserts it and auto-seals batches, all inside the caller's transaction.
- **Sessions are chained.** A dashboard login appends `LOGIN` + `AUTHENTICATION` to the `system` stream under a fresh session id. That id is the token's `sid` claim. A token is valid only while that chained session has no `LOGOUT` (`auth/service.py: session_is_open`).
- **Pure cores.** `crypto/` and `provenance/` import neither the DB nor FastAPI, so they are exhaustively unit-tested.
- **Versioned rule files.** `config/transitions.v1.json` is hashed, and its version plus SHA-256 appear in every verification report.
- **Roles** are a single `operators.role` text column with a CHECK constraint (`admin`, `auditor`, `ingestor`). They are enforced by `require_roles()` dependencies.
- **Frontend:** one CSS file with tokens and dark mode, a top-bar nav, pages per feature, `useLoader` for data, and no component or icon library.

### 1.2 Proposed architecture [Eng on top of Reuse]

```
                     ┌───────────────────────── Browser (untrusted) ─────────────────────────┐
                     │  React app shell · capability-driven nav · per-file allowed_actions  │
                     └───────────────────────────────┬──────────────────────────────────────┘
                                                     │ HTTPS in deployment (dev: HTTP on localhost)
                                                     │ Authorization: Bearer <JWT>
┌────────────────────────────────────────────────────▼─────────────────────────────────────────────┐
│ FastAPI                                                                                           │
│  ① Authenticate token ─► ② Chained session open? ─► ③ Account active, role unchanged?  [Reuse]   │
│  ④ Build AccessRequest (identity, role, action, file, classification, ownership, grants, context)│
│  ⑤ access.policy.decide()  ── pure, versioned policy file ──►  Decision(ALLOW|DENY, reason)  [Eng]│
│  ⑥ Audit: append_event(system stream, user's session, FILE_* / FILE_ACCESS_DENIED)       [Reuse] │
│  ⑦ On ALLOW: perform the operation in the SAME transaction as ⑥ (fail-closed)              [Eng] │
│  ⑧ Respond (403 with explanation, 404 if undiscoverable, or result + audit reference)            │
└──────────┬──────────────────────────────┬───────────────────────────────────┬─────────────────────┘
           │                              │                                   │
   PostgreSQL (mutable state)     PostgreSQL (tamper-evident)          File store (blobs)
   files, file_versions,          audit_events (hash chain)            /var/lib/tracelock/files
   file_permissions, ...          batches (Merkle roots)               opaque keys, never user names
           │                              │                                   │
           └──────────── Integrity & governance verification (§12) ──────────┘
                 blob SHA-256  ⇄  file_versions.sha256  ⇄  SHA-256 recorded in the chained event
```

**The central idea.** The file module keeps its *state* in ordinary mutable tables, but every *change and every access decision* is written to the hash chain. The chain becomes the trusted history against which the mutable state can be checked (§12.3). This is what links the module to the research.

---

## 2. Threat model

### 2.1 Assets
- The **contents** of organisational files, in particular RESTRICTED and HIGHLY_RESTRICTED ones.
- **File metadata**, including the names of restricted files, which can themselves be sensitive.
- **Governance state:** ownership, classification and grants.
- The **audit chain** of decisions and operations, and its Merkle roots.
- **Credentials and sessions.**

### 2.2 Adversaries

| ID | Adversary | Capabilities | In scope? |
|---|---|---|---|
| ZA1 | **Curious or malicious insider** (valid account) | Calls any API directly (bypassing the UI), guesses or harvests file IDs, crafts requests, uploads malicious files | **Yes**, the main target |
| ZA2 | **Session thief** | Holds a stolen, still-valid bearer token | Partly. Limited by session age and step-up for high classifications; not prevented |
| ZA3 | **Privilege escalator** | Tries to share more than they hold, downgrade classifications, self-grant, or change their role | **Yes** |
| ZA4 | **Storage tamperer** | Write access to the file store and/or DB rows after the fact (paper §II adversary, extended to files) | **Detected, not prevented** (tamper-evident) |
| ZA5 | **Full rewriter** | DB superuser/host: rewrites blobs, metadata, chain and roots consistently | **Not detected.** Same as the paper's A2 limitation (§IX-B) |
| ZA6 | **Unauthenticated network attacker** | Anonymous requests | Yes for access (always 401); denial-of-service is out of scope |

### 2.3 Threats and mitigations

| Threat | Mitigation | Section |
|---|---|---|
| Path traversal / arbitrary filesystem access | User-supplied names are **never** used in paths. Storage keys are server-generated UUIDs, regex-validated, with resolved paths checked to stay under the storage root | §6, §16 |
| Malicious filenames (control chars, RTL override, `..`, reserved names, overlong) | Sanitiser: basename only, NFC, reject control/bidi characters, length ≤ 255 bytes, allowlisted extension; `Content-Disposition` RFC 6266 encoding | §16.2 |
| MIME spoofing / polyglots | The extension allowlist must agree with server-side magic-byte detection; the client `Content-Type` is ignored; the served MIME comes from the server; `nosniff` | §16.3 |
| Oversized uploads / disk exhaustion | `Content-Length` required and checked before reading; byte counting while streaming; configurable max; optional per-user quota | §16.4 |
| Executing uploaded files | Store outside any served/static path; no execute bits; never interpret, render as HTML or unzip contents; inline only for images/PDF under a sandbox CSP | §16.5 |
| IDOR (guessing another user's file ID) | Every request is authorised against the specific file. Undiscoverable files return **404** (not 403), and the attempt is still chained | §9.4 |
| Broken access control / frontend-only checks | Backend policy engine on every endpoint; the UI only renders the backend's `allowed_actions` | §9 |
| Privilege escalation via sharing | You cannot grant a permission you do not effectively hold. MANAGE_PERMISSIONS cannot be granted. HIGHLY_RESTRICTED shares are owner/admin-only | §7.4 |
| Classification laundering (downgrade, then leak) | Downgrades need MANAGE_PERMISSIONS (admin); upgrades are allowed for owners | §10.3 |
| Session misuse / stolen token | Chained session must be open; maximum session age per classification; step-up re-authentication for HIGHLY_RESTRICTED; logout revokes | §9.3 |
| File replacement attacks (swap content silently) | Every replacement is a new immutable version with its SHA-256 recorded in a chained event; the 3-layer integrity check | §11, §12 |
| Integrity failure (blob altered on disk) | Verify-before-serve: SHA-256 is recomputed on every download/preview; a mismatch blocks the download and chains `FILE_INTEGRITY_FAILURE` | §12 |
| Race conditions around versions | Row lock (`SELECT … FOR UPDATE`) plus a required `base_version` (optimistic check), with `UNIQUE(file_id, version_number)` as a backstop | §11.3 |
| Information leakage in errors | Generic 404 for undiscoverable files; validation errors never echo values [Reuse]; the storage key is never returned | §14 |
| Restricted names in the immutable audit log | Filenames of RESTRICTED+ files are redacted in event payloads (Z11) | §13.3 |
| Unauthorised access to storage paths | No static file serving; bytes are only streamed by the authorised handler; the volume is mounted only into the backend | §6 |
| Direct DB tampering with grants/ownership | Not prevented. **Detected** by governance reconciliation against the chain (§12.3) unless the chain is also rewritten (ZA5) | §12.3 |

### 2.4 Trust assumptions (extending SECURITY_LIMITATIONS §3)

| # | Assumption | Source |
|---|---|---|
| T1–T7 | Unchanged from `SECURITY_LIMITATIONS.md` | [Paper]/[Reuse] |
| ZT1 | The policy file and the backend code are trusted (they are configuration and code, like T2) | [Eng] |
| ZT2 | The server clock is used for session age, step-up windows and rate windows. Clock steps are clamped for events [Reuse], but not for policy windows | [Eng] |
| ZT3 | The client IP is only as reliable as the network path. Behind the Vite dev proxy or Docker NAT it is the proxy's address, so IP signals are **advisory only** | [Eng] |
| ZT4 | Humans classify files correctly. A mis-classified file is protected at its (wrong) level | [Eng] |

---

## 3. Trust boundaries

```
 ┌──────────────┐  B1  ┌──────────────────────┐  B2  ┌──────────────────────┐
 │ Browser /    │─────►│ FastAPI process      │─────►│ PostgreSQL           │
 │ API client   │      │ (trusted code, T2)   │      │ state + audit chain  │
 │ UNTRUSTED    │◄─────│ policy file (ZT1)    │      │ tamper-EVIDENT only  │
 └──────────────┘      └──────────┬───────────┘      └──────────────────────┘
                                  │ B3
                                  ▼
                       ┌──────────────────────┐
                       │ File store volume    │  tamper-EVIDENT via SHA-256 + chain anchor
                       └──────────────────────┘
 B4: Docker host / DB superuser. Everything to the right of B1 is compromised (ZA5).
```

| Boundary | What crosses it | Rule |
|---|---|---|
| **B1** client → API | Tokens, filenames, bytes, IDs, claimed MIME types | Nothing is trusted. Everything is validated server-side; authorisation runs on every request |
| **B2** API → DB | Rows, chained events | The DB is trusted for availability, **not** for integrity. Integrity comes from re-verification |
| **B3** API → file store | Opaque keys, bytes | Bytes are re-hashed on every read. Keys are never derived from user input |
| **B4** host | — | Out of scope (paper §IX-B) |

---

## 4. Components

### 4.1 Backend modules

| Module | Purpose (plain language) | Pure? | Tag |
|---|---|---|---|
| `app/access/model.py` | Enumerations (Action, Permission, Classification, ReasonCode) and the `AccessRequest` / `Decision` data classes | yes | [Eng] |
| `app/access/policy_file.py` | Loads and validates `config/access_policy.v1.json`; computes its SHA-256 (mirrors `provenance/rules.py`) | yes | [Eng] |
| `app/access/policy.py` | `decide(request, policy) -> Decision`. The whole Zero-Trust decision, a pure function | yes | [Eng] |
| `app/access/context.py` | Gathers context signals (session age, time since authentication, recent denials and downloads) **from the chained events** | no | [Eng] |
| `app/files/validation.py` | Filename sanitising, extension allowlist, magic-byte type detection, OOXML/OLE checks | yes | [Eng] |
| `app/files/storage.py` | `StorageBackend` protocol + `LocalFileStorage` (atomic writes, hashing while streaming, size limit) | I/O only | [Eng] |
| `app/files/audit.py` | Builds event payloads (redaction, reason codes, signals) and calls `append_event` | no | [Eng] on [Reuse] |
| `app/files/service.py` | Orchestrates every operation: lock → decide → audit → mutate → commit | no | [Eng] |
| `app/files/integrity.py` | 3-layer integrity check and governance reconciliation | no | [Eng] |
| `app/api/v1/files.py`, `security.py`, `admin.py` | HTTP endpoints (§14) | no | [Eng] |
| `app/lab/file_scenarios.py` | File tamper scenarios F1–F6 on lab-only files (§17.4) | no | [Eng] |
| `config/access_policy.v1.json` | Role matrix, classification requirements, context thresholds | data | [Eng] |
| `config/transitions.v2.json` | Superset of v1 adding the file and admin event types (§13.4) | data | [Eng] on [Paper] |

**Design rule (same as the existing core):** `access/` and `files/validation.py` are pure. The decision logic can be tested exhaustively without Docker and explained on one slide.

### 4.2 Reused unchanged [Reuse]
- `crypto/` (canonical encoding, chain, Merkle). The event payloads are new, but the hashing does not change.
- `provenance/checks.py`. It gets new rules through `transitions.v2.json`, not new code.
- `ingestion/service.py: append_event`, `batching/`, `verification/engine.py`.
- Auth tokens, Argon2id, chained login/logout, logout revocation.
- The tamper lab safety model: only `lab` streams and lab-origin files may be mutated.

---

## 5. Database design

### 5.1 Principles [Eng]
1. **Reuse before adding.**
   - Users are the existing `operators`.
   - Sessions are the existing chained sessions.
   - Access and operation events are the existing `audit_events`.
   - No parallel `sessions`, `file_access_events` or `audit_log` table is created.
2. **Mutable state ≠ evidence.** The new tables hold *current state* and are mutable. The *evidence* of every change is the chained event. State rows store an **audit reference** `(audit_stream_id, audit_chain_index)` *without* a foreign key, following the `verification_runs` pattern, so the reference survives tampering and can be cross-checked.
3. **No destructive overwrites.** Versions are immutable rows. Deletion is soft, and purge keeps a tombstone (Z14).
4. **Binary content is not stored in PostgreSQL** (§6).

### 5.2 Changes to existing tables

**`operators`** (Z1: extend, do not replace)

| Change | Detail |
|---|---|
| `role` CHECK | `admin`, `auditor`, `manager`, `employee`, `ingestor` (Z16) |
| `+ display_name text NULL` | Shown in the UI and the share dialog |
| `+ department text NULL` | Informational in v1 ([Future] attribute-based rules) |
| `+ updated_at timestamptz` | |

The table keeps its name (renaming it would touch every auth test). The UI calls these accounts **Users**. `DATABASE.md` will document that "operator = platform user account".

**`audit_events`**: no column changes. Hashing is unchanged. New **indexes only**:
- `ix_audit_events_file_id ON audit_events (stream_id, (event_payload->>'file_id')) WHERE event_payload ? 'file_id'`, for file history.
- `ix_audit_events_type_time ON audit_events (stream_id, event_type, event_timestamp)`, for dashboard counts and denial windows.

**`log_streams`**: the `system` stream's description is updated to "Platform activity: sign-ins, file governance and access decisions". This is metadata only; it is not hashed.

### 5.3 New tables

#### `files`: the logical document (current state)

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | Random (v4); unguessable, but secrecy of IDs is **not** relied on |
| display_name | text NOT NULL | Sanitised, NFC, ≤ 255 bytes UTF-8 |
| extension | text NOT NULL | Lowercase, from the allowlist; fixed for the life of the file |
| mime_type | text NOT NULL | Determined by the server, not the client |
| classification | text NOT NULL | CHECK in the five levels (§10) |
| owner_id | uuid NOT NULL FK → operators | |
| created_by | uuid NOT NULL FK → operators | The original uploader (never changes) |
| current_version | integer NOT NULL | CHECK ≥ 1; refers to `file_versions.version_number` (avoids a circular FK) |
| description | text NULL | ≤ 1,000 characters |
| origin | text NOT NULL default `'user'` | CHECK in (`user`, `demo`, `lab`). The UI badges `demo`/`lab` (CLAUDE.md: separate sample data from genuine data) |
| created_at / updated_at | timestamptz NOT NULL | |
| deleted_at / deleted_by | NULL / FK NULL | Soft delete (trash) |
| purged_at | timestamptz NULL | Blobs removed; row kept as a tombstone |
| last_accessed_at | timestamptz NULL | A cache for sorting only; the authoritative record is the chain |

Indexes: `(owner_id)`, `(classification)`, `(created_at)`, `(updated_at)`, partial `(deleted_at) WHERE deleted_at IS NOT NULL`, `(origin)`. Search uses `ILIKE` on `display_name`. A `pg_trgm` index is optional if search becomes slow (measured, not assumed).

#### `file_versions`: immutable content versions

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| file_id | uuid NOT NULL FK → files ON DELETE RESTRICT | |
| version_number | integer NOT NULL | `UNIQUE(file_id, version_number)`, CHECK ≥ 1 |
| storage_key | text NOT NULL | Opaque server key (§6). **Never returned by the API** |
| sha256 | bytea NOT NULL | CHECK `octet_length = 32` |
| size_bytes | bigint NOT NULL | CHECK ≥ 0 |
| mime_type | text NOT NULL | Detected for this version |
| original_filename | text NOT NULL | The sanitised name as uploaded (display only) |
| uploaded_by | uuid NOT NULL FK → operators | |
| created_at | timestamptz NOT NULL | |
| change_reason | text NULL | ≤ 500 characters |
| restored_from_version | integer NULL | Set when this version was created by a restore |
| audit_stream_id / audit_chain_index | uuid / bigint NOT NULL | The chained event that created this version (no FK, see §5.1) |
| last_verified_at / last_integrity_status | timestamptz NULL / text NULL | **Cache only**, explicitly untrusted; the chained check events are the evidence |

The application never UPDATEs these rows, except for the two cache columns.

#### `file_permissions`: explicit grants (also "shares")

| Column | Type | Notes |
|---|---|---|
| id | uuid PK | |
| file_id | uuid NOT NULL FK → files | |
| grantee_id | uuid NOT NULL FK → operators | User-level grants only in v1 |
| permissions | text[] NOT NULL | CHECK non-empty, `<@` the known set, and containing neither `CREATE` (workspace-level) nor `MANAGE_PERMISSIONS` (§7.4) |
| granted_by | uuid NOT NULL FK → operators | |
| reason | text NULL | |
| created_at | timestamptz NOT NULL | |
| expires_at | timestamptz NULL | Optional time-boxed access |
| revoked_at / revoked_by | NULL | Revocation keeps history |
| audit_stream_id / audit_chain_index | uuid / bigint NOT NULL | The chained `FILE_SHARE` / `FILE_PERMISSION_CHANGE` |

A partial unique index on `(file_id, grantee_id) WHERE revoked_at IS NULL` allows one active grant per user per file. Changing a grant means revoking it and creating a new one, so history is never overwritten.

#### `access_requests` (optional, phase ZT-10; Z15)

`id`, `file_id`, `requester_id`, `requested_permissions text[]`, `justification`, `status` (`PENDING`/`APPROVED`/`REJECTED`/`CANCELLED`), `decided_by`, `decided_at`, `decision_note`, `created_at`. A partial unique index allows one pending request per requester per file. An approval creates a normal grant (chained).

### 5.4 Tables deliberately **not** created

| Suggested table | Why not |
|---|---|
| `file_shares` | A share *is* an explicit grant. A second table would allow two sources of truth to disagree |
| `file_access_events` | Access decisions are `audit_events` in the `system` stream. A copy would be unprotected by the chain and could contradict it |
| `file_integrity_records` | Every integrity check is a chained `FILE_INTEGRITY_CHECK`/`FAILURE` event. Two cache columns on the version serve the UI |
| `file_access_policies` | The policy is a versioned, hashed config file (Z4), like `transitions.v1.json` |
| `roles`, `permissions`, `role_permissions` | Roles and their permissions are defined in the policy file. A DB copy would be unaudited mutable configuration (Z4) |

### 5.5 Migrations
- `0005_identity_roles`: the operators CHECK, new operator columns, the audit_events indexes, the system stream description.
- `0006_files`: `files`, `file_versions`, `file_permissions`.
- `0007_access_requests` (only if Z15 is approved).

Each migration has a tested `downgrade`. `tests/api/conftest.py` TRUNCATE lists are extended.

---

## 6. File storage design [Eng]

### 6.1 Abstraction

```python
class StorageBackend(Protocol):
    def put(self, source: BinaryIO, max_bytes: int) -> StoredBlob: ...   # streams, hashes, counts
    def open(self, key: str) -> BinaryIO: ...
    def exists(self, key: str) -> bool: ...
    def delete(self, key: str) -> None: ...                               # purge only
@dataclass(frozen=True)
class StoredBlob: key: str; sha256: bytes; size_bytes: int
```

The service layer depends only on this protocol. A future `S3Storage` (S3-compatible or MinIO) implements the same four methods. Its keys become object names, and server-side checksums are optional because TraceLock re-hashes anyway. [Future]

### 6.2 `LocalFileStorage`
- **Root:** `TRACELOCK_STORAGE_ROOT` (default `/var/lib/tracelock/files`). In Compose this is a **named volume** `filestore` mounted only into `backend`. The Dockerfile creates the directory owned by uid 1000 (`app`) before `USER app`.
- **Key:** `uuid4().hex` (Z17). Path = `root/key[0:2]/key`. Keys are validated against `^[0-9a-f]{32}$` before any path is built, and the resolved path is checked to be inside `root`.
- **Write:**
  1. Stream into `root/.tmp/<random>` in chunks, updating SHA-256 and a byte counter.
  2. Abort and delete the temp file if the counter exceeds `max_bytes`.
  3. `fsync`, then `os.replace` into place (atomic on one filesystem).
  4. Mode `0o640`.
- **Ordering with the database:** the blob is written **before** the DB transaction. If the transaction fails, the blob is an orphan. Orphans are harmless (unreferenced and never served). They are removed by an admin `storage-gc` CLI command that deletes unreferenced keys older than one hour. The reverse order (DB first) could reference a blob that does not exist.
- **Why random keys rather than content-addressing:**
  - No cross-file deduplication side effects.
  - Purging one file can never remove another file's content.
  - Identical content uploaded under different classifications stays separate.
  - The integrity check does not depend on the key.

### 6.3 What is never done
- No static file serving of the storage root.
- Names, extensions or IDs supplied by users are never used in paths.
- Uploaded archives are never unzipped to disk, and no uploaded content is executed or converted.

---

## 7. Permission model [Eng]

### 7.1 Permissions

| Permission | Allows | Action(s) |
|---|---|---|
| `READ` | See metadata; in-browser preview of content | VIEW |
| `DOWNLOAD` | Download content as an attachment | DOWNLOAD |
| `CREATE` | Create a new file (initial upload) | CREATE (= "upload a new file") |
| `UPLOAD` | Upload a new **version** of an existing file | UPLOAD |
| `UPDATE` | Edit description; **upgrade** classification | UPDATE |
| `RENAME` | Change the display name | RENAME |
| `DELETE` | Move to trash | DELETE |
| `RESTORE` | Restore a previous version; restore from trash | RESTORE |
| `SHARE` | Grant others a subset of your own effective permissions | SHARE |
| `VERIFY` | Run an integrity check | VERIFY |
| `MANAGE_PERMISSIONS` | Revoke anyone's grants; transfer ownership; **downgrade** classification; purge | MANAGE_PERMISSIONS |

`CREATE` is checked at the workspace level (there is no file yet). Every other permission is checked against a specific file.

### 7.2 Sources of permission

```
effective(user, file) =  role_permissions(user.role, file.classification)
                       ∪ owner_permissions            if user is file.owner
                       ∪ ⋃ active_grants(user, file)  (not revoked, not expired)
```

Then **classification requirements** (§10) may still deny, even when a permission is present. For example, a role grant is not enough at RESTRICTED, or step-up is required. **Context requirements** (§9.3) may also deny.

### 7.3 Owner permissions (policy file)
`READ, DOWNLOAD, UPLOAD, UPDATE, RENAME, DELETE, RESTORE, SHARE, VERIFY`. Owners **cannot** downgrade a classification, transfer ownership or purge. Those need `MANAGE_PERMISSIONS`.

### 7.4 Anti-escalation rules for sharing
1. The grantor must hold `SHARE` on the file **and** every permission being granted, **after** context requirements are applied.
2. `MANAGE_PERMISSIONS` and `SHARE` are not grantable at HIGHLY_RESTRICTED. Elsewhere, `SHARE` is grantable but `MANAGE_PERMISSIONS` never is.
3. Grants on HIGHLY_RESTRICTED files: only the owner or an admin, and a reason is required.
4. Self-grants are allowed only for admins. They are always chained, and the Investigation view flags them (break-glass visibility, Z9).
5. The grantee must be an active, non-`ingestor` account.

Each violated rule is a DENY with a specific reason code, and the denial is itself chained.

---

## 8. Role model [Eng] (Z16)

| Role | Purpose | Dashboard | File content by role | Notes |
|---|---|---|---|---|
| `admin` | Platform and security administration | Full | PUBLIC–CONFIDENTIAL by role; RESTRICTED+ only through an explicit grant (a self-grant is visible) | Has `MANAGE_PERMISSIONS`; user management |
| `auditor` | Audit, verification, investigation | Audit + Security (read) | **None by role** (metadata only) | Separation of duties: can verify integrity and read history without reading content |
| `manager` | Department lead | Files | PUBLIC–CONFIDENTIAL | Can share up to CONFIDENTIAL |
| `employee` | Standard user | Files | PUBLIC–INTERNAL | |
| `ingestor` | Service account [Reuse] | None | None | Unchanged: API event ingestion only |

**Role × classification matrix** (role permissions only, before ownership, grants and context; `·` = none):

| Role \ Class | PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED | HIGHLY_RESTRICTED |
|---|---|---|---|---|---|
| admin | R D U Up Rn Del Res S V M | R D U Up Rn Del Res S V M | R D U Up Rn Del Res S V M | V M | V M |
| auditor | R V | V | V | V | V |
| manager | R D S | R D S | R D S | · | · |
| employee | R D | R D | · | · | · |
| ingestor | · | · | · | · | · |

R = READ, D = DOWNLOAD, U = UPDATE, Up = UPLOAD, Rn = RENAME, Del = DELETE, Res = RESTORE, S = SHARE, V = VERIFY, M = MANAGE_PERMISSIONS.

`CREATE` (workspace level): admin, manager, employee.

The auditor's INTERNAL+ `V` means the auditor can verify integrity (a hash comparison) but not read content. The integrity response never contains file bytes.

**Department scope (Z20, added in the Access Control phase).** Role access is limited to the user's own department on these levels:
- employees: INTERNAL;
- managers: INTERNAL and CONFIDENTIAL.

A file belongs to its uploader's department. Outside it, and for users without a department, only ownership or an explicit grant gives access. The matrix above therefore reads "within the same department" for those cells. See §27.

**Discoverability (metadata visibility):**
- admin and auditor see metadata for all non-lab files; this is needed for investigation.
- Everyone else sees a file only if they have any effective permission on it: by role, ownership or grant.

**Capabilities sent to the frontend** (`GET /auth/me`, derived server-side from the role through the policy file): `files:use`, `files:create`, `security:view`, `audit:view`, `admin:users`, `lab:use` (also requires `TRACELOCK_LAB_ENABLED`), `research:view`. The frontend builds its navigation **only** from these. The backend enforces each endpoint independently.

---

## 9. Zero-Trust access decision flow [Eng]

### 9.1 Request model (pure)

```python
@dataclass(frozen=True)
class AccessRequest:
    principal: Principal          # operator_id, username, role, is_active
    action: Action                # VIEW, DOWNLOAD, CREATE, UPLOAD, UPDATE, RENAME, DELETE, SHARE, RESTORE, VERIFY, MANAGE_PERMISSIONS
    resource: Resource | None     # file_id, classification, owner_id, deleted, origin  (None for CREATE / missing file)
    grants: frozenset[Permission] # from active, unexpired grants for this principal on this file
    context: Context              # see 9.3
    extra: ActionDetails | None   # e.g. target classification, permissions to grant

@dataclass(frozen=True)
class Decision:
    effect: Literal["ALLOW", "DENY"]
    reason_code: ReasonCode       # primary reason
    reasons: tuple[ReasonCode, ...]   # every failed requirement, for explanation
    message: str                  # human text, no secrets
    required_permission: Permission | None
    permission_source: Literal["ROLE", "OWNER", "GRANT"] | None
    discoverable: bool            # False → respond 404
    signals: Mapping[str, int | str | bool]   # evaluated context (integers only, no floats: tl-v1 rule)
    policy_id: str                # "access-policy.v1 sha256:…"
```

### 9.2 Algorithm (deny by default)

```
 ① token valid?                        no  → 401 INVALID_TOKEN                          [Reuse]
 ② chained session open?               no  → 401 SESSION_ENDED  (+ sessionless chained FILE_ACCESS_DENIED,
                                                                  only when the token signature was valid)
 ③ account active & role unchanged?    no  → 401                                        [Reuse]
 ④ load file (incl. deleted); lab-origin files are invisible outside the lab
 ⑤ decide():
     a. role == ingestor                                → DENY  ROLE_NOT_PERMITTED
     b. file missing / purged                           → DENY  NOT_FOUND           (discoverable = false)
     c. file in trash and action ∉ {RESTORE, VERIFY, VIEW-metadata, MANAGE_PERMISSIONS}
                                                        → DENY  FILE_DELETED
     d. required permission ∉ effective permissions     → DENY  NO_PERMISSION
     e. classification needs grant/owner, but source == ROLE
                                                        → DENY  GRANT_REQUIRED
     f. context requirements of the classification (9.3), each a separate reason:
          session_age > max                             → DENY  SESSION_TOO_OLD   (re-login)
          step-up required and auth_age > window        → DENY  STEP_UP_REQUIRED  (re-enter password)
          recent_denials ≥ threshold                    → DENY  DENIAL_BURST
          recent_downloads ≥ limit                      → DENY  RATE_LIMIT
          IP not in allowed CIDRs (if configured)       → DENY  IP_NOT_ALLOWED
          outside allowed hours (if configured)         → DENY  OUTSIDE_HOURS
     g. action-specific rules: share escalation (7.4), classification downgrade, cross-extension replacement
     h. otherwise                                       → ALLOW (reason ALLOW_ROLE | ALLOW_OWNER | ALLOW_GRANT)
     discoverable = admin/auditor, or any effective permission, or owner, or any active grant
 ⑥ append chained event in the caller's session (13)
 ⑦ ALLOW → perform the operation in the same transaction; DENY → commit the denial event alone
 ⑧ respond: ALLOW → result + audit reference; DENY & discoverable → 403 ACCESS_DENIED / STEP_UP_REQUIRED
            with explanation; DENY & not discoverable → 404 FILE_NOT_FOUND
```

Every failed requirement is collected, not just the first, so the UI can explain everything that would need to change. The primary reason is the first in the order above.

### 9.3 Context signals (computed per request) [Eng]

| Signal | Source | Used for |
|---|---|---|
| `session_age_s` | Now − timestamp of the session's chained `LOGIN` | Maximum session age per classification |
| `auth_age_s` | Now − timestamp of the latest chained `AUTHENTICATION` or `REAUTHENTICATION` in the session | Step-up window |
| `recent_denials` | Count of chained `FILE_ACCESS_DENIED` by this user in the last *W* minutes | Denial-burst rule; investigation flag |
| `recent_downloads` | Count of chained `FILE_DOWNLOAD` by this user in the last hour | Per-classification download rate |
| `ip_address` | `request.client.host` (proxy headers are **not** trusted unless a trusted proxy is configured) | Optional CIDR rule; recorded for investigation |
| `ownership` | `OWNER` / `GRANTEE` / `ROLE` / `NONE` | Explanation; recorded |
| `request_id` | Generated per request | Correlates an event with application logs |

Signals are **read from the chain**, not from separate counters. This keeps "what the policy saw" reproducible from the evidence. These are heuristics for access decisions and auditing, **not** threat detection (no ML, as required).

**Step-up re-authentication:** `POST /auth/reauthenticate {password}` appends `REAUTHENTICATION` (success) or `REAUTHENTICATION_FAILED` to the user's session. This is password re-entry, **not MFA**, and is documented as such (Z10).

### 9.4 404 versus 403 (Z8)
- A user who cannot discover a file gets **404**, exactly as if it did not exist. This prevents probing restricted files by ID.
- The attempt is still chained as `FILE_ACCESS_DENIED` (`reason: NOT_FOUND` or `NO_PERMISSION`, plus a `discoverable=false` signal). Investigators therefore see IDOR probing even though the user does not.
- A user who *can* see the file but lacks the specific permission gets **403** with the full explanation (§19.5).

---

## 10. File classification policy [Eng]

### 10.1 Levels and requirements (policy file defaults; Z4)

| Level | Rank | Content access by role? | Explicit grant or owner needed | Max session age | Step-up within | Download limit | Preview | Name in audit payload |
|---|---|---|---|---|---|---|---|---|
| PUBLIC | 0 | yes (all non-ingestor roles) | no | — | — | — | yes | yes |
| INTERNAL | 1 | employee, manager, admin | no | — | — | — | yes | yes |
| CONFIDENTIAL | 2 | manager, admin | no (roles above) / yes (others) | 8 h | — | — | yes | yes |
| RESTRICTED | 3 | **no** | **yes** | 60 min | — | 20 / h | yes | **redacted** |
| HIGHLY_RESTRICTED | 4 | **no** | **yes**, owner/admin-issued, with reason | 30 min | **10 min** | 5 / h | **no** (download only) | **redacted** |

Additional rules:
- **Denial burst:** ≥ 5 denials in 10 minutes blocks CONFIDENTIAL+ content actions until the window passes, and flags the user in Investigation.
- **Optional:** `allowed_cidrs` and `allowed_hours` per level. **Off by default**, because Docker NAT makes IP meaningless in development (ZT3) and time rules would surprise during a demo.
- Metadata views of RESTRICTED+ files are chained as `FILE_VIEW` with `scope: "metadata"`. For lower levels only content previews are chained, to avoid flooding the chain (`audit_metadata_view_from: "RESTRICTED"`).

### 10.2 Policy file sketch

```json
{
  "version": "access-policy.v1",
  "default_effect": "DENY",
  "classifications": {
    "RESTRICTED": { "rank": 3, "content_requires_grant_or_owner": true,
                    "max_session_age_minutes": 60, "step_up_minutes": null,
                    "max_downloads_per_hour": 20, "preview_allowed": true,
                    "redact_name_in_audit": true, "allowed_cidrs": null, "allowed_hours": null }
  },
  "roles": {
    "employee": { "workspace": ["CREATE"],
                  "by_classification": { "PUBLIC": ["READ","DOWNLOAD"], "INTERNAL": ["READ","DOWNLOAD"] } }
  },
  "owner_permissions": ["READ","DOWNLOAD","UPLOAD","UPDATE","RENAME","DELETE","RESTORE","SHARE","VERIFY"],
  "signals": { "denial_burst": { "window_minutes": 10, "threshold": 5, "from_classification": "CONFIDENTIAL" } },
  "audit_metadata_view_from": "RESTRICTED"
}
```

The loader validates internal consistency. Examples: every role in the file matches the DB CHECK constraint, ranks are unique, and `MANAGE_PERMISSIONS` is never in `owner_permissions`. **Startup fails** on an invalid file (fail closed). Each decision event records `policy: "access-policy.v1 sha256:…"`.

### 10.3 Classification changes
- **Upgrade** (e.g. INTERNAL → RESTRICTED) needs `UPDATE`. Owners can upgrade.
- **Downgrade** needs `MANAGE_PERMISSIONS` and a reason. This prevents "downgrade, then share widely".
- Both are chained as `FILE_UPDATE` with `{from, to, reason}`. Existing grants are kept but re-evaluated under the new level on the next request.

---

## 11. Versioning model [Eng]

### 11.1 Rules
- Uploading a new version never touches the previous blob or row. Version *n+1* is a new `file_versions` row and a new blob.
- **Restore** of version *k* creates version *n+1* with `restored_from_version = k`. It reuses *k*'s storage key, and the SHA-256 is re-verified first. History is strictly linear and append-only, and "what was current when" stays answerable.
- A replacement must have the **same extension** as the file. This avoids type confusion; a different type is a new file.
- Every version records: number, SHA-256, size, MIME, uploader, timestamp, change reason and audit reference.

### 11.2 Events
`FILE_VERSION_CREATED` (replacement) and `FILE_VERSION_RESTORED` (restore). Each records `{file_id, version, previous_version, sha256, size_bytes, restored_from?}`.

### 11.3 Concurrency
1. `SELECT … FROM files WHERE id = :id FOR UPDATE` (row lock).
2. The request must carry `base_version`. If `base_version ≠ files.current_version`, the response is **409 VERSION_CONFLICT** (optimistic check: you uploaded over something you had not seen).
3. Then `append_event` (stream advisory lock), then insert the version and update `current_version`, then commit.
4. `UNIQUE(file_id, version_number)` is the final backstop.

**Lock order is fixed** to avoid deadlocks: file row lock(s) first, then the stream advisory lock. A test fires two concurrent replacements with the same `base_version` and expects exactly one 201 and one 409.

### 11.4 Delete, trash, purge (Z14)
- `DELETE` → soft delete (`deleted_at`), chained `FILE_DELETE`.
- `RESTORE` from trash → chained `FILE_UNDELETE`.
- **Purge** (admin, `MANAGE_PERMISSIONS`, only from trash) → removes the blobs, sets `purged_at` and chains `FILE_PURGE`. Rows remain as a tombstone, so every historic audit event still resolves to a name, classification and hashes. This is a deliberate trade-off against storage reclamation, documented in §23.

---

## 12. File integrity model [Eng]

### 12.1 Fingerprint
SHA-256 over the exact stored bytes, computed **while streaming** the upload, before anything is committed. It is stored as 32 raw bytes and displayed as hex. [Reuse: `hashlib`, hex conventions]

### 12.2 Three-layer integrity check (per version)

| Layer | Compares | Detects | Result codes |
|---|---|---|---|
| **L1 content** | SHA-256 and size of the blob now ⇄ `file_versions.sha256` / `size_bytes` | Blob modified, truncated or replaced on disk | `CONTENT_MISMATCH`, `BLOB_MISSING` |
| **L2 anchor** | `file_versions.sha256` ⇄ `sha256` in the **chained** event at `(audit_stream_id, audit_chain_index)` | Blob **and** DB hash changed together (an attacker "fixing" the metadata) | `METADATA_MISMATCH`, `ANCHOR_MISSING` |
| **L3 evidence** | That chained event re-hashes to its stored `entry_hash`, its `prev_hash` matches its predecessor, and (if sealed) its Merkle proof verifies against the batch root | The anchoring event itself was edited | `ANCHOR_TAMPERED` |

**Status:** `INTACT` only if L1–L3 all pass.

**Why L2 and L3 matter (the research connection).** Without them, an attacker with disk *and* DB write access can replace a file and update its stored hash, and an L1 check would say "intact". The anchor is protected by the paper's chain and Merkle batches. Changing it as well requires breaking the chain, which full stream verification detects (S1/S2-style). Only a **full consistent rewrite** of the chain and roots (ZA5, paper §IX-B) defeats this. The lab demonstrates that honestly (F6).

**When checks run:**
- **Verify-before-serve:** every download and preview runs L1 (hashing ≤ 25 MiB before sending).
  - On failure the bytes are **not** served: 409 `INTEGRITY_FAILURE`, plus a chained `FILE_INTEGRITY_FAILURE`.
  - On success the `FILE_DOWNLOAD` event records the verified SHA-256.
- **On demand** (`VERIFY` permission): L1 + L2 + L3, chained as `FILE_INTEGRITY_CHECK` or `FILE_INTEGRITY_FAILURE`.
- **Bulk scan** (admin): every current version, synchronous with a cap in v1 (larger scans via the CLI). One chained summary event, plus one failure event per failing version.

### 12.3 Governance reconciliation [Eng; candidate research contribution]

Mutable governance state is checked against the chained history:

| Check | Rule |
|---|---|
| `GRANT_UNANCHORED` | Every active grant has a matching chained `FILE_SHARE` (same file, grantee, permissions) that is not followed by a revoking `FILE_PERMISSION_CHANGE` |
| `OWNER_UNANCHORED` | The current owner equals the uploader or the target of the latest chained ownership change |
| `CLASSIFICATION_UNANCHORED` | The current classification equals the latest chained value (upload or `FILE_UPDATE`) |
| `VERSION_UNANCHORED` | Every version row has its anchoring event, and `current_version` equals the latest chained version event |
| `STATE_DELETED_UNANCHORED` | Trash/purge state agrees with the chained `FILE_DELETE`/`FILE_UNDELETE`/`FILE_PURGE` |

This detects someone who `INSERT`s a grant straight into the DB to give themselves access. It is detected **after the fact**: the grant works at runtime until reconciliation runs. That is honest tamper-evidence, not prevention.

---

## 13. Audit integration [Paper pipeline reused; event vocabulary Eng]

### 13.1 Where events go (Z2)

All file-governance events are appended to the **existing `system` stream**, inside the **acting user's chained login session** (the token's `sid`), through the **existing `append_event()`**. Consequences:
- A user's activity is one provenance-checked session, for example: `LOGIN → AUTHENTICATION → FILE_VIEW → FILE_ACCESS_DENIED → REAUTHENTICATION → FILE_DOWNLOAD → LOGOUT`.
- The **paper's five checks now protect file history** without new code:
  - a forged `FILE_DOWNLOAD` inserted after `LOGOUT` fails P2;
  - one attributed to another user fails P1;
  - a deleted denial event leaves a sequence gap (P4) and a previous-event mismatch (P3);
  - a file event before `AUTHENTICATION` fails P5.
- Merkle batching, verification, the dashboard's hash-relationship view and the existing tamper lab all apply as they are.
- The Q6 capture-time policy still holds. If a file event would violate provenance (e.g. a race with logout), it is stored as `SECURITY_VIOLATION`, and the file operation is **aborted**.

The alternative, a separate `files` stream, was rejected: the session's `LOGIN`/`AUTHENTICATION` would be in another chain, so P1–P5 could not be applied to file events.

**Cost:** every file operation serialises on the `system` stream's advisory lock for the duration of a short transaction. This is fine for a prototype; throughput is measured in ZT-E4, not assumed.

### 13.2 Event vocabulary

| Event type | Emitted when | Session? |
|---|---|---|
| `FILE_UPLOAD` | A new file is created (CREATE) | yes |
| `FILE_VIEW` | Content preview; metadata view for RESTRICTED+ | yes |
| `FILE_DOWNLOAD` | Download served (after the L1 check passed) | yes |
| `FILE_UPDATE` | Description or classification changed | yes |
| `FILE_RENAME` | Display name changed | yes |
| `FILE_DELETE` / `FILE_UNDELETE` / `FILE_PURGE` | Trash lifecycle | yes |
| `FILE_SHARE` | A grant was created | yes |
| `FILE_PERMISSION_CHANGE` | A grant was revoked; ownership transferred | yes |
| `FILE_VERSION_CREATED` | A replacement version was uploaded | yes |
| `FILE_VERSION_RESTORED` | An old version was restored as the new current version | yes |
| `FILE_ACCESS_DENIED` | **Any** DENY decision on a file action | yes (sessionless only for an ended session with a valid signature) |
| `FILE_INTEGRITY_CHECK` | Integrity check passed | yes |
| `FILE_INTEGRITY_FAILURE` | Integrity check failed or download blocked | yes |
| `REAUTHENTICATION` / `REAUTHENTICATION_FAILED` | Step-up attempt | yes |
| `USER_CREATED` / `USER_UPDATED` | Admin user management (role, active flag) | yes |
| `USER_PROVISIONED` | User created via the CLI (no session) | sessionless |

**Z3: no separate `FILE_ACCESS_GRANTED`.** An ALLOW decision is recorded *inside* the operation's own event (`decision: "ALLOW"`, `reason_code`, `policy`). This gives exactly **one chained event per decision**:
- ALLOW → the operation event;
- DENY → `FILE_ACCESS_DENIED`.

Emitting both a GRANTED event and an operation event would double the chain length without adding information. If you prefer the literal list, `FILE_ACCESS_GRANTED` can be emitted before each operation event instead.

`FILE_CREATE` is not a separate type: CREATE is the initial upload (`FILE_UPLOAD`).

### 13.3 Event payload (part of E_n, therefore hashed) [Reuse encoding rules: no floats, NFC, ≤ 2⁵³]

```json
{ "file_id": "7c1e…", "version": 3, "classification": "RESTRICTED", "filename": "[redacted]",
  "action": "DOWNLOAD", "decision": "DENY", "reason_code": "GRANT_REQUIRED",
  "reasons": ["GRANT_REQUIRED"], "required_permission": "DOWNLOAD", "permission_source": "ROLE",
  "policy": "access-policy.v1 sha256:9f2a…", "sha256": null, "size_bytes": null,
  "ip_address": "172.18.0.1", "request_id": "b2c4…",
  "signals": { "session_age_s": 1840, "auth_age_s": 1840, "recent_denials": 2,
               "recent_downloads": 0, "ownership": "NONE", "discoverable": true } }
```

The context C_n (user, session, previous event, sequence number, timestamp) is added by the **existing** enrichment layer, exactly as the paper defines it. The paper's example "EMP102 · DOWNLOAD · salary_report.xlsx · RESTRICTED · DENY · S8392" maps onto `actor_user_id`, `session_id`, `event_type` and this payload.

**Redaction (Z11).** For RESTRICTED+ files the payload stores `"[redacted]"` instead of the name. The chain is immutable, so a sensitive name written into it can never be removed. Authorised viewers see the name, resolved through `file_id` in the UI.

### 13.4 Transition rules `transitions.v2.json` (Z5)
- **Superset invariant:** every v1 pair is still allowed, and v2 adds **no** new pairs between v1 event types. Login → FILE_OPEN stays disallowed, so the paper's §VI-F example (T4.6) behaves identically.
- **New types:**
  - Let *A* = the new authenticated-activity types (all session file events, `REAUTHENTICATION*` and `USER_*`).
  - `AUTHENTICATION → A`, and each `a ∈ A → A ∪ {LOGOUT}`.
  - The v1 activity types (`FILE_OPEN`, `FILE_EDIT`, `DB_ACCESS`) are not connected to *A*. The system stream never produces them, and leaving them unconnected keeps the superset invariant trivially true.
- `USER_PROVISIONED` is sessionless.
- **Server-only types:** `SECURITY_VIOLATION` plus all v2 file/user/reauth types. External ingestion (`POST /streams/{id}/events`) rejects them, so an ingestor cannot forge file-governance evidence into another stream. This needs a small `server_only_events` field in the rule file.
- **Verification** uses v2 (the rule version is already recorded per run [Reuse]).
- **The workload generator stays pinned to v1.** `generator._session_path` walks `rules.allowed`, so with v2 the same seed would generate different streams and break T7.3 reproducibility and the recorded smoke run. A test asserts that the generator's output for a fixed seed is unchanged.

---

## 14. API design [Eng]

Conventions are as in `API_SPEC.md` [Reuse]: `/api/v1`, the error shape, hex hashes and ISO timestamps. Every file response carries `allowed_actions: string[]` computed by the policy engine for the caller. **The frontend never infers permissions itself.**

### 14.1 Auth and users

| Method | Path | Who | Notes |
|---|---|---|---|
| GET | `/auth/me` | any | + `capabilities`, `display_name`, `session: {started_at, authenticated_at}` |
| POST | `/auth/reauthenticate` | any | `{password}` → chained `REAUTHENTICATION` / `_FAILED` |
| GET | `/operators` | admin | List users |
| POST | `/operators` | admin | [Reuse] + chained `USER_CREATED`; roles extended |
| PATCH | `/operators/{id}` | admin | `{role?, is_active?, display_name?, department?}` → chained `USER_UPDATED`. Admins cannot demote or deactivate themselves (lock-out guard) |
| GET | `/directory/users?q=` | `files:use` | Minimal `{id, username, display_name}` for the share dialog |

### 14.2 Files

| Method | Path | Permission | Event |
|---|---|---|---|
| GET | `/files?scope=all\|mine\|shared\|recent\|trash&q=&classification=&type=&owner=&uploader=&from=&to=&access=&sort=&order=&limit=&offset=` | discoverable only | — (listing is not chained) |
| POST | `/files` (multipart: `file`, `classification`, `description?`) | CREATE | `FILE_UPLOAD` |
| GET | `/files/{id}` | READ (metadata) | `FILE_VIEW` (metadata) for RESTRICTED+ |
| GET | `/files/{id}/content?disposition=inline\|attachment&version=` | READ (inline) / DOWNLOAD | `FILE_VIEW` / `FILE_DOWNLOAD` |
| GET | `/files/{id}/preview` | READ | `FILE_VIEW`: txt/csv as JSON text (first 64 KiB) |
| PATCH | `/files/{id}` | RENAME / UPDATE / MANAGE_PERMISSIONS (downgrade) | `FILE_RENAME` / `FILE_UPDATE` |
| GET | `/files/{id}/versions` | READ | — |
| POST | `/files/{id}/versions` (multipart: `file`, `base_version`, `change_reason?`) | UPLOAD | `FILE_VERSION_CREATED` |
| POST | `/files/{id}/versions/{n}/restore` `{base_version, reason}` | RESTORE | `FILE_VERSION_RESTORED` |
| DELETE | `/files/{id}` | DELETE | `FILE_DELETE` |
| POST | `/files/{id}/undelete` | RESTORE | `FILE_UNDELETE` |
| DELETE | `/files/{id}/purge` | MANAGE_PERMISSIONS | `FILE_PURGE` |
| GET | `/files/{id}/permissions` | READ (own grant) / SHARE / MANAGE (all) | — |
| POST | `/files/{id}/permissions` `{grantee_id, permissions[], expires_at?, reason?}` | SHARE | `FILE_SHARE` |
| DELETE | `/files/{id}/permissions/{grant_id}` | SHARE (own grants) / MANAGE | `FILE_PERMISSION_CHANGE` |
| PUT | `/files/{id}/owner` `{owner_id, reason}` | MANAGE_PERMISSIONS | `FILE_PERMISSION_CHANGE` |
| POST | `/files/{id}/integrity` | VERIFY | `FILE_INTEGRITY_CHECK` / `_FAILURE` |
| GET | `/files/{id}/history` | READ, or auditor/admin | — (reads the chain by `file_id`; each row includes `hash_matches`/`link_matches` [Reuse]) |
| GET | `/files/{id}/access-check?action=` | discoverable | — (dry run for the UI; **not** chained, since nothing was accessed) |

Every DENY on these endpoints chains a `FILE_ACCESS_DENIED`.

### 14.3 Security and investigation (auditor, admin)

| Method | Path | Notes |
|---|---|---|
| GET | `/security/summary?from=&to=` | Dashboard tiles and chart series, computed from DB + chain |
| GET | `/security/denials?user=&file=&reason=&from=&to=` | Chained `FILE_ACCESS_DENIED` events with chain links |
| GET | `/security/events?type=&user=&file=&decision=` | All file and user governance events |
| GET | `/security/integrity` | Per-version status (cache) + recent check events |
| POST | `/security/integrity/scan` | Admin; bulk scan (§12.2) |
| GET | `/security/governance-check` | Reconciliation (§12.3) |
| GET | `/security/investigations/users/{username}` | Timeline: decisions, denials, bursts, self-grants, IPs; each row linked to its chain index and batch |
| GET | `/security/policy` | Active policy (role matrix, classification table) + version + SHA-256 |
| GET | `/admin/settings` | Effective non-secret configuration: max upload, allowed types, lab flag, storage backend |

### 14.4 Error codes (new)

| HTTP | Code | When |
|---|---|---|
| 403 | `ACCESS_DENIED` | DENY on a discoverable file. Details: `{action, decision, reason_code, reasons, required_permission, classification, your_role, your_permissions, audit: {stream_id, chain_index}}` |
| 403 | `STEP_UP_REQUIRED` | As above, plus `{step_up_minutes}`; the UI opens the re-auth dialog |
| 404 | `FILE_NOT_FOUND` | Missing **or** undiscoverable (identical response) |
| 409 | `VERSION_CONFLICT` | Stale `base_version` |
| 409 | `INTEGRITY_FAILURE` | Download/preview blocked by L1 |
| 411 | `LENGTH_REQUIRED` | Upload without `Content-Length` |
| 413 | `FILE_TOO_LARGE` | Over the configured maximum |
| 415 | `UNSUPPORTED_FILE_TYPE` / `FILE_TYPE_MISMATCH` | Extension not allowed / content does not match the extension |
| 422 | `INVALID_FILENAME` | Sanitiser rejection |
| 503 | `STORAGE_UNAVAILABLE` | Storage root not writable or readable |

The response includes the denial's **chain index**. The UI can therefore say "This attempt was recorded as audit event #1234 in the system stream", and link to it.

### 14.5 Downloads without leaking tokens
The frontend fetches content with the `Authorization` header and builds a `Blob`/object URL. Tokens are **never** put in URLs, which would leak through logs and history. This works up to the 25 MiB default. Signed one-time download tickets are [Future] for large files.

---

## 15. Frontend architecture [Eng]

### 15.1 Structure

```
frontend/src/
  app/            App.tsx (routes), AppShell (sidebar + top bar), nav.ts (capability → nav items), redirects
  api/            client.ts (+ multipart upload, blob download), types.ts, files.ts, security.ts, admin.ts
  auth/           AuthProvider (+capabilities, session info), StepUpDialog, RequireCapability
  ui/             design system: Button, IconButton, Badge, ClassificationBadge, DecisionBadge, StatusDot,
                  DataTable (sortable headers, sticky, server-side paging), FilterBar, SearchInput, Tabs,
                  Card, StatTile, Dialog (native <dialog>), ConfirmDialog, Drawer, Toast/Toaster,
                  EmptyState, Skeleton, ErrorState, Field/Select/TextArea, Hash, Timeline, Icon
  styles/         tokens.css (light/dark), base.css, components.css
  features/
    dashboard/    DashboardPage (role-aware)
    files/        FilesPage (scopes), FileDetailPage (tabs), UploadDialog, NewVersionDialog, ShareDialog,
                  AccessDeniedPanel, VersionsTab, PermissionsTab, ActivityTab, IntegrityTab, TrashPage
    security/     PoliciesPage, DeniedAccessPage, IntegrityPage, SecurityEventsPage, InvestigationPage,
                  AccessRequestsPage (ZT-10)
    audit/        existing Streams / Events / EventDetail / Session / Batches / Verification pages, moved
    research/     existing LabPage, ExperimentsPage (+ file scenarios F1–F6)
    admin/        UsersPage, RolesPage (read-only matrix from /security/policy), SettingsPage (read-only)
```

### 15.2 Rules
- **Authorisation is reflected, never decided.**
  - The navigation comes from `capabilities`.
  - Action buttons come from `allowed_actions`.
  - A 403 is always handled gracefully, because the backend is the authority and state may change between render and click.
- **State:** keep the existing `useLoader` pattern. Filters, sort and scope live in URL search params, so views are shareable and reload-safe. No global state library.
- **New dependency (Z12):** `lucide-react` for consistent, tree-shaken, accessible icons (ISC licence). No CSS framework and no component library; the design system is plain CSS on tokens. **Optional (Z13):** Vitest + Testing Library for the client and the permission-reflecting components.
- **Charts:** Plotly (existing), lazy-loaded, fed only by API data. The `check:metrics` build guard [Reuse] continues to scan all of `src/`.
- **Sample data labelling:** `origin=demo|lab` files and synthetic/lab streams always show a badge and a banner [Reuse pattern].

---

## 16. Security controls (implementation checklist) [Eng]

### 16.1 Authorisation
- One `FileService` entry point per operation. Each calls `policy.decide()`; there is **no code path** that touches a file without a decision.
- A test enumerates every `/files*` route and asserts an unauthorised principal is denied, so a new route cannot ship unguarded.
- IDs in paths are UUID-typed (FastAPI validation). Grant and version IDs are always looked up **scoped to the file** (`WHERE file_id = :id AND id = :grant_id`), which prevents cross-file IDOR.

### 16.2 Filename sanitisation (pure)
- Take the basename after both `/` and `\`, then apply NFC.
- Reject: empty names; `.`/`..`; control characters (C0/C1); bidi overrides (U+202A–U+202E, U+2066–U+2069); NUL; names over 255 UTF-8 bytes; Windows reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`); trailing dots or spaces.
- The extension (after the last dot, lowercased) must be in the allowlist.
- Double extensions such as `report.pdf.exe` are judged by the **last** extension, so this one is rejected.
- `Content-Disposition: attachment; filename="<ascii fallback>"; filename*=UTF-8''<percent-encoded>` prevents header injection.

### 16.3 Type validation (pure, Z6: standard library only)

| Extension(s) | Required content signature | Extra checks |
|---|---|---|
| `.pdf` | `%PDF-` | — |
| `.png` | `89 50 4E 47 0D 0A 1A 0A` | — |
| `.jpg` `.jpeg` | `FF D8 FF` | — |
| `.docx` `.xlsx` `.pptx` | ZIP `PK 03 04` | Central directory read with `zipfile` (**no decompression**). Must contain `[Content_Types].xml` and `word/` / `xl/` / `ppt/` respectively. Reject if it contains `vbaProject.bin` (macros). Entry-count cap against zip bombs |
| `.doc` `.xls` `.ppt` | OLE2 `D0 CF 11 E0 A1 B1 1A E1` | The three cannot be told apart without parsing; accepted on the signature (documented) |
| `.txt` `.csv` | No NUL bytes in the first 8 KiB; must decode as UTF-8 (BOM allowed) | CSV previews render as text, never as a spreadsheet, so there is no formula execution. Downloaded CSVs can still carry formula injection into Excel: documented, [Future] sanitisation |

- The client's `Content-Type` is ignored.
- The **served** MIME comes from the server's table.
- `X-Content-Type-Options: nosniff` on every response.
- The allowlist is configurable (`TRACELOCK_ALLOWED_EXTENSIONS`), but each enabled extension **must** have a signature rule. Startup fails otherwise.
- SVG, HTML, JS and archives are deliberately **not** allowed (active content).

### 16.4 Size limits
- `TRACELOCK_MAX_UPLOAD_BYTES` (default 25 MiB).
- `Content-Length` is required (411 otherwise) and checked **before** the body is read (413). Bytes are counted again while streaming, because the header is untrusted.
- **Known limitation:** Starlette/python-multipart spools the body to a temporary file before the handler runs. The early `Content-Length` check bounds this, but the request body limit should also be set at a reverse proxy in deployment.
- **Optional:** a per-user storage quota.

### 16.5 Serving content
- `Content-Security-Policy: default-src 'none'; img-src 'self' blob:; sandbox` and `Cache-Control: no-store` on content responses.
- Inline disposition only for PNG, JPEG and PDF (PDF preview only below HIGHLY_RESTRICTED). Everything else is attachment-only.
- **Honest limitation:** a preview transfers the bytes. READ without DOWNLOAD is a usability control, **not DRM**. A user can screenshot or save what they can see.

### 16.6 Other controls
- **Secrets:** no new secrets. Storage paths and storage keys are never logged or returned.
- **Logging:** application logs record `request_id`, the decision and the reason code, but never tokens, passwords or file contents [Reuse rule].
- **Fail closed:** a policy file error, a storage root that is not writable, or a failed audit append → the operation is refused. **No audit, no action.**
- **Unauthenticated requests are not chained**, to avoid letting anonymous clients flood the chain. They are logged at application level only. This matches the existing behaviour, except for `LOGIN_FAILED`.

---

## 17. Testing strategy [Eng, following TESTING.md rules: independent oracles, fixed seeds, isolation]

### 17.1 Unit (no DB)

| ID | Test |
|---|---|
| ZT1.1 | **Exhaustive policy matrix:** 5 roles × 5 classifications × 11 actions × {owner, grant, none} × {deleted, live}. Compared with an **independent oracle** written directly from §8 and §10 tables in the test file, not from the policy code |
| ZT1.2 | Context rules: session age, step-up window boundaries (just inside / just outside), denial burst, rate limit, optional CIDR and hours |
| ZT1.3 | Share anti-escalation (each rule in §7.4) and classification downgrade |
| ZT1.4 | Discoverability: undiscoverable → `discoverable=false` for every non-admin/auditor role |
| ZT1.5 | Policy file validation: inconsistent roles, missing levels, MANAGE in owner permissions → load error; SHA-256 recorded |
| ZT1.6 | `transitions.v2`: superset invariant against v1, no new pairs between v1 types; T4.6 still produces exactly the paper's findings; file-session scenarios (event after LOGOUT, before AUTHENTICATION, deleted denial) fail the right P-check |
| ZT1.7 | Generator pinned to v1: a fixed seed reproduces the previously recorded event-type sequence |
| ZT2.1 | Filename sanitiser: traversal (`../../etc/passwd`, `..\\..\\x`), absolute paths, RTL-override spoof (`gnp.exe` shown as `exe.png`), reserved names, NUL, overlong names, double extensions, NFC/NFD |
| ZT2.2 | Type detection: each allowed type accepted; spoofed pairs rejected (PNG renamed `.pdf`, EXE renamed `.docx`, HTML renamed `.txt` with NUL, a ZIP that is not OOXML, OOXML with `vbaProject.bin`); polyglot files; empty files |
| ZT2.3 | Storage: key regex, path confinement, atomic write (no partial file after an abort), size-limit abort removes the temp file, SHA-256 checked against `hashlib` over the same bytes |
| ZT2.4 | Payload builder: no floats, redaction for RESTRICTED+, every value encodable by `canonical_json` [Reuse] |

### 17.2 API (DB-backed, tmp storage root)

| ID | Test |
|---|---|
| ZT3.1 | **Route guard enumeration:** every `/files*`, `/security*`, `/admin*` route → 401 without a token and denial for the wrong role/permission |
| ZT3.2 | **IDOR:** user B requests user A's RESTRICTED file by ID → 404 (body identical to a random UUID's), and a chained `FILE_ACCESS_DENIED` exists |
| ZT3.3 | **Exactly one chained event per decision** for every endpoint, with the expected type, decision and reason code |
| ZT3.4 | A denial is committed even though the response is 403/404; an ALLOW whose mutation fails rolls back its event (fail-closed) |
| ZT3.5 | After a full workflow (upload, view, deny, share, version, restore, delete, undelete, verify, logout), `verify_stream(system)` → **VALID**, zero findings [Reuse engine] |
| ZT3.6 | Upload limits: 411, 413 (header and streamed), 415 type mismatch, 422 bad name; no blob or row left behind |
| ZT3.7 | Response headers: `nosniff`, CSP sandbox, RFC 6266 disposition, `no-store` |
| ZT4.1 | Version race: two concurrent replacements with the same `base_version` → one 201, one 409; versions contiguous |
| ZT4.2 | Restore creates version n+1 with `restored_from_version`; old blobs unchanged (bytes and hash) |
| ZT4.3 | Sharing escalation, self-grant (non-admin denied, admin chained and flagged), expired grant denied, revoked grant denied |
| ZT4.4 | Classification upgrade by owner allowed; downgrade by owner denied; downgrade by admin with reason allowed and chained |
| ZT4.5 | Step-up: HIGHLY_RESTRICTED download → 403 STEP_UP_REQUIRED → reauthenticate → allowed within the window → denied after it (injected clock) |
| ZT4.6 | Ended session (after logout) with a still-signed token → 401 + sessionless chained denial |
| ZT5.1 | L1: modify blob bytes → download 409 + `FILE_INTEGRITY_FAILURE`; bytes not served |
| ZT5.2 | L2: modify blob and `file_versions.sha256` consistently → `METADATA_MISMATCH` |
| ZT5.3 | L3: additionally edit the anchoring event's payload → `ANCHOR_TAMPERED`, and stream verification → TAMPERING_DETECTED |
| ZT5.4 | Reconciliation: grant `INSERT`ed by SQL → `GRANT_UNANCHORED`; owner/classification changed by SQL → detected |
| ZT6.x | Security APIs: counts equal the hand-counted fixture events; investigation timeline links resolve to existing chain indices |

### 17.3 Frontend
- `npm run build` (metrics guard + `tsc` + Vite) [Reuse].
- If Z13 is approved, Vitest:
  - the API client error mapping;
  - `AccessDeniedPanel` renders backend details verbatim;
  - action buttons render exactly the `allowed_actions` received;
  - the nav renders exactly the capabilities.
- A manual browser walkthrough checklist per page (logged in TESTING.md, as in Phase 8).

### 17.4 File tamper lab scenarios (expected outcome stored **before** verification [Reuse rule])

They run only on `origin='lab'` files, whose events are written to a fresh **lab** stream with a synthetic session. A guard refuses non-lab files, tested like T7.2.

| ID | Tampering | Attacker | Expected detected? | Expected by |
|---|---|---|---|---|
| F1 | Modify blob bytes | A0 | Yes | L1 |
| F2 | Delete blob | A0 | Yes | L1 `BLOB_MISSING` |
| F3 | Modify blob + `file_versions.sha256` | A1-file | Yes | L2 |
| F4 | F3 + edit the anchoring event's payload (no rehash) | A0-chain | Yes | L3 / `CHAIN_HASH` |
| F5 | F4 + recompute that event's own hash | A1 | Yes | `CHAIN_LINK` at k+1 |
| F6 | F4 + full rewrite of all later hashes and roots | A2 | **No** (expected) | Paper §IX-B limitation; negative control |
| F7 | Grant inserted directly by SQL | A0-state | Yes | Reconciliation |

---

## 18. Failure scenarios

| Scenario | Behaviour |
|---|---|
| Blob written, DB transaction fails | Orphan blob, never referenced or served; removed by `storage-gc` |
| DB unavailable | 503 [Reuse health]; no file operation possible (no audit, no action) |
| Storage root unavailable or not writable | 503 `STORAGE_UNAVAILABLE`; startup readiness check warns |
| Disk full during upload | Temp file removed; 507/503; no rows, no event |
| Blob missing or hash mismatch at download | Not served; 409 `INTEGRITY_FAILURE`; chained `FILE_INTEGRITY_FAILURE` |
| Audit append rejected by provenance (e.g. logout raced the request) | `SECURITY_VIOLATION` committed [Reuse Q6]; operation aborted; 409 |
| Two concurrent version uploads | One wins; the other gets 409 `VERSION_CONFLICT` |
| Rename/metadata race | Serialised by the row lock; last writer wins; both chained |
| Grant expires between listing and download | Download denied at decision time (decisions are never cached) |
| User deactivated or role changed mid-session | The next request is 401 [Reuse: role-mismatch check] |
| Token expires mid-upload | The request completes if it was authorised at start (decision time); the next request is 401 |
| Policy file missing or invalid | Startup fails (fail closed) |
| Clock steps backwards | Event timestamps clamped [Reuse Q15]; policy windows may be off by the step (ZT2, documented) |
| Zip bomb / huge OOXML central directory | Entry-count and central-directory size caps; never decompressed |
| Very long sessions with many events | `append_event` replays the session history per append (O(session length)), so latency grows with session length. Measured in ZT-E4 |
| Lab file scenario targets a real file | Refused by the guard (`LabSafetyError` pattern) |

---

## 19. UI redesign plan [Eng]

### 19.1 Design direction
An enterprise security console: calm, dense where it helps (tables), clear hierarchy, colour reserved for meaning.

- **Tokens:**
  - neutral slate surfaces, **one** accent (blue);
  - semantic colours only for status: ok, warn, danger, info;
  - a 4/8 px spacing scale;
  - 6 px radius on controls, 8 px on cards;
  - 1 px borders instead of heavy shadows;
  - the system font stack (no web-font dependency) with tabular numbers;
  - a monospace stack for hashes.
- **Theme:** light and dark through `data-theme` on `<html>`, defaulting to `prefers-color-scheme`, with a toggle in the user menu (per-viewer preference in `localStorage`, guarded). The existing tokens are migrated, not discarded.
- **Classification badges:** each level has a distinct hue **plus** a text label **plus** an icon (never colour alone):
  - PUBLIC: neutral, globe icon;
  - INTERNAL: blue, building icon;
  - CONFIDENTIAL: amber, lock icon;
  - RESTRICTED: orange-red, shield icon;
  - HIGHLY_RESTRICTED: red, filled shield-alert icon with a bordered badge.
- **Decision badges:** ALLOW (green check) and DENY (red x). Integrity: INTACT, MISMATCH, UNVERIFIED.
- **Avoid:** gradients, decorative illustrations, large hero areas, animation beyond 150 ms state transitions (with `prefers-reduced-motion` respected), and rainbow charts.
- **Accessibility:**
  - every control has a label;
  - focus rings visible;
  - dialogs trap focus (native `<dialog>`);
  - toasts use `aria-live="polite"`;
  - tables use `<th scope>`;
  - contrast ≥ WCAG AA in both themes.
- **Responsive:** the sidebar collapses to icons below 1200 px and becomes a drawer below 768 px. Tables scroll horizontally inside their card, never the page.

### 19.2 App shell

```
┌────────────┬─────────────────────────────────────────────────────────────────────────┐
│ ◆ TraceLock│  ⌕ Search files…                     [DEMO DATA]  ● API online  ☾  alice ▾│
│            ├─────────────────────────────────────────────────────────────────────────┤
│ Dashboard  │  Files / All files                                       [⤒ Upload file]│
│ FILES      │  ┌──────────────────────────────────────────────────────────────────┐  │
│  All files │  │ [Classification ▾] [Type ▾] [Owner ▾] [Date ▾] [Access ▾]  Clear │  │
│  My files  │  ├──────────────────────────────────────────────────────────────────┤  │
│  Shared    │  │ Name ↑            Class.          Type  Owner  Size  Modified  ⋯ │  │
│  Recent    │  │ ▤ q3-budget.xlsx  ⛨ RESTRICTED    XLSX  dana   1.2MB 2h ago    ⋯ │  │
│  Trash     │  │ ▤ handbook.pdf    ◯ PUBLIC        PDF   admin  640KB 3d ago    ⋯ │  │
│ SECURITY   │  └──────────────────────────────────────────────────────────────────┘  │
│  Policies  │                                              ‹ 1 2 3 ›  50 per page   │
│  Denied    │                                                                         │
│  Integrity │                                                                         │
│  Events    │                                                                         │
│  Investig. │                                                                         │
│ AUDIT      │                                                                         │
│  Streams…  │                                                                         │
│ RESEARCH   │                                                                         │
│ ADMIN      │                                                                         │
└────────────┴─────────────────────────────────────────────────────────────────────────┘
```

Sections appear only when `/auth/me` returns the capability.

### 19.3 Dashboard (role-aware)
- **Everyone:** recent files, shared with me, my recent activity, **my denied attempts** (transparency builds trust in the policy).
- **Admin / auditor** stat tiles:
  - total files;
  - added (7 days);
  - accessed (7 days);
  - RESTRICTED+ files;
  - integrity failures (open);
  - denied attempts (24 hours);
  - `system` stream last verification status, linking to Verify.
- **Charts** (only where meaningful; data from `/security/summary`):
  1. **Access decisions over time:** stacked ALLOW/DENY per day. Shows spikes in denials.
  2. **Files by classification:** horizontal bar, in classification order (an ordered category, so not a pie).
  3. **Denials by reason code:** horizontal bar. Answers "why are people blocked?".
  4. **File activity over time:** uploads, versions and downloads per day.
- File-type distribution is shown as a compact table rather than a chart, because it rarely drives a decision.

### 19.4 File detail

```
 Files / q3-budget.xlsx
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │ ▤ q3-budget.xlsx   ⛨ RESTRICTED   v4   ✓ Integrity intact (checked 10:02)     │
 │ Owner dana · Uploaded by dana · Created 2026-10-01 · Updated 2h ago · 1.2 MB   │
 │ SHA-256 9f2a41…c08e [copy]                                                      │
 │ [⤓ Download] [👁 Preview] [✎ Rename] [⤒ New version] [⇆ Share] [✓ Verify]      │
 │   (only actions in allowed_actions are rendered)                               │
 ├ Overview │ Versions │ Permissions │ Activity │ Integrity ────────────────────────┤
 │ Activity: timeline of chained events: time · user · event · decision · reason  │
 │           · chain #1234 ↗ (opens Audit › Event detail with hash relationships) │
 └───────────────────────────────────────────────────────────────────────────────┘
```

### 19.5 Access-denied panel (from the backend 403 details, verbatim)

```
 ┌ ✕ ACCESS DENIED ─────────────────────────────────────────────────────────────┐
 │ You signed in successfully, but you do not have permission to DOWNLOAD this  │
 │ RESTRICTED document.                                                          │
 │ Required permission     DOWNLOAD                                              │
 │ Classification          ⛨ RESTRICTED: requires an explicit grant or ownership│
 │ Your role               employee  (role grants: none at RESTRICTED)           │
 │ Your permissions        READ (granted by dana, expires 2026-10-09)            │
 │ Decision                DENY · GRANT_REQUIRED · access-policy.v1              │
 │ This attempt was recorded as audit event #1234 in the system stream. [View]   │
 │                                    [Request access]  [Close]                  │
 └───────────────────────────────────────────────────────────────────────────────┘
```

`STEP_UP_REQUIRED` opens a password re-entry dialog instead, then retries once.

### 19.6 Other required patterns
- **Empty states** with one next action (e.g. "No files shared with you yet").
- **Skeleton rows** while loading.
- **Inline error state** with retry.
- **Confirmation dialogs** for delete, purge (type the filename to confirm), revoke, ownership transfer and classification downgrade.
- **Toasts** for completed actions, including the chain index.

---

## 20. Migration plan from the current TraceLock UI [Eng]

1. **Foundation first (ZT-7), no new features.**
   - Introduce tokens, the `ui/` components, the AppShell and the capability nav.
   - Move the existing pages into `features/audit` and `features/research` and re-skin them.
   - Behaviour must be identical. In particular, `KindBadge` and `DataBanner` keep their wording.
2. **Route map with redirects.** Old bookmarks and `DEMO.md` steps keep working.

   | Old | New |
   |---|---|
   | `/streams` | `/audit/streams` |
   | `/streams/:id/events[/:n]` | `/audit/streams/:id/events[/:n]` |
   | `/streams/:id/sessions/:sid` | `/audit/streams/:id/sessions/:sid` |
   | `/streams/:id/batches` | `/audit/streams/:id/batches` |
   | `/streams/:id/verification` | `/audit/streams/:id/verification` |
   | `/lab` | `/research/lab` |
   | `/experiments` | `/research/experiments` |
   | (default `/streams`) | `/dashboard` |

   The navigation adds direct shortcuts: Audit › Audit events, Hash chain, Merkle batches and Verification open the `system` stream's tabs.
3. **Then the file and security features** (ZT-8, ZT-9) inside the new shell.
4. **Unchanged:**
   - token handling (`sessionStorage`);
   - the ingestor-only screen;
   - the lazy Plotly chunk;
   - the metrics guard;
   - the synthetic/lab banners.
5. **`DEMO.md` and `demo_walkthrough.py`** are updated in ZT-10, using the new routes and a seeded demo file set with `origin='demo'`.

---

## 21. Implementation phases

Each phase follows the CLAUDE.md workflow:
1. objective, files and approach;
2. implement only that phase;
3. tests pass;
4. summary;
5. **wait for approval**.

| Phase | Scope | Main deliverables |
|---|---|---|
| **ZT-0** | Design (this document) + decisions Z1–Z19 | `docs/ZERO_TRUST_FILE_MODULE.md` |
| **ZT-1** | Identity and policy core (pure) | Migration `0005` (roles, operator columns, indexes); `access/` (model, policy file loader, `decide`); `access_policy.v1.json`; `transitions.v2.json` + `server_only_events`; generator pinned to v1; tests ZT1.x |
| **ZT-2** | Validation and storage | `files/validation.py`, `files/storage.py`; `python-multipart` dependency; `filestore` volume, Dockerfile directory, settings, `.env.example`; tests ZT2.x |
| **ZT-3** | Core file operations + audit integration | Migration `0006`; `files/service.py`, `files/audit.py`, `access/context.py`; endpoints: create, list, detail, content, preview, rename, update; `reauthenticate`; tests ZT3.x |
| **ZT-4** | Versions, trash, sharing, ownership, classification | Remaining file endpoints; concurrency and escalation tests ZT4.x |
| **ZT-5** | Integrity and governance | `files/integrity.py`; verify-before-serve; on-demand and bulk checks; reconciliation; lab scenarios F1–F7; tests ZT5.x |
| **ZT-6** | Security, investigation and admin APIs | `/security/*`, `/operators` list/patch (chained), `/admin/settings`, `/directory/users`; tests ZT6.x |
| **ZT-7** | Frontend foundation redesign | Tokens + theme, `ui/` library, AppShell, capability nav, existing pages migrated with redirects; `lucide-react` |
| **ZT-8** | Frontend file experience | Dashboard, file table, file detail tabs, upload/new version/share/step-up dialogs, access-denied panel, trash |
| **ZT-9** | Frontend security and admin | Denied access, integrity, security events, investigation, policies, users, roles, settings |
| **ZT-10** | Completion | Access requests (if Z15); demo seed (`origin=demo`); DEMO script; experiments ZT-E1–E4 (§22.2); all docs updated; final security table with test IDs |

---

## 22. Acceptance criteria

### 22.1 Per phase (summary; each phase's detailed list will be written into PROJECT_PLAN.md when it starts)
- **ZT-1:**
  - the policy matrix test agrees with the independent oracle on every combination;
  - the v2 superset invariant holds;
  - T4.6 is unchanged;
  - the generator output for a fixed seed is unchanged;
  - all existing tests still pass.
- **ZT-2:**
  - every malicious-filename and spoofed-type fixture is rejected;
  - no path outside the storage root is reachable;
  - an aborted upload leaves no file.
- **ZT-3:**
  - every endpoint produces exactly one chained event per decision;
  - the system stream verifies VALID after the workflow;
  - IDOR returns 404 and is chained;
  - no file operation is possible without a decision (route enumeration test).
- **ZT-4:**
  - the version race gives 1×201 + 1×409;
  - no escalation path in the §7.4 tests;
  - downgrade is admin-only;
  - restore is non-destructive.
- **ZT-5:**
  - F1–F5 and F7 are detected and F6 is not, matching the expectations stored beforehand;
  - a download never serves mismatched bytes.
- **ZT-6:** security summaries equal hand-counted fixtures; every investigation row links to a real chain index.
- **ZT-7:**
  - every pre-existing page works at its new route and old URLs redirect;
  - the build and metrics guard pass;
  - both themes meet AA contrast on the token pairs.
- **ZT-8/9:**
  - the UI renders only backend-authorised actions;
  - a denied action shows the backend explanation and audit reference;
  - every page has loading, empty and error states;
  - manual browser walkthrough recorded.
- **ZT-10:**
  - the demo runs end to end from a fresh clone;
  - `SECURITY_LIMITATIONS.md` §5 lists each new protection with its test IDs;
  - no unmeasured number appears anywhere.

### 22.2 New experiments (definitions only; **no results exist**)

| ID | Metric | Procedure (to be detailed in EXPERIMENTS.md before running) |
|---|---|---|
| ZT-E1 | Policy decision latency | `perf_counter` around `decide()` (pure), and end-to-end per endpoint; median/IQR over R repetitions |
| ZT-E2 | Integrity overhead vs file size | Upload and verify-before-serve time for 1 KiB … 25 MiB; hash time separated from I/O |
| ZT-E3 | File tamper detection rate | F1–F7 × trials, with Wilson intervals [Reuse metrics]; F6 expected 0 |
| ZT-E4 | Audit write throughput under file load | Operations per second with N concurrent users serialised on the system stream lock; append latency vs session length |

---

## 23. Risks and limitations

These will be merged into `SECURITY_LIMITATIONS.md`.

| # | Limitation |
|---|---|
| L1 | **Tamper-evident, not tamper-proof.** Someone with DB and storage write access can change files, grants and ownership. Reconciliation and integrity checks **detect** this afterwards, unless the chain and roots are fully rewritten (ZA5; paper §IX-B). Nothing here prevents a DB superuser |
| L2 | **Access is decided from mutable state.** A grant inserted by SQL works until reconciliation runs |
| L3 | **SHA-256 does not prevent modification.** It only reveals it. Unkeyed hashes can be recomputed (A1); see S2 and F5 |
| L4 | **Preview ≠ DRM.** Anything a user can view, they can copy. Downloaded copies leave the system's control entirely |
| L5 | **No malware scanning.** Type validation is not antivirus. ClamAV in a sidecar is [Future] |
| L6 | **No encryption at rest** for blobs or DB [Future] |
| L7 | **Step-up is password re-entry, not MFA** |
| L8 | **Context signals are heuristics.** The IP is unreliable behind proxies or Docker NAT (ZT3). Rate and denial thresholds are arbitrary defaults that can block legitimate users or miss slow attackers. No ML is used |
| L9 | **Everything rests on correct classification by humans** (ZT4) and on events being captured faithfully (paper T1) |
| L10 | **The immutable chain conflicts with erasure.** A name written into a payload cannot be removed; redaction (Z11) reduces but does not remove this. Purge keeps tombstones |
| L11 | **Throughput:** all platform writes serialise on the `system` stream lock. Per-append session replay grows with session length. To be measured (ZT-E4) |
| L12 | **Large files:** verify-before-serve reads the file twice. Fine at 25 MiB, not for very large files ([Future]: streaming verification with chunk hashes) |
| L13 | **Policy changes need a restart** (versioned file). This is deliberate for reproducibility, but less convenient than a policy editor |
| L14 | **Unauthenticated probing is not chained** (to avoid flooding). It is visible only in application logs |
| L15 | **Metadata exposure to admin/auditor:** they see the names of all files (RESTRICTED+ names are redacted only in the chain). This is a deliberate investigation trade-off |

### 23.1 Future research opportunities [Future]
- **Keyed or anchored file hashes:** HMAC'd or externally anchored version hashes would close F5/F6 (the paper's own §X direction, applied to content).
- **A formal treatment of governance reconciliation** (§12.3): proving which state tamperings are detectable given a chain-anchored history.
- **Access-semantic provenance rules:** transition rules such as "DOWNLOAD requires a preceding VIEW decision in the session", and their false-alarm cost.
- **Privacy-preserving audit:** reconciling hash-chain immutability with redaction and erasure (e.g. per-field commitments).
- **Streaming and chunked content verification** for large objects; S3-compatible storage with server-side checksums.
- **Anomaly detection over decision events.** Explicitly **not** in scope; ML requires your approval.

---

## 24. Open decisions (need your approval)

| # | Decision | Recommendation | Alternative |
|---|---|---|---|
| Z1 | Identity store | **Extend `operators`** (new roles + columns); show them as "Users" | A separate `users` table (duplicates auth, sessions and tokens) |
| Z2 | Audit stream for file events | **The existing `system` stream, inside the user's chained login session**, so P1–P5 protect file history | A separate `files` stream (breaks per-session provenance) |
| Z3 | Event per decision | **One event per decision** (operation event on ALLOW, `FILE_ACCESS_DENIED` on DENY) | Also emit `FILE_ACCESS_GRANTED` before each operation (2× events) |
| Z4 | Policy storage | **Versioned JSON policy file** (hash in every decision), with grants in the DB | Admin-editable policy tables (needs its own chained change events and loses reproducibility) |
| Z5 | Transition rules | **`transitions.v2` superset; generator pinned to v1; v2 file types server-only** | Edit v1 in place (breaks reproducibility of recorded results) |
| Z6 | File type detection | **Standard-library signature checks** (no new dependency) | `python-magic` (needs system libmagic) or `filetype` (new dependency) |
| Z7 | Preview | **PNG/JPEG/PDF inline under a sandbox CSP; TXT/CSV as escaped text; Office download-only; no preview at HIGHLY_RESTRICTED** | Download-only for everything |
| Z8 | Undiscoverable files | **404 + chained denial** | 403 everywhere (leaks existence) |
| Z9 | Admin access to RESTRICTED+ content | **Only through an explicit, chained, flagged self-grant** | Implicit admin access |
| Z10 | Step-up for HIGHLY_RESTRICTED | **Password re-entry within 10 min**, documented as not MFA | None, or real MFA/TOTP (new dependency, larger scope) |
| Z11 | Filenames in audit payloads | **Redact for RESTRICTED+** | Always include (easier investigation, permanent exposure) |
| Z12 | Frontend styling | **Hand-built design system on CSS tokens + `lucide-react` icons** | Tailwind/shadcn, or MUI/Mantine (heavier; generic look) |
| Z13 | Frontend tests | **Add Vitest + Testing Library** for the client and permission-reflecting components | Build/type-check only (as now) |
| Z14 | Delete semantics | **Soft delete → trash; admin purge removes blobs and keeps a tombstone** | Hard delete (orphans audit references) |
| Z15 | Access-request workflow | **Include in ZT-10** (optional; can be dropped) | Omit |
| Z16 | Role set | **admin, auditor, manager, employee, ingestor** | Fewer roles (e.g. merge manager into employee + grants) |
| Z17 | Storage keys | **Random UUID keys** | Content-addressed (SHA-256) keys with deduplication |
| Z18 | Upload limit | **25 MiB default**, configurable | Other value |
| Z20 | Employees must not automatically reach every INTERNAL/CONFIDENTIAL file (Access Control phase requirement) | **Department-scoped role access** (employees INTERNAL; managers INTERNAL and CONFIDENTIAL), set per role in the policy file | Grant-only access to INTERNAL+ (no role access at all) |
| Z19 | CLAUDE.md | Add this document to "Required Documentation" | Leave CLAUDE.md unchanged (I will not edit it without your approval) |

---

## 25. Files expected to change

### 25.1 Modify — backend

| File | Change |
|---|---|
| `backend/app/db/models.py` | `ROLES` extended; operator columns; `File`, `FileVersion`, `FilePermission` (+ `AccessRequest`) |
| `backend/app/api/v1/__init__.py` | Register the `files`, `security`, `admin` routers |
| `backend/app/api/deps.py` | `RequestContext` (IP, request_id); capability dependencies; policy dependency |
| `backend/app/api/v1/auth.py` | `me` + capabilities and session info; `reauthenticate`; operator list/patch; chained user events |
| `backend/app/api/v1/schemas.py` | Role literal; operator fields |
| `backend/app/api/v1/streams.py` | Ingestion rejects `server_only_events` (not just `SECURITY_VIOLATION`) |
| `backend/app/auth/service.py` | `reauthenticate`; session start/auth-time lookups from the chain |
| `backend/app/core/config.py` | Storage root, max upload, allowed extensions, policy path |
| `backend/app/provenance/rules.py` | Default → v2; `server_only_events`; `V1_RULES_PATH` constant |
| `backend/app/lab/generator.py` | Pin generation to v1 rules |
| `backend/app/experiments/__main__.py`, `runner.py` | Pass v1 rules to generation, v2 to verification (the experiment config records both) |
| `backend/app/cli.py` | New roles; chained `USER_PROVISIONED`; `storage-gc` command |
| `backend/requirements.in` / `.txt` | `python-multipart` (required by FastAPI for multipart uploads) |
| `backend/Dockerfile` | Create the storage directory owned by `app` |
| `backend/tests/api/conftest.py` | TRUNCATE new tables; temporary storage-root fixture |
| `backend/tests/unit/test_provenance.py` | Expectations that reference `DEFAULT_RULES_PATH` (v1 → v2 hash) |
| `backend/scripts/demo_walkthrough.py` | File-governance demo section (ZT-10) |
| `docker-compose.yml` | `filestore` volume; new environment variables |
| `.env.example` | New settings, with placeholders only |

### 25.2 Modify — frontend
`src/App.tsx`, `src/main.tsx`, `src/auth.tsx`, `src/api/client.ts`, `src/api/types.ts`, `src/components.tsx` (split into `ui/`), `src/index.css` (split into `styles/`), all five `src/pages/*.tsx` (moved and re-skinned), `package.json` / `package-lock.json` (`lucide-react`; Vitest if Z13), `vite.config.ts` (test config if Z13).

### 25.3 Modify — documentation
`README.md`, `docs/PROJECT_PLAN.md`, `ARCHITECTURE.md`, `DATABASE.md`, `API_SPEC.md`, `VERIFICATION.md` (v2 rules, integrity layers, reconciliation), `EXPERIMENTS.md` (ZT-E1–E4, F1–F7), `SECURITY_LIMITATIONS.md`, `TESTING.md`, `DEMO.md`, and `CLAUDE.md` (only if Z19 is approved).

### 25.4 New files
- **Backend app code:**
  - `backend/app/access/{__init__,model,policy_file,policy,context}.py`
  - `backend/app/files/{__init__,validation,storage,service,audit,integrity}.py`
  - `backend/app/api/v1/{files,security,admin}.py`
  - `backend/app/lab/file_scenarios.py`
- **Config:** `backend/config/access_policy.v1.json`, `backend/config/transitions.v2.json`
- **Migrations:** `backend/alembic/versions/20261005_0005_identity_roles.py`, `…_0006_files.py`, (`…_0007_access_requests.py`)
- **Backend tests:**
  - `backend/tests/unit/test_access_policy.py` (+ independent oracle), `test_transitions_v2.py`, `test_file_validation.py`, `test_storage.py`, `test_file_payloads.py`
  - `backend/tests/api/test_files_*.py`, `test_file_integrity.py`, `test_security_api.py`, `test_file_lab.py`
  - `backend/tests/fixtures/files/` (small benign and malicious samples, generated in tests where possible)
- **Frontend:**
  - `frontend/src/{app,ui,styles,features/*}/…` as listed in §15.1
  - `frontend/src/test/…` if Z13 is approved

---

## 26. Implementation status

### 26.1 Foundation phase (2026-10-05)

**Scope.** The Foundation phase combines:
- the identity part of ZT-1;
- all of ZT-2;
- the schema half of ZT-3.

**Not yet implemented** (they depend on this foundation):
- the decision engine (`access/policy.py`) and the policy file;
- `transitions.v2`;
- audit event emission and every endpoint.

**Implemented**

| Area | Files | Notes |
|---|---|---|
| Vocabulary | `app/access/model.py` | `Classification` (with rank), `Permission`, `Action`, `REQUIRED_PERMISSION`, `GRANTABLE_PERMISSIONS`, `FileOrigin`, `IntegrityStatus`. The DB CHECK constraints are generated from these |
| Roles | `app/db/models.py`, `app/api/v1/schemas.py`, migration `0005` | `manager` and `employee` added to the **existing** `operators` table and auth stack. No new user, session or token system |
| Schema | `app/db/models.py`, migration `0006` | `files`, `file_versions`, `file_permissions` with the constraints and indexes of §5.3; audit references without FK; two `audit_events` indexes (no column changes) |
| Validation | `app/files/validation.py` | `clean_filename` (§16.2) and `verify_content` (§16.3), standard library only |
| Storage | `app/files/storage.py`, `app/api/deps.py` (`get_storage`) | `StorageBackend` protocol and `LocalFileStorage` (§6.2) |
| Settings | `app/core/config.py` | `TRACELOCK_STORAGE_ROOT`, `TRACELOCK_MAX_UPLOAD_BYTES` (default 25 MiB, max 1 GiB), `TRACELOCK_ALLOWED_EXTENSIONS` (every entry must have a content rule, otherwise startup fails) |
| Request/response models | `app/files/schemas.py` | Ready for the endpoints; unknown fields forbidden; no response model has a `storage_key` field |
| Docker | `backend/Dockerfile`, `docker-compose.yml`, `.env.example` | Named volume `filestore` at `/var/lib/tracelock/files`, owned by uid 1000, mode 750, mounted into `backend` only |
| Frontend | `src/api/types.ts`, `src/App.tsx` | Only the new roles in the `Role` type, plus a "not available yet" screen for manager/employee (they have no audit access) |

### 26.2 Refinements made during implementation (none change the approved design's intent)

1. **`CREATE` is not grantable on a file** (it is workspace-level). A DB constraint enforces this together with the `MANAGE_PERMISSIONS` rule.
2. **Empty files are rejected** for every type (`EMPTY_FILE`).
3. **Filename rules made explicit:**
   - leading dots are rejected;
   - Windows-invalid characters (`<>:"/\|?*`) are rejected;
   - the 255 limit counts UTF-8 **bytes**;
   - every Unicode control, format (bidi, zero-width), private-use or unassigned character is rejected.
4. **`python-multipart` is not added yet.** No upload endpoint exists; it arrives with the first one.
5. **The storage root is created on first use** (`get_storage`), so the API still starts if the volume is missing. Upload endpoints will report `STORAGE_UNAVAILABLE` (§14.4).
6. **Downgrading migration `0005` fails, by design,** while manager or employee accounts exist. It never deletes users.
7. **Integrity status values** are fixed by a CHECK constraint on `file_versions.last_integrity_status`.

### 26.3 Foundation → next phase
Delivered in §26.4.

### 26.4 Secure File Management phase (2026-10-05)

**Implemented**

| Area | Files | Notes |
|---|---|---|
| Policy file | `config/access_policy.v1.json`, `app/access/policy_file.py` | §8 matrix and §10 table. Validated on load (e.g. RESTRICTED+ role entries may only hold VERIFY/MANAGE). SHA-256 recorded in every decision event. **Loaded at startup: an invalid file stops the app** |
| Decision engine | `app/access/policy.py` | Pure `decide()` and `is_discoverable()`; all failed requirements collected; reason codes as in §9.2 |
| Context signals | `app/access/context.py` | Session age (chained LOGIN), time since authentication (chained AUTHENTICATION/REAUTHENTICATION), denials in the burst window, downloads in the last hour — all read from the chain |
| Rules v2 | `config/transitions.v2.json`, `app/provenance/rules.py` | Strict superset of v1. 19 new session types + sessionless `USER_PROVISIONED`. `server_only_events` rejected by external ingestion. **Verification now uses v2; the generator stays pinned to v1** (`GENERATION_RULES`) |
| Audit bridge | `app/files/audit.py` | The only writer of file events: `append_event` into the `system` stream, in the caller's chained session. Payload: decision, reason codes, policy id, signals, file id, classification, (redacted) name, hashes |
| Service | `app/files/service.py` | upload, list/search/filter/sort, detail, content (download / inline view), rename/update, soft delete, new version, version list, restore, integrity check |
| Integrity | `app/files/integrity.py` | L1/L2/L3 per §12.2, including a Merkle membership proof when the anchoring event is sealed |
| HTTP | `app/api/v1/files.py`, `app/api/upload_limit.py`, `POST /auth/reauthenticate` | Size limit enforced by middleware **before** multipart parsing (411/413); RFC 6266 disposition; `nosniff`, sandbox CSP, `no-store`; `X-TraceLock-Audit-Index` header |
| Dependency | `python-multipart==0.0.32` | Required by FastAPI for `UploadFile`/`Form` |

**Deviations from the design, and decisions taken while implementing**
1. **Not in this phase** (your list did not include them):
   - sharing/grant endpoints, undelete, purge, ownership transfer, user management, `/security/*`;
   - their event types already exist in v2, so no v3 is needed.
   - Grants are evaluated whenever they exist; the tests insert them directly.
2. **Context rules do not apply to VERIFY.** An integrity check compares hashes and discloses no content, and auditors must be able to run it.
3. **Metadata views** (`GET /files/{id}`, `GET /files/{id}/versions`) need only discoverability, not READ. They are chained as `FILE_VIEW` (`scope: metadata|versions`) for RESTRICTED+.
4. **Restore of a version** first re-verifies that version's bytes (L1). A corrupted old version is never made current; this is chained as `FILE_INTEGRITY_FAILURE` with `trigger: RESTORE`.
5. **Downloads read at most `size_bytes + 1` bytes** and serve exactly the bytes that were hashed. There is no re-read between the check and sending, so there is no time-of-check/time-of-use gap. The cost is that a whole file is held in memory (≤ 25 MiB by default).
6. **One clock per request.** `get_clock` is used for policy windows **and** for the timestamps of file and re-authentication events, so the two always agree. In production it is the wall clock.
7. **Integrity failures are chained without a policy verdict.** The access was allowed, but the content failed, so the payload says `decision: "BLOCKED"` with `reason_code` = the integrity status.
8. **Ended sessions:** a request with a still-signed token after logout gets 401 and is **not** chained (existing behaviour). If logout races a request that already passed authentication, the provenance policy rejects the event: the operation is aborted, a `SECURITY_VIOLATION` is stored, and the response is `409 AUDIT_REJECTED`.
9. **Rename keeps the extension.** A new version must have the same extension (`415 EXTENSION_MISMATCH`). Classification downgrades need MANAGE_PERMISSIONS **and** a reason (`422 REASON_REQUIRED`).
10. **No new pairs between v1 types.** File events connect only after AUTHENTICATION, so `LOGIN → FILE_DOWNLOAD` is a provenance failure, just like the paper's `LOGIN → FILE_OPEN`.
11. **L3 also checks the successor's link.** Without it, an attacker who edits the anchoring event *and* recomputes its own hash (A1) passed L3 while the anchor was still unsealed. Coverage review found this gap, and it was fixed in this phase.
    - Remaining case: the anchor is the **newest** record and unsealed, so it has no successor and no root. It stays undetectable; this is the tail limitation, documented as a negative control.
12. **Test harness:** the session fixture now empties the test database before rebuilding it, because migration `0005` deliberately refuses to downgrade while manager/employee accounts exist.

### 26.5 Next phase (awaiting approval)
- Sharing and permission management:
  - grant/revoke endpoints with the §7.4 anti-escalation rules;
  - ownership transfer;
  - undelete and purge.
- Governance reconciliation (§12.3).
- Security, investigation and admin APIs.
- File tamper lab scenarios F1–F7.


---

## 27. Policy decision flow (Access Control phase, 2026-10-05)

### 27.1 Where decisions are made

| Component | File | Role |
|---|---|---|
| **Policy file** | `config/access_policy.v1.json` | The configurable rules: role × classification permissions, department scopes, classification requirements, sharing rules, context thresholds. Versioned and hashed |
| **Policy decision point** (pure) | `app/access/policy.py` | `decide()`, `decide_grant()`, `decide_revoke()`, `decide_transfer()`, `update_actions()`, `is_discoverable()`. **Every authorization rule of the file module is here.** No DB, no HTTP |
| **Policy enforcement point** | `app/access/enforcer.py` (`PolicyEnforcer`) | Gathers inputs, calls the policy, chains the decision, raises 403/404, builds the listing filter |
| **Context** | `app/access/context.py` | Signals read from the audit chain |
| **Authentication gate** | `app/api/deps.py: get_audited_operator` | Token, chained session and account checks; rejected tokens on file endpoints are chained |
| Services and controllers | `app/files/service.py`, `app/api/v1/files.py` | Call `require*` before touching anything; **contain no authorization rules** |

### 27.2 Inputs of every decision

| Input | Source |
|---|---|
| Authenticated identity, user id | Verified JWT, then the `operators` row |
| Role | `operators.role`. The token's role claim must match it, otherwise 401 |
| Department, account active | `operators.department`, `operators.is_active` |
| Session, and its validity | The token's `sid` must be an open chained session (no LOGOUT) |
| Requested action | VIEW, DOWNLOAD, UPLOAD, CREATE, UPDATE, RENAME, DELETE, SHARE, RESTORE, VERIFY, MANAGE_PERMISSIONS |
| Resource, classification, ownership, department, lifecycle | The `files` row |
| Explicit permissions | Active, unexpired `file_permissions` rows of this user for this file |
| Request context | Client IP and a per-request id (recorded in the event) |
| Timestamp | The request clock (`get_clock`). It is the same clock used for the event's chained timestamp |
| Security signals | Session age, time since (re-)authentication, denials in the last 10 minutes, downloads in the last hour, all from the chain |

### 27.3 The flow

```
request --> get_audited_operator --401--> chained UNAUTHENTICATED_ACCESS (sessionless) --> 401
               | ok: identity + open chained session + active account + unchanged role
               v
   service loads the resource (row-locked for changes)
               v
   PolicyEnforcer.require*(action, resource)
               v
   policy.decide / decide_grant / decide_revoke / decide_transfer   (pure)
     1 role may use the workspace?             roles.<r>.metadata_visibility
     2 account active?                         accounts.active
     3 resource exists?                        resource.exists
     4 lifecycle allows it? (trash: VERIFY)    lifecycle.trash
     5 permission held?   role (classification, department scope) | owner | grant
                          else GRANT_REQUIRED (explicit-access levels),
                               DEPARTMENT_MISMATCH, or NO_PERMISSION (default_deny)
     6 classification and context:            session age, step-up, denial burst,
                                               download rate, preview
     7 sharing / revoke / transfer rules:     subset, grantable, self-grant, eligible grantee,
                                               owner-or-manager, grantor
               v
   Decision{ALLOW|DENY, reason, reasons, rule, rules, message, policy_id, signals}
        | DENY                                         | ALLOW
        v                                              v
   chain FILE_ACCESS_DENIED (own commit)          chain the operation event (FILE_DOWNLOAD,
   discoverable? 403 ACCESS_DENIED /               FILE_SHARE, ...) with decision, rule and
                 STEP_UP_REQUIRED with details     policy, in the SAME transaction as the change
   otherwise     404 FILE_NOT_FOUND
```

### 27.4 What the decision returns

- **`decision`:** ALLOW or DENY.
- **`reason`:** a reason code (`ALLOW_ROLE`, `ALLOW_OWNER`, `ALLOW_GRANT`, `DEPARTMENT_MISMATCH`, `GRANT_REQUIRED`, `SHARE_ESCALATION`, ...), plus a human-readable `message`.
- **Policy information:**
  - `rule` is the rule that allowed the request, or the first rule that failed, e.g. `roles.employee.by_classification[INTERNAL] (same department)` or `classifications.RESTRICTED.requires_explicit_access`;
  - `rules` lists every failed rule;
  - `policy` is `access-policy.v1 sha256:...`.
- All of this is written into the chained event. On a 403 it is also returned in `error.details`: `rule`, `rules`, `policy`, `reason_code`, `reasons`, `required_permission`, `classification`, `your_role`, `your_permissions`, `evaluated_at`, and `audit {stream_id, chain_index}`.

### 27.5 Which decisions are chained

| Decision | Chained as |
|---|---|
| Every DENY on a file or sharing operation | `FILE_ACCESS_DENIED` (rule, policy, signals) |
| Every rejected token / ended session / inactive account on a file endpoint | `UNAUTHENTICATED_ACCESS`, sessionless. The claimed user is named only when the signature is valid. Only the **route template** is recorded, never the raw path |
| ALLOW: upload, download, inline view, rename, update, delete, new version, restore, integrity check, share, revoke, ownership transfer | The operation's own event, carrying `decision: ALLOW`, the rule and the policy |
| ALLOW: metadata view, version list, permission list | `FILE_VIEW` (scope `metadata`, `versions`, `permissions`) **for RESTRICTED+ only** (policy `audit_metadata_views`) |
| ALLOW: file listing; `allowed_actions` computation | Not chained (no access to any particular file; would flood the chain). Documented limitation |

### 27.6 Sharing and permission-management rules (§7.4, now enforced)

| Rule | Policy rule id |
|---|---|
| Two ways to grant:<br>• **SHARE**, passing on only permissions you currently hold;<br>• **MANAGE_PERMISSIONS**, a permission manager (admin) granting any grantable permission | `sharing.subset_of_own_permissions` / `sharing.manage_permissions` |
| `CREATE` and `MANAGE_PERMISSIONS` are never grantable. `SHARE` is not grantable on HIGHLY_RESTRICTED files (`share_is_grantable`) | `sharing.grantable[LEVEL]` (+ a validation 422 for the never-grantable ones) |
| No self-grants. Exception: a permission manager may grant themselves access, as an audited break-glass (`signals.self_grant = true`, `path = MANAGE_PERMISSIONS`) | `sharing.no_self_grant` |
| The grantee must be an active account with a workspace role (not an ingestor) | `sharing.grantee_active_and_workspace_role` |
| HIGHLY_RESTRICTED: only the owner or a permission manager may share, and a reason is required | `classifications.HIGHLY_RESTRICTED.share_owner_or_manager_only` |
| Revoke: a permission manager, the owner, or the original grantor (who must still hold SHARE) | `sharing.revoke_by_grantor_owner_or_manager` |
| Ownership transfer: MANAGE_PERMISSIONS only. The new owner must be another eligible user. A reason is required | `ownership.transfer_requires_manage_permissions` |
| Grant IDs are looked up **within their file**. A grant id used through another file is "not found" | (enforced by the query) |

### 27.7 What is not trusted
- **Hidden buttons.** `allowed_actions` is advice for the UI. A test calls every endpoint directly for six user types and checks the result equals the backend decision.
- **The role claim in the token.** It must match the database.
- **Fields the client may not set.** Owner, uploader, department, hashes, versions and audit references cannot be set by the client (unknown fields are rejected or ignored).
- **File IDs and grant IDs.** These are lookup keys only.
- **The SQL listing filter on its own.** It is a second expression of `is_discoverable`, and a test checks the two agree for every user and file.

### 27.8 Known limitations of this phase
- **Department is a single text attribute per user and file.** There are no hierarchies or multi-department users. Ownership transfer does not change a file's department.
- **Chaining rejected tokens lets anonymous clients add events.** This is the same exposure as the existing `LOGIN_FAILED`; there is no rate limiting (SECURITY_LIMITATIONS section 5).
- **Decisions use mutable state.** Grants and ownership are read from tables; reconciliation against the chain (§12.3) is still future work.

---

## 28. File sharing and permission management (2026-10-05)

### 28.1 What a grant is
A row in `file_permissions` targets **exactly one** of:
- **a user** (`grantee_id`): a *share*;
- **a role** (`grantee_role`): a *permission assignment* to every user with that role, **for that one file**.

Migration `0008` added `grantee_role`, a "one target" constraint, a unique active role grant per file, and `revoked_audit_chain_index`.

Role-wide permissions across *all* files remain in the versioned policy file. Changing them is a deliberate policy-version change, not a runtime API action.

### 28.2 Who may change permissions

| Change | Who | Rule id |
|---|---|---|
| Grant to a user | **SHARE** holders (subset of their own permissions), or **MANAGE_PERMISSIONS** holders | `sharing.subset_of_own_permissions` / `sharing.manage_permissions` |
| Grant to a role | **MANAGE_PERMISSIONS** only (reaches many people). Not to `ingestor`. Not on HIGHLY_RESTRICTED (`role_grants_allowed=false`) | `sharing.role_grant_requires_manage_permissions` |
| Modify a grant (re-grant to the same target) | The same rules as a new grant. The old grant is **superseded** (revoked and linked to the new event), never edited | as above |
| Revoke a user grant | Permission manager, owner, or the original grantor (still holding SHARE) | `sharing.revoke_by_grantor_owner_or_manager` |
| Revoke a role grant | Permission manager only | `default_deny` otherwise |
| Ownership transfer, classification change | MANAGE_PERMISSIONS (downgrade); UPDATE (upgrade) | `ownership.*`, §10.3 |
| Never grantable | `CREATE`, `MANAGE_PERMISSIONS` (validation 422); `SHARE` on HIGHLY_RESTRICTED | `sharing.grantable[LEVEL]` |

### 28.3 Conflicting permissions
- **Allows add up.** Effective = role policy (classification, department) ∪ owner ∪ active user grants ∪ active role grants.
- **There are no "deny" grants.** Lifecycle (trash), classification requirements (explicit access, session age, step-up, rate limits, preview) and context rules **always apply on top**, so a grant can never bypass them.
- **Expired or revoked grants contribute nothing.** Another active grant (e.g. a role grant) still applies.

### 28.4 Events

| Event | When | Payload |
|---|---|---|
| `FILE_SHARED` / `FILE_SHARE_REVOKED` | User grant created or modified / revoked | `grantee {type, id, username}`, `permissions`, `change` (GRANT / MODIFY / REVOKE), `previous_state`, `new_state`, `decision`, `rule`, `policy`, `file_id`, `classification` |
| `FILE_PERMISSION_GRANTED` / `FILE_PERMISSION_REVOKED` | Role grant created or modified / revoked | as above, with `grantee {type: role, role}` |
| `FILE_ACCESS_POLICY_CHANGED` | Ownership transfer; classification change | `previous_state` / `new_state` (`owner_id` or `classification`), `reason` |
| `FILE_ACCESS_DENIED` | Any refused change | requested `grantee`, `permissions`, reasons and rules |

**Actor, session and timestamp** are the chained context of every event (`actor_user_id`, `session_id`, `event_timestamp`), so they are covered by the hash.

`FILE_SHARE` and `FILE_PERMISSION_CHANGE` (from the Access Control phase) were renamed in `transitions.v2` before it was ever committed or used.

### 28.5 Endpoints
- `GET /files/{id}/permissions`: **active** grants.
  - Owners and permission managers see all of them.
  - Others see only grants they issued, received personally, or received through their role.
- `GET /files/{id}/permissions/history`: every grant ever made, including superseded and revoked ones, each with the chain index of the event that created it and of the one that revoked it. **Owner or MANAGE_PERMISSIONS only.**
- `POST /files/{id}/permissions` `{grantee_id | grantee_role, permissions, expires_at?, reason?}`. Re-granting the same target replaces the grant (201, `change: MODIFY`).
- `DELETE /files/{id}/permissions/{grant_id}` and `PUT /files/{id}/owner` as in §27.

---

## 29. File security investigation (2026-10-05)

### 29.1 Principles
- **One audit trail.** Investigation reads the chained `audit_events` of the `system` stream, nothing else. There is no second log and no new table.
- **Read-only.** Investigating creates no events, so the evidence being examined is not changed by examining it (tested).
- **Who.** `admin` and `auditor` only, through the existing `Reader` role check. Everyone else gets 403; no token gets 401.
- **Redaction stays.** Payload filenames of RESTRICTED+ files remain `[redacted]`. The current name is shown only in the file views, which both investigator roles may already see under the policy (`metadata_visibility = all`).

Module: `app/investigation/service.py`. Endpoints: `app/api/v1/security.py`.

### 29.2 Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/security/events` | Search, newest first. Filters: `user`, `file_id`, `action`, `decision` (ALLOW / DENY / BLOCKED), `classification`, `event_type` (repeatable), `category`, `since`, `until`. Paging by `cursor` (chain index) and `limit` |
| GET | `/security/events/{chain_index}` | Full event, its **hash-chain relationship** (stored vs recomputed hash, link to predecessor, successor's link back), its **Merkle batch** (range, stored vs recomputed root, membership proof) and the **related file and its versions** |
| POST | `/security/events/{chain_index}/verify` | Re-verifies the event: hash, both links, batch root and proof, and the paper's five provenance checks within its session |
| GET | `/security/files/{file_id}/timeline` | Every chained event about the file, oldest first, plus all versions with their anchoring chain indices |
| GET | `/security/files/{file_id}/integrity` | File integrity vs audit-log integrity for the file (§29.3) |
| GET | `/security/findings?since&until&threshold` | Heuristic findings (§29.4); default window: last 24 hours |

**Categories:**
- `denied`: `FILE_ACCESS_DENIED`;
- `unauthenticated`: `UNAUTHENTICATED_ACCESS`;
- `integrity`: `FILE_INTEGRITY_*`;
- `permissions`: share, grant, revoke and access-policy events;
- `deletion`: `FILE_DELETE`, `FILE_PURGE`;
- `restoration`: `FILE_VERSION_RESTORED`, `FILE_UNDELETE`;
- `replacement`: `FILE_VERSION_CREATED`;
- `access`: `FILE_VIEW`, `FILE_DOWNLOAD`;
- `authentication`: `REAUTHENTICATION*`, `SECURITY_VIOLATION`.

### 29.3 Two different conditions

| | **FILE INTEGRITY FAILURE** | **AUDIT LOG INTEGRITY FAILURE** |
|---|---|---|
| Meaning | The file's stored bytes, or its stored SHA-256, no longer match what an **intact** audit event recorded | The audit evidence itself fails verification |
| Detected by | `CONTENT_MISMATCH` / `BLOB_MISSING` (bytes vs DB), or `METADATA_MISMATCH` (DB hash vs an anchor whose own verification passes) | The anchor event's hash, its links, or its Merkle batch fail; or full verification of the system stream reports `TAMPERING_DETECTED` |
| Reported fields | `expected_sha256` (DB), `anchored_sha256` (chain), `actual_sha256` (bytes), `file_status`, `first_affected_version`, `first_affected_audit_event` (the anchoring event the file no longer matches) | `anchor_status`, `anchor_chain_status`, `anchor_merkle_status`, `anchors_failing`, and the stream verdict with `first_affected_audit_event`, `first_failed_check` and `first_failing_batch_index` |
| Example | Someone edits the blob on disk: **file failure**, log **VALID** | Someone edits the upload event: **log failure**, file **INTACT** |

**How they are kept apart:**
- A DB-hash mismatch counts as a *file* failure only when the anchor itself verifies.
- When the anchor is broken, the problem is reported as an *audit-log* failure, and the file is not blamed.
- Both can be reported together.

**Merkle status of one event:**
- `UNSEALED`: protected by the chain only;
- `VALID`: root recomputed from re-hashed records equals the stored root, and the proof verifies;
- `ROOT_MISMATCH`: also reported for an intact event whose batch-mate was altered (its own proof may still verify);
- `RANGE_INCONSISTENT`: records missing from the batch's range.

### 29.4 Findings (heuristics, not threat detection)

| Finding | Basis (chained events in the window) |
|---|---|
| `repeated_denials` | Users with ≥ `threshold` `FILE_ACCESS_DENIED`, with distinct files and first/last time |
| `unauthenticated_attempts` | `UNAUTHENTICATED_ACCESS` per claimed user (null = not attributable) |
| `high_frequency_downloads` | Users with ≥ `threshold` downloads |
| `probing_unknown_or_hidden_files` | Denials where the file was not discoverable (unknown or hidden IDs) |
| `integrity_failures` | `FILE_INTEGRITY_FAILURE` events |
| `break_glass_self_grants` | `FILE_SHARED` with `signals.self_grant = true` |
| `classification_downgrades` | `FILE_ACCESS_POLICY_CHANGED` with `downgrade = true` |
| `deletions`, `failed_reauthentications`, `provenance_violations` | The corresponding events |

**Limitations:**
- **Thresholds are parameters, not learned baselines.** No ML is used.
- **Investigation reads must be trusted** (paper T2/T7). A compromised investigator account sees everything the auditor role sees.
- **Full stream verification runs on each file integrity investigation.** Its cost grows with the stream (O(N), measured in EXPERIMENTS for the engine).

---

## 30. Frontend redesign (2026-10-05)

### 30.1 What existed
- **Routing:** react-router with flat routes and a top-bar nav.
- **Components:** one `components.tsx`.
- **Styling:** one `index.css` with tokens and dark mode.
- **No:** icons, layout system, skeletons, dialogs, toasts or tests.
- **Reworked, not duplicated:** login, streams, the per-stream audit pages, the tamper lab and experiments.

### 30.2 Design system [Eng]
- **`src/styles/tokens.css`:**
  - typography, spacing, radii and surfaces;
  - accent and focus colours;
  - reserved status colours (ok / warn / danger / info);
  - five classification colours;
  - synthetic and lab data colours;
  - a validated chart palette (dataviz reference instance);
  - light and dark themes (OS preference, or the toggle via `data-theme`).
- **`src/styles/app.css`:** shell, nav, buttons, inputs, tables, badges, alerts, dialogs, toasts, tabs, KPI tiles, skeletons, empty states, charts, chain strip and verdicts. The class names the original pages use are kept, so those pages adopt the system without logic changes.
- **`src/ui/`:**
  - `primitives.tsx`: page header, panel, KPI tile, skeleton, empty and error states, key-value list, hash with copy, menu, formatters;
  - `badges.tsx`: classification, decision (ALLOW/DENY/BLOCKED), integrity (VERIFIED / INTEGRITY FAILURE), verification (VALID / TAMPER DETECTED); every badge has a text label **and** an icon, never colour alone;
  - `feedback.tsx`: native `<dialog>`, confirm dialog, toasts;
  - `charts.tsx`: dependency-free SVG with a table view and hover titles;
  - `access.tsx`: access-denied panel plus a step-up re-authentication flow wrapping every protected action.
- **One new runtime dependency:** `lucide-react` (icons). Dev-only: `vitest`, `@testing-library/react`, `@testing-library/dom`, `jsdom`. Plotly stays lazy on the experiments page only.

### 30.3 Navigation and permission-aware UI
- **The navigation is derived from the role** (`src/app/nav.ts`):
  - employees and managers: Overview and Files;
  - auditors: also Security, Audit and Experiments;
  - admins: also the Tamper lab and Administration;
  - ingestors: no dashboard.
- **Items without a backend yet are tagged "Planned".** Each page says why: access policies, access requests, roles, permissions, system settings.
- **File actions come only from the backend's `allowed_actions`.** Hidden buttons are not a control: the backend still enforces everything, and a refused action shows the backend's explanation (rule, required permission, role and the audit event that recorded it).

### 30.4 Pages
- **Overview** (real data only; each panel names its scope):
  - KPIs: files visible, protected files, recently accessed, denied attempts, integrity failures, unauthenticated attempts, audit-chain status;
  - charts: allow vs deny per day, files by classification, security event categories;
  - lists: recent file activity and recent security events.
- **Files:** all / mine / shared / recent / trash, with search, classification and type filters, sorting, paging, file-type icons, owner, modified time, version, size and integrity. The file actions are upload with progress, download, preview, verify and trash with confirmation.
- **File detail:** tabs for Overview (SHA-256, version, size, type, created, modified, owner, uploader, department), Integrity (VERIFIED / INTEGRITY FAILURE, per-version fingerprints), Permissions (current and history, share, revoke), Versions (download, restore with confirmation), and Access history / audit trail (security roles).
- **Security:** findings, denied access, file integrity, and event search with every filter in the URL.
- **Investigation:**
  - The event page pivots from the event to the user, the file (and its permissions), the session, the hash chain (predecessor → this → successor, stored vs recomputed) and the Merkle batch (roots, proof), with one-click re-verification including provenance.
  - The file investigation page shows **FILE INTEGRITY** and **AUDIT LOG INTEGRITY** as two separate verdicts, with expected, anchored and actual hashes.
- **Audit:**
  - the existing stream pages, restyled, with a new **Hash chain** tab that checks stored links between consecutive records;
  - Merkle batches, verification and sessions unchanged in behaviour.
- **Old URLs redirect:** `/streams/*` goes to `/audit/streams/*`, `/lab` to `/research/lab`, `/experiments` to `/research/experiments`.

### 30.5 Known limits
- **Sharing with a user needs that user's account ID.** There is no user directory endpoint yet. The ID is shown on the user chip (hover) and on the Users page for users created there.
- **Owners are shown as "You" or a short account ID**, for the same reason.
- **PDF preview opens in a new tab** through a blob URL: the browser's PDF viewer, not an iframe. Images preview in a dialog. Office files are download-only.
- **The overview's decision chart uses up to the latest 500 security events of the last 14 days**, and says so when more exist.
- **`src/index.css` is no longer imported.** It is kept until you approve deleting it (CLAUDE.md rule 8).
