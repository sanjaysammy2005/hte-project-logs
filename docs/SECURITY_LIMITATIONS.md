# TraceLock — Threat Model, Trust Assumptions and Limitations

Tags: **[Paper]** · **[Rec]** · **[Gap]**.

TraceLock is **tamper-evident, not tamper-proof**. It can reveal that stored audit records changed. It cannot stop anyone from changing them, and hashing alone does not prevent modification. **[Paper §IX-B]**

## 1. Assets

- The stored audit records: the events and their context.
- The integrity metadata: the entry hashes and the Merkle roots.
- The verification result and its trustworthiness.
- Operator credentials.

## 2. Adversary [Paper §II]

- The adversary gains access to the stored audit records **after** they are generated.
- They can **read and rewrite** stored records.
- They try to hide activity by **modification, deletion, insertion or reordering**.
- **[Paper]** They are assumed **not** to regenerate a fully consistent chain and set of batch roots. The paper names this as a residual risk (§II, §IX-B).

**[Rec]** For the evaluation we make the attacker's abilities explicit as A0 (naive), A1 (recomputes a single record's hash) and A2 (full rewrite). See EXPERIMENTS §3. Because SHA-256 is unkeyed, A1 is cheap. The paper's assumption therefore really excludes A2-style recomputation of everything downstream, not "computing hashes" as such.

## 3. Trust assumptions [Paper §II, §IX-B]

| # | Assumption | Source |
|---|---|---|
| T1 | Events are captured faithfully before they enter the pipeline. | Paper §II |
| T2 | The verification code is trusted (not modified by the attacker). | Paper §II |
| T3 | Context is only as reliable as the application that supplies it. | Paper §IX-B |
| T4 | The allowed-transition rules are correct for the application. | Paper §IX-B |
| T5 | The attacker does not recompute the entire chain and all roots. | Paper §II |
| T6 | The server clock assigns timestamps in non-decreasing order under the append lock. | [Rec] |
| T7 | The operator running verification reads the result through an uncompromised dashboard/API. | [Rec] |

## 4. What is NOT detected

| Limitation | Why | Source |
|---|---|---|
| **Full consistent rewrite** of the records, hashes and Merkle roots | Everything is stored locally and SHA-256 is unkeyed, so the result verifies as Valid | Paper §IX-B |
| **Events altered before capture**, or false context supplied by the application | The chain protects what was recorded, not whether it was true | Paper §IX-B |
| **Tail truncation** (deleting the newest records and, if needed, the batches covering them) | No later record or root refers to them, and nothing outside the DB records the chain head | [Gap] not discussed in paper |
| **Rollback** to an older, internally consistent copy of the database | An older consistent state verifies as Valid | [Gap] not discussed in paper |
| **Unsealed records** | They are protected by the chain only, not by a Merkle root, until a batch is sealed | [Rec] consequence of batching |
| **Compromised verification code or verifier credentials** | Breaks trust assumption T2/T7 | Paper §II (T2) |
| **Database superuser / host compromise** | Equivalent to an A2 attacker | Paper §IX-B |
| **Merkle duplicate-leaf ambiguity** if leaf counts were not checked | Duplicating the last node allows [a,b,c] ≡ [a,b,c,c] | [Rec] see VERIFICATION §5.4; mitigated by the `leaf_count` check |

## 5. Protections implemented and tested

**Final status (Phase 10).** A protection is listed here only if an automated test proves it. Test files are under `backend/tests/`.

| Protection | Test IDs | Where tested | Status |
|---|---|---|---|
| Unambiguous canonical serialization (length-prefixed, NFC, strict JSON) | T2.1–T2.4, T2.11, T5.3 | `unit/crypto/test_canonical.py`, `unit/crypto/test_vectors.py`, `api/test_events.py` | **implemented + tested**, including the DB round-trip and an independent reference implementation |
| Hash-chain detection of modification, deletion, insertion and reordering | T2.5–T2.10, T6.3 | `unit/crypto/test_chain.py`, `api/test_verification_api.py` | **implemented + tested** in memory and on stored rows changed with SQL |
| Five provenance checks + timestamp order | T4.1–T4.8, T6.3 | `unit/test_provenance.py`, `api/test_verification_api.py` | **implemented + tested** |
| Merkle roots rebuilt from recomputed hashes + leaf-count/range check | T3.1–T3.7, T6.1–T6.6 | `unit/crypto/test_merkle.py`, `unit/test_engine.py`, `api/test_verification_api.py` | **implemented + tested** |
| Verification never crashes on corrupted or unencodable stored data | T2 robustness cases | `unit/crypto/test_chain.py` | **implemented + tested** |
| Serialised appends (no chain forks under concurrency) | T5.4 | `api/test_ingestion_concurrency.py` | **implemented + tested** (20 × 50 parallel appends) |
| Non-decreasing timestamps despite clock steps (Q15) | T5.4 clamp test | `api/test_ingestion_concurrency.py` | **implemented + tested** |
| Ingestion-time provenance enforcement; violations recorded (Q6) | T5.5 | `api/test_events.py` | **implemented + tested** |
| Server-only context fields cannot be supplied by clients | T5.2 | `api/test_events.py` | **implemented + tested** |
| Operator authentication: Argon2id, generic failure message, failed logins audited | T5.6, T5.7 | `api/test_auth.py`, `unit/test_security.py` | **implemented + tested** |
| Token integrity: expiry, signature, `alg=none`, role escalation rejected; logout revokes | T5.8 | `api/test_auth.py`, `unit/test_security.py` | **implemented + tested** (10 s clock-skew leeway, see §6) |
| Role-based access (admin / auditor / ingestor) | T5.6 | `api/test_auth.py`, `api/test_verification_api.py`, `api/test_lab.py` | **implemented + tested** |
| No secrets in logs, reprs or validation errors | T1.2, T5.7 | `unit/test_config.py`, `api/test_auth.py` | **implemented + tested** (after the Alembic logger fix in Phase 6) |
| Tamper lab only mutates `lab` clones; off by default | T7.1, T7.2 | `api/test_lab.py` | **implemented + tested** |
| Expectations recorded before verification (no post-hoc adjustment) | T7.4 | `api/test_lab.py` | **implemented + tested** |
| Dashboard charts contain no hard-coded metrics | T8.2 | `frontend/scripts/check-no-hardcoded-metrics.mjs` (runs on every build) | **implemented + tested** |

**Not implemented** (documented decisions, not oversights):
- **Keyed hashing, signatures and external anchoring (Q11).** These are future work in the paper. Without them, S10 (tail truncation) and S11 (full rewrite) remain undetected.
- **Database privilege separation (Q12).** This is deferred to the deployment work, together with HTTPS and production configuration.
- **Password change or reset.** There is no feature for either; a lost password is replaced by creating a new operator with the CLI.
- **Rate limiting of logins.** Failed logins are audited but not throttled.

## 6. Clock behaviour observed during development

The Docker Desktop VM's wall clock was measured stepping **backwards** (up to 1.1 s within 40 s). TraceLock handles this in three ways:
- event timestamps are clamped to be non-decreasing at ingestion (Q15);
- token validation allows 10 s of skew;
- all durations use a monotonic timer.

A deployment on a host with stable NTP-disciplined time is still preferable.

## 7. Mitigations the paper proposes as future work [Paper §IX-B, §X]

These are **not implemented in v1** (Q11):
- **Keyed hashing (HMAC)** of the chain with a key held outside the database.
- **Digital signatures** over batch roots.
- **External anchoring** of roots in append-only or WORM storage.
- Cross-host aggregation of roots, and formal analysis.

**[Rec, optional Phase 10 extension]** An "export checkpoint" button. It would download a signed-off record of `(stream_id, chain_index, entry_hash, latest batch root, time)` that the operator stores elsewhere (printed, emailed, or kept on a USB drive). Comparing against a checkpoint would detect tail truncation and rollback up to that point. This goes beyond the paper and would be labelled that way.

## 8. Other operational notes [Rec]

- **Privacy.** Records contain user IDs, IP addresses and resource names in plaintext. Encryption is out of scope, as it is in the paper. Use only synthetic or consented data.
- **False alarms.** Strict transition rules can flag legitimate behaviour (Paper §IX-B). The ingestion-time rule enforcement (Q6) prevents stored false alarms but **rejects** unusual genuine events, which are then recorded as `SECURITY_VIOLATION`.
- **Availability.** An attacker could block logging (denial of service). This is not addressed.
- **Secrets.** The JWT signing key and DB passwords come from environment variables and are never committed or logged.
