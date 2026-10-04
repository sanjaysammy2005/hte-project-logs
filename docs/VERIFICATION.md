# TraceLock — Integrity, Provenance and Verification Specification

Tags: **[Paper]** · **[Rec]** · **[Gap]** (see `PROJECT_PLAN.md` §5).

This is the core methodology document. Everything marked [Paper] is taken directly from the research paper. Everything marked [Rec] fills a gap the paper leaves open, and can be changed once you decide on the open question.

---

## 1. Notation

**[Paper §VI-B]**
- *n*: position of a record in the **global** log stream (1, 2, 3, …).
- E_n: the event.
- C_n = (u_n, s_n, e_{n-1}, q_n, t_n): its context, made up of the user, the session, the previous event, the sequence number and the timestamp.
- H_n: the chain value (hash) of record *n*.
- H₀: a fixed genesis value.
- ‖: byte concatenation.

**[Gap — notation]** The paper writes the previous event as e_{n-1}, which reads like the previous record in the *global* stream. But §VI-C says "sequence numbers and previous events are tracked **per session**", and Table III's example (sequence 3, previous event Authentication) is per session. **[Rec]** We interpret the previous event as the previous event *in the same session*. The hash chain itself (H_{n-1}) is global. This matches the paper's text and its worked example.

---

## 2. Canonical serialization

### 2.1 Why it matters

**[Paper §VI-A]** "A canonical, deterministic serialisation is essential: the same logical record must always produce identical bytes, otherwise verification would raise false mismatch alerts."

**[Gap → Q1]** The paper defines the hash input only as E_n ‖ C_n ‖ H_{n-1}. It does not say how each part becomes bytes. Plain concatenation of text fields is **ambiguous**: user "U1" with session "0S" and user "U10" with session "S" both produce "U10S". That is a real forgery path.

**[Rec]** Scheme `tl-v1` uses length-prefixed fields. It keeps the paper's order and structure (E, then C, then H_{n-1}) and makes field boundaries unambiguous.

**Decision (2026-10-04):** Q1–Q4 were approved as recommended:
- length-prefixed concatenation;
- the payload is hashed as part of E_n;
- the timestamp is part of C_n;
- H₀ is 32 zero bytes.

These are implemented in `backend/app/crypto/canonical.py` and `chain.py` (Phase 2).

### 2.2 Encoding of E_n (scheme `tl-v1`) [Rec]

```
str(x)      = uint32_be(len(utf8(x))) ‖ utf8(x)          # x is NFC-normalised text
opt(x)      = 0x00                       if x is null
            = 0x01 ‖ str(x)              otherwise
enc(E_n)    = str(event_type) ‖ str(canonical_json(event_payload))
```

`canonical_json(payload)` is built as follows:
- UTF-8 encoding;
- object keys sorted lexicographically by code point;
- no insignificant whitespace (separators `,` and `:`);
- `ensure_ascii = false`;
- allowed values are only strings, integers, booleans, null, and nested objects/arrays of those;
- floats are **rejected** at ingestion, to avoid differences in how numbers are formatted;
- an empty payload is `{}`.

Additional strictness rules, added in Phase 2 **[Rec]**. A value that breaks any of them raises `CanonicalizationError`, so it is never hashed or stored.
- **Integers** must lie within ±(2⁵³ − 1). Larger values cannot be represented exactly by every JSON consumer; the dashboard's JavaScript is one example.
- **NUL characters** (`\x00`) are rejected in every text field. PostgreSQL `text` and `jsonb` cannot store them, so such a record could never round-trip through the database.
- **Unpaired surrogates** are rejected, because they are not valid Unicode and cannot be encoded as UTF-8.
- **Duplicate keys after NFC** are rejected. Two payload keys that differ only in normalisation form (`"café"` composed vs decomposed) would collide.
- **Arrays:** tuples and lists encode identically.
- **Booleans** are kept as `true`/`false`. They are never treated as the integers 1/0.

**[Gap → Q2]** The paper never says whether E_n is only the event name ("Open File") or also its details (which file, from which IP, success or failure). If details are stored but not hashed, an attacker can change *which file* was opened without detection. **[Rec]** Hash both the type and the payload, as above.

### 2.3 Encoding of C_n [Paper fields, Rec encoding]

```
enc(C_n) = opt(actor_user_id)
         ‖ opt(session_id)
         ‖ opt(prev_event_type)        # "__START__" for the first event of a session; null if sessionless
         ‖ opt(decimal(session_seq))   # e.g. "3"; null if sessionless
         ‖ str(timestamp)              # "YYYY-MM-DDTHH:MM:SS.ffffffZ", UTC, microseconds
```

**[Gap → Q3]** The abstract and §IV list the context as (user, session, previous event, sequence number). Eq. 1 and Table III also include the **timestamp**. **[Rec]** Follow Eq. 1 and include it.

The timestamp is assigned by the server, never by the client. It is truncated to microseconds, which is what PostgreSQL `timestamptz` stores, so the value survives a database round-trip unchanged. The Phase 5 tests check this round-trip.

### 2.4 Hash input [Paper Eq. 1 + Rec encoding]

```
H_n = SHA-256( enc(E_n) ‖ enc(C_n) ‖ H_{n-1} )      H_{n-1} as 32 raw bytes
```

Hashes are stored as 32-byte `bytea` and displayed as lowercase hex.

**Alternative (if you prefer it for Q1):** `H_n = SHA-256(canonical_json({"event":…, "context":…, "prev_hash": hex}))`. This is easier to read but departs further from the paper's "byte concatenation" wording.

### 2.5 Published test vectors

**Files:**
- **`backend/tests/vectors/tl-v1.json`:** a chain of five records. Each entry gives the inputs, the previous hash, the full hash-input bytes (hex) and the entry hash.
- **`backend/tests/reference_tl_v1.py`:** the independent reference implementation that generated the vectors. It uses only the Python standard library and shares no code with `app/`. It has its own hand-written JSON serialiser and a decoder. Run it with `python tests/reference_tl_v1.py`.
- **Production check:** the production code must reproduce every byte (test T2.11).

| # | Event | Notes | entry_hash |
|---|---|---|---|
| 1 | LOGIN | first record, prev = H₀ | `e263cfbfdfc9a080db54b79f49d590c30a64c4c90a1fea89189920ffd8b87f88` |
| 2 | AUTHENTICATION | | `1603dd15bf70760d765a8d4db9ac9047a116716d42eb17f5a31ce714190c548c` |
| 3 | FILE_OPEN | paper Table III example (U101, S5001, after Authentication, seq 3, 10:15:32) | `0a74f43614e3cb28817e5cc30dbd51e6e198c9170784834b0aec379f5f518433` |
| 4 | IP_SECURITY_EVENT | sessionless (all optional context fields null) | `28f06b741dbec03ab78241f9b0a67f9823475e4faac4e7d7a816eca243925154` |
| 5 | FILE_EDIT | `+05:30` timestamp and decomposed "é" (tests UTC conversion and NFC) | `aedf8122fb915199cbe2c192bb24979da51e417ff583899922e71fb0ea60a869` |

Byte-by-byte breakdown of record 3's hash input, for checking by hand:

```
00000009 46494c455f4f50454e                      str("FILE_OPEN")
0000001f 7b227265736f75726365223a222f7265706f7274732f71332e786c7378227d
                                                 str('{"resource":"/reports/q3.xlsx"}')
01 00000004 55313031                             opt("U101")
01 00000005 5335303031                           opt("S5001")
01 0000000e 41555448454e5449434154494f4e         opt("AUTHENTICATION")
01 00000001 33                                   opt("3")
0000001b 323032362d31302d30345431303a31353a33322e3030303030305a
                                                 str("2026-10-04T10:15:32.000000Z")
1603dd15…0c548c                                  H_2 (32 raw bytes)
```

SHA-256 of these bytes gives `0a74f436…5f518433`.

---

## 3. Hash chain

**[Paper §V-C, §VI-B]**
- Each record's hash includes the previous record's hash.
- The first record uses the genesis value H₀.
- Changing any earlier record changes its hash and therefore "every subsequent chain value".
- The chain runs across the **whole log stream** and continues across batch boundaries.

**[Gap → Q4]** H₀ is "fixed" but its value is not given. **[Rec]** H₀ = 32 zero bytes (`00…00`), stored in `log_streams.genesis_hash`.

**[Rec]** Appends are serialised with a per-stream PostgreSQL advisory lock, so each record links to exactly one predecessor (ARCHITECTURE §8).

**Behaviour verified in Phase 2** (pure, in-memory; tests in `tests/unit/crypto/test_chain.py`):

| Tampering | First finding reported |
|---|---|
| Event or context field changed at k (attacker A0) | `CHAIN_HASH` at k, and nothing else; cascade count = N − k + 1 |
| Same, and the attacker recomputes H_k (A1) | `CHAIN_LINK` at k+1 |
| Record k deleted | `CHAIN_INDEX_CONTINUITY` + `CHAIN_LINK` at the successor; `CHAIN_LINK` only if the indices were renumbered |
| Forged record inserted before k with a correct own hash, indices renumbered | `CHAIN_LINK` at the original record k (now k+1); the forged record itself passes the chain checks and is left to provenance (Phase 4) |
| Records k and j swapped | `CHAIN_LINK` (or `CHAIN_INDEX_CONTINUITY`) at k |
| Content that cannot be encoded (e.g. a float written directly into the DB) | `CHAIN_HASH` at k with `expected = "<unencodable record: …>"`. Verification does not crash. |
| **Last record deleted** | **Not detected** (tail truncation, SECURITY §4) |
| **Full rewrite from k (A2)** | **Not detected** (paper §IX-B) |

---

## 4. Provenance verification

**[Paper §VI-C]** "A hash shows that a record changed; it does not show that an unchanged record still belongs where it is." Five questions are asked of every record:

| # | Check | Paper definition | Check name |
|---|---|---|---|
| P1 | **Who?** | The user in the entry must match the user who owns the session, as established by the authentication event. | `PROV_WHO` |
| P2 | **Which session?** | The session ID must refer to a valid session of that user, and the event must fall within the session's lifetime. | `PROV_SESSION` |
| P3 | **What happened before?** | The previous-event field must equal the actual preceding event of the same session. | `PROV_PREV_EVENT` |
| P4 | **What sequence number?** | Exactly one greater than the preceding event in the session, so gaps and duplicates become visible. | `PROV_SEQUENCE` |
| P5 | **Does this event belong here?** | (previous event, current event) must be an allowed transition. The allowed set is defined per application. | `PROV_TRANSITION` |

**[Paper]** "A record is accepted only when its chain value and all five provenance checks succeed."

### 4.1 Interpretations needed [Gap → Q8, Q9]

- **Session ownership (Q8).** The paper says the owner is established by the *authentication* event, but in its example *Login* comes before Authentication. **[Rec]**
  - LOGIN starts a session and *claims* a user.
  - AUTHENTICATION must name the same user, and *confirms* that user as owner.
  - Every later event must name the owner.
- **Session lifetime (Q9).** This is not defined. **[Rec]** A session lives from its first event (which must be LOGIN) to LOGOUT. After that:
  - any event in the same session, or reuse of the session ID, fails P2;
  - an event whose timestamp is earlier than the session's start fails P2.
  - There is no idle timeout in v1.
- **First event of a session.** **[Rec]** `prev_event_type = "__START__"`, `session_seq = 1`, and the transition (`__START__`, type) must be allowed. Only LOGIN is allowed from `__START__`. Sequence numbers starting at 1 agree with the paper's deletion example ("jumps from 1 to 3").

**Decision (2026-10-04):** Q5–Q9, Q15 and `transitions.v1` were approved as recommended. They are implemented in `backend/app/provenance/` with rules in `backend/config/transitions.v1.json` (Phase 4). Tests are in `tests/unit/test_provenance.py`.

Implementation details that the approved recommendations did not cover:
- **No AUTHENTICATION seen yet.** If a session has no AUTHENTICATION, later events are compared with the user LOGIN claimed. The missing authentication is reported by `PROV_TRANSITION` instead. This keeps the paper's §VI-F example at exactly its three predicted provenance findings.
- **Owner after a mismatch.** The owner is taken from the AUTHENTICATION record even when it disagrees with LOGIN, as the paper's P1 states. A tampered AUTHENTICATION user therefore flags AUTHENTICATION and every later event that names a different user.
- **Changed sequence number.** State advances with each record's *actual* sequence number. A deletion then gives a single `PROV_SEQUENCE` finding, but a changed sequence number on a record is also reported at its successor.
- **Missing LOGIN.** A session whose first event is not LOGIN fails `PROV_TRANSITION` (and `PROV_PREV_EVENT`/`PROV_SEQUENCE` if its stored fields say otherwise), not `PROV_SESSION`.
- **Sessionless records** must be one of the rule file's sessionless event types and must have no previous event or sequence number; otherwise they fail `PROV_SESSION`.
- **Rule file checks.** The file is validated when loaded: no overlap between session and sessionless types, the role events are session events, all targets are known, `__START__` leads only to LOGIN, and LOGOUT is terminal.
- **Check order** for each record: `PROV_TIMESTAMP_ORDER`, then P1–P5.

### 4.2 Additional ordering check and sessionless events [Gap → Q7, Q15]

- **[Paper Table IV]** lists "sequence numbers and timestamps out of order" as evidence of reordering. **[Rec]** Check `PROV_TIMESTAMP_ORDER`: t_n ≥ t_{n-1} along the global chain. This is safe because timestamps are assigned by the server while the append lock is held.
- **[Paper §VI-A]** lists "IP-related security events" as events of interest, but they often have no session. **[Rec]** Sessionless events (`session_id = null`) take part in the chain, the timestamp-order check and the Merkle batches. P1–P5 are reported as *not applicable* for them.

### 4.3 Is a provenance failure always tampering? [Gap → Q6]

The paper reports any failed check as "Tampering Detected". But suppose a genuine client really did send "Open File" before "Authentication". If that event were stored as-is, verification would report tampering when nothing had been tampered with.

**[Rec]** Enforce the same rules at ingestion:
- reject the session event with HTTP 409;
- append a sessionless `SECURITY_VIOLATION` event that records the attempt.

With this policy, every stored record satisfied provenance when it was captured. Any provenance failure found later therefore points to a change made *after* capture, which keeps the paper's meaning of "Tampering Detected".

### 4.4 Allowed transitions — default rule set `transitions.v1` [Rec, based on paper examples]

**[Paper]** gives only examples:
- the normal sequence Login → Authentication → Open File → Edit File → Logout;
- "Authentication before Open File" is allowed;
- Login → Open File is **not** allowed.

The full table below is our proposal:

| From \ To | LOGIN | AUTHENTICATION | FILE_OPEN | FILE_EDIT | DB_ACCESS | LOGOUT |
|---|---|---|---|---|---|---|
| `__START__` | ✔ | | | | | |
| LOGIN | | ✔ | | | | ✔ (abandoned) |
| AUTHENTICATION | | | ✔ | | ✔ | ✔ |
| FILE_OPEN | | | ✔ | ✔ | ✔ | ✔ |
| FILE_EDIT | | | ✔ | ✔ | ✔ | ✔ |
| DB_ACCESS | | | ✔ | | ✔ | ✔ |
| LOGOUT | (terminal — no further events) | | | | | |

The sessionless types are `LOGIN_FAILED`, `IP_SECURITY_EVENT` and `SECURITY_VIOLATION`.

**[Paper §IX-B]** Overly strict rules could raise false alarms. That risk is measured by the false-positive experiments.

---

## 5. Merkle batch verification

### 5.1 Procedure [Paper §VI-D, Eq. 2]

- The leaves of a batch of *m* entries are the entry hashes H_n, in chain order.
- Internal nodes are `M_{i,j} = SHA-256( M_{i+1,2j} ‖ M_{i+1,2j+1} )`. Level 0 is the root, M₀,₀.
- When a level has an odd number of nodes, **the last node is duplicated**.
- The root is stored with the batch ID, the range of entries covered and a timestamp.
- A single record's membership is proven with O(log *m*) sibling hashes. The whole batch is checked with one root comparison.
- Because the chain continues across batches, removing an entire batch also breaks the chain.

### 5.2 Details the paper leaves open [Gap → Q10]

- **Batch formation.** **[Rec]** Use a fixed size `batch_size`, configurable per stream (default 64). An admin can also "seal now", which closes a partial batch. Records not yet sealed are protected only by the chain, and the report lists them as *unbatched*.
- **Single-leaf batch.** **[Rec]** The root is the leaf itself (no hashing).
- **Node byte format.** **[Rec]** Children are concatenated as 32 raw bytes each, not as hex text.

**Decision (2026-10-04):** Q10 and Q14 were approved as recommended. Implemented in `backend/app/crypto/merkle.py` as scheme `paper-dup-v1` (Phase 3). `check_batch()` returns `MERKLE_RANGE` when the leaf count differs from the stored count, and `MERKLE_ROOT` when the recomputed root differs. Tests: `tests/unit/crypto/test_merkle.py`.

### 5.3 Membership proof [Rec format]

A proof is a list of `{sibling: hex, position: "left" | "right"}` entries, ordered from leaf to root. When a node was duplicated, its sibling is the node itself. To verify, fold the proof from the leaf and compare the result with the stored root.

### 5.4 Known weakness of duplicate-last-node [Gap → Q14]

With duplication and no separation between leaves and internal nodes, the leaf lists `[a, b, c]` and `[a, b, c, c]` produce the **same root**. (This is the same issue as Bitcoin CVE-2012-2459.)

**[Rec]** Implement the paper's procedure exactly, and add these checks on every batch:
- the stored `leaf_count` equals `last − first + 1`;
- the number of records actually present in that range equals `leaf_count`.

This closes the ambiguity in our setting.

The alternative is RFC 6962 (Certificate Transparency, the paper's ref. [4]). It hashes leaves as `SHA-256(0x00 ‖ data)` and nodes as `SHA-256(0x01 ‖ left ‖ right)`, and does not duplicate nodes. It is stronger, but it changes the paper's Eq. 2. It is available as scheme `rfc6962-v1` only if you approve it.

---

## 6. Verification algorithm

**[Paper §V-E, §VI-E]** The engine "reads the stored records in order, recomputes each chain value, re-applies the provenance checks and rebuilds the Merkle root of each batch". The result is either **Valid**, or **Tampering Detected** together with the batch identifier, the index of the first failing record and the failed check.

### 6.1 Steps [Rec, implementing the paper]

```
records ← SELECT * FROM audit_events WHERE stream_id = S ORDER BY chain_index
prev    ← (index 0, hash H₀)
for r in records:
    CHAIN_INDEX_CONTINUITY : r.chain_index == prev.index + 1
    CHAIN_LINK             : r.prev_hash   == prev.stored_hash      (H₀ for first)
    CHAIN_HASH             : SHA256(enc(E)‖enc(C)‖r.prev_hash) == r.entry_hash
    PROV_TIMESTAMP_ORDER   : r.ts >= prev.ts
    if r.session_id: P1..P5 against replayed session state (§6.3)
    prev ← r
for b in batches ORDER BY batch_index:
    MERKLE_RANGE           : contiguous with previous batch, leaf_count matches,
                             all indices in range present
    MERKLE_ROOT            : merkle_root(hashes in range) == b.merkle_root
status ← VALID if no findings else TAMPERING_DETECTED
first failing record ← the finding with the smallest chain_index
                       (ties broken in the order the checks are listed above)
```

### 6.2 Localization: why "stored-link" checking [Rec]

The paper notes that one modification "changes every subsequent chain value". If the verifier fed its *recomputed* hash into the next record, every record after the tampered one would fail, which buries where the change happened. TraceLock instead checks each record against its **stored** predecessor hash (CHAIN_LINK) and its own **stored** hash (CHAIN_HASH). Both the first failure and its extent stay sharp. The report still states how many later records would fail a full cascade recomputation, so the paper's property remains visible.

### 6.3 Session-state replay [Rec]

The verifier keeps one state entry per session ID:

```
{claimed_user, owner, last_type, last_seq, start_ts, closed}
```

This state is built **only from the chained records**. After a failing record, the state still advances using that record's actual values. A single deletion therefore produces findings at one point instead of a cascade of false findings.

### 6.4 Expected detections (from the paper, to be tested)

**[Paper Table IV]** The paper states these as *expected*. TraceLock must *test* them (EXPERIMENTS §3).

| Operation | Checks expected to fire |
|---|---|
| Modification | CHAIN_HASH at k (or CHAIN_LINK at k+1 if the attacker recomputes H_k); MERKLE_ROOT; provenance if context changed |
| Deletion | CHAIN_INDEX_CONTINUITY + CHAIN_LINK at successor; PROV_SEQUENCE, PROV_PREV_EVENT, possibly PROV_TRANSITION; MERKLE_RANGE/ROOT |
| Insertion | CHAIN_LINK at successor; PROV_SEQUENCE (duplicate); PROV_TRANSITION / PROV_WHO / PROV_SESSION; MERKLE |
| Reordering | CHAIN_LINK; PROV_SEQUENCE; PROV_TIMESTAMP_ORDER; MERKLE_ROOT |
| Context forgery | CHAIN_HASH; PROV_WHO / PROV_SESSION |
| Full consistent rewrite | **Not detected** by local verification (paper's own statement) |

**[Paper §VI-F] worked example.** Deleting "Authentication" from Login, Authentication, Open File, Edit File, Logout gives:
- a chain mismatch at Open File;
- a sequence jump from 1 to 3;
- previous event "Authentication" ≠ the actual predecessor "Login";
- a disallowed transition Login → Open File;
- a different Merkle root.

This exact case is acceptance test T4.6 in `TESTING.md`.

### 6.5 Report format [Rec]

```json
{
  "run_id": "…", "stream_id": "…", "status": "TAMPERING_DETECTED",
  "first_failure": {"chain_index": 1043, "batch_id": "…", "batch_index": 17,
                    "check": "CHAIN_LINK"},
  "checks": {"CHAIN_HASH": {"passed": 4999, "failed": 0}, "CHAIN_LINK": {"passed": 4998, "failed": 1}, "…": {}},
  "findings": [{"chain_index": 1043, "check": "CHAIN_LINK", "expected": "ab12…", "actual": "9f0c…"}],
  "cascade_affected_records": 3958,
  "records_checked": 5000, "unbatched_records": 8,
  "rules_version": "transitions.v1 sha256:…", "hash_scheme": "tl-v1", "merkle_scheme": "paper-dup-v1",
  "duration_ms": 0.0
}
```

The stored findings list is capped (default 1,000); the counts are always complete. `duration_ms` is measured and never estimated.
