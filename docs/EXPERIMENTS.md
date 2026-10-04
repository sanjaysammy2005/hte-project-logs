# TraceLock — Experimental Evaluation Plan

Tags: **[Paper]** · **[Rec]** · **[Gap]**.

> **No results exist yet.** The paper itself states that "no measured performance figures are claimed at this stage" (§VIII). Every result table in this document stays marked **NOT YET MEASURED** until the Phase 9 experiments have actually run.

## 1. What the paper specifies [Paper §VII]

- **Platform:** the application prototype with a local database on a commodity machine. The machine's specification must be reported with the results.
- **Three scenarios:**
  1. **Normal operation.** Representative sequences (logins, authentication, file access, edits, logouts) for multiple users and concurrent sessions, then verification of the untampered log. This measures the false-alarm rate, which "should be zero".
  2. **Tampering.** Modification, deletion, insertion and reordering of stored records, plus alteration of context fields (user and session IDs). Each is followed by verification, to confirm detection and to locate the first affected record.
  3. **Scale.** Increasing batch sizes and log volumes, to assess verification time and per-record storage overhead.
- **Metrics:** detection rate per tampering type, false-alarm rate, accuracy of locating the first affected record, verification time per batch, and storage overhead per record.

**[Gap]** The paper gives no formulas, dataset sizes, repetition counts, attacker capabilities or statistical procedure. Everything below marked [Rec] is our proposal.

## 2. Test conditions [Rec]

- All experiments run on **synthetic streams** from the seeded workload generator, or on **lab clones** of them. They never run on primary data.
- The **environment is captured automatically** for every run:
  - CPU model and core count, RAM and OS;
  - Docker resource limits;
  - Python, PostgreSQL and library versions;
  - the git commit hash.
- **Timing:**
  - Wall-clock time is measured with `time.perf_counter()` around the verification call.
  - It is broken down into DB read, chain checks, provenance checks and Merkle checks.
  - One warm-up run is discarded, and each measurement is repeated R = 10 times.
  - We report the median and the interquartile range (IQR), plus min and max.
- **Fixed seeds:** each configuration uses fixed seeds, so detection outcomes are reproducible.

## 3. Tampering scenarios [Paper Table IV + Rec]

**Attacker models [Rec]**, made explicit because the paper's threat model (§II) assumes the attacker does *not* produce a fully consistent chain:
- **A0 naive:** edits stored fields only.
- **A1 record-consistent:** edits a record **and** recomputes that record's own `entry_hash`. SHA-256 is unkeyed, so this is easy.
- **A2 full rewrite:** recomputes every later hash and every affected batch root. The paper says this is **not detected** (§IX-B, Table IV last row).

| ID | Scenario | Attacker | Expected detected? | Ground-truth first affected record | Source of expectation |
|---|---|---|---|---|---|
| S1 | Modify event payload at k | A0 | Yes | k | Paper Table IV |
| S2 | Modify event payload at k | A1 | Yes | k+1 (CHAIN_LINK) | Derived from Eq. 1 |
| S3 | Modify context (user) at k | A0 | Yes | k | Paper Table IV "context forgery" |
| S4 | Modify context (session) at k | A1 | Yes | k (PROV_WHO/SESSION) or k+1 | Paper §VI-C |
| S5 | Delete record k (k not last) | A0 | Yes | successor of k | Paper §VI-F |
| S6 | Insert forged record before k | A1 (renumbers chain_index) | Yes | the inserted record (provenance) or k (CHAIN_LINK) | Paper Table IV |
| S7 | Swap records k and j (k<j) | A0 | Yes | k | Paper Table IV |
| S8 | Delete an entire sealed batch | A0 | Yes | first record after the batch | Paper §VI-D |
| S9 | Paper worked example: delete AUTHENTICATION | A0 | Yes | the following FILE_OPEN | Paper §VI-F |
| S10 | Tail truncation: delete the last *t* records | A0 | **No** (expected) | — | [Gap] not covered by the paper |
| S11 | Full consistent rewrite from k | A2 | **No** (expected) | — | Paper §IX-B |

Notes:
- **Ground truth for S6.** The scenario report stores both the *true* locus (the inserted record) and the *chain-only* locus, so that localization accuracy is reported for each definition. **[Gap]** The paper does not say which one "first affected record" means.
- **S10 and S11** are negative controls. They must show "not detected". If they unexpectedly show "detected", that points to a bug, not a strength.
- **Target positions.** k is sampled uniformly from valid positions with the scenario seed. Positions at the start of the stream, at batch boundaries and in the last batch are added as fixed extra cases.
- **Expected outcomes are written to `tamper_scenarios` before verification runs.**

## 4. Metric definitions [Rec formulas for Paper §VII metrics]

### 4.1 Detection rate (per scenario type T)
```
DR(T) = #trials of T reported TAMPERING_DETECTED / #trials of T
```
Reported with a 95% Wilson score interval. Default 100 trials per T and dataset size.

### 4.2 False-positive (false-alarm) rate
Run level:
```
FPR = #verification runs on untampered streams reporting TAMPERING_DETECTED / #runs on untampered streams
```
Record level (for diagnosis): the number of findings on untampered streams, which should be 0.

Untampered streams include concurrent interleaved sessions, sessionless events, single-event batches and partial batches. These are the cases most likely to expose serialization or rule bugs.

### 4.3 Localization accuracy
```
LA(T) = #detected trials where first_failing_chain_index == ground-truth index / #detected trials of T
```
For S6, LA is computed under both ground-truth definitions (see §3).

### 4.4 Verification time
- The total time for a full verification of N records.
- Time per batch: `(time for the MERKLE checks) / #batches`, plus time per record.
- Single-record membership proof generation and verification time against batch size *m*.

Expected complexity from the paper (§VIII) is O(N) full verification, O(*m*) tree building and O(log *m*) proofs. The experiments test whether measurements follow this trend; this is not assumed.

### 4.5 Storage overhead
```
overhead_per_record = (pg_total_relation_size(audit_events_N) − pg_total_relation_size(baseline_N)) / N
batch_overhead      = pg_total_relation_size(batches) / N
```
`baseline_N` is a table holding the same N events with only (id, event_type, payload, actor_user_id, session_id, timestamp), with no context or hash columns. Both tables are measured after `VACUUM FULL; ANALYZE`, with comparable indexes reported separately.

## 5. Experiment matrix [Rec]

| Dimension | Values |
|---|---|
| Records N | 1,000 · 10,000 · 100,000 (1,000,000 if time allows) |
| Batch size m | 16 · 64 · 256 · 1,024 |
| Users / sessions | 10 users, 5 sessions each (N=1k) scaled proportionally |
| Concurrency | sessions interleaved randomly in the global stream |
| Tamper trials | 100 per scenario per N (N ≤ 10k); 20 for N = 100k |
| Timing repetitions | R = 10 after 1 warm-up |
| Seeds | fixed list recorded in `experiment_runs.config` |

These sizes suit a final-year project on one laptop and can be reduced if verification turns out slower than expected. Any reduction will be documented.

## 6. Results

| Metric | Value | Conditions |
|---|---|---|
| Detection rate (S1–S9) | **NOT YET MEASURED** | |
| Detection rate (S10, S11 negative controls) | **NOT YET MEASURED** | |
| False-positive rate | **NOT YET MEASURED** | |
| Localization accuracy | **NOT YET MEASURED** | |
| Verification time | **NOT YET MEASURED** | |
| Storage overhead per record | **NOT YET MEASURED** | |

## 7. Threats to validity [Rec]

- **Synthetic workloads** may not reflect real application behaviour.
- **The transition rules were written by us.** Different rules change both detection and false-alarm behaviour (the paper notes this in §IX-B).
- **Single machine.** Timing depends on the hardware and on Docker overhead.
- **Simulated attacker.** The scenarios simulate the attacker models above; a real attacker may behave differently.
- **Implementation bugs** could inflate detection. The negative controls (S10, S11) and independent test vectors help catch this.
