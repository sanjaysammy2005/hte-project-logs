# TraceLock — Demo Script

A 12–15 minute live demonstration for the research presentation. It shows each part of the paper's method working on real data. It also shows, honestly, what the method does **not** detect.

## Before the presentation (10 minutes)

1. Start Docker Desktop, then run from the repository root:
   ```bash
   docker compose up -d
   docker compose run --rm backend alembic upgrade head
   ```
2. In `.env`, set `TRACELOCK_LAB_ENABLED=true`, then run `docker compose up -d backend`.
3. If there is no admin yet, create one:
   ```bash
   docker compose run --rm backend python -m app.cli create-operator --username admin --role admin
   ```
4. Seed the demo data through the real API. This also rehearses everything you will show:
   ```bash
   # PowerShell:  $env:DEMO_ADMIN_PASSWORD = "<admin password>"
   # Git Bash:    export DEMO_ADMIN_PASSWORD='<admin password>'
   docker compose run --rm -e DEMO_ADMIN_PASSWORD backend python scripts/demo_walkthrough.py
   ```
   The script prints each step with the values it received from the API. Keep the output in a terminal window as a backup in case the browser misbehaves.
5. Open http://localhost:5173 and sign in as `admin`.
6. Optionally, open a terminal at `D:\Projects\TraceLock` and have `docker compose run --rm backend pytest -q` ready for step 8.

## The demonstration

| # | Show | Say (paper reference) |
|---|---|---|
| 1 | **Streams** page | "Each stream is one hash chain. The `system` stream records every sign-in to TraceLock itself, so the auditor's own actions are audited. The coloured badges separate real data from synthetic and lab data." |
| 2 | Open `demo-clinic-…` → **Events** | "The application sent only user, session, event and details. TraceLock added the **context** from the paper: sequence number, previous event and timestamp (§V-B, Table III)." |
| 3 | Click record **#3 (FILE_OPEN)** | "This is the paper's Table III example. The hash covers the event **and** its context **and** the previous hash: Eq. 1, H_n = SHA-256(E_n ‖ C_n ‖ H_{n−1}). Stored and recomputed hashes match ✓, and the stored previous hash matches the real predecessor ✓." |
| 4 | Same page → **Get and verify membership proof** | "Records are grouped into Merkle batches (§VI-D). This proves record #3 belongs to its batch with two sibling hashes, not the whole batch. That's O(log m)." |
| 5 | Record **#6 SECURITY_VIOLATION** | "Someone tried to open a file in a session that had already ended, under a different user. The five provenance checks (§VI-C) rejected it **at capture**, and the attempt itself was logged as evidence." |
| 6 | **Verification** tab → Run verification | "The engine recomputes every chain value, re-applies the provenance checks and rebuilds every batch root (§VI-E). It reports VALID, with a measured time." |
| 7 | **Tamper lab** → Scenario results | "Each scenario tampers with a **copy**. The expected outcome is stored before verification runs, so the results can't be adjusted afterwards." Point at: **S1** (modification, located at the exact record), **S9** (the paper's own deletion example, §VI-F), **S10** and **S11** (**not detected**). |
| 8 | Click **S9 → detected** → open the first failing record | "Exactly what the paper predicts: the chain breaks at Open File, the sequence jumps, the previous event no longer matches, and Login → Open File is not allowed." |
| 9 | Click **S11** | "This is the paper's own limitation (§IX-B). An attacker who rewrites **every** later hash and batch root leaves a log that verifies as VALID. The method is tamper-**evident**, not tamper-proof. Closing this needs a trust anchor outside the database: HMAC keys, signed roots or external publication. That's future work in §X." |
| 10 | **Experiments** page | "These are measured results stored by the experiment harness, with their configuration and machine. Nothing is hard-coded; a build check enforces that. The smoke run is small (10 trials), so the intervals are wide." Point out **S2's localization**: "When the attacker also recomputes the edited record's hash, detection lands one record late. That's inherent to an unkeyed chain." |
| 11 | *(optional)* terminal: `pytest -q` | "About 300 automated tests, including tampering done directly in the database with SQL, independent test vectors and deliberate code breaks." |

## Likely questions

**Why not use a blockchain?**
- The paper deliberately avoids distributed consensus and extra infrastructure (§I, §IX-A).
- The trade-off is the local trust model. That is exactly what S11 demonstrates.

**Can an administrator just rewrite everything?**
- Yes. With write access to all records, hashes and roots, they can produce a consistent log (S11), and deleting the newest records is also undetected (S10).
- These are documented in `SECURITY_LIMITATIONS.md` §4, not hidden.

**Why does verification flag record k+1 instead of k in S2?**
- SHA-256 has no secret key, so an attacker can recompute the edited record's own hash.
- The first inconsistency is then the link stored in the next record.

**How is the encoding made unambiguous?**
- Every field is length-prefixed, so "U1"+"0S" and "U10"+"S" hash differently.
- Published test vectors are reproduced by an independent implementation (`VERIFICATION.md` §2.5).

**What if a legitimate user does something unusual?**
- It is rejected at capture and logged as a `SECURITY_VIOLATION` (Q6).
- So a later provenance failure always means the data changed after capture.
- The cost: overly strict rules can reject legitimate behaviour (paper §IX-B).

**Are the results statistically meaningful?**
- The smoke run is not. It has 10 trials per scenario on about 1,000 records.
- The full matrix (`experiments/full.json`) still has to be run. See `EXPERIMENTS.md` §6.

## If something goes wrong

| Problem | Fix |
|---|---|
| Login fails (401) | Usernames and passwords are case-sensitive. Every failed attempt appears as `LOGIN_FAILED` in the `system` stream. Create a new admin with the CLI if needed. |
| Tamper lab says "disabled" | Set `TRACELOCK_LAB_ENABLED=true` in `.env`, then `docker compose up -d backend`. |
| Dashboard blank or "backend unreachable" | `docker compose ps` should show three healthy services. Check `docker compose logs backend`. |
| Port already in use | Change `BACKEND_HOST_PORT` / `FRONTEND_HOST_PORT` / `POSTGRES_HOST_PORT` in `.env`. |
