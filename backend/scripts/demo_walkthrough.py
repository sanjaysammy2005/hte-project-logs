"""TraceLock live demo: drives the real API and narrates each step.

Run against a running stack (an admin account must exist):

    docker compose run --rm -e DEMO_ADMIN_PASSWORD backend python scripts/demo_walkthrough.py

Environment:
    DEMO_API_URL          default http://backend:8000/api/v1 (the compose service)
    DEMO_ADMIN_USER       default "admin"
    DEMO_ADMIN_PASSWORD   required

The script creates (once) a demo auditor and a demo ingestor with random passwords that are
used only inside this run and never printed. The tamper-lab part runs only when the lab is
enabled (TRACELOCK_LAB_ENABLED=true); it modifies cloned lab streams only. Every value shown
is read from API responses; nothing is simulated.
"""

import os
import secrets
import sys
import uuid

import httpx

API = os.environ.get("DEMO_API_URL", "http://backend:8000/api/v1")
RUN = uuid.uuid4().hex[:6]
client = httpx.Client(base_url=API, timeout=300)


def heading(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def say(text: str) -> None:
    print(f"  {text}")


def login(username: str, password: str) -> dict[str, str]:
    response = client.post("/auth/login", json={"username": username, "password": password})
    if response.status_code != 200:
        sys.exit(f"login failed for {username!r}: {response.status_code} {response.text}")
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def demo_account(admin: dict[str, str], role: str) -> dict[str, str]:
    """Create a fresh demo operator for this run and log in as it."""
    username, password = f"demo-{role}-{RUN}", secrets.token_urlsafe(18)
    created = client.post(
        "/operators", headers=admin, json={"username": username, "password": password, "role": role}
    )
    created.raise_for_status()
    return login(username, password)


def main() -> None:
    admin_password = os.environ.get("DEMO_ADMIN_PASSWORD")
    if not admin_password:
        sys.exit("set DEMO_ADMIN_PASSWORD (the password of the admin account)")
    admin = login(os.environ.get("DEMO_ADMIN_USER", "admin"), admin_password)
    ingestor, auditor = demo_account(admin, "ingestor"), demo_account(admin, "auditor")

    heading("1. Context-enriched, hash-chained capture (paper §IV-§VI-B)")
    stream = client.post(
        "/streams",
        headers=admin,
        json={
            "name": f"demo-clinic-{RUN}",
            "batch_size": 4,
            "description": "Demo stream for the presentation",
        },
    ).json()
    say(f"Admin created primary stream {stream['name']} (batch size 4).")
    say("The application (ingestor role) sends only: user, session, event type, details.")
    say("TraceLock adds sequence number, previous event, timestamp and the hash link:")
    for event_type, payload in [
        ("LOGIN", {"ip_address": "10.0.0.12"}),
        ("AUTHENTICATION", {"method": "password", "outcome": "success"}),
        ("FILE_OPEN", {"resource": "/records/patient-1042.pdf"}),
        ("FILE_EDIT", {"resource": "/records/patient-1042.pdf"}),
        ("LOGOUT", {}),
    ]:
        e = client.post(
            f"/streams/{stream['id']}/events",
            headers=ingestor,
            json={
                "actor_user_id": "dr.rao",
                "session_id": "S-7001",
                "event_type": event_type,
                "payload": payload,
            },
        ).json()
        say(
            f"#{e['chain_index']} {event_type:<15} seq={e['session_seq']} "
            f"prev={e['prev_event_type']:<15} prev_hash={e['prev_hash'][:10]}… "
            f"hash={e['entry_hash'][:10]}…"
        )

    heading("2. Provenance rules enforced at capture (paper §VI-C, policy Q6)")
    r = client.post(
        f"/streams/{stream['id']}/events",
        headers=ingestor,
        json={
            "actor_user_id": "intruder",
            "session_id": "S-7001",
            "event_type": "FILE_OPEN",
            "payload": {"resource": "/records/patient-1042.pdf"},
        },
    )
    error = r.json()["error"]
    say(
        f"'intruder' opens a file in dr.rao's ended session -> HTTP {r.status_code} {error['code']}"
    )
    say(f"failed checks: {[c['check'] for c in error['details']['failed_checks']]}")
    say(f"stored instead as SECURITY_VIOLATION #{error['details']['security_event_chain_index']}")

    heading("3. Roles")
    read = client.get(f"/streams/{stream['id']}/events", headers=ingestor).status_code
    create = client.post("/streams", json={"name": "x"}, headers=auditor).status_code
    say(f"ingestor reads events     -> {read}")
    say(f"auditor creates a stream  -> {create}")

    heading("4. Merkle batches and verification (paper §VI-D, §VI-E)")
    client.post(
        f"/streams/{stream['id']}/batches/seal", headers=admin, json={"include_partial": True}
    )
    report = client.post(f"/streams/{stream['id']}/verify", headers=auditor).json()
    say(
        f"Auditor verifies: {report['status']} - {report['records_checked']} records, "
        f"{report['batches_checked']} batches, {report['duration_ms']:.1f} ms (measured)"
    )
    proof = client.get(f"/streams/{stream['id']}/events/3/proof", headers=auditor).json()
    valid = client.post(
        "/proofs/verify",
        headers=auditor,
        json={"leaf": proof["leaf"], "merkle_root": proof["merkle_root"], "proof": proof["proof"]},
    ).json()
    say(
        f"Record #3 is in batch {proof['batch_index']}: {len(proof['proof'])}-step Merkle proof "
        f"-> valid={valid['valid']}"
    )

    heading("5. Controlled tampering on copies (paper Table IV, §VI-F, §IX-B)")
    workload = client.post(
        "/lab/workloads",
        headers=admin,
        json={
            "name": f"demo-synthetic-{RUN}",
            "users": 3,
            "sessions_per_user": 3,
            "events_per_session": 8,
            "seed": 2026,
            "batch_size": 8,
        },
    )
    if workload.status_code == 404:
        say("Tamper lab is disabled (set TRACELOCK_LAB_ENABLED=true to include this part).")
    else:
        work = workload.json()
        say(f"Synthetic workload: {work['record_count']} records (seed 2026, reproducible).")
        for code in ["S1", "S3", "S5", "S9", "S10", "S11"]:
            s = client.post(
                "/lab/scenarios",
                headers=admin,
                json={"source_stream_id": work["id"], "scenario_type": code, "seed": 7},
            ).json()
            actual = "DETECTED" if s["actual_detected"] else "not detected"
            where = (
                f"first failure #{s['first_failure_index']} {s['first_failure_check']}"
                if s["actual_detected"]
                else ""
            )
            say(
                f"{code:<3} [{s['attacker_model']}] {s['description']:<52} -> {actual:<12} "
                f"{where} ({s['outcome']})"
            )
        source = client.post(f"/streams/{work['id']}/verify", headers=auditor).json()
        say(f"Original workload after all scenarios: {source['status']} (copies were tampered)")

    heading("6. Every operator login is itself audited")
    client.post("/auth/logout", headers=auditor)
    after = client.get("/auth/me", headers=auditor)
    say(f"Auditor logged out; old token -> {after.status_code} {after.json()['error']['code']}")
    system = next(s for s in client.get("/streams", headers=admin).json() if s["name"] == "system")
    check = client.post(f"/streams/{system['id']}/verify", headers=admin).json()
    say(f"System stream ({check['records_checked']} login/logout records) -> {check['status']}")
    print("\nOpen http://localhost:5173 to explore the same data in the dashboard.")


if __name__ == "__main__":
    main()
