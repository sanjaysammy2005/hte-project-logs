"""ZT-INV: file security investigation over the audit chain (ZERO_TRUST_FILE_MODULE §29).

Investigation is read-only and uses the chained events as its only source. FILE INTEGRITY
FAILURE and AUDIT LOG INTEGRITY FAILURE must be reported as different conditions.
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.batching.service import seal_batches
from app.crypto.chain import compute_entry_hash
from app.db.models import AuditEvent, LogStream
from app.files.storage import LocalFileStorage
from app.ingestion.service import to_chained
from tests.api.conftest import User
from tests.api.file_helpers import API, blob_path, new_version, system_events, uploaded
from tests.file_samples import PDF

pytestmark = pytest.mark.usefixtures("file_storage")
SEC = f"{API}/security"


@pytest.fixture
def org(sign_in: Callable[..., User]) -> dict[str, User]:
    return {
        name: sign_in(name, role, department)
        for name, role, department in [
            ("ada", "admin", "IT"),
            ("aud", "auditor", None),
            ("owner", "employee", "Engineering"),
            ("finance", "employee", "Finance"),
            ("boss", "manager", "Engineering"),
            ("ivan", "ingestor", None),
        ]
    }


def search(client, investigator: User, **params) -> list[dict]:
    response = client.get(f"{SEC}/events", params=params, headers=investigator.headers)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def edit_payload(db: Session, stream: LogStream, chain_index: int, key: str, value: str) -> None:
    db.execute(
        text(
            "UPDATE audit_events SET event_payload ="
            " jsonb_set(event_payload, CAST(:path AS text[]),"
            " to_jsonb(CAST(:v AS text))) WHERE stream_id = :s AND chain_index = :i"
        ),
        {"path": "{" + key + "}", "v": value, "s": stream.id, "i": chain_index},
    )
    db.commit()


def rehash(db: Session, stream: LogStream, chain_index: int) -> None:
    row = db.scalars(
        select(AuditEvent).where(
            AuditEvent.stream_id == stream.id, AuditEvent.chain_index == chain_index
        )
    ).one()
    row.entry_hash = compute_entry_hash(to_chained(row).record, bytes(row.prev_hash))
    db.commit()


@pytest.fixture
def activity(client: TestClient, org) -> dict:
    """A realistic slice of activity: uploads, a denial, a share, a new version, a restore, a
    downgrade, a deletion and a download."""
    doc = uploaded(client, org["owner"], name="plan.pdf", classification="INTERNAL")
    secret = uploaded(client, org["owner"], name="salaries.pdf", classification="RESTRICTED")
    h = org["owner"].headers
    client.get(f"{API}/files/{doc['id']}/content", headers=org["finance"].headers)  # denied (404)
    client.post(
        f"{API}/files/{doc['id']}/permissions",
        json={"grantee_id": str(org["finance"].id), "permissions": ["READ"]},
        headers=h,
    )
    new_version(client, org["owner"], doc["id"], 1, PDF + b"%2\n")
    client.post(f"{API}/files/{doc['id']}/versions/1/restore", json={"base_version": 2}, headers=h)
    client.get(f"{API}/files/{secret['id']}/content", headers=h)
    client.patch(
        f"{API}/files/{doc['id']}",
        json={"classification": "PUBLIC", "reason": "published"},
        headers=org["ada"].headers,
    )  # noqa: E501
    client.delete(f"{API}/files/{secret['id']}", headers=h)
    return {"doc": doc, "secret": secret}


# --- access ------------------------------------------------------------------------------------


@pytest.mark.parametrize("who", ["owner", "boss", "ivan"])
def test_only_security_roles_may_investigate(client, org, who) -> None:
    for path in ("/events", "/findings", "/events/1"):
        assert client.get(f"{SEC}{path}", headers=org[who].headers).status_code == 403
    assert client.get(f"{SEC}/events").status_code == 401


def test_investigation_is_read_only(client, db, org, activity) -> None:
    before = len(system_events(db))
    doc = activity["doc"]["id"]
    for path in (
        "/events",
        "/findings",
        f"/files/{doc}/timeline",
        f"/files/{doc}/integrity",
        "/events/3",
    ):
        assert client.get(f"{SEC}{path}", headers=org["aud"].headers).status_code == 200
    assert client.post(f"{SEC}/events/3/verify", headers=org["aud"].headers).status_code == 200
    assert len(system_events(db)) == before  # no second log, no new events


# --- search ------------------------------------------------------------------------------------


def test_search_filters(client, org, activity) -> None:
    doc, secret = activity["doc"]["id"], activity["secret"]["id"]
    aud = org["aud"]

    denied = search(client, aud, category="denied")
    assert [e["user"] for e in denied] == ["finance"]
    assert denied[0]["decision"] == "DENY" and denied[0]["rule"]
    assert {e["event_type"] for e in search(client, aud, category="permissions")} == {
        "FILE_SHARED", "FILE_ACCESS_POLICY_CHANGED",
    }  # fmt: skip
    assert [e["event_type"] for e in search(client, aud, category="deletion")] == ["FILE_DELETE"]
    assert [e["event_type"] for e in search(client, aud, category="restoration")] == [
        "FILE_VERSION_RESTORED"
    ]
    assert [e["event_type"] for e in search(client, aud, category="replacement")] == [
        "FILE_VERSION_CREATED"
    ]

    assert {e["user"] for e in search(client, aud, user="finance")} == {"finance"}
    by_file = search(client, aud, file_id=doc)
    assert by_file and all(e["file_id"] == doc for e in by_file)
    assert [e["file_id"] for e in search(client, aud, action="DELETE")] == [secret]
    assert {e["decision"] for e in search(client, aud, decision="DENY")} == {"DENY"}
    restricted = search(client, aud, classification="RESTRICTED")
    assert restricted and all(e["file_id"] == secret for e in restricted)
    assert all(e["filename"] == "[redacted]" for e in restricted)  # names never leave redaction
    assert (
        search(client, aud, event_type="FILE_UPLOAD", user="owner")[0]["event_type"]
        == "FILE_UPLOAD"
    )
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert search(client, aud, since=future) == []
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    assert len(search(client, aud, since=past, until=future)) == len(search(client, aud))


def test_search_pagination_newest_first(client, org, activity) -> None:
    first = client.get(f"{SEC}/events", params={"limit": 3}, headers=org["ada"].headers).json()
    indices = [e["chain_index"] for e in first["items"]]
    assert indices == sorted(indices, reverse=True) and first["next_cursor"] == indices[-1]
    nxt = client.get(
        f"{SEC}/events",
        params={"limit": 3, "cursor": first["next_cursor"]},
        headers=org["ada"].headers,
    ).json()  # noqa: E501
    assert max(e["chain_index"] for e in nxt["items"]) < indices[-1]


@pytest.mark.parametrize(
    "params",
    [
        {"decision": "MAYBE"},
        {"category": "everything"},
        {"limit": 0},
        {"action": "drop table"},
        {"file_id": "x"},
    ],
)
def test_invalid_search_parameters(client, org, params) -> None:
    assert client.get(f"{SEC}/events", params=params, headers=org["ada"].headers).status_code == 422


# --- one event ---------------------------------------------------------------------------------


def test_inspect_event_shows_chain_merkle_and_versions(
    client, db, org, activity, system_stream
) -> None:
    event = search(client, org["aud"], category="replacement")[0]
    detail = client.get(f"{SEC}/events/{event['chain_index']}", headers=org["aud"].headers).json()

    assert detail["event"]["event_type"] == "FILE_VERSION_CREATED"
    assert detail["event"]["payload"]["version"] == 2
    chain = detail["chain"]
    assert chain["status"] == "VALID" and chain["hash_matches"] and chain["link_matches"]
    assert chain["predecessor"]["chain_index"] == event["chain_index"] - 1
    assert chain["successor"]["links_back"] is True
    assert detail["merkle"]["status"] == "UNSEALED"
    assert [v["version_number"] for v in detail["related_file"]["versions"]] == [1, 2, 3]

    seal_batches(db, system_stream, include_partial=True)
    db.commit()
    sealed = client.get(f"{SEC}/events/{event['chain_index']}", headers=org["aud"].headers).json()[
        "merkle"
    ]
    assert sealed["status"] == "VALID" and sealed["proof_valid"]
    assert sealed["recomputed_root"] == sealed["batch"]["stored_root"]


def test_verify_event_valid(client, org, activity) -> None:
    event = search(client, org["aud"], category="permissions")[-1]
    report = client.post(
        f"{SEC}/events/{event['chain_index']}/verify", headers=org["aud"].headers
    ).json()
    assert report["status"] == "VALID"
    assert report["provenance"]["status"] == "VALID" and report["provenance"]["session_events"] > 2


def test_unknown_event(client, org) -> None:
    response = client.get(f"{SEC}/events/999999", headers=org["ada"].headers)
    assert response.status_code == 404 and response.json()["error"]["code"] == "EVENT_NOT_FOUND"


def test_tampered_event_is_an_audit_log_integrity_failure(
    client, db, org, activity, system_stream
) -> None:
    target = search(client, org["aud"], category="deletion")[0]["chain_index"]
    edit_payload(db, system_stream, target, "action", "VIEW")  # attacker hides the deletion

    report = client.post(f"{SEC}/events/{target}/verify", headers=org["aud"].headers).json()
    assert report["status"] == "AUDIT_LOG_INTEGRITY_FAILURE"
    assert report["chain"]["hash_matches"] is False


def test_rehashed_event_caught_by_successor_and_merkle(
    client, db, org, activity, system_stream
) -> None:
    target = search(client, org["aud"], category="deletion")[0]["chain_index"]
    client.get(f"{API}/files", headers=org["owner"].headers)
    client.get(
        f"{API}/files/{activity['doc']['id']}/content", headers=org["owner"].headers
    )  # a successor
    seal_batches(db, system_stream, include_partial=True)
    db.commit()
    edit_payload(db, system_stream, target, "action", "VIEW")
    rehash(db, system_stream, target)  # attacker A1: the event's own hash is consistent again

    report = client.post(f"{SEC}/events/{target}/verify", headers=org["aud"].headers).json()
    assert report["status"] == "AUDIT_LOG_INTEGRITY_FAILURE"
    assert report["chain"]["hash_matches"] is True
    assert report["chain"]["successor"]["links_back"] is False
    assert report["merkle"]["status"] == "ROOT_MISMATCH"


# --- files: timeline and the two kinds of integrity failure ---------------------------------


def test_file_timeline(client, org, activity) -> None:
    doc = activity["doc"]["id"]
    timeline = client.get(f"{SEC}/files/{doc}/timeline", headers=org["aud"].headers).json()
    types = [e["event_type"] for e in timeline["events"]]
    assert types[0] == "FILE_UPLOAD"
    assert {
        "FILE_ACCESS_DENIED",
        "FILE_SHARED",
        "FILE_VERSION_CREATED",
        "FILE_VERSION_RESTORED",
    } <= set(types)
    indices = [e["chain_index"] for e in timeline["events"]]
    assert indices == sorted(indices)
    assert [v["version_number"] for v in timeline["versions"]] == [1, 2, 3]


def test_file_integrity_intact(client, org, activity) -> None:
    report = client.get(
        f"{SEC}/files/{activity['doc']['id']}/integrity", headers=org["aud"].headers
    ).json()
    assert report["file_integrity"]["status"] == "INTACT"
    assert report["audit_log_integrity"]["status"] == "VALID"
    assert report["audit_log_integrity"]["stream"]["status"] == "VALID"
    v1 = report["versions"][0]
    assert v1["expected_sha256"] == v1["anchored_sha256"] == v1["actual_sha256"]


def test_modified_blob_is_a_file_integrity_failure_not_an_audit_one(
    client, db, org, activity, file_storage: LocalFileStorage
) -> None:
    doc = activity["doc"]["id"]
    blob_path(file_storage, db, doc, version=2).write_bytes(PDF.replace(b"1.7", b"1.4") + b"%2\n")
    report = client.get(f"{SEC}/files/{doc}/integrity", headers=org["aud"].headers).json()

    fi, al = report["file_integrity"], report["audit_log_integrity"]
    assert fi["status"] == "FILE_INTEGRITY_FAILURE" and al["status"] == "VALID"
    assert fi["first_affected_version"] == 2
    v2 = report["versions"][1]
    assert v2["file_status"] == "CONTENT_MISMATCH"
    assert v2["actual_sha256"] != v2["expected_sha256"] == v2["anchored_sha256"]
    assert (
        fi["first_affected_audit_event"] == v2["anchor_chain_index"]
    )  # the event it no longer matches
    assert v2["anchor_status"] == "VALID" and v2["anchor_chain_status"] == "VALID"


def test_db_hash_swapped_is_a_file_integrity_failure(client, db, org, activity) -> None:
    doc = activity["doc"]["id"]
    db.execute(
        text("UPDATE file_versions SET sha256 = :h WHERE file_id = :f AND version_number = 1"),
        {"h": b"\x01" * 32, "f": doc},
    )  # noqa: E501
    db.commit()
    report = client.get(f"{SEC}/files/{doc}/integrity", headers=org["aud"].headers).json()
    assert report["file_integrity"]["status"] == "FILE_INTEGRITY_FAILURE"
    assert report["versions"][0]["file_status"] in {"CONTENT_MISMATCH", "METADATA_MISMATCH"}
    assert report["audit_log_integrity"]["status"] == "VALID"


def test_tampered_anchor_is_an_audit_log_integrity_failure(
    client, db, org, activity, system_stream
) -> None:
    doc = activity["doc"]
    anchor = doc["current"]["audit_chain_index"]
    edit_payload(db, system_stream, anchor, "size_bytes", "0")
    report = client.get(f"{SEC}/files/{doc['id']}/integrity", headers=org["aud"].headers).json()

    al = report["audit_log_integrity"]
    assert al["status"] == "AUDIT_LOG_INTEGRITY_FAILURE"
    assert anchor in al["anchors_failing"]
    assert al["stream"]["status"] == "TAMPERING_DETECTED"
    assert al["stream"]["first_affected_audit_event"] == anchor
    assert al["stream"]["first_failed_check"] == "CHAIN_HASH"
    assert report["file_integrity"]["status"] == "INTACT"  # the bytes themselves are fine
    assert report["versions"][0]["anchor_chain_status"] == "BROKEN"


def test_unknown_file(client, org) -> None:
    for path in ("timeline", "integrity"):
        response = client.get(
            f"{SEC}/files/00000000-0000-4000-8000-00000000abcd/{path}", headers=org["ada"].headers
        )
        assert response.status_code == 404


# --- findings ------------------------------------------------------------------------------------


def test_findings(client, db, org, activity, file_storage: LocalFileStorage) -> None:
    doc, secret = activity["doc"]["id"], activity["secret"]["id"]
    for _ in range(3):  # repeated denied attempts, probing a hidden file
        client.get(f"{API}/files/{secret}/content", headers=org["boss"].headers)
    for _ in range(3):
        client.get(f"{API}/files/{doc}/content", headers=org["finance"].headers)  # high frequency
    client.get(f"{API}/files/{doc}", headers={"Authorization": "Bearer junk"})
    client.post(
        f"{API}/files/{doc}/permissions",
        json={"grantee_id": str(org["ada"].id), "permissions": ["READ"], "reason": "incident"},
        headers=org["ada"].headers,
    )  # break-glass self-grant
    blob_path(file_storage, db, doc, version=3).unlink()
    client.get(f"{API}/files/{doc}/content", headers=org["owner"].headers)  # integrity failure

    f = client.get(f"{SEC}/findings", params={"threshold": 3}, headers=org["aud"].headers).json()

    denials = {r["user"]: r for r in f["repeated_denials"]}
    assert denials["boss"]["count"] == 3 and denials["boss"]["distinct_files"] == 1
    assert "boss" in {r["user"] for r in f["probing_unknown_or_hidden_files"]}
    assert "finance" in {r["user"] for r in f["high_frequency_downloads"]}
    assert [e["event_type"] for e in f["integrity_failures"]] == ["FILE_INTEGRITY_FAILURE"]
    assert [e["user"] for e in f["break_glass_self_grants"]] == ["ada"]
    assert [e["file_id"] for e in f["classification_downgrades"]] == [doc]
    assert [e["file_id"] for e in f["deletions"]] == [secret]
    one = client.get(f"{SEC}/findings", params={"threshold": 1}, headers=org["aud"].headers).json()
    assert one["unauthenticated_attempts"][0]["user"] is None  # garbage token: not attributable


def test_findings_window_and_validation(client, org, activity) -> None:
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    empty = client.get(
        f"{SEC}/findings", params={"since": future, "threshold": 1}, headers=org["aud"].headers
    )
    assert empty.status_code == 422  # since after the default 'until' (now)
    later = (datetime.now(UTC) + timedelta(days=2)).isoformat()
    quiet = client.get(
        f"{SEC}/findings",
        params={"since": future, "until": later, "threshold": 1},
        headers=org["aud"].headers,
    )  # noqa: E501
    assert quiet.status_code == 200 and quiet.json()["deletions"] == []


def test_rehash_detected_by_successor_link_alone(client, db, org, activity, system_stream) -> None:
    """Unsealed: no Merkle root protects the event, so only the next record's link shows it."""
    target = search(client, org["aud"], category="deletion")[0]["chain_index"]
    client.get(f"{API}/files/{activity['doc']['id']}/content", headers=org["owner"].headers)
    edit_payload(db, system_stream, target, "action", "VIEW")
    rehash(db, system_stream, target)

    report = client.post(f"{SEC}/events/{target}/verify", headers=org["aud"].headers).json()
    assert report["merkle"]["status"] == "UNSEALED"
    assert report["chain"]["status"] == "BROKEN"
    assert report["status"] == "AUDIT_LOG_INTEGRITY_FAILURE"


def test_untouched_event_in_a_tampered_batch(client, db, org, activity, system_stream) -> None:
    """The event itself is intact and its own membership proof still verifies, but a batch-mate
    was changed: the recomputed batch root no longer matches the stored one."""
    deletion = search(client, org["aud"], category="deletion")[0]["chain_index"]
    upload = search(client, org["aud"], event_type="FILE_UPLOAD")[-1]["chain_index"]
    seal_batches(db, system_stream, include_partial=True)
    db.commit()
    edit_payload(db, system_stream, deletion, "action", "VIEW")

    report = client.post(f"{SEC}/events/{upload}/verify", headers=org["aud"].headers).json()
    assert report["chain"]["status"] == "VALID"
    assert report["merkle"]["proof_valid"] is True
    assert report["merkle"]["status"] == "ROOT_MISMATCH"
    assert report["status"] == "AUDIT_LOG_INTEGRITY_FAILURE"
