"""ZT5 + context: file integrity layers, tampering, missing objects, step-up and session rules.

Tampering is done the way an attacker with disk/DB access would: by editing blobs on disk and
rows with SQL, never through the API. The isolated test database and a per-test storage root
are used; nothing outside them is touched.
"""

import hashlib
import io
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.access.audit import Actor
from app.access.model import Role
from app.api.deps import get_policy
from app.core.config import get_settings
from app.core.errors import APIError
from app.crypto.chain import compute_entry_hash
from app.db.models import ROLES, AuditEvent, FileVersion, LogStream, Operator
from app.files.schemas import FileCreateIn, VersionCreateIn
from app.files.service import FileService
from app.files.storage import LocalFileStorage
from app.ingestion.service import to_chained
from app.lab.generator import WorkloadSpec, generate_workload
from app.provenance.rules import V1_RULES_PATH, load_rules
from app.verification.engine import verify_stream
from tests.api.conftest import Clock, User
from tests.api.file_helpers import API, blob_path, last_event, system_events, uploaded
from tests.file_samples import PDF

pytestmark = pytest.mark.usefixtures("file_storage")


@pytest.fixture
def owner(sign_in: Callable[..., User]) -> User:
    return sign_in("olivia", "employee")


@pytest.fixture
def doc(client: TestClient, owner: User) -> dict:
    return uploaded(client, owner, name="contract.pdf", classification="INTERNAL")


def verify(client: TestClient, user: User, file_id: str, **params) -> dict:
    response = client.post(f"{API}/files/{file_id}/integrity", params=params, headers=user.headers)
    assert response.status_code == 200, response.text
    return response.json()


# --- integrity success -------------------------------------------------------------------------


def test_integrity_success(client: TestClient, db: Session, owner: User, doc: dict) -> None:
    report = verify(client, owner, doc["id"])

    assert report["status"] == "INTACT"
    (v1,) = report["versions"]
    assert (v1["content"], v1["anchor"], v1["evidence"]) == ("OK", "OK", "OK")
    assert v1["expected_sha256"] == v1["actual_sha256"] == doc["current"]["sha256"]
    event = last_event(db, "FILE_INTEGRITY_CHECK")
    assert report["audit"]["chain_index"] == event.chain_index
    assert event.event_payload["status"] == "INTACT"
    db.expire_all()
    stored = db.scalars(select(FileVersion)).one()
    assert stored.last_integrity_status == "INTACT" and stored.last_verified_at is not None


def test_integrity_after_batch_sealing_checks_merkle_proof(
    client: TestClient, db: Session, owner: User, system_stream: LogStream
) -> None:
    """Upload enough events that the anchor ends up in a sealed batch (batch size 64)."""
    file = uploaded(client, owner)
    for _ in range(70):
        client.get(f"{API}/files/{file['id']}/content", headers=owner.headers)
    report = verify(client, owner, file["id"])
    assert report["status"] == "INTACT"
    anchor = report["versions"][0]["anchor_chain_index"]
    sealed = db.execute(
        text(
            "SELECT 1 FROM batches WHERE stream_id = :s"
            " AND :i BETWEEN first_chain_index AND last_chain_index"
        ),
        {"s": system_stream.id, "i": anchor},
    ).first()
    assert sealed is not None


def test_auditor_verifies_without_reading(client: TestClient, sign_in, owner: User) -> None:
    file = uploaded(client, owner, classification="RESTRICTED")
    auditor = sign_in("aria", "auditor")

    assert verify(client, auditor, file["id"])["status"] == "INTACT"
    assert (
        client.get(f"{API}/files/{file['id']}/content", headers=auditor.headers).status_code == 403
    )


def test_verify_requires_permission(client: TestClient, sign_in, owner: User, doc: dict) -> None:
    stranger = sign_in("sam", "employee")  # can read INTERNAL files, but has no VERIFY
    response = client.post(f"{API}/files/{doc['id']}/integrity", headers=stranger.headers)
    assert response.status_code == 403
    assert response.json()["error"]["details"]["required_permission"] == "VERIFY"


# --- integrity failure: L1 content ---------------------------------------------------------------


def test_modified_blob_is_detected_and_never_served(
    client: TestClient, db: Session, owner: User, doc: dict, file_storage: LocalFileStorage
) -> None:
    blob_path(file_storage, db, doc["id"]).write_bytes(PDF.replace(b"1.7", b"1.4"))  # same size

    download = client.get(f"{API}/files/{doc['id']}/content", headers=owner.headers)
    assert download.status_code == 409
    error = download.json()["error"]
    assert error["code"] == "INTEGRITY_FAILURE" and error["details"]["status"] == "CONTENT_MISMATCH"
    assert b"%PDF" not in download.content  # the tampered bytes were not sent
    failure = last_event(db, "FILE_INTEGRITY_FAILURE")
    assert failure.event_payload["trigger"] == "DOWNLOAD"
    assert error["details"]["audit"]["chain_index"] == failure.chain_index
    assert system_events(db, "FILE_DOWNLOAD") == []

    report = verify(client, owner, doc["id"])
    assert report["status"] == "CONTENT_MISMATCH"
    assert report["versions"][0]["actual_sha256"] != report["versions"][0]["expected_sha256"]
    assert last_event(db).event_type == "FILE_INTEGRITY_FAILURE"


def test_truncated_or_inflated_blob_detected(
    client: TestClient, db: Session, owner: User, doc: dict, file_storage: LocalFileStorage
) -> None:
    path = blob_path(file_storage, db, doc["id"])
    for content in (PDF[:-1], PDF + b"\x00" * 10_000_000):
        path.write_bytes(content)
        assert verify(client, owner, doc["id"])["status"] == "CONTENT_MISMATCH"


def test_missing_storage_object(
    client: TestClient, db: Session, owner: User, doc: dict, file_storage: LocalFileStorage
) -> None:
    blob_path(file_storage, db, doc["id"]).unlink()

    download = client.get(f"{API}/files/{doc['id']}/content", headers=owner.headers)
    assert download.status_code == 409
    assert download.json()["error"]["details"]["status"] == "BLOB_MISSING"
    report = verify(client, owner, doc["id"])
    assert report["status"] == "BLOB_MISSING" and report["versions"][0]["actual_sha256"] is None


def test_restore_refuses_a_corrupted_version(
    client: TestClient, db: Session, owner: User, doc: dict, file_storage: LocalFileStorage
) -> None:
    client.post(
        f"{API}/files/{doc['id']}/versions",
        files={"file": ("v2.pdf", PDF + b"%2\n", "application/pdf")},
        data={"base_version": "1"},
        headers=owner.headers,
    )
    blob_path(file_storage, db, doc["id"], version=1).write_bytes(b"%PDF-evil")
    response = client.post(
        f"{API}/files/{doc['id']}/versions/1/restore",
        json={"base_version": 2},
        headers=owner.headers,
    )
    assert response.status_code == 409 and response.json()["error"]["code"] == "INTEGRITY_FAILURE"
    assert last_event(db, "FILE_INTEGRITY_FAILURE").event_payload["trigger"] == "RESTORE"
    assert system_events(db, "FILE_VERSION_RESTORED") == []


# --- integrity failure: L2 anchor and L3 evidence ------------------------------------------------


def _tamper_db_hash(db: Session, file_id: str, new_bytes: bytes) -> None:
    db.execute(
        text("UPDATE file_versions SET sha256 = :h, size_bytes = :n WHERE file_id = :f"),
        {"h": hashlib.sha256(new_bytes).digest(), "n": len(new_bytes), "f": file_id},
    )
    db.commit()


def test_blob_and_metadata_replaced_together_detected_by_chain_anchor(
    client: TestClient, db: Session, owner: User, doc: dict, file_storage: LocalFileStorage
) -> None:
    """An attacker swaps the content AND fixes the stored hash: L1 passes, L2 catches it."""
    forged = PDF.replace(b"%%EOF", b"% forged\n%%EOF")
    blob_path(file_storage, db, doc["id"]).write_bytes(forged)
    _tamper_db_hash(db, doc["id"], forged)

    assert client.get(f"{API}/files/{doc['id']}/content", headers=owner.headers).content == forged
    report = verify(client, owner, doc["id"])
    v = report["versions"][0]
    assert report["status"] == "METADATA_MISMATCH"
    assert (v["content"], v["anchor"], v["evidence"]) == ("OK", "METADATA_MISMATCH", "OK")


def test_anchor_event_edited_detected(
    client: TestClient,
    db: Session,
    owner: User,
    doc: dict,
    file_storage: LocalFileStorage,
    system_stream: LogStream,
) -> None:
    """...and if the attacker also edits the anchoring event, L3 and stream verification fire."""
    forged = PDF.replace(b"%%EOF", b"% forged\n%%EOF")
    blob_path(file_storage, db, doc["id"]).write_bytes(forged)
    _tamper_db_hash(db, doc["id"], forged)
    anchor = doc["current"]["audit_chain_index"]
    db.execute(
        text(
            "UPDATE audit_events SET event_payload ="
            " jsonb_set(event_payload, '{sha256}', to_jsonb(CAST(:h AS text)))"
            " WHERE stream_id = :s AND chain_index = :i"
        ),
        {"h": hashlib.sha256(forged).hexdigest(), "s": system_stream.id, "i": anchor},
    )
    db.commit()

    v = verify(client, owner, doc["id"])["versions"][0]
    assert (v["content"], v["anchor"], v["evidence"]) == ("OK", "OK", "ANCHOR_TAMPERED")
    run, report = verify_stream(db, system_stream, load_rules())
    db.rollback()
    assert run.status == "TAMPERING_DETECTED"
    assert report.first_failure.chain_index == anchor and report.first_failure.check == "CHAIN_HASH"


def test_missing_anchor_detected(client: TestClient, db: Session, owner: User, doc: dict) -> None:
    db.execute(text("UPDATE file_versions SET audit_chain_index = 999999"))
    db.commit()
    assert verify(client, owner, doc["id"])["versions"][0]["anchor"] == "ANCHOR_MISSING"


def test_specific_version_check(client: TestClient, owner: User, doc: dict) -> None:
    assert verify(client, owner, doc["id"], version=1)["versions"][0]["version"] == 1
    missing = client.post(
        f"{API}/files/{doc['id']}/integrity", params={"version": 5}, headers=owner.headers
    )
    assert missing.status_code == 404


# --- context: session age, step-up, bursts, rate limits -------------------------------------------


def test_session_too_old_for_restricted(client: TestClient, owner: User, clock: Clock) -> None:
    file = uploaded(client, owner, classification="RESTRICTED")
    url = f"{API}/files/{file['id']}/content"
    assert client.get(url, headers=owner.headers).status_code == 200

    clock.offset = timedelta(minutes=61)
    response = client.get(url, headers=owner.headers)
    assert response.status_code == 403
    assert response.json()["error"]["details"]["reason_code"] == "SESSION_TOO_OLD"
    # Lower classifications are not affected.
    internal = uploaded(client, owner, classification="INTERNAL")
    assert (
        client.get(f"{API}/files/{internal['id']}/content", headers=owner.headers).status_code
        == 200
    )


def test_step_up_reauthentication_for_highly_restricted(
    client: TestClient, db: Session, owner: User, clock: Clock
) -> None:
    file = uploaded(client, owner, classification="HIGHLY_RESTRICTED")
    url = f"{API}/files/{file['id']}/content"
    assert client.get(url, headers=owner.headers).status_code == 200  # just authenticated

    clock.offset = timedelta(minutes=11)
    stale = client.get(url, headers=owner.headers)
    assert stale.status_code == 403
    error = stale.json()["error"]
    assert error["code"] == "STEP_UP_REQUIRED" and error["details"]["step_up_minutes"] == 10

    wrong = client.post(
        f"{API}/auth/reauthenticate", json={"password": "nope"}, headers=owner.headers
    )
    assert wrong.status_code == 403 and wrong.json()["error"]["code"] == "REAUTHENTICATION_FAILED"
    assert client.get(url, headers=owner.headers).status_code == 403

    # Re-authenticating restarts the step-up window (timestamped by the same clock as the policy).
    ok = client.post(
        f"{API}/auth/reauthenticate", json={"password": owner.password}, headers=owner.headers
    )
    assert ok.status_code == 200
    assert client.get(url, headers=owner.headers).status_code == 200
    kinds = [e.event_type for e in system_events(db) if e.actor_user_id == "olivia"]
    assert "REAUTHENTICATION_FAILED" in kinds and "REAUTHENTICATION" in kinds


def test_denial_burst_pauses_sensitive_access(client: TestClient, sign_in, owner: User) -> None:
    manager = sign_in("mia", "manager")
    target = uploaded(client, manager, classification="CONFIDENTIAL")
    probe = uploaded(client, owner, classification="INTERNAL")
    url = f"{API}/files/{target['id']}/content"
    assert client.get(url, headers=manager.headers).status_code == 200

    for _ in range(5):  # five denied attempts (e.g. probing deletes on someone else's file)
        assert (
            client.delete(f"{API}/files/{probe['id']}", headers=manager.headers).status_code == 403
        )
    blocked = client.get(url, headers=manager.headers)
    assert blocked.status_code == 403
    assert blocked.json()["error"]["details"]["reason_code"] == "DENIAL_BURST"


def test_download_rate_limit(client: TestClient, owner: User) -> None:
    file = uploaded(client, owner, classification="HIGHLY_RESTRICTED")
    url = f"{API}/files/{file['id']}/content"
    statuses = [client.get(url, headers=owner.headers).status_code for _ in range(6)]
    assert statuses == [200] * 5 + [403]


# --- audit pipeline edge cases -----------------------------------------------------------------


def test_operation_aborted_when_audit_event_is_rejected(
    db: Session, owner: User, file_storage: LocalFileStorage, client: TestClient
) -> None:
    """If the session closed between authentication and the audit append (race with logout),
    the provenance policy rejects the event: nothing is stored, the attempt is recorded."""
    client.post(f"{API}/auth/logout", headers=owner.headers)
    operator = db.get(Operator, owner.id)
    session_id = last_event(db, "LOGOUT").session_id
    actor = Actor(operator, session_id, "127.0.0.1", uuid.uuid4().hex)
    service = FileService(
        db,
        file_storage,
        get_settings(),
        get_policy(),
        load_rules(),
        actor,
        lambda: datetime.now(UTC),
    )
    meta = FileCreateIn(classification="PUBLIC")
    with pytest.raises(APIError) as error:
        service.upload("late.pdf", io.BytesIO(PDF), len(PDF), meta)

    assert error.value.code == "AUDIT_REJECTED"
    assert last_event(db).event_type == "SECURITY_VIOLATION"
    assert db.scalars(select(FileVersion)).all() == []
    assert [p for p in file_storage.root.rglob("*") if p.is_file()] == []  # blob discarded


def test_generator_output_unchanged_by_v2_rules(db: Session) -> None:
    """Pinning: the same seed gives the same synthetic events whether v1 or v2 verifies them."""

    def events(name: str, rules) -> list[tuple]:
        spec = WorkloadSpec(name, users=3, sessions_per_user=2, events_per_session=6, seed=7)
        stream = generate_workload(db, spec, rules)
        return [
            (e.event_type, e.actor_user_id, e.session_id, e.event_payload, bytes(e.entry_hash))
            for e in db.scalars(
                select(AuditEvent)
                .where(AuditEvent.stream_id == stream.id)
                .order_by(AuditEvent.chain_index)
            )
        ]

    assert events("w-v2", load_rules()) == events("w-v1", load_rules(V1_RULES_PATH))


def test_role_enum_matches_database_roles() -> None:
    assert ROLES == tuple(r.value for r in Role)


def _rehash_anchor(db: Session, stream: LogStream, chain_index: int, sha256_hex: str) -> None:
    """Attacker A1: edit the anchoring event's payload and recompute its own entry hash."""
    row = db.scalars(
        select(AuditEvent).where(
            AuditEvent.stream_id == stream.id, AuditEvent.chain_index == chain_index
        )
    ).one()
    row.event_payload = {**row.event_payload, "sha256": sha256_hex}
    row.entry_hash = compute_entry_hash(to_chained(row).record, bytes(row.prev_hash))
    db.commit()


def test_anchor_rehashed_by_attacker_detected_by_successor_link(
    client: TestClient,
    db: Session,
    owner: User,
    doc: dict,
    file_storage: LocalFileStorage,
    system_stream: LogStream,
) -> None:
    """A1 on an unsealed anchor: its own hash is consistent again, but the next record's link
    is not (the paper's chain property)."""
    # Any later chained event (a download here) gives the anchor a successor.
    assert client.get(f"{API}/files/{doc['id']}/content", headers=owner.headers).status_code == 200
    forged = PDF.replace(b"%%EOF", b"% forged\n%%EOF")
    blob_path(file_storage, db, doc["id"]).write_bytes(forged)
    _tamper_db_hash(db, doc["id"], forged)
    _rehash_anchor(
        db, system_stream, doc["current"]["audit_chain_index"], hashlib.sha256(forged).hexdigest()
    )

    v = verify(client, owner, doc["id"])["versions"][0]
    assert (v["content"], v["anchor"], v["evidence"]) == ("OK", "OK", "ANCHOR_TAMPERED")


def test_negative_control_rehashed_newest_anchor_is_not_detected(
    client: TestClient,
    db: Session,
    owner: User,
    file_storage: LocalFileStorage,
    system_stream: LogStream,
) -> None:
    """Honest limitation (SECURITY_LIMITATIONS §4, tail truncation / paper §IX-B): if the
    anchoring event is the newest record and not yet sealed, an attacker who rewrites blob,
    stored hash and the event (recomputing its hash) leaves nothing inconsistent to find."""
    doc = uploaded(client, owner, name="tail.pdf")
    forged = PDF.replace(b"%%EOF", b"% forged\n%%EOF")
    blob_path(file_storage, db, doc["id"]).write_bytes(forged)
    _tamper_db_hash(db, doc["id"], forged)
    _rehash_anchor(
        db, system_stream, doc["current"]["audit_chain_index"], hashlib.sha256(forged).hexdigest()
    )

    assert verify(client, owner, doc["id"])["status"] == "INTACT"  # expected: NOT detected
    run, _ = verify_stream(db, system_stream, load_rules())
    db.rollback()
    assert run.status == "VALID"


class _BrokenStorage(LocalFileStorage):
    def put(self, source, max_bytes):  # noqa: ANN001
        raise PermissionError("read-only volume")


def test_storage_unavailable_returns_503_and_stores_nothing(
    client: TestClient, db: Session, owner: User, tmp_path_factory: pytest.TempPathFactory
) -> None:
    from app.api.deps import get_storage
    from app.main import app

    app.dependency_overrides[get_storage] = lambda: _BrokenStorage(tmp_path_factory.mktemp("ro"))
    response = client.post(
        f"{API}/files",
        files={"file": ("a.pdf", PDF, "application/pdf")},
        data={"classification": "PUBLIC"},
        headers=owner.headers,
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "STORAGE_UNAVAILABLE"
    assert db.scalars(select(FileVersion)).all() == []
    assert system_events(db, "FILE_UPLOAD") == []


def test_rejected_version_audit_discards_new_blob(
    client: TestClient, db: Session, owner: User, doc: dict, file_storage: LocalFileStorage
) -> None:
    client.post(f"{API}/auth/logout", headers=owner.headers)
    session_id = last_event(db, "LOGOUT").session_id
    actor = Actor(db.get(Operator, owner.id), session_id, None, uuid.uuid4().hex)
    service = FileService(
        db,
        file_storage,
        get_settings(),
        get_policy(),
        load_rules(),
        actor,
        lambda: datetime.now(UTC),
    )
    with pytest.raises(APIError) as error:
        service.new_version(
            uuid.UUID(doc["id"]), "v2.pdf", io.BytesIO(PDF + b"%2\n"), len(PDF) + 3,
            VersionCreateIn(base_version=1),
        )  # fmt: skip
    assert error.value.code == "AUDIT_REJECTED"
    db.expire_all()
    assert [v.version_number for v in db.scalars(select(FileVersion))] == [1]
    assert len([p for p in file_storage.root.rglob("*") if p.is_file()]) == 1  # only version 1
