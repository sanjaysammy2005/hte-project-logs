"""ZT-F7: file-module schema: constraints, relationships, indexes (ZERO_TRUST_FILE_MODULE §5).

Rows are inserted directly (there is no file service yet) to prove that the database itself
rejects malformed state, independent of application code.
"""

import hashlib
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import File, FilePermission, FileVersion, LogStream, Operator
from app.files.schemas import FileOut, GrantOut

SHA = hashlib.sha256(b"content").digest()


@pytest.fixture
def people(make_operator: Callable[..., Operator]) -> dict[str, Operator]:
    return {role: make_operator(f"{role}-1", role) for role in ("admin", "manager", "employee")}


def new_file(owner: Operator, **overrides: Any) -> File:
    values: dict[str, Any] = {
        "display_name": "q3-budget.xlsx",
        "extension": "xlsx",
        "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "classification": "RESTRICTED",
        "owner_id": owner.id,
        "created_by": owner.id,
        "current_version": 1,
    }
    return File(**{**values, **overrides})


def new_version(file: File, uploader: Operator, stream: LogStream, **overrides: Any) -> FileVersion:
    values: dict[str, Any] = {
        "file_id": file.id,
        "version_number": 1,
        "storage_key": uuid.uuid4().hex,
        "sha256": SHA,
        "size_bytes": 7,
        "mime_type": file.mime_type,
        "original_filename": file.display_name,
        "uploaded_by": uploader.id,
        "audit_stream_id": stream.id,
        "audit_chain_index": 1,
    }
    return FileVersion(**{**values, **overrides})


def new_grant(file: File, grantee: Operator, granter: Operator, **overrides: Any) -> FilePermission:
    values: dict[str, Any] = {
        "file_id": file.id,
        "grantee_id": grantee.id,
        "granted_by": granter.id,
        "permissions": ["READ"],
        "audit_stream_id": uuid.uuid4(),
        "audit_chain_index": 5,
    }
    return FilePermission(**{**values, **overrides})


def assert_rejected(db: Session, row: Any) -> None:
    db.add(row)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


@pytest.fixture
def stored_file(db: Session, people: dict[str, Operator], system_stream: LogStream) -> File:
    file = new_file(people["manager"])
    db.add(file)
    db.flush()
    db.add(new_version(file, people["manager"], system_stream))
    db.commit()
    return file


# --- files -------------------------------------------------------------------------------------


def test_file_and_version_round_trip(
    db: Session, stored_file: File, people: dict[str, Operator], system_stream: LogStream
) -> None:
    db.add(new_version(stored_file, people["manager"], system_stream, version_number=2))
    stored_file.current_version = 2
    db.commit()
    db.expire_all()

    file = db.get(File, stored_file.id)
    assert file is not None and [v.version_number for v in file.versions] == [1, 2]
    assert file.origin == "user" and file.deleted_at is None
    out = FileOut.build(file, file.versions[-1])
    assert out.current is not None and out.current.sha256 == SHA.hex()
    assert "storage_key" not in out.model_dump_json()


@pytest.mark.parametrize(
    "overrides",
    [
        {"classification": "SECRET"},
        {"classification": "restricted"},
        {"origin": "imported"},
        {"display_name": ""},
        {"display_name": "x" * 256},
        {"extension": "PDF"},
        {"extension": "../pdf"},
        {"extension": ""},
        {"description": "x" * 1001},
        {"current_version": 0},
        {"deleted_at": datetime.now(UTC)},  # deleted without deleted_by
        {"purged_at": datetime.now(UTC)},  # purged without being deleted
        {"owner_id": uuid.uuid4()},  # owner must be an existing user
        {"created_by": uuid.uuid4()},
    ],
)
def test_malformed_files_rejected(
    db: Session, people: dict[str, Operator], overrides: dict
) -> None:
    assert_rejected(db, new_file(people["manager"], **overrides))


def test_soft_delete_and_purge_states_accepted(db: Session, people: dict[str, Operator]) -> None:
    now = datetime.now(UTC)
    db.add(new_file(people["manager"], deleted_at=now, deleted_by=people["admin"].id))
    db.add(
        new_file(people["manager"], deleted_at=now, deleted_by=people["admin"].id, purged_at=now)
    )
    db.commit()


def test_users_with_files_cannot_be_deleted(db: Session, stored_file: File) -> None:
    with pytest.raises(IntegrityError):
        db.execute(text("DELETE FROM operators WHERE id = :id"), {"id": stored_file.owner_id})
    db.rollback()


# --- versions ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"version_number": 0},
        {"storage_key": "../../etc/passwd"},
        {"storage_key": "A" * 32},
        {"storage_key": "0" * 31},
        {"sha256": SHA[:31]},
        {"sha256": SHA + b"\x00"},
        {"size_bytes": -1},
        {"original_filename": ""},
        {"change_reason": "x" * 501},
        {"version_number": 2, "restored_from_version": 2},  # must restore an earlier version
        {"version_number": 2, "restored_from_version": 0},
        {"audit_chain_index": 0},
        {"last_integrity_status": "PROBABLY_FINE"},
        {"uploaded_by": uuid.uuid4()},
    ],
)
def test_malformed_versions_rejected(
    db: Session,
    stored_file: File,
    people: dict[str, Operator],
    system_stream: LogStream,
    overrides: dict,
) -> None:
    values = {"version_number": 2, **overrides}
    assert_rejected(db, new_version(stored_file, people["manager"], system_stream, **values))


def test_duplicate_version_number_rejected(
    db: Session, stored_file: File, people: dict[str, Operator], system_stream: LogStream
) -> None:
    assert_rejected(db, new_version(stored_file, people["manager"], system_stream))


def test_version_needs_existing_file(
    db: Session, people: dict[str, Operator], system_stream: LogStream
) -> None:
    orphan = new_file(people["manager"])
    orphan.id = uuid.uuid4()  # never inserted
    assert_rejected(db, new_version(orphan, people["manager"], system_stream))


def test_restore_reuses_storage_key_without_conflict(
    db: Session, stored_file: File, people: dict[str, Operator], system_stream: LogStream
) -> None:
    v1 = stored_file.versions[0]
    db.add(
        new_version(
            stored_file,
            people["manager"],
            system_stream,
            version_number=2,
            storage_key=v1.storage_key,
            restored_from_version=1,
        )
    )
    db.commit()


def test_files_with_versions_cannot_be_hard_deleted(db: Session, stored_file: File) -> None:
    with pytest.raises(IntegrityError):
        db.execute(text("DELETE FROM files WHERE id = :id"), {"id": stored_file.id})
    db.rollback()


# --- grants ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"permissions": []},
        {"permissions": ["ROOT"]},
        {"permissions": ["read"]},
        {"permissions": ["READ", "MANAGE_PERMISSIONS"]},  # never grantable
        {"permissions": ["CREATE"]},
        {"reason": "x" * 501},
        {"audit_chain_index": 0},
        {"revoked_at": datetime.now(UTC)},  # revoked without revoked_by
        {"expires_at": datetime.now(UTC) - timedelta(days=1)},  # expires before creation
    ],
)
def test_malformed_grants_rejected(
    db: Session, stored_file: File, people: dict[str, Operator], overrides: dict
) -> None:
    assert_rejected(db, new_grant(stored_file, people["employee"], people["manager"], **overrides))


def test_one_active_grant_per_user_per_file(
    db: Session, stored_file: File, people: dict[str, Operator]
) -> None:
    first = new_grant(stored_file, people["employee"], people["manager"])
    db.add(first)
    db.commit()
    assert_rejected(db, new_grant(stored_file, people["employee"], people["manager"]))

    # Changing a grant = revoke + new grant; the revoked row stays as history.
    first.revoked_at, first.revoked_by = datetime.now(UTC), people["manager"].id
    db.add(
        new_grant(
            stored_file, people["employee"], people["manager"], permissions=["DOWNLOAD", "READ"]
        )
    )
    db.commit()

    rows = db.scalars(select(FilePermission).where(FilePermission.file_id == stored_file.id)).all()
    assert len(rows) == 2 and sum(r.revoked_at is None for r in rows) == 1
    assert {tuple(GrantOut.build(r).permissions) for r in rows} == {("READ",), ("DOWNLOAD", "READ")}


def test_grant_to_unknown_user_rejected(
    db: Session, stored_file: File, people: dict[str, Operator]
) -> None:
    ghost = Operator(id=uuid.uuid4(), username="ghost", password_hash="x", role="employee")
    assert_rejected(db, new_grant(stored_file, ghost, people["manager"]))


# --- operators and indexes ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "ok"),
    [
        ({"role": "manager"}, True),
        ({"role": "employee", "display_name": "Erin Employee", "department": "Finance"}, True),
        ({"role": "superuser"}, False),
        ({"role": "employee", "display_name": ""}, False),
        ({"role": "employee", "department": "x" * 129}, False),
    ],
)
def test_operator_role_and_profile_constraints(db: Session, overrides: dict, ok: bool) -> None:
    row = Operator(username=f"u-{uuid.uuid4().hex[:8]}", password_hash="x", **overrides)
    if ok:
        db.add(row)
        db.commit()
        assert row.updated_at is not None
    else:
        assert_rejected(db, row)


def test_expected_indexes_exist(test_engine: Engine) -> None:
    inspector = inspect(test_engine)
    names = {
        table: {i["name"] for i in inspector.get_indexes(table)}
        for table in ("files", "file_versions", "file_permissions", "audit_events")
    }
    assert {
        "ix_files_owner_id",
        "ix_files_created_by",
        "ix_files_classification",
        "ix_files_created_at",
        "ix_files_updated_at",
        "ix_files_origin",
        "ix_files_deleted_at",
    } <= names["files"]
    assert {"ix_file_versions_uploaded_by", "ix_file_versions_storage_key"} <= names[
        "file_versions"
    ]
    assert {
        "uq_file_permissions_active_grant",
        "ix_file_permissions_file_id",
        "ix_file_permissions_grantee_active",
    } <= names["file_permissions"]
    assert {"ix_audit_events_file_id", "ix_audit_events_type_time"} <= names["audit_events"]


def test_file_history_lookup_uses_payload_index(
    test_engine: Engine, system_stream: LogStream
) -> None:
    """The planner can answer "events about file X" from the expression index."""
    with test_engine.connect() as conn:
        conn.execute(text("SET enable_seqscan = off"))
        plan = (
            conn.execute(
                text(
                    "EXPLAIN SELECT chain_index FROM audit_events"
                    " WHERE stream_id = :s AND (event_payload ->> 'file_id') = :f"
                ),
                {"s": system_stream.id, "f": str(uuid.uuid4())},
            )
            .scalars()
            .all()
        )
    assert any("ix_audit_events_file_id" in line for line in plan)
