"""ZT-F4: Pydantic request/response models of the file module (§14)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.files.schemas import (
    FileCreateIn,
    FileOut,
    FileUpdateIn,
    FileVersionOut,
    GrantCreateIn,
    GrantOut,
    VersionCreateIn,
)

GRANTEE = uuid.uuid4()


def test_create_accepts_known_classification() -> None:
    assert FileCreateIn(classification="RESTRICTED").classification == "RESTRICTED"


@pytest.mark.parametrize("value", ["SECRET", "restricted", "", None])
def test_create_rejects_unknown_classification(value: object) -> None:
    with pytest.raises(ValidationError):
        FileCreateIn(classification=value)


@pytest.mark.parametrize(
    "extra",
    [
        {"owner_id": str(uuid.uuid4())},
        {"sha256": "00" * 32},
        {"storage_key": "0" * 32},
        {"current_version": 7},
        {"audit_chain_index": 1},
    ],
)
def test_server_assigned_fields_cannot_be_supplied(extra: dict) -> None:
    with pytest.raises(ValidationError):
        FileCreateIn(classification="PUBLIC", **extra)


def test_description_bounds() -> None:
    FileCreateIn(classification="PUBLIC", description="x" * 1000)
    for bad in ("x" * 1001, "nul\x00"):
        with pytest.raises(ValidationError):
            FileCreateIn(classification="PUBLIC", description=bad)


def test_update_requires_a_change() -> None:
    with pytest.raises(ValidationError):
        FileUpdateIn()
    with pytest.raises(ValidationError):
        FileUpdateIn(reason="only a reason")


@pytest.mark.parametrize(
    "name", ["../evil.pdf", "a/b.pdf", "x" + chr(0x202E) + "gpj.exe", "CON.txt", "noext"]
)
def test_update_display_name_is_sanitised(name: str) -> None:
    with pytest.raises(ValidationError):
        FileUpdateIn(display_name=name)


def test_update_display_name_normalised_to_nfc() -> None:
    decomposed = "cafe" + chr(0x301) + ".pdf"
    assert FileUpdateIn(display_name=decomposed).display_name == "caf" + chr(0xE9) + ".pdf"


def test_version_create_requires_positive_base_version() -> None:
    assert VersionCreateIn(base_version=3).base_version == 3
    for bad in (0, -1):
        with pytest.raises(ValidationError):
            VersionCreateIn(base_version=bad)


def test_grant_normalises_permissions() -> None:
    grant = GrantCreateIn(grantee_id=GRANTEE, permissions=["DOWNLOAD", "READ", "READ"])
    assert grant.permissions == ["DOWNLOAD", "READ"]


@pytest.mark.parametrize(
    "permissions", [[], ["MANAGE_PERMISSIONS"], ["READ", "CREATE"], ["ROOT"], ["read"]]
)
def test_grant_rejects_empty_unknown_or_escalating_permissions(permissions: list) -> None:
    with pytest.raises(ValidationError):
        GrantCreateIn(grantee_id=GRANTEE, permissions=permissions)


def test_grant_expiry_must_be_aware_and_in_the_future() -> None:
    future = datetime.now(UTC) + timedelta(days=1)
    assert GrantCreateIn(grantee_id=GRANTEE, permissions=["READ"], expires_at=future).expires_at
    for bad in (datetime.now(UTC) - timedelta(seconds=1), datetime.now() + timedelta(days=1)):
        with pytest.raises(ValidationError):
            GrantCreateIn(grantee_id=GRANTEE, permissions=["READ"], expires_at=bad)


def test_responses_never_expose_the_storage_key() -> None:
    for model in (FileOut, FileVersionOut, GrantOut):
        assert not any("storage" in field for field in model.model_fields)
