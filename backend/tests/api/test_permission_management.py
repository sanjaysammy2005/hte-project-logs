"""ZT-SH: file sharing and permission management (user grants, role grants, history).

Every permission change must be a chained event naming actor, target, file, permissions,
previous and new state, timestamp, session and decision.
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.db.models import LogStream
from app.provenance.rules import load_rules
from app.verification.engine import verify_stream
from tests.api.conftest import Clock, User
from tests.api.file_helpers import API, last_event, system_events, uploaded

pytestmark = pytest.mark.usefixtures("file_storage")


@pytest.fixture
def org(sign_in: Callable[..., User]) -> dict[str, User]:
    return {
        name: sign_in(name, role, department)
        for name, role, department in [
            ("ada", "admin", "IT"),
            ("owner", "employee", "Engineering"),
            ("colleague", "employee", "Engineering"),
            ("finance", "employee", "Finance"),
            ("boss", "manager", "Engineering"),
            ("aud", "auditor", None),
        ]
    }


def share(client, actor: User, file_id: str, permissions: list[str], user: User | None = None,
          role: str | None = None, **extra):  # fmt: skip
    body: dict = {"permissions": permissions, **extra}
    if user is not None:
        body["grantee_id"] = str(user.id)
    if role is not None:
        body["grantee_role"] = role
    return client.post(f"{API}/files/{file_id}/permissions", json=body, headers=actor.headers)


def revoke(client, actor: User, file_id: str, grant_id: str):
    return client.delete(f"{API}/files/{file_id}/permissions/{grant_id}", headers=actor.headers)


def download(client, user: User, file_id: str) -> int:
    return client.get(f"{API}/files/{file_id}/content", headers=user.headers).status_code


def denials(db: Session) -> int:
    return len(system_events(db, "FILE_ACCESS_DENIED"))


# --- granting and revoking (user) ---------------------------------------------------------------


def test_grant_to_user_is_chained_with_full_context(client, db, org) -> None:
    file = uploaded(client, org["owner"], classification="RESTRICTED")
    assert download(client, org["finance"], file["id"]) == 404  # access before permission

    response = share(client, org["owner"], file["id"], ["READ", "DOWNLOAD"], user=org["finance"])

    assert response.status_code == 201
    event = last_event(db, "FILE_SHARED")
    p = event.event_payload
    assert event.actor_user_id == "owner" and event.session_id is not None  # actor, session
    assert event.event_timestamp is not None  # timestamp (hashed context)
    assert p["file_id"] == file["id"] and p["classification"] == "RESTRICTED"
    assert p["grantee"] == {"type": "user", "id": str(org["finance"].id), "username": "finance"}
    assert p["permissions"] == ["DOWNLOAD", "READ"]
    assert p["previous_state"] == {"grant_id": None, "permissions": []}
    assert p["new_state"]["permissions"] == ["DOWNLOAD", "READ"]
    assert p["new_state"]["grant_id"] == response.json()["grant"]["id"]
    assert p["decision"] == "ALLOW" and p["rule"] == "sharing.subset_of_own_permissions"
    assert p["change"] == "GRANT"
    assert download(client, org["finance"], file["id"]) == 200  # explicit user permission


def test_revoke_user_grant_removes_access(client, db, org) -> None:
    file = uploaded(client, org["owner"], classification="RESTRICTED")
    grant_id = share(
        client, org["owner"], file["id"], ["READ", "DOWNLOAD"], user=org["finance"]
    ).json()["grant"]["id"]
    assert download(client, org["finance"], file["id"]) == 200

    response = revoke(client, org["owner"], file["id"], grant_id)

    assert response.status_code == 200
    p = last_event(db, "FILE_SHARE_REVOKED").event_payload
    assert p["grantee"] == {"type": "user", "id": str(org["finance"].id)}
    assert p["previous_state"]["permissions"] == ["DOWNLOAD", "READ"]
    assert p["new_state"] == {"grant_id": None, "permissions": []}
    assert download(client, org["finance"], file["id"]) == 404  # access after revocation


def test_modifying_a_grant_records_previous_state(client, db, org) -> None:
    file = uploaded(client, org["owner"], classification="RESTRICTED")
    first = share(
        client, org["owner"], file["id"], ["READ", "DOWNLOAD"], user=org["finance"]
    ).json()
    second = share(client, org["owner"], file["id"], ["READ"], user=org["finance"])

    assert second.status_code == 201
    p = last_event(db, "FILE_SHARED").event_payload
    assert p["change"] == "MODIFY"
    assert p["previous_state"]["grant_id"] == first["grant"]["id"]
    assert p["previous_state"]["permissions"] == ["DOWNLOAD", "READ"]
    assert p["new_state"]["permissions"] == ["READ"]
    assert download(client, org["finance"], file["id"]) == 403  # reduced: READ only now
    current = client.get(
        f"{API}/files/{file['id']}/permissions", headers=org["owner"].headers
    ).json()
    assert [g["permissions"] for g in current["grants"]] == [["READ"]]


# --- role grants (role-based permission on one file) ---------------------------------------------


def test_admin_grants_a_role_access_to_one_file(client, db, org) -> None:
    file = uploaded(client, org["owner"], classification="RESTRICTED")
    assert download(client, org["finance"], file["id"]) == 404

    response = share(client, org["ada"], file["id"], ["READ", "DOWNLOAD"], role="employee")

    assert response.status_code == 201
    p = last_event(db, "FILE_PERMISSION_GRANTED").event_payload
    assert p["grantee"] == {"type": "role", "role": "employee"}
    assert p["rule"] == "sharing.role_grant_requires_manage_permissions"
    # Every employee, in any department, now reaches this one file; other roles do not.
    assert download(client, org["finance"], file["id"]) == 200
    assert download(client, org["colleague"], file["id"]) == 200
    assert last_event(db, "FILE_DOWNLOAD").event_payload["reason_code"] == "ALLOW_GRANT"
    assert download(client, org["boss"], file["id"]) == 404
    listed = client.get(f"{API}/files", params={"scope": "shared"}, headers=org["finance"].headers)
    assert [f["id"] for f in listed.json()["items"]] == [file["id"]]

    grant_id = response.json()["grant"]["id"]
    assert revoke(client, org["ada"], file["id"], grant_id).status_code == 200
    assert last_event(db, "FILE_PERMISSION_REVOKED").event_payload["grantee"]["role"] == "employee"
    assert download(client, org["finance"], file["id"]) == 404


@pytest.mark.parametrize(
    ("actor", "level", "role", "status", "reason"),
    [
        ("owner", "RESTRICTED", "employee", 403, "GRANT_REQUIRED"),  # owners hold SHARE, not MANAGE
        ("boss", "CONFIDENTIAL", "employee", 403, "NO_PERMISSION"),  # SHARE is not enough
        ("ada", "HIGHLY_RESTRICTED", "employee", 403, "ROLE_GRANT_NOT_ALLOWED"),
        ("ada", "INTERNAL", "ingestor", 403, "GRANTEE_NOT_ELIGIBLE"),
        ("finance", "INTERNAL", "employee", 404, None),  # cannot even see the file
    ],
)
def test_unauthorized_role_grants(client, db, org, actor, level, role, status, reason) -> None:
    owner = "boss" if level == "CONFIDENTIAL" else "owner"
    file = uploaded(client, org[owner], classification=level)
    before = denials(db)
    response = share(client, org[actor], file["id"], ["READ"], role=role, reason="x")
    assert response.status_code == status, response.text
    assert denials(db) == before + 1
    if reason:
        assert last_event(db, "FILE_ACCESS_DENIED").event_payload["reason_code"] == reason
    assert system_events(db, "FILE_PERMISSION_GRANTED") == []


def test_role_grants_are_revoked_only_by_permission_managers(client, db, org) -> None:
    file = uploaded(client, org["owner"], classification="INTERNAL")
    grant_id = share(client, org["ada"], file["id"], ["READ"], role="manager").json()["grant"]["id"]
    before = denials(db)
    assert revoke(client, org["owner"], file["id"], grant_id).status_code == 403  # even the owner
    assert revoke(client, org["boss"], file["id"], grant_id).status_code == 403  # a grantee
    assert denials(db) == before + 2
    assert revoke(client, org["ada"], file["id"], grant_id).status_code == 200


# --- unauthorized grant / revoke, escalation ------------------------------------------------


@pytest.mark.parametrize(
    ("setup", "actor", "permissions", "target", "status", "reason"),
    [
        (None, "colleague", ["READ"], "finance", 403, "NO_PERMISSION"),  # reader, no SHARE
        (None, "aud", ["READ"], "finance", 403, "NO_PERMISSION"),
        (["READ", "SHARE"], "finance", ["READ", "DOWNLOAD"], "colleague", 403, "SHARE_ESCALATION"),
        (["READ", "SHARE"], "finance", ["READ", "UPDATE"], "colleague", 403, "SHARE_ESCALATION"),
        (["READ", "SHARE"], "finance", ["READ", "DOWNLOAD"], "finance", 403, "SELF_GRANT"),
        (["READ", "DOWNLOAD"], "finance", ["READ"], "colleague", 403, "NO_PERMISSION"),
    ],
)
def test_unauthorized_grants_and_escalation(
    client, db, org, setup, actor, permissions, target, status, reason
) -> None:  # noqa: E501
    file = uploaded(client, org["owner"], classification="INTERNAL")
    if setup:
        assert (
            share(client, org["owner"], file["id"], setup, user=org["finance"]).status_code == 201
        )
    before = denials(db)
    response = share(client, org[actor], file["id"], permissions, user=org[target])
    assert response.status_code == status, response.text
    assert denials(db) == before + 1
    assert last_event(db, "FILE_ACCESS_DENIED").event_payload["reason_code"] == reason


def test_grantee_cannot_raise_their_own_grant(client, db, org) -> None:
    """Re-sharing to oneself to swap READ+SHARE for READ+SHARE+DOWNLOAD must fail."""
    file = uploaded(client, org["owner"], classification="RESTRICTED")
    share(client, org["owner"], file["id"], ["READ", "SHARE"], user=org["finance"])
    response = share(
        client, org["finance"], file["id"], ["READ", "SHARE", "DOWNLOAD"], user=org["finance"]
    )
    assert response.status_code == 403
    reasons = response.json()["error"]["details"]["reasons"]
    assert {"SELF_GRANT", "SHARE_ESCALATION"} <= set(reasons)
    assert download(client, org["finance"], file["id"]) == 403


@pytest.mark.parametrize(
    "permissions", [["MANAGE_PERMISSIONS"], ["CREATE"], ["READ", "MANAGE_PERMISSIONS"]]
)
def test_never_grantable_permissions(client, org, permissions) -> None:
    file = uploaded(client, org["owner"], classification="INTERNAL")
    for kwargs in ({"user": org["finance"]}, {"role": "employee"}):
        assert share(client, org["ada"], file["id"], permissions, **kwargs).status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        {"permissions": ["READ"]},
        {
            "permissions": ["READ"],
            "grantee_role": "employee",
            "grantee_id": "00000000-0000-0000-0000-000000000001",
        },
    ],
)  # noqa: E501
def test_grant_needs_exactly_one_target(client, org, body) -> None:
    file = uploaded(client, org["owner"])
    response = client.post(
        f"{API}/files/{file['id']}/permissions", json=body, headers=org["owner"].headers
    )
    assert response.status_code == 422


def test_unauthorized_revoke(client, db, org) -> None:
    file = uploaded(client, org["owner"], classification="INTERNAL")
    grant_id = share(client, org["owner"], file["id"], ["READ"], user=org["finance"]).json()[
        "grant"
    ]["id"]
    before = denials(db)
    assert revoke(client, org["colleague"], file["id"], grant_id).status_code == 403  # not grantor
    assert revoke(client, org["finance"], file["id"], grant_id).status_code == 403  # the grantee
    assert revoke(client, org["aud"], file["id"], grant_id).status_code == 403
    assert denials(db) == before + 3
    assert system_events(db, "FILE_SHARE_REVOKED") == []


# --- conflicting permissions ---------------------------------------------------------------------


def test_role_and_user_grants_add_up(client, db, org) -> None:
    file = uploaded(client, org["owner"], classification="RESTRICTED")
    role_grant = share(client, org["ada"], file["id"], ["READ"], role="employee").json()["grant"][
        "id"
    ]
    user_grant = share(
        client, org["owner"], file["id"], ["READ", "DOWNLOAD"], user=org["finance"]
    ).json()["grant"]["id"]

    assert download(client, org["finance"], file["id"]) == 200  # READ (role) ∪ DOWNLOAD (user)
    assert download(client, org["colleague"], file["id"]) == 403  # role grant only: READ

    revoke(client, org["owner"], file["id"], user_grant)
    assert download(client, org["finance"], file["id"]) == 403  # the role grant still gives READ
    assert (
        client.get(f"{API}/files/{file['id']}", headers=org["finance"].headers).status_code == 200
    )

    revoke(client, org["ada"], file["id"], role_grant)
    assert (
        client.get(f"{API}/files/{file['id']}", headers=org["finance"].headers).status_code == 404
    )


def test_role_grant_overrides_missing_department_but_not_requirements(
    client, db, org, clock: Clock
) -> None:  # noqa: E501
    """Grants only add permissions; lifecycle and context rules still win."""
    file = uploaded(client, org["owner"], classification="RESTRICTED")
    share(client, org["owner"], file["id"], ["READ", "DOWNLOAD"], user=org["finance"])
    clock.offset = timedelta(minutes=61)  # RESTRICTED: session at most 60 minutes
    response = client.get(f"{API}/files/{file['id']}/content", headers=org["finance"].headers)
    assert response.status_code == 403
    assert response.json()["error"]["details"]["reason_code"] == "SESSION_TOO_OLD"
    clock.offset = timedelta(0)
    client.delete(f"{API}/files/{file['id']}", headers=org["owner"].headers)
    assert download(client, org["finance"], file["id"]) == 404  # trashed: grantees lose sight


def test_expired_user_grant_falls_back_to_role_grant(client, db, org, clock: Clock) -> None:
    file = uploaded(client, org["owner"], classification="INTERNAL")
    soon = (datetime.now(UTC) + timedelta(minutes=5)).isoformat()
    share(
        client, org["owner"], file["id"], ["READ", "DOWNLOAD"], user=org["finance"], expires_at=soon
    )
    share(client, org["ada"], file["id"], ["READ"], role="employee")
    assert download(client, org["finance"], file["id"]) == 200
    clock.offset = timedelta(minutes=10)
    assert download(client, org["finance"], file["id"]) == 403  # only the role grant's READ left


def test_role_policy_and_explicit_grants_compared(client, db, org) -> None:
    """Role-based (policy) access vs explicit permission on the same INTERNAL file."""
    file = uploaded(client, org["owner"], classification="INTERNAL")
    assert download(client, org["colleague"], file["id"]) == 200  # role, same department
    assert download(client, org["finance"], file["id"]) == 404  # role, other department
    share(client, org["owner"], file["id"], ["READ", "DOWNLOAD"], user=org["finance"])
    assert download(client, org["finance"], file["id"]) == 200  # explicit grant
    assert last_event(db, "FILE_DOWNLOAD").event_payload["reason_code"] == "ALLOW_GRANT"


# --- views and history -------------------------------------------------------------------------


def test_permission_history(client, db, org, system_stream: LogStream) -> None:
    file = uploaded(client, org["owner"], classification="INTERNAL")
    first = share(client, org["owner"], file["id"], ["READ"], user=org["finance"]).json()["grant"]
    second = share(
        client, org["owner"], file["id"], ["READ", "DOWNLOAD"], user=org["finance"]
    ).json()["grant"]
    role = share(client, org["ada"], file["id"], ["READ"], role="manager").json()["grant"]
    revoke(client, org["ada"], file["id"], role["id"])

    url = f"{API}/files/{file['id']}/permissions"
    history = client.get(f"{url}/history", headers=org["owner"].headers).json()["grants"]
    assert [g["id"] for g in history] == [first["id"], second["id"], role["id"]]
    superseded, current, revoked = history
    assert superseded["revoked_audit_chain_index"] == second["audit_chain_index"]
    assert current["revoked_at"] is None
    assert revoked["grantee_role"] == "manager" and revoked["revoked_audit_chain_index"] is not None
    active = client.get(url, headers=org["owner"].headers).json()["grants"]
    assert [g["id"] for g in active] == [second["id"]]  # current view: active grants only

    assert client.get(f"{url}/history", headers=org["ada"].headers).status_code == 200  # manager
    before = denials(db)
    assert client.get(f"{url}/history", headers=org["finance"].headers).status_code == 403
    assert client.get(f"{url}/history", headers=org["colleague"].headers).status_code == 403
    assert denials(db) == before + 2

    run, report = verify_stream(db, system_stream, load_rules())
    db.rollback()
    assert run.status == "VALID", report.findings[:3]


def test_access_policy_changes_are_chained(client, db, org) -> None:
    file = uploaded(client, org["owner"], classification="INTERNAL")
    client.patch(
        f"{API}/files/{file['id']}",
        json={"classification": "RESTRICTED"},
        headers=org["owner"].headers,
    )
    p = last_event(db, "FILE_ACCESS_POLICY_CHANGED").event_payload
    assert (p["previous_state"], p["new_state"]) == (
        {"classification": "INTERNAL"},
        {"classification": "RESTRICTED"},
    )
    client.put(
        f"{API}/files/{file['id']}/owner",
        json={"owner_id": str(org["colleague"].id), "reason": "handover"},
        headers=org["ada"].headers,
    )  # noqa: E501
    p = last_event(db, "FILE_ACCESS_POLICY_CHANGED").event_payload
    assert p["previous_state"] == {"owner_id": str(org["owner"].id)}
    assert p["new_state"] == {"owner_id": str(org["colleague"].id)}
