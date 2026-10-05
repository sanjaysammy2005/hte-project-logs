"""ZT-AC: Zero-Trust authorization through the API (ZERO_TRUST_FILE_MODULE §9).

Every request here is a direct API call, exactly what a client bypassing the dashboard can
send. Each denial must be refused server-side AND leave a chained audit event naming the rule.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.access.audit import Actor
from app.access.enforcer import PolicyEnforcer
from app.access.policy import is_discoverable
from app.api.deps import get_policy
from app.core.config import get_settings
from app.db.models import File, FilePermission, LogStream, Operator
from app.provenance.rules import load_rules
from app.verification.engine import verify_stream
from tests.api.conftest import Clock, User
from tests.api.file_helpers import API, last_event, new_version, system_events, uploaded
from tests.file_samples import PDF

pytestmark = pytest.mark.usefixtures("file_storage")


@pytest.fixture
def org(sign_in: Callable[..., User]) -> dict[str, User]:
    """Two departments, every role, and one employee without a department."""
    return {
        name: sign_in(name, role, department)
        for name, role, department in [
            ("ada", "admin", "IT"),
            ("aud", "auditor", None),
            ("eng_mgr", "manager", "Engineering"),
            ("eng_1", "employee", "Engineering"),
            ("eng_2", "employee", "Engineering"),
            ("fin_mgr", "manager", "Finance"),
            ("fin_1", "employee", "Finance"),
            ("nodept", "employee", None),
            ("ivan", "ingestor", None),
        ]
    }


def denials(db: Session) -> list:
    return system_events(db, "FILE_ACCESS_DENIED")


def assert_denied(response, db: Session, before: int, status: int = 403, reason: str | None = None):
    """Refused, and exactly one chained FILE_ACCESS_DENIED naming a rule was added."""
    assert response.status_code == status, response.text
    events = denials(db)
    assert len(events) == before + 1, "the denial was not chained"
    payload = events[-1].event_payload
    assert payload["decision"] == "DENY" and payload["rule"] and payload["policy"]
    if reason:
        assert payload["reason_code"] == reason
    if status == 403:
        details = response.json()["error"]["details"]
        assert details["rule"] == payload["rule"] and details["policy"] == payload["policy"]
        assert details["audit"]["chain_index"] == events[-1].chain_index
    return payload


def get(client, user, path, **params):
    return client.get(f"{API}/files/{path}", params=params, headers=user.headers)


# --- authenticated + permitted / denied ----------------------------------------------------------


def test_authenticated_and_permitted(client: TestClient, db: Session, org) -> None:
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    response = get(client, org["eng_2"], f"{file['id']}/content")

    assert response.status_code == 200
    allow = last_event(db, "FILE_DOWNLOAD").event_payload
    assert allow["decision"] == "ALLOW" and allow["reason_code"] == "ALLOW_ROLE"
    assert allow["rule"] == "roles.employee.by_classification[INTERNAL] (same department)"
    assert allow["policy"].startswith("access-policy.v1 sha256:")


@pytest.mark.parametrize("who", ["fin_1", "fin_mgr", "nodept"])
def test_employee_does_not_reach_every_internal_file(client, db, org, who) -> None:
    """Being an employee (or manager) of the organisation is not enough for INTERNAL files."""
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    before = len(denials(db))
    payload = assert_denied(get(client, org[who], f"{file['id']}/content"), db, before, 404)
    assert payload["reason_code"] in {"DEPARTMENT_MISMATCH", "NO_PERMISSION"}
    listed = client.get(f"{API}/files", headers=org[who].headers).json()["items"]
    assert file["id"] not in {f["id"] for f in listed}


def test_employee_does_not_reach_confidential_even_in_own_department(client, db, org) -> None:
    file = uploaded(client, org["eng_mgr"], classification="CONFIDENTIAL")
    before = len(denials(db))
    assert_denied(
        get(client, org["eng_1"], f"{file['id']}/content"), db, before, 404, "NO_PERMISSION"
    )
    assert get(client, org["eng_mgr"], f"{file['id']}/content").status_code == 200  # owner
    other_mgr = get(client, org["fin_mgr"], f"{file['id']}/content")
    assert other_mgr.status_code == 404  # managers are department-scoped too


def test_cross_department_denial_is_explained_when_discoverable(client, db, org) -> None:
    """With a READ grant the Finance employee can see the file, so the denial explains itself."""
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    share = client.post(
        f"{API}/files/{file['id']}/permissions",
        json={"grantee_id": str(org["fin_1"].id), "permissions": ["READ"]},
        headers=org["eng_1"].headers,
    )
    assert share.status_code == 201
    before = len(denials(db))
    response = get(client, org["fin_1"], f"{file['id']}/content")
    # Her role would grant DOWNLOAD inside her own department: the department is what fails.
    payload = assert_denied(response, db, before, 403, "DEPARTMENT_MISMATCH")
    assert payload["rule"] == "roles.employee.department_scoped[INTERNAL]"
    assert payload["signals"]["same_department"] is False
    assert response.json()["error"]["details"]["your_permissions"] == ["READ"]


# --- wrong role / missing permission / wrong owner -----------------------------------------------


@pytest.mark.parametrize(
    ("who", "status", "reason"),
    [("aud", 403, "NO_PERMISSION"), ("ivan", 404, "ROLE_NOT_PERMITTED")],
)
def test_wrong_role(client, db, org, who, status, reason) -> None:
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    before = len(denials(db))
    assert_denied(get(client, org[who], f"{file['id']}/content"), db, before, status, reason)


def test_ingestor_cannot_use_any_file_endpoint(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="PUBLIC")
    h, fid = org["ivan"].headers, file["id"]
    grant_body = {"grantee_id": str(org["eng_2"].id), "permissions": ["READ"]}
    calls = [
        ("post", f"{API}/files", None),
        ("get", f"{API}/files/{fid}", None),
        ("get", f"{API}/files/{fid}/content", None),
        ("patch", f"{API}/files/{fid}", {"display_name": "x.pdf"}),
        ("delete", f"{API}/files/{fid}", None),
        ("post", f"{API}/files/{fid}/integrity", None),
        ("get", f"{API}/files/{fid}/permissions", None),
        ("post", f"{API}/files/{fid}/permissions", grant_body),
    ]  # fmt: skip
    for method, url, body in calls:
        kwargs = {"json": body} if body else {}
        if url.endswith("/files"):
            kwargs = {"files": {"file": ("a.pdf", PDF)}, "data": {"classification": "PUBLIC"}}
        assert client.request(method, url, headers=h, **kwargs).status_code in (403, 404), url
    assert client.get(f"{API}/files", headers=h).json()["items"] == []


def test_missing_permission(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    db.add(
        FilePermission(
            file_id=uuid.UUID(file["id"]), grantee_id=org["eng_2"].id, granted_by=org["eng_1"].id,
            permissions=["READ"], audit_stream_id=uuid.uuid4(), audit_chain_index=1,
        )
    )  # fmt: skip
    db.commit()
    before = len(denials(db))
    response = get(client, org["eng_2"], f"{file['id']}/content")
    payload = assert_denied(response, db, before, 403, "GRANT_REQUIRED")
    assert payload["required_permission"] == "DOWNLOAD"
    assert payload["rule"] == "classifications.RESTRICTED.requires_explicit_access"


@pytest.mark.parametrize(
    ("method", "path", "body", "permission"),
    [
        ("patch", "", {"display_name": "taken.pdf"}, "RENAME"),
        ("patch", "", {"description": "mine now"}, "UPDATE"),
        ("delete", "", None, "DELETE"),
        ("post", "/versions/1/restore", {"base_version": 2}, "RESTORE"),
        ("post", "/integrity", None, "VERIFY"),
    ],
)
def test_wrong_owner(client, db, org, method, path, body, permission) -> None:
    """eng_2 can read eng_1's INTERNAL file (same department) but owns nothing about it."""
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    new_version(client, org["eng_1"], file["id"], 1, PDF + b"%2\n")
    before = len(denials(db))
    kwargs = {"json": body} if body else {}
    response = client.request(
        method, f"{API}/files/{file['id']}{path}", headers=org["eng_2"].headers, **kwargs
    )
    payload = assert_denied(response, db, before, 403, "NO_PERMISSION")
    assert payload["required_permission"] == permission
    # ...while the owner may.
    owner = client.request(
        method, f"{API}/files/{file['id']}{path}", headers=org["eng_1"].headers, **kwargs
    )
    assert owner.status_code in (200, 201)


def test_wrong_owner_cannot_upload_a_new_version(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    before = len(denials(db))
    assert_denied(
        new_version(client, org["eng_2"], file["id"], 1), db, before, 403, "NO_PERMISSION"
    )


@pytest.mark.parametrize("who", ["eng_mgr", "eng_2", "fin_mgr"])
def test_restricted_file_hidden_from_everyone_without_explicit_access(client, db, org, who) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    before = len(denials(db))
    for path in ("", "/content", "/versions"):
        assert get(client, org[who], f"{file['id']}{path}").status_code == 404
    assert len(denials(db)) == before + 3


def test_admin_sees_restricted_metadata_but_not_content(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    assert get(client, org["ada"], file["id"]).status_code == 200
    before = len(denials(db))
    assert_denied(
        get(client, org["ada"], f"{file['id']}/content"), db, before, 403, "GRANT_REQUIRED"
    )


# --- sessions ------------------------------------------------------------------------------------


def unauthenticated_events(db: Session) -> list:
    return system_events(db, "UNAUTHENTICATED_ACCESS")


def test_expired_token_is_refused_and_attributed(client, db, org) -> None:
    file = uploaded(client, org["eng_1"])
    claims = jwt.decode(
        org["eng_1"].headers["Authorization"][7:], options={"verify_signature": False}
    )
    past = datetime.now(UTC) - timedelta(hours=2)
    expired = jwt.encode(
        {**claims, "iat": past, "exp": past + timedelta(minutes=30)},
        get_settings().jwt_secret.get_secret_value(),
        algorithm="HS256",
    )
    response = client.get(
        f"{API}/files/{file['id']}/content", headers={"Authorization": f"Bearer {expired}"}
    )

    assert response.status_code == 401 and response.json()["error"]["code"] == "INVALID_TOKEN"
    event = unauthenticated_events(db)[-1]
    assert event.session_id is None and event.actor_user_id == "eng_1"  # signature was valid
    assert event.event_payload["reason"] == "INVALID_TOKEN"
    assert (
        event.event_payload["route"] == "/files/{file_id}/content"
    )  # a template, never the raw path
    assert system_events(db, "FILE_DOWNLOAD") == []


def test_policy_session_age_limit(client, db, org, clock: Clock) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    clock.offset = timedelta(minutes=61)
    before = len(denials(db))
    payload = assert_denied(
        get(client, org["eng_1"], f"{file['id']}/content"), db, before, 403, "SESSION_TOO_OLD"
    )
    assert payload["rule"] == "classifications.RESTRICTED.max_session_age_minutes=60"


@pytest.mark.parametrize("case", ["logged_out", "garbage", "missing", "forged_signature"])
def test_invalid_sessions_are_refused_and_chained(client, db, org, case) -> None:
    file = uploaded(client, org["eng_1"], classification="PUBLIC")
    headers = dict(org["eng_2"].headers)
    if case == "logged_out":
        client.post(f"{API}/auth/logout", headers=headers)
    elif case == "garbage":
        headers = {"Authorization": "Bearer not.a.jwt"}
    elif case == "missing":
        headers = {}
    else:
        claims = jwt.decode(headers["Authorization"][7:], options={"verify_signature": False})
        headers = {"Authorization": "Bearer " + jwt.encode(claims, "x" * 40, algorithm="HS256")}
    before = len(unauthenticated_events(db))

    response = client.get(f"{API}/files/{file['id']}/content", headers=headers)

    assert response.status_code == 401
    events = unauthenticated_events(db)
    assert len(events) == before + 1
    expected_user = "eng_2" if case == "logged_out" else None  # only a valid signature attributes
    assert events[-1].actor_user_id == expected_user
    assert events[-1].event_payload["reason"] == response.json()["error"]["code"]


@pytest.mark.parametrize("change", ["deactivated", "role_changed"])
def test_account_changes_revoke_access_immediately(client, db, org, change) -> None:
    file = uploaded(client, org["eng_1"], classification="PUBLIC")
    operator = db.get(Operator, org["eng_2"].id)
    if change == "deactivated":
        operator.is_active = False
    else:
        operator.role = "manager"  # the token still claims "employee"
    db.commit()
    response = get(client, org["eng_2"], f"{file['id']}/content")
    assert response.status_code == 401
    assert unauthenticated_events(db)[-1].actor_user_id == "eng_2"


def test_system_stream_valid_after_all_kinds_of_denials(
    client, db, org, system_stream: LogStream
) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    get(client, org["eng_2"], f"{file['id']}/content")
    client.get(f"{API}/files/{file['id']}", headers={"Authorization": "Bearer junk"})
    client.delete(f"{API}/files/{file['id']}", headers=org["aud"].headers)
    run, report = verify_stream(db, system_stream, load_rules())
    db.rollback()
    assert run.status == "VALID", report.findings[:3]


# --- sharing -------------------------------------------------------------------------------------


def share(client, user, file_id, grantee, permissions, **extra):
    body = {"grantee_id": str(grantee.id), "permissions": permissions, **extra}
    return client.post(f"{API}/files/{file_id}/permissions", json=body, headers=user.headers)


def test_owner_shares_and_grantee_gains_exactly_that(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    assert get(client, org["fin_1"], f"{file['id']}/content").status_code == 404

    response = share(client, org["eng_1"], file["id"], org["fin_1"], ["READ", "DOWNLOAD"])
    assert response.status_code == 201
    event = last_event(db, "FILE_SHARED")
    assert response.json()["audit"]["chain_index"] == event.chain_index
    assert event.event_payload["rule"] == "sharing.subset_of_own_permissions"
    assert event.event_payload["grantee"]["id"] == str(org["fin_1"].id)

    assert get(client, org["fin_1"], f"{file['id']}/content").status_code == 200
    assert last_event(db, "FILE_DOWNLOAD").event_payload["reason_code"] == "ALLOW_GRANT"
    shared = client.get(f"{API}/files", params={"scope": "shared"}, headers=org["fin_1"].headers)
    assert [f["id"] for f in shared.json()["items"]] == [file["id"]]
    # ...but nothing else.
    before = len(denials(db))
    rename = client.patch(
        f"{API}/files/{file['id']}", json={"display_name": "x.pdf"}, headers=org["fin_1"].headers
    )
    assert_denied(rename, db, before, 403, "GRANT_REQUIRED")
    # Re-sharing replaces the grant (previous state recorded) instead of stacking grants.
    assert share(client, org["eng_1"], file["id"], org["fin_1"], ["READ"]).status_code == 201


@pytest.mark.parametrize(
    ("sharer", "level", "grantee", "permissions", "status", "reason"),
    [
        ("eng_2", "INTERNAL", "fin_1", ["READ"], 403, "NO_PERMISSION"),  # reader without SHARE
        ("eng_mgr", "CONFIDENTIAL", "eng_2", ["READ", "UPDATE"], 403, "SHARE_ESCALATION"),
        ("eng_1", "INTERNAL", "ivan", ["READ"], 403, "GRANTEE_NOT_ELIGIBLE"),
        ("fin_1", "INTERNAL", "eng_2", ["READ"], 404, "NO_PERMISSION"),  # cannot even see it
        ("aud", "INTERNAL", "eng_2", ["READ"], 403, "NO_PERMISSION"),
    ],
)
def test_unauthorized_sharing(
    client, db, org, sharer, level, grantee, permissions, status, reason
) -> None:
    if sharer == "eng_mgr":  # a manager reaching a colleague's CONFIDENTIAL file by role
        file = uploaded(client, org["ada"], classification="CONFIDENTIAL")
        db.query(File).filter(File.id == uuid.UUID(file["id"])).update(
            {"department": "Engineering"}
        )
        db.commit()
    else:
        file = uploaded(client, org["eng_1"], classification=level)
    before = len(denials(db))
    response = share(client, org[sharer], file["id"], org[grantee], permissions)
    assert_denied(response, db, before, status, reason)
    db.expire_all()
    assert db.scalars(select(FilePermission)).all() == []


def test_self_grant_is_refused(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    before = len(denials(db))
    assert_denied(
        share(client, org["eng_1"], file["id"], org["eng_1"], ["READ"]),
        db,
        before,
        403,
        "SELF_GRANT",
    )


@pytest.mark.parametrize("permissions", [["MANAGE_PERMISSIONS"], ["CREATE"], ["READ", "ROOT"], []])
def test_escalating_permissions_rejected_at_validation(client, org, permissions) -> None:
    file = uploaded(client, org["eng_1"])
    assert share(client, org["eng_1"], file["id"], org["eng_2"], permissions).status_code == 422


def test_highly_restricted_sharing(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="HIGHLY_RESTRICTED")
    no_reason = share(client, org["eng_1"], file["id"], org["eng_2"], ["READ"])
    assert no_reason.status_code == 422 and no_reason.json()["error"]["code"] == "REASON_REQUIRED"
    before = len(denials(db))
    reshare = share(
        client, org["eng_1"], file["id"], org["eng_2"], ["READ", "SHARE"], reason="audit"
    )
    assert_denied(reshare, db, before, 403, "NOT_GRANTABLE")
    ok = share(client, org["eng_1"], file["id"], org["eng_2"], ["READ", "DOWNLOAD"], reason="audit")
    assert ok.status_code == 201


def test_admin_break_glass_self_grant_is_allowed_and_flagged(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    response = share(
        client, org["ada"], file["id"], org["ada"], ["READ", "DOWNLOAD"], reason="incident 42"
    )
    assert response.status_code == 201
    payload = last_event(db, "FILE_SHARED").event_payload
    assert (
        payload["signals"]["self_grant"] is True
        and payload["signals"]["path"] == "MANAGE_PERMISSIONS"
    )
    assert payload["rule"] == "sharing.manage_permissions"
    assert get(client, org["ada"], f"{file['id']}/content").status_code == 200


# --- permission modification ----------------------------------------------------------------------


def test_revocation_rules(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    grant_id = share(client, org["eng_1"], file["id"], org["eng_2"], ["READ", "DOWNLOAD"]).json()[
        "grant"
    ]["id"]
    url = f"{API}/files/{file['id']}/permissions/{grant_id}"

    before = len(denials(db))
    assert_denied(
        client.delete(url, headers=org["eng_2"].headers), db, before, 403, "GRANT_REQUIRED"
    )
    assert_denied(client.delete(url, headers=org["fin_1"].headers), db, before + 1, 404)
    revoked = client.delete(url, headers=org["eng_1"].headers)
    assert revoked.status_code == 200
    change = last_event(db, "FILE_SHARE_REVOKED").event_payload
    assert change["change"] == "REVOKE" and change["previous_state"]["grant_id"] == grant_id
    assert get(client, org["eng_2"], f"{file['id']}/content").status_code == 404  # access gone
    assert client.delete(url, headers=org["eng_1"].headers).status_code == 409
    other = client.delete(
        f"{API}/files/{file['id']}/permissions/{uuid.uuid4()}", headers=org["eng_1"].headers
    )
    assert other.status_code == 404 and other.json()["error"]["code"] == "GRANT_NOT_FOUND"


def test_grant_ids_are_scoped_to_their_file(client, db, org) -> None:
    """A grant id from file A cannot be used through file B (IDOR on sub-resources)."""
    a = uploaded(client, org["eng_1"], classification="INTERNAL")
    b = uploaded(client, org["eng_1"], classification="INTERNAL")
    grant_id = share(client, org["eng_1"], a["id"], org["fin_1"], ["READ"]).json()["grant"]["id"]
    response = client.delete(
        f"{API}/files/{b['id']}/permissions/{grant_id}", headers=org["eng_1"].headers
    )
    assert response.status_code == 404
    db.expire_all()
    assert db.get(FilePermission, uuid.UUID(grant_id)).revoked_at is None


def test_permission_listing_is_scoped(client, org) -> None:
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    share(client, org["eng_1"], file["id"], org["fin_1"], ["READ"])
    share(client, org["eng_1"], file["id"], org["fin_mgr"], ["READ"])
    url = f"{API}/files/{file['id']}/permissions"
    assert len(client.get(url, headers=org["eng_1"].headers).json()["grants"]) == 2  # owner
    assert len(client.get(url, headers=org["ada"].headers).json()["grants"]) == 2  # manager role
    mine = client.get(url, headers=org["fin_1"].headers).json()["grants"]
    assert [g["grantee_id"] for g in mine] == [str(org["fin_1"].id)]  # only their own
    assert client.get(url, headers=org["nodept"].headers).status_code == 404


def test_ownership_transfer(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    url = f"{API}/files/{file['id']}/owner"
    body = {"owner_id": str(org["eng_2"].id), "reason": "role change"}

    before = len(denials(db))
    assert_denied(
        client.put(url, json=body, headers=org["eng_1"].headers), db, before, 403, "NO_PERMISSION"
    )
    ingestor = {"owner_id": str(org["ivan"].id), "reason": "x"}
    assert_denied(
        client.put(url, json=ingestor, headers=org["ada"].headers),
        db,
        before + 1,
        403,
        "GRANTEE_NOT_ELIGIBLE",
    )
    assert (
        client.put(
            url, json={"owner_id": str(org["eng_2"].id)}, headers=org["ada"].headers
        ).status_code
        == 422
    )

    moved = client.put(url, json=body, headers=org["ada"].headers)
    assert moved.status_code == 200 and moved.json()["owner_id"] == str(org["eng_2"].id)
    change = last_event(db, "FILE_ACCESS_POLICY_CHANGED").event_payload
    assert change["change"] == "OWNER_TRANSFER" and change["previous_state"]["owner_id"] == str(
        org["eng_1"].id
    )
    assert (
        client.delete(f"{API}/files/{file['id']}", headers=org["eng_1"].headers).status_code == 403
    )
    assert (
        client.patch(
            f"{API}/files/{file['id']}",
            json={"description": "new owner"},
            headers=org["eng_2"].headers,
        ).status_code
        == 200
    )


# --- privilege escalation and frontend bypass ---------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"owner_id": "00000000-0000-0000-0000-000000000001"},
        {"permissions": ["MANAGE_PERMISSIONS"]},
        {"department": "Finance"},
        {"created_by": "00000000-0000-0000-0000-000000000001"},
    ],
)
def test_hidden_fields_cannot_be_smuggled_into_updates(client, db, org, body) -> None:
    file = uploaded(client, org["eng_1"])
    response = client.patch(f"{API}/files/{file['id']}", json=body, headers=org["eng_1"].headers)
    assert response.status_code == 422
    db.expire_all()
    stored = db.get(File, uuid.UUID(file["id"]))
    assert (stored.owner_id, stored.department) == (org["eng_1"].id, "Engineering")


def test_role_claim_tampering_on_file_endpoints(client, db, org) -> None:
    file = uploaded(client, org["eng_1"], classification="RESTRICTED")
    claims = jwt.decode(
        org["eng_2"].headers["Authorization"][7:], options={"verify_signature": False}
    )
    forged = jwt.encode(
        {**claims, "role": "admin"}, get_settings().jwt_secret.get_secret_value(), algorithm="HS256"
    )
    response = client.get(
        f"{API}/files/{file['id']}", headers={"Authorization": f"Bearer {forged}"}
    )
    assert response.status_code == 401  # the stored role, not the token's claim, is authoritative


def test_upload_cannot_choose_another_owner_or_department(client, org) -> None:
    response = client.post(
        f"{API}/files",
        files={"file": ("a.pdf", PDF)},
        data={
            "classification": "INTERNAL",
            "owner_id": str(org["ada"].id),
            "department": "Finance",
        },
        headers=org["eng_1"].headers,
    )
    body = response.json()
    assert response.status_code == 201
    assert (body["owner_id"], body["department"]) == (str(org["eng_1"].id), "Engineering")


ENDPOINT_FOR = {
    "DOWNLOAD": ("get", "/content", None),
    "RENAME": ("patch", "", {"display_name": "renamed.pdf"}),
    "UPDATE": ("patch", "", {"description": "changed"}),
    "DELETE": ("delete", "", None),
    "VERIFY": ("post", "/integrity", None),
}


@pytest.mark.parametrize("who", ["eng_1", "eng_2", "fin_1", "aud", "ada", "eng_mgr"])
@pytest.mark.parametrize("action", list(ENDPOINT_FOR))
def test_direct_api_calls_match_backend_allowed_actions(client, db, org, who, action) -> None:
    """The dashboard hides buttons using ``allowed_actions``; hiding is NOT the control.
    Calling every endpoint directly gives exactly what the backend decides, for every user."""
    file = uploaded(client, org["eng_1"], classification="INTERNAL")
    detail = get(client, org[who], file["id"])
    advertised = set(detail.json()["allowed_actions"]) if detail.status_code == 200 else set()
    method, path, body = ENDPOINT_FOR[action]
    kwargs = {"json": body} if body else {}
    response = client.request(
        method, f"{API}/files/{file['id']}{path}", headers=org[who].headers, **kwargs
    )
    if action in advertised:
        assert response.status_code in (200, 201), (who, action, response.text)
    else:
        assert response.status_code in (403, 404), (who, action, response.status_code)


def test_listing_filter_agrees_with_the_policy(client, db, org, file_storage) -> None:
    """The SQL visibility filter is a second expression of ``is_discoverable``; they must agree."""
    for owner in ("eng_1", "fin_1", "eng_mgr", "ada"):
        for level in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "HIGHLY_RESTRICTED"):
            uploaded(client, org[owner], classification=level, name=f"{owner}-{level}.pdf")
    some = db.scalars(select(File)).all()
    share(
        client,
        org["eng_1"],
        str(next(f.id for f in some if f.display_name == "eng_1-RESTRICTED.pdf")),
        org["fin_1"],
        ["READ"],
    )
    db.expire_all()
    files = db.scalars(select(File)).all()
    for name, user in org.items():
        actor = Actor(db.get(Operator, user.id), "S-x", None, "r")
        enforcer = PolicyEnforcer(db, get_policy(), load_rules(), actor, lambda: datetime.now(UTC))
        grants = enforcer.grants(f.id for f in files)
        expected = {
            f.id for f in files
            if is_discoverable(
                get_policy(), actor.principal, enforcer.facts(f), grants.get(f.id, frozenset())
            )
        }  # fmt: skip
        listed = client.get(f"{API}/files", params={"limit": 200}, headers=user.headers).json()[
            "items"
        ]
        assert {uuid.UUID(f["id"]) for f in listed} == expected, name
