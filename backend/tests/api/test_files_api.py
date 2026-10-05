"""ZT3/ZT4: secure file lifecycle through the API (ZERO_TRUST_FILE_MODULE §9, §11, §14, §16).

Each test checks both the HTTP outcome and its evidence in the hash chain.
"""

import hashlib
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import File, FilePermission, LogStream
from app.files.storage import LocalFileStorage
from app.provenance.rules import load_rules
from app.verification.engine import verify_stream
from tests.api.conftest import User
from tests.api.file_helpers import (
    API,
    file_count,
    last_event,
    new_version,
    stored_files,
    system_events,
    upload,
    uploaded,
)
from tests.file_samples import DOCX, EXE, PDF, PNG, TXT

pytestmark = pytest.mark.usefixtures("file_storage")


@pytest.fixture
def people(sign_in: Callable[..., User]) -> dict[str, User]:
    return {
        name: sign_in(name, role)
        for name, role in [
            ("ada", "admin"),
            ("aud", "auditor"),
            ("max", "manager"),
            ("emma", "employee"),
            ("eric", "employee"),
            ("ivan", "ingestor"),
        ]
    }


def grant(db: Session, file_id: str, grantee: User, granter: User, perms: list[str], **kw) -> None:
    db.add(
        FilePermission(
            file_id=uuid.UUID(file_id),
            grantee_id=grantee.id,
            granted_by=granter.id,
            permissions=perms,
            audit_stream_id=uuid.uuid4(),
            audit_chain_index=1,
            **kw,
        )
    )
    db.commit()


def assert_system_stream_valid(db: Session, system_stream: LogStream) -> None:
    run, report = verify_stream(db, system_stream, load_rules())
    db.rollback()
    assert run.status == "VALID", report.findings[:3]


# --- upload ------------------------------------------------------------------------------------


def test_valid_upload_creates_file_version_blob_and_chained_event(
    client: TestClient,
    db: Session,
    people: dict[str, User],
    file_storage: LocalFileStorage,
    system_stream: LogStream,
) -> None:
    body = uploaded(client, people["emma"], name="Q3 notes.txt", data=TXT, description="draft")

    assert body["display_name"] == "Q3 notes.txt" and body["extension"] == "txt"
    assert body["mime_type"] == "text/plain" and body["classification"] == "INTERNAL"
    assert body["owner_id"] == body["created_by"] == str(people["emma"].id)
    assert body["current"]["sha256"] == hashlib.sha256(TXT).hexdigest()  # independent oracle
    assert body["current"]["size_bytes"] == len(TXT)
    assert "storage_key" not in str(body)
    # .txt is never rendered inline, so VIEW is not offered; the owner can do the rest.
    assert set(body["allowed_actions"]) == {
        "DOWNLOAD", "UPLOAD", "UPDATE", "RENAME", "DELETE", "RESTORE", "SHARE", "VERIFY"
    }  # fmt: skip

    event = last_event(db, "FILE_UPLOAD")
    assert body["audit"]["chain_index"] == event.chain_index
    assert body["current"]["audit_chain_index"] == event.chain_index
    assert event.actor_user_id == "emma" and event.session_id is not None
    assert event.prev_event_type == "AUTHENTICATION"  # inside emma's chained login session
    p = event.event_payload
    assert p["file_id"] == body["id"] and p["sha256"] == body["current"]["sha256"]
    assert p["decision"] == "ALLOW" and p["reason_code"] == "ALLOW_ROLE"
    assert p["policy"].startswith("access-policy.v1 sha256:")
    assert len(stored_files(file_storage)) == 1
    assert_system_stream_valid(db, system_stream)


def test_client_mime_type_is_ignored(client: TestClient, people: dict[str, User]) -> None:
    body = uploaded(client, people["emma"], content_type="text/html")
    assert body["mime_type"] == "application/pdf"


@pytest.mark.parametrize(
    ("name", "data", "status", "code"),
    [
        ("tool.exe", EXE, 415, "UNSUPPORTED_FILE_TYPE"),
        ("page.html", b"<script>alert(1)</script>", 415, "UNSUPPORTED_FILE_TYPE"),
        ("image.svg", b"<svg onload=alert(1)/>", 415, "UNSUPPORTED_FILE_TYPE"),
        ("README", TXT, 422, "MISSING_EXTENSION"),
        ("photo.pdf", PNG, 415, "FILE_TYPE_MISMATCH"),  # MIME mismatch
        ("invoice.docx", EXE, 415, "FILE_TYPE_MISMATCH"),  # executable disguised as a document
        ("notes.txt", EXE, 415, "FILE_TYPE_MISMATCH"),
        ("empty.pdf", b"", 422, "EMPTY_FILE"),
        ("a" + chr(0x202E) + "txt.exe.pdf", PDF, 422, "INVALID_FILENAME"),  # RTL spoof
        ("..", PDF, 422, "INVALID_FILENAME"),
        ("CON.pdf", PDF, 422, "INVALID_FILENAME"),
    ],
)
def test_rejected_uploads_leave_nothing_behind(
    client: TestClient,
    db: Session,
    people: dict[str, User],
    file_storage: LocalFileStorage,
    name: str,
    data: bytes,
    status: int,
    code: str,
) -> None:
    response = upload(client, people["emma"], name=name, data=data)

    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code
    assert file_count(db) == 0 and stored_files(file_storage) == []
    assert system_events(db, "FILE_UPLOAD") == []


@pytest.mark.parametrize(
    ("raw", "stored"),
    [
        ("../../../../etc/passwd.txt", "passwd.txt"),
        ("..\\..\\windows\\system32\\evil.txt", "evil.txt"),
        ("/var/lib/tracelock/files/ab/cdef.txt", "cdef.txt"),
    ],
)
def test_path_traversal_names_never_reach_the_filesystem(
    client: TestClient,
    people: dict[str, User],
    file_storage: LocalFileStorage,
    tmp_path_factory: pytest.TempPathFactory,
    raw: str,
    stored: str,
) -> None:
    body = uploaded(client, people["emma"], name=raw, data=TXT)

    assert body["display_name"] == stored  # only a display label
    paths = stored_files(file_storage)
    assert len(paths) == 1
    # The blob lives at <root>/<2 hex>/<32 hex>, whatever the user called the file.
    relative = paths[0].relative_to(file_storage.root).parts
    assert len(relative) == 2 and len(relative[1]) == 32 and relative[0] == relative[1][:2]


def test_unknown_classification_rejected(client: TestClient, people: dict[str, User]) -> None:
    response = upload(client, people["emma"], classification="TOP_SECRET")
    assert response.status_code == 422


def test_server_assigned_fields_cannot_be_smuggled_in(
    client: TestClient, people: dict[str, User]
) -> None:
    response = upload(client, people["emma"], owner_id=str(people["ada"].id))
    body = response.json()
    assert response.status_code == 201 and body["owner_id"] == str(people["emma"].id)


def test_oversized_upload_rejected_before_parsing(
    client: TestClient,
    db: Session,
    people: dict[str, User],
    file_storage: LocalFileStorage,
    upload_limit: Callable[[int], None],
) -> None:
    upload_limit(1000)
    response = upload(client, people["emma"], name="big.txt", data=b"a" * 200_000)

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "FILE_TOO_LARGE"
    # Proof that the check happens before parsing: a tiny file with a huge *form field* would
    # otherwise reach validation (422); the middleware answers 413 from Content-Length alone.
    padded = upload(client, people["emma"], name="tiny.txt", data=b"a", description="x" * 200_000)
    assert padded.status_code == 413
    assert file_count(db) == 0 and stored_files(file_storage) == []


def test_oversized_file_within_header_allowance_still_rejected(
    client: TestClient,
    db: Session,
    people: dict[str, User],
    file_storage: LocalFileStorage,
    upload_limit: Callable[[int], None],
) -> None:
    """Content-Length passes the early check (multipart allowance); the file is still too big."""
    upload_limit(1000)
    response = upload(client, people["emma"], name="big.txt", data=b"a" * 5000)

    assert response.status_code == 413
    assert file_count(db) == 0 and stored_files(file_storage) == []


def test_exact_limit_accepted(
    client: TestClient, people: dict[str, User], upload_limit: Callable[[int], None]
) -> None:
    upload_limit(1000)
    assert upload(client, people["emma"], name="ok.txt", data=b"a" * 1000).status_code == 201


def test_upload_without_content_length_rejected(
    client: TestClient, people: dict[str, User]
) -> None:
    def body():
        yield b'--x\r\nContent-Disposition: form-data; name="classification"\r\n\r\nPUBLIC\r\n--x--'

    response = client.post(
        f"{API}/files",
        content=body(),
        headers={**people["emma"].headers, "Content-Type": "multipart/form-data; boundary=x"},
    )
    assert response.status_code == 411
    assert response.json()["error"]["code"] == "LENGTH_REQUIRED"


@pytest.mark.parametrize("who", ["aud", "ivan"])
def test_roles_without_create_cannot_upload(
    client: TestClient, db: Session, people: dict[str, User], who: str
) -> None:
    response = upload(client, people[who])

    assert response.status_code == 403
    assert file_count(db) == 0
    denied = last_event(db, "FILE_ACCESS_DENIED")
    assert denied.actor_user_id == people[who].operator.username
    assert denied.event_payload["action"] == "CREATE"


# --- invalid and unknown IDs (IDOR) --------------------------------------------------------------


@pytest.mark.parametrize("bad", ["not-a-uuid", "..%2F..%2Fetc%2Fpasswd", "1", "' OR 1=1 --"])
def test_malformed_file_ids_rejected(client: TestClient, people: dict[str, User], bad: str) -> None:
    for method, path in [("get", ""), ("get", "/content"), ("delete", ""), ("post", "/integrity")]:
        response = client.request(method, f"{API}/files/{bad}{path}", headers=people["ada"].headers)
        assert response.status_code in (404, 422), (method, path, response.status_code)
        assert response.status_code != 200


def test_unknown_and_forbidden_files_are_indistinguishable(
    client: TestClient, db: Session, people: dict[str, User]
) -> None:
    secret = uploaded(client, people["max"], classification="CONFIDENTIAL")
    unknown = client.get(f"{API}/files/{uuid.uuid4()}", headers=people["emma"].headers)
    forbidden = client.get(f"{API}/files/{secret['id']}", headers=people["emma"].headers)

    assert unknown.status_code == forbidden.status_code == 404
    assert unknown.json() == forbidden.json()  # no classification, no audit index, no hint
    probes = system_events(db, "FILE_ACCESS_DENIED")
    assert [e.event_payload["reason_code"] for e in probes] == ["NOT_FOUND", "NO_PERMISSION"]
    assert all(e.event_payload["signals"]["discoverable"] is False for e in probes)


# --- listing, search, filters, sorting ---------------------------------------------------------


@pytest.fixture
def catalogue(client: TestClient, people: dict[str, User]) -> dict[str, dict]:
    files = {
        "handbook": uploaded(client, people["ada"], name="Handbook.pdf", classification="PUBLIC"),
        "roadmap": uploaded(
            client, people["max"], name="roadmap 50%.docx", data=DOCX, classification="INTERNAL"
        ),
        "budget": uploaded(
            client, people["max"], name="budget.pdf", data=PDF * 3, classification="CONFIDENTIAL"
        ),
        "salaries": uploaded(
            client, people["ada"], name="salaries.pdf", classification="RESTRICTED"
        ),
        "emma_notes": uploaded(
            client, people["emma"], name="notes.txt", data=TXT, classification="RESTRICTED"
        ),
    }
    return files


def names(response) -> list[str]:
    assert response.status_code == 200, response.text
    return [f["display_name"] for f in response.json()["items"]]


@pytest.mark.parametrize(
    ("who", "visible"),
    [
        ("ada", {"Handbook.pdf", "roadmap 50%.docx", "budget.pdf", "salaries.pdf", "notes.txt"}),
        ("aud", {"Handbook.pdf", "roadmap 50%.docx", "budget.pdf", "salaries.pdf", "notes.txt"}),
        ("max", {"Handbook.pdf", "roadmap 50%.docx", "budget.pdf"}),
        ("emma", {"Handbook.pdf", "roadmap 50%.docx", "notes.txt"}),  # + her own RESTRICTED file
        ("eric", {"Handbook.pdf", "roadmap 50%.docx"}),
        ("ivan", set()),
    ],
)
def test_listing_shows_only_discoverable_files(
    client: TestClient, people: dict[str, User], catalogue: dict, who: str, visible: set
) -> None:
    response = client.get(f"{API}/files", headers=people[who].headers)
    assert set(names(response)) == visible
    assert response.json()["total"] == len(visible)


def test_listing_is_not_chained(client: TestClient, db: Session, people, catalogue) -> None:
    before = len(system_events(db))
    client.get(f"{API}/files", headers=people["ada"].headers)
    assert len(system_events(db)) == before


def test_search_filters_and_sorting(client: TestClient, people, catalogue) -> None:
    h = people["ada"].headers
    get = lambda **p: names(client.get(f"{API}/files", params=p, headers=h))  # noqa: E731

    assert get(q="BUDGET") == ["budget.pdf"]  # case-insensitive
    assert get(q="50%") == ["roadmap 50%.docx"]  # % is literal, not a wildcard
    assert get(q="%") == ["roadmap 50%.docx"]
    assert get(q="_") == []
    assert set(get(classification=["RESTRICTED"])) == {"salaries.pdf", "notes.txt"}
    assert set(get(classification=["PUBLIC", "INTERNAL"])) == {"Handbook.pdf", "roadmap 50%.docx"}
    assert get(type="docx") == ["roadmap 50%.docx"]
    assert set(get(owner=str(people["max"].id))) == {"roadmap 50%.docx", "budget.pdf"}
    assert get(uploader=str(people["emma"].id)) == ["notes.txt"]
    assert get(sort="name", order="asc") == sorted(get(sort="name"), key=str.lower)
    assert get(sort="name", order="asc")[0] == "budget.pdf"
    assert get(sort="size", order="desc")[0] == "roadmap 50%.docx"  # the DOCX sample is largest
    by_level = get(sort="classification", order="desc")
    assert by_level[0] in {"salaries.pdf", "notes.txt"} and by_level[-1] == "Handbook.pdf"
    page = client.get(f"{API}/files", params={"limit": 2, "offset": 2, "sort": "name"}, headers=h)
    assert len(page.json()["items"]) == 2 and page.json()["total"] == 5
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    assert get(created_from=future) == []


@pytest.mark.parametrize(
    "params",
    [{"sort": "storage_key"}, {"order": "sideways"}, {"limit": 0}, {"limit": 201},
     {"type": "../pdf"}, {"classification": "SECRET"}, {"scope": "everything"}, {"q": "a\x00b"}],
)  # fmt: skip
def test_invalid_list_parameters_rejected(client: TestClient, people, params) -> None:
    assert (
        client.get(f"{API}/files", params=params, headers=people["ada"].headers).status_code == 422
    )


def test_scopes(client: TestClient, db: Session, people, catalogue) -> None:
    grant(db, catalogue["budget"]["id"], people["emma"], people["max"], ["READ"])
    h = people["emma"].headers
    assert names(client.get(f"{API}/files", params={"scope": "mine"}, headers=h)) == ["notes.txt"]
    assert names(client.get(f"{API}/files", params={"scope": "shared"}, headers=h)) == [
        "budget.pdf"
    ]
    client.get(f"{API}/files/{catalogue['handbook']['id']}/content", headers=h)
    assert names(client.get(f"{API}/files", params={"scope": "recent"}, headers=h)) == [
        "Handbook.pdf"
    ]


# --- details -----------------------------------------------------------------------------------


def test_restricted_metadata_views_are_chained(
    client: TestClient, db: Session, people, catalogue
) -> None:
    before = len(system_events(db, "FILE_VIEW"))
    internal = client.get(
        f"{API}/files/{catalogue['roadmap']['id']}", headers=people["aud"].headers
    )
    restricted = client.get(
        f"{API}/files/{catalogue['salaries']['id']}", headers=people["aud"].headers
    )

    assert internal.status_code == restricted.status_code == 200
    assert internal.json()["audit"] is None
    assert restricted.json()["allowed_actions"] == ["VERIFY"]  # auditor: metadata, no content
    views = system_events(db, "FILE_VIEW")
    assert len(views) == before + 1
    assert views[-1].event_payload["scope"] == "metadata"
    assert views[-1].event_payload["filename"] == "[redacted]"  # never written into the chain


# --- download ----------------------------------------------------------------------------------


def test_download_serves_exact_bytes_with_safe_headers(
    client: TestClient, db: Session, people
) -> None:
    file = uploaded(client, people["emma"], name="Résumé final.pdf", classification="PUBLIC")
    response = client.get(f"{API}/files/{file['id']}/content", headers=people["eric"].headers)

    assert response.status_code == 200 and response.content == PDF
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="R_sum_ final.pdf"')  # ASCII fallback
    assert "filename*=UTF-8''R%C3%A9sum%C3%A9%20final.pdf" in disposition  # exact name
    event = last_event(db, "FILE_DOWNLOAD")
    assert response.headers["x-tracelock-audit-index"] == str(event.chain_index)
    assert event.actor_user_id == "eric" and event.event_payload["verified"] is True


def test_unauthorized_downloads(client: TestClient, db: Session, people, catalogue) -> None:
    # Undiscoverable: a manager's CONFIDENTIAL file for an employee → 404, but chained.
    hidden = client.get(
        f"{API}/files/{catalogue['budget']['id']}/content", headers=people["emma"].headers
    )
    assert hidden.status_code == 404
    assert last_event(db, "FILE_ACCESS_DENIED").event_payload["action"] == "DOWNLOAD"

    # Discoverable but not permitted: the auditor sees INTERNAL metadata, may not read content.
    response = client.get(
        f"{API}/files/{catalogue['roadmap']['id']}/content", headers=people["aud"].headers
    )
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "ACCESS_DENIED"
    d = error["details"]
    assert d["reason_code"] == "NO_PERMISSION" and d["required_permission"] == "DOWNLOAD"
    assert d["classification"] == "INTERNAL" and d["your_role"] == "auditor"
    assert d["audit"]["chain_index"] == last_event(db, "FILE_ACCESS_DENIED").chain_index
    assert "signed in successfully" in error["message"]


def test_admin_needs_explicit_grant_for_restricted_content(
    client: TestClient, db: Session, people, catalogue
) -> None:
    response = client.get(
        f"{API}/files/{catalogue['emma_notes']['id']}/content", headers=people["ada"].headers
    )
    assert response.status_code == 403
    assert response.json()["error"]["details"]["reason_code"] == "GRANT_REQUIRED"


def test_grants_control_restricted_access(
    client: TestClient, db: Session, people, catalogue
) -> None:
    file_id = catalogue["salaries"]["id"]
    eric, url = people["eric"], f"{API}/files/{file_id}/content"
    assert client.get(url, headers=eric.headers).status_code == 404  # no grant: undiscoverable

    grant(db, file_id, eric, people["ada"], ["READ"])
    denied = client.get(url, headers=eric.headers)
    assert denied.status_code == 403  # discoverable now, but READ is not DOWNLOAD
    assert denied.json()["error"]["details"]["your_permissions"] == ["READ"]

    db.query(FilePermission).delete()
    db.commit()
    grant(db, file_id, eric, people["ada"], ["READ", "DOWNLOAD"])
    allowed = client.get(url, headers=eric.headers)
    assert allowed.status_code == 200
    assert last_event(db, "FILE_DOWNLOAD").event_payload["reason_code"] == "ALLOW_GRANT"


@pytest.mark.parametrize("state", ["expired", "revoked"])
def test_expired_or_revoked_grants_do_not_count(
    client: TestClient, db: Session, people, catalogue, state
) -> None:
    file_id = catalogue["salaries"]["id"]
    now = datetime.now(UTC)
    extra = (
        {"created_at": now - timedelta(days=2), "expires_at": now - timedelta(days=1)}
        if state == "expired"
        else {"revoked_at": now, "revoked_by": people["ada"].id}
    )
    grant(db, file_id, people["eric"], people["ada"], ["READ", "DOWNLOAD"], **extra)
    response = client.get(f"{API}/files/{file_id}/content", headers=people["eric"].headers)
    assert response.status_code == 404


def test_inline_view(client: TestClient, db: Session, people) -> None:
    image = uploaded(client, people["emma"], name="chart.png", data=PNG, classification="PUBLIC")
    doc = uploaded(client, people["emma"], name="plan.docx", data=DOCX, classification="PUBLIC")

    shown = client.get(
        f"{API}/files/{image['id']}/content",
        params={"disposition": "inline"},
        headers=people["eric"].headers,
    )
    assert shown.status_code == 200 and shown.headers["content-disposition"].startswith("inline;")
    assert last_event(db, "FILE_VIEW").event_payload["action"] == "VIEW"
    office = client.get(
        f"{API}/files/{doc['id']}/content",
        params={"disposition": "inline"},
        headers=people["eric"].headers,
    )
    assert office.status_code == 415  # Office documents are never rendered in the browser


def test_highly_restricted_cannot_be_previewed(client: TestClient, people) -> None:
    file = uploaded(
        client, people["emma"], name="x.png", data=PNG, classification="HIGHLY_RESTRICTED"
    )
    response = client.get(
        f"{API}/files/{file['id']}/content",
        params={"disposition": "inline"},
        headers=people["emma"].headers,
    )
    assert response.status_code == 403
    assert response.json()["error"]["details"]["reason_code"] == "PREVIEW_NOT_ALLOWED"


def test_unknown_version_download(client: TestClient, people) -> None:
    file = uploaded(client, people["emma"])
    response = client.get(
        f"{API}/files/{file['id']}/content", params={"version": 9}, headers=people["emma"].headers
    )
    assert response.status_code == 404 and response.json()["error"]["code"] == "VERSION_NOT_FOUND"


# --- rename / update ---------------------------------------------------------------------------


def test_owner_renames_and_event_is_chained(client: TestClient, db: Session, people) -> None:
    file = uploaded(client, people["emma"])
    response = client.patch(
        f"{API}/files/{file['id']}",
        json={"display_name": "final.pdf"},
        headers=people["emma"].headers,
    )

    assert response.status_code == 200 and response.json()["display_name"] == "final.pdf"
    p = last_event(db, "FILE_RENAME").event_payload
    assert (p["old_name"], p["new_name"]) == ("report.pdf", "final.pdf")


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"display_name": "../../etc/passwd.pdf"}, "VALIDATION_ERROR"),
        ({"display_name": "report.exe"}, "EXTENSION_CHANGE_NOT_ALLOWED"),
        ({"display_name": "report.txt"}, "EXTENSION_CHANGE_NOT_ALLOWED"),
        ({"owner_id": str(uuid.uuid4())}, "VALIDATION_ERROR"),
        ({}, "VALIDATION_ERROR"),
    ],
)
def test_invalid_updates_rejected(client: TestClient, db: Session, people, body, code) -> None:
    file = uploaded(client, people["emma"])
    response = client.patch(f"{API}/files/{file['id']}", json=body, headers=people["emma"].headers)
    assert response.status_code == 422 and response.json()["error"]["code"] == code
    db.expire_all()
    assert db.get(File, uuid.UUID(file["id"])).display_name == "report.pdf"


def test_unauthorized_update(client: TestClient, db: Session, people) -> None:
    file = uploaded(client, people["emma"], classification="PUBLIC")
    url = f"{API}/files/{file['id']}"

    rename = client.patch(url, json={"display_name": "pwned.pdf"}, headers=people["eric"].headers)
    assert rename.status_code == 403  # eric can read PUBLIC files, but not rename them
    assert rename.json()["error"]["details"]["required_permission"] == "RENAME"
    reclass = client.patch(
        url, json={"classification": "RESTRICTED"}, headers=people["aud"].headers
    )
    assert reclass.status_code == 403
    db.expire_all()
    stored = db.get(File, uuid.UUID(file["id"]))
    assert (stored.display_name, stored.classification) == ("report.pdf", "PUBLIC")
    assert [e.event_payload["action"] for e in system_events(db, "FILE_ACCESS_DENIED")] == [
        "RENAME",
        "UPDATE",
    ]


def test_classification_upgrade_and_downgrade(client: TestClient, db: Session, people) -> None:
    file = uploaded(client, people["emma"], classification="INTERNAL")
    url = f"{API}/files/{file['id']}"

    up = client.patch(url, json={"classification": "CONFIDENTIAL"}, headers=people["emma"].headers)
    assert up.status_code == 200 and up.json()["classification"] == "CONFIDENTIAL"
    assert last_event(db, "FILE_ACCESS_POLICY_CHANGED").event_payload["changes"][
        "classification"
    ] == {
        "from": "INTERNAL",
        "to": "CONFIDENTIAL",
    }

    # The owner may not lower it again (classification laundering).
    down = client.patch(url, json={"classification": "PUBLIC"}, headers=people["emma"].headers)
    assert down.status_code == 403
    assert down.json()["error"]["details"]["required_permission"] == "MANAGE_PERMISSIONS"
    # An admin may, but only with a reason.
    no_reason = client.patch(url, json={"classification": "PUBLIC"}, headers=people["ada"].headers)
    assert no_reason.status_code == 422 and no_reason.json()["error"]["code"] == "REASON_REQUIRED"
    ok = client.patch(
        url, json={"classification": "PUBLIC", "reason": "published"}, headers=people["ada"].headers
    )
    assert ok.status_code == 200
    p = last_event(db, "FILE_ACCESS_POLICY_CHANGED").event_payload
    assert p["downgrade"] is True and p["reason"] == "published"


def test_rename_of_restricted_file_is_redacted_in_chain(
    client: TestClient, db: Session, people
) -> None:
    file = uploaded(client, people["emma"], name="layoffs.pdf", classification="RESTRICTED")
    client.patch(
        f"{API}/files/{file['id']}",
        json={"display_name": "plan.pdf"},
        headers=people["emma"].headers,
    )
    p = last_event(db, "FILE_RENAME").event_payload
    assert p["old_name"] == p["new_name"] == p["filename"] == "[redacted]"
    assert "layoffs" not in str([e.event_payload for e in system_events(db)])


# --- delete ------------------------------------------------------------------------------------


def test_unauthorized_deletion(client: TestClient, db: Session, people) -> None:
    file = uploaded(client, people["emma"], classification="PUBLIC")
    for who in ("eric", "aud", "max"):
        response = client.delete(f"{API}/files/{file['id']}", headers=people[who].headers)
        assert response.status_code == 403, who
    db.expire_all()
    assert db.get(File, uuid.UUID(file["id"])).deleted_at is None


def test_deleted_file_is_protected(client: TestClient, db: Session, people, file_storage) -> None:
    file = uploaded(client, people["emma"], classification="PUBLIC")
    url = f"{API}/files/{file['id']}"
    deleted = client.delete(url, headers=people["emma"].headers)
    assert deleted.status_code == 200 and deleted.json()["event_type"] == "FILE_DELETE"

    # Not listed, not downloadable, not changeable; others cannot even see it.
    assert names(client.get(f"{API}/files", headers=people["eric"].headers)) == []
    assert (
        client.get(f"{API}/files/{file['id']}/content", headers=people["eric"].headers).status_code
        == 404
    )
    own = client.get(f"{API}/files/{file['id']}/content", headers=people["emma"].headers)
    assert (
        own.status_code == 403 and own.json()["error"]["details"]["reason_code"] == "FILE_DELETED"
    )
    assert client.delete(url, headers=people["emma"].headers).status_code == 403
    assert new_version(client, people["emma"], file["id"], 1).status_code == 403
    # The owner and admins see it in the trash; content stays intact and verifiable.
    assert names(
        client.get(f"{API}/files", params={"scope": "trash"}, headers=people["emma"].headers)
    ) == ["report.pdf"]
    assert (
        names(client.get(f"{API}/files", params={"scope": "trash"}, headers=people["eric"].headers))
        == []
    )
    assert (
        client.post(f"{url}/integrity", headers=people["emma"].headers).json()["status"] == "INTACT"
    )
    assert len(stored_files(file_storage)) == 1  # soft delete: nothing destroyed


# --- versions ----------------------------------------------------------------------------------


def test_version_creation_keeps_history(
    client: TestClient, db: Session, people, file_storage
) -> None:
    file = uploaded(client, people["emma"])
    v2_bytes = PDF + b"% revision 2\n"
    response = new_version(client, people["emma"], file["id"], base=1, data=v2_bytes)

    assert response.status_code == 201
    body = response.json()
    assert body["current_version"] == 2
    assert body["current"]["sha256"] == hashlib.sha256(v2_bytes).hexdigest()
    p = last_event(db, "FILE_VERSION_CREATED").event_payload
    assert (p["version"], p["previous_version"]) == (2, 1)
    h = people["emma"].headers
    assert client.get(f"{API}/files/{file['id']}/content", headers=h).content == v2_bytes
    old = client.get(f"{API}/files/{file['id']}/content", params={"version": 1}, headers=h)
    assert old.content == PDF  # version 1 untouched
    versions = client.get(f"{API}/files/{file['id']}/versions", headers=h).json()
    assert [v["version_number"] for v in versions["versions"]] == [2, 1]
    assert len(stored_files(file_storage)) == 2


def test_stale_base_version_cannot_overwrite(client: TestClient, db: Session, people) -> None:
    file = uploaded(client, people["emma"])
    assert new_version(client, people["emma"], file["id"], base=1).status_code == 201
    stale = new_version(client, people["emma"], file["id"], base=1)

    assert stale.status_code == 409
    assert stale.json()["error"]["details"] == {"current_version": 2, "base_version": 1}
    assert len(system_events(db, "FILE_VERSION_CREATED")) == 1


def test_concurrent_replacements_one_wins(
    client: TestClient, db: Session, people, file_storage
) -> None:
    file = uploaded(client, people["emma"])
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda i: (
                    new_version(client, people["emma"], file["id"], 1, PDF + bytes([i])).status_code
                ),
                [1, 2],
            )
        )
    assert sorted(results) == [201, 409]
    versions = client.get(
        f"{API}/files/{file['id']}/versions", headers=people["emma"].headers
    ).json()
    assert [v["version_number"] for v in versions["versions"]] == [2, 1]
    assert len(stored_files(file_storage)) == 2  # the loser's blob was never written or was removed


@pytest.mark.parametrize(
    ("name", "data", "status", "code"),
    [("v.txt", TXT, 415, "EXTENSION_MISMATCH"), ("v.pdf", PNG, 415, "FILE_TYPE_MISMATCH"),
     ("v.exe", EXE, 415, "UNSUPPORTED_FILE_TYPE")],
)  # fmt: skip
def test_invalid_replacements_rejected(
    client: TestClient, people, file_storage, name, data, status, code
) -> None:
    file = uploaded(client, people["emma"])
    response = new_version(client, people["emma"], file["id"], 1, data=data, name=name)
    assert response.status_code == status and response.json()["error"]["code"] == code
    assert len(stored_files(file_storage)) == 1


def test_unauthorized_version_upload(client: TestClient, people) -> None:
    file = uploaded(client, people["emma"], classification="PUBLIC")
    assert new_version(client, people["eric"], file["id"], 1).status_code == 403
    assert new_version(client, people["ivan"], file["id"], 1).status_code == 404


def test_version_restoration(client: TestClient, db: Session, people, file_storage) -> None:
    file = uploaded(client, people["emma"])
    new_version(client, people["emma"], file["id"], 1, PDF + b"%v2\n")
    url = f"{API}/files/{file['id']}/versions/1/restore"
    response = client.post(
        url, json={"base_version": 2, "reason": "v2 was wrong"}, headers=people["emma"].headers
    )

    assert response.status_code == 201
    body = response.json()
    assert body["current_version"] == 3
    assert body["current"]["restored_from_version"] == 1
    assert body["current"]["sha256"] == hashlib.sha256(PDF).hexdigest()
    p = last_event(db, "FILE_VERSION_RESTORED").event_payload
    assert (p["version"], p["restored_from"], p["previous_version"]) == (3, 1, 2)
    content = client.get(f"{API}/files/{file['id']}/content", headers=people["emma"].headers)
    assert content.content == PDF
    assert len(stored_files(file_storage)) == 2  # restore reuses version 1's blob, nothing copied
    assert (
        client.post(f"{API}/files/{file['id']}/integrity", headers=people["emma"].headers).json()[
            "status"
        ]
        == "INTACT"
    )


@pytest.mark.parametrize(
    ("version", "base", "status", "code"),
    [
        (9, 2, 404, "VERSION_NOT_FOUND"),
        (0, 2, 404, "VERSION_NOT_FOUND"),
        (2, 2, 409, "ALREADY_CURRENT"),
        (1, 1, 409, "VERSION_CONFLICT"),
    ],
)
def test_invalid_restorations(client: TestClient, people, version, base, status, code) -> None:
    file = uploaded(client, people["emma"])
    new_version(client, people["emma"], file["id"], 1, PDF + b"%v2\n")
    response = client.post(
        f"{API}/files/{file['id']}/versions/{version}/restore",
        json={"base_version": base},
        headers=people["emma"].headers,
    )
    assert response.status_code == status and response.json()["error"]["code"] == code


def test_unauthorized_restoration(client: TestClient, db: Session, people) -> None:
    file = uploaded(client, people["emma"], classification="PUBLIC")
    new_version(client, people["emma"], file["id"], 1, PDF + b"%v2\n")
    response = client.post(
        f"{API}/files/{file['id']}/versions/1/restore",
        json={"base_version": 2},
        headers=people["eric"].headers,
    )
    assert response.status_code == 403
    assert response.json()["error"]["details"]["required_permission"] == "RESTORE"
    assert system_events(db, "FILE_VERSION_RESTORED") == []


# --- whole workflow ----------------------------------------------------------------------------


def test_full_lifecycle_keeps_the_system_stream_valid(
    client: TestClient, db: Session, people, system_stream: LogStream
) -> None:
    h = people["emma"].headers
    file = uploaded(client, people["emma"], classification="RESTRICTED")
    url = f"{API}/files/{file['id']}"
    client.get(url, headers=h)
    client.get(f"{url}/content", headers=h)
    client.get(f"{url}/content", headers=people["eric"].headers)  # denied
    new_version(client, people["emma"], file["id"], 1, PDF + b"%2\n")
    client.post(f"{url}/versions/1/restore", json={"base_version": 2}, headers=h)
    client.patch(url, json={"display_name": "renamed.pdf"}, headers=h)
    client.post(f"{url}/integrity", headers=h)
    client.delete(url, headers=h)
    client.post(f"{API}/auth/logout", headers=h)

    emma = [e for e in system_events(db) if e.actor_user_id == "emma"]
    assert [e.event_type for e in emma] == [
        "LOGIN", "AUTHENTICATION", "FILE_UPLOAD", "FILE_VIEW", "FILE_DOWNLOAD",
        "FILE_VERSION_CREATED", "FILE_VERSION_RESTORED", "FILE_RENAME",
        "FILE_INTEGRITY_CHECK", "FILE_DELETE", "LOGOUT",
    ]  # fmt: skip
    assert [e.session_seq for e in emma] == list(range(1, 12))  # one gap-free chained session
    assert_system_stream_valid(db, system_stream)


def test_file_event_types_cannot_be_ingested_by_clients(client: TestClient, people) -> None:
    created = client.post(
        f"{API}/streams", json={"name": "app"}, headers=people["ada"].headers
    ).json()
    response = client.post(
        f"{API}/streams/{created['id']}/events",
        json={"event_type": "FILE_DOWNLOAD", "actor_user_id": "x"},
        headers=people["ada"].headers,
    )
    assert response.status_code == 422 and response.json()["error"]["code"] == "UNKNOWN_EVENT_TYPE"
