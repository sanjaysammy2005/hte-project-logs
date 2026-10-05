"""Helpers for the file-module API tests."""

from typing import Any

from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import SYSTEM_STREAM_NAME, AuditEvent, File, FileVersion, LogStream
from app.files.storage import LocalFileStorage
from tests.api.conftest import User
from tests.file_samples import PDF

API = "/api/v1"


def upload(
    client: TestClient,
    user: User,
    name: str = "report.pdf",
    data: bytes = PDF,
    classification: str = "INTERNAL",
    content_type: str = "application/octet-stream",
    **form: str,
) -> Response:
    return client.post(
        f"{API}/files",
        files={"file": (name, data, content_type)},
        data={"classification": classification, **form},
        headers=user.headers,
    )


def uploaded(client: TestClient, user: User, **kwargs: Any) -> dict:
    response = upload(client, user, **kwargs)
    assert response.status_code == 201, response.text
    return response.json()


def new_version(
    client: TestClient, user: User, file_id: str, base: int, data: bytes = PDF, name="v.pdf"
) -> Response:
    return client.post(
        f"{API}/files/{file_id}/versions",
        files={"file": (name, data, "application/pdf")},
        data={"base_version": str(base)},
        headers=user.headers,
    )


def system_events(db: Session, event_type: str | None = None) -> list[AuditEvent]:
    db.expire_all()
    query = (
        select(AuditEvent)
        .join(LogStream, LogStream.id == AuditEvent.stream_id)
        .where(LogStream.name == SYSTEM_STREAM_NAME)
        .order_by(AuditEvent.chain_index)
    )
    if event_type:
        query = query.where(AuditEvent.event_type == event_type)
    return list(db.scalars(query))


def last_event(db: Session, event_type: str | None = None) -> AuditEvent:
    events = system_events(db, event_type)
    assert events, f"no {event_type} event"
    return events[-1]


def blob_path(storage: LocalFileStorage, db: Session, file_id: str, version: int = 1):
    db.expire_all()
    row = db.scalars(
        select(FileVersion).where(
            FileVersion.file_id == file_id, FileVersion.version_number == version
        )
    ).one()
    return storage.root / row.storage_key[:2] / row.storage_key


def stored_files(storage: LocalFileStorage) -> list:
    return [p for p in storage.root.rglob("*") if p.is_file()]


def file_count(db: Session) -> int:
    db.expire_all()
    return len(db.scalars(select(File.id)).all())
