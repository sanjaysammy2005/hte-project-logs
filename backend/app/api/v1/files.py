"""File lifecycle endpoints (ZERO_TRUST_FILE_MODULE §14.2).

Thin HTTP layer: parse and validate input, call FileService, shape the response. Every
authorization decision and audit event happens in the service.
"""

import uuid
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from fastapi.responses import Response
from pydantic import BaseModel, ValidationError

from app.access.model import Classification
from app.api.deps import get_file_service
from app.core.errors import APIError
from app.files.schemas import (
    AuditRef,
    FileCreateIn,
    FileListOut,
    FileOut,
    FileUpdateIn,
    FileVersionOut,
    GrantCreateIn,
    GrantListOut,
    GrantOut,
    GrantResultOut,
    IntegrityReportOut,
    OwnerTransferIn,
    RestoreIn,
    VersionCreateIn,
    VersionIntegrityOut,
    VersionListOut,
)
from app.files.service import FileService, FileView, ListQuery

router = APIRouter(prefix="/files", tags=["files"])
Service = Annotated[FileService, Depends(get_file_service)]
AUDIT_HEADER = "X-TraceLock-Audit-Index"


def _form_model[M: BaseModel](model: type[M], **values: object) -> M:
    """Validate multipart form fields with the same Pydantic models as JSON bodies."""
    try:
        return model(**{k: v for k, v in values.items() if v is not None})
    except ValidationError as exc:
        errors = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")}
            for e in exc.errors()
        ]
        raise APIError(422, "VALIDATION_ERROR", "Invalid request", {"errors": errors}) from exc


def _out(view: FileView) -> FileOut:
    return FileOut.build(view.file, view.current, view.allowed_actions, view.audit_event)


def content_disposition(disposition: str, filename: str) -> str:
    """RFC 6266: an ASCII fallback plus the exact UTF-8 name; no header injection possible."""
    fallback = "".join(
        c if c.isascii() and c.isprintable() and c not in '"\\' else "_" for c in filename
    )
    return f"{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"


@router.post("", response_model=FileOut, status_code=status.HTTP_201_CREATED)
def upload_file(
    service: Service,
    file: Annotated[UploadFile, File(description="The file to upload")],
    classification: Annotated[str, Form()],
    description: Annotated[str | None, Form()] = None,
) -> FileOut:
    meta = _form_model(FileCreateIn, classification=classification, description=description)
    return _out(service.upload(file.filename, file.file, file.size, meta))


@router.get("", response_model=FileListOut)
def list_files(
    service: Service,
    scope: Literal["all", "mine", "shared", "recent", "trash"] = "all",
    q: Annotated[str | None, Query(max_length=200, pattern=r"^[^\x00]*$")] = None,
    classification: Annotated[list[Classification] | None, Query()] = None,
    type: Annotated[str | None, Query(pattern=r"^[a-z0-9]{1,10}$")] = None,  # noqa: A002
    owner: uuid.UUID | None = None,
    uploader: uuid.UUID | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    sort: Literal[
        "name", "created_at", "updated_at", "size", "classification", "last_accessed"
    ] = "updated_at",
    order: Literal["asc", "desc"] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> FileListOut:
    query = ListQuery(
        scope=scope,
        q=q,
        classifications=tuple(classification or ()),
        extension=type,
        owner_id=owner,
        uploader_id=uploader,
        created_from=created_from,
        created_to=created_to,
        sort=sort,
        order=order,
        limit=limit,
        offset=offset,
    )
    views, total = service.list_files(query)
    return FileListOut(items=[_out(v) for v in views], total=total, limit=limit, offset=offset)


@router.get("/{file_id}", response_model=FileOut)
def get_file(file_id: uuid.UUID, service: Service) -> FileOut:
    return _out(service.detail(file_id))


@router.get("/{file_id}/content")
def get_content(
    file_id: uuid.UUID,
    service: Service,
    disposition: Literal["attachment", "inline"] = "attachment",
    version: Annotated[int | None, Query(ge=1)] = None,
) -> Response:
    content = service.content(file_id, disposition == "inline", version)
    return Response(
        content=content.data,
        # The server's MIME type for the validated format, never the client's claim.
        media_type=content.mime_type,
        headers={
            "Content-Disposition": content_disposition(disposition, content.filename),
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; img-src 'self' data:; sandbox",
            "Cache-Control": "no-store",
            AUDIT_HEADER: str(content.audit_event.chain_index),
        },
    )


@router.patch("/{file_id}", response_model=FileOut)
def update_file(file_id: uuid.UUID, body: FileUpdateIn, service: Service) -> FileOut:
    return _out(service.update(file_id, body))


@router.delete("/{file_id}", response_model=AuditRef)
def delete_file(file_id: uuid.UUID, service: Service) -> AuditRef:
    return AuditRef.build(service.delete(file_id))  # type: ignore[return-value]


@router.get("/{file_id}/versions", response_model=VersionListOut)
def list_versions(file_id: uuid.UUID, service: Service) -> VersionListOut:
    file, versions, event = service.versions(file_id)
    return VersionListOut(
        file_id=file.id,
        current_version=file.current_version,
        versions=[FileVersionOut.build(v) for v in versions],
        audit=AuditRef.build(event),
    )


@router.post("/{file_id}/versions", response_model=FileOut, status_code=status.HTTP_201_CREATED)
def upload_version(
    file_id: uuid.UUID,
    service: Service,
    file: Annotated[UploadFile, File()],
    base_version: Annotated[str, Form()],
    change_reason: Annotated[str | None, Form()] = None,
) -> FileOut:
    meta = _form_model(VersionCreateIn, base_version=base_version, change_reason=change_reason)
    return _out(service.new_version(file_id, file.filename, file.file, file.size, meta))


@router.post(
    "/{file_id}/versions/{version_number}/restore",
    response_model=FileOut,
    status_code=status.HTTP_201_CREATED,
)
def restore_version(
    file_id: uuid.UUID,
    version_number: int,
    body: RestoreIn,
    service: Service,
) -> FileOut:
    return _out(service.restore(file_id, version_number, body.base_version, body.reason))


@router.post("/{file_id}/integrity", response_model=IntegrityReportOut)
def verify_integrity(
    file_id: uuid.UUID,
    service: Service,
    version: Annotated[int | None, Query(ge=1)] = None,
) -> IntegrityReportOut:
    report = service.verify(file_id, version)
    return IntegrityReportOut(
        file_id=report.file.id,
        status=report.status.value,
        versions=[
            VersionIntegrityOut(**vars(v) | {"status": v.status.value}) for v in report.versions
        ],
        audit=AuditRef.build(report.audit_event),  # type: ignore[arg-type]
    )


# --- sharing and permission management (SHARE / MANAGE_PERMISSIONS) ------------------------------


@router.get("/{file_id}/permissions", response_model=GrantListOut)
def list_permissions(file_id: uuid.UUID, service: Service) -> GrantListOut:
    file, grants = service.list_grants(file_id)
    return GrantListOut(file_id=file.id, grants=[GrantOut.build(g) for g in grants])


@router.get("/{file_id}/permissions/history", response_model=GrantListOut)
def permission_history(file_id: uuid.UUID, service: Service) -> GrantListOut:
    file, grants = service.grant_history(file_id)
    return GrantListOut(file_id=file.id, grants=[GrantOut.build(g) for g in grants])


@router.post(
    "/{file_id}/permissions", response_model=GrantResultOut, status_code=status.HTTP_201_CREATED
)
def share_file(file_id: uuid.UUID, body: GrantCreateIn, service: Service) -> GrantResultOut:
    result = service.grant(file_id, body)
    return GrantResultOut(
        grant=GrantOut.build(result.grant), audit=AuditRef.build(result.audit_event)
    )


@router.delete("/{file_id}/permissions/{grant_id}", response_model=GrantResultOut)
def revoke_permission(file_id: uuid.UUID, grant_id: uuid.UUID, service: Service) -> GrantResultOut:
    result = service.revoke(file_id, grant_id)
    return GrantResultOut(
        grant=GrantOut.build(result.grant), audit=AuditRef.build(result.audit_event)
    )


@router.put("/{file_id}/owner", response_model=FileOut)
def transfer_owner(file_id: uuid.UUID, body: OwnerTransferIn, service: Service) -> FileOut:
    return _out(service.transfer_owner(file_id, body.owner_id, body.reason))
