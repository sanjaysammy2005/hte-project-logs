"""Pydantic models for file-module requests and responses (ZERO_TRUST_FILE_MODULE §14).

Request models forbid unknown fields, so a client cannot smuggle in server-assigned values
(owner, uploader, hashes, version numbers, audit references). Response models are built from
rows explicitly and have no ``storage_key`` field, so the storage location can never leak.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Self

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from app.access.model import GRANTABLE_PERMISSIONS, Action, Classification, Permission, Role
from app.db.models import AuditEvent, File, FilePermission, FileVersion
from app.files.validation import FilenameError, clean_filename

# Free text: bounded, no NUL (PostgreSQL text cannot store it).
Description = Annotated[str, Field(max_length=1000, pattern=r"^[^\x00]*$")]
Reason = Annotated[str, Field(min_length=1, max_length=500, pattern=r"^[^\x00]*$")]


def _display_name(value: str) -> str:
    # The extension allowlist and "same extension as the file" rule need the file, so they are
    # checked by the service; here only the name's own safety is validated.
    try:
        return clean_filename(value).name
    except FilenameError as exc:
        raise ValueError(str(exc)) from exc


DisplayName = Annotated[str, Field(min_length=1, max_length=255), AfterValidator(_display_name)]


class FileCreateIn(BaseModel):
    """Form fields sent with a new upload (the filename comes from the uploaded part)."""

    model_config = ConfigDict(extra="forbid")
    classification: Classification
    description: Description | None = None


class FileUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: DisplayName | None = None
    description: Description | None = None
    classification: Classification | None = None
    reason: Reason | None = None  # required by the policy for classification downgrades

    @model_validator(mode="after")
    def _something_to_change(self) -> Self:
        if self.display_name is None and self.description is None and self.classification is None:
            raise ValueError("nothing to update")
        return self


class VersionCreateIn(BaseModel):
    """Form fields sent with a replacement upload."""

    model_config = ConfigDict(extra="forbid")
    base_version: int = Field(ge=1)  # optimistic check: the version the client last saw
    change_reason: Reason | None = None


class GrantCreateIn(BaseModel):
    """Grant permissions on one file to exactly one target: a user or a role."""

    model_config = ConfigDict(extra="forbid")
    grantee_id: uuid.UUID | None = None
    grantee_role: Role | None = None
    permissions: list[Permission] = Field(min_length=1, max_length=len(Permission))
    expires_at: AwareDatetime | None = None
    reason: Reason | None = None

    @model_validator(mode="after")
    def _grantable(self) -> Self:
        if (self.grantee_id is None) == (self.grantee_role is None):
            raise ValueError("give exactly one of grantee_id or grantee_role")
        not_grantable = set(self.permissions) - GRANTABLE_PERMISSIONS
        if not_grantable:
            raise ValueError(f"not grantable on a file: {', '.join(sorted(not_grantable))}")
        self.permissions = sorted(set(self.permissions))
        if self.expires_at is not None and self.expires_at <= datetime.now(UTC):
            raise ValueError("expires_at must be in the future")
        return self


class OwnerTransferIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner_id: uuid.UUID
    reason: Reason


class RestoreIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_version: int = Field(ge=1)
    reason: Reason | None = None


class AuditRef(BaseModel):
    """Where the chained event recording this operation is (system stream, chain index)."""

    stream_id: uuid.UUID
    chain_index: int
    event_type: str

    @classmethod
    def build(cls, event: AuditEvent | None) -> "AuditRef | None":
        if event is None:
            return None
        return cls(
            stream_id=event.stream_id, chain_index=event.chain_index, event_type=event.event_type
        )


class FileVersionOut(BaseModel):
    version_number: int
    sha256: str
    size_bytes: int
    mime_type: str
    original_filename: str
    uploaded_by: uuid.UUID
    created_at: datetime
    change_reason: str | None
    restored_from_version: int | None
    audit_stream_id: uuid.UUID
    audit_chain_index: int
    last_verified_at: datetime | None
    last_integrity_status: str | None

    @classmethod
    def build(cls, v: FileVersion) -> "FileVersionOut":
        return cls(
            version_number=v.version_number,
            sha256=bytes(v.sha256).hex(),
            size_bytes=v.size_bytes,
            mime_type=v.mime_type,
            original_filename=v.original_filename,
            uploaded_by=v.uploaded_by,
            created_at=v.created_at,
            change_reason=v.change_reason,
            restored_from_version=v.restored_from_version,
            audit_stream_id=v.audit_stream_id,
            audit_chain_index=v.audit_chain_index,
            last_verified_at=v.last_verified_at,
            last_integrity_status=v.last_integrity_status,
        )


class FileOut(BaseModel):
    id: uuid.UUID
    display_name: str
    extension: str
    mime_type: str
    classification: Classification
    owner_id: uuid.UUID
    created_by: uuid.UUID
    current_version: int
    description: str | None
    origin: str
    department: str | None
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None
    last_accessed_at: datetime | None
    current: FileVersionOut | None
    # What the backend would allow this caller to do right now; the UI only reflects it.
    allowed_actions: list[Action] = []
    audit: AuditRef | None = None

    @classmethod
    def build(
        cls,
        f: File,
        current: FileVersion | None,
        allowed_actions: list[Action] | None = None,
        audit_event: AuditEvent | None = None,
    ) -> "FileOut":
        return cls(
            id=f.id,
            display_name=f.display_name,
            extension=f.extension,
            mime_type=f.mime_type,
            classification=Classification(f.classification),
            owner_id=f.owner_id,
            created_by=f.created_by,
            current_version=f.current_version,
            description=f.description,
            origin=f.origin,
            department=f.department,
            created_at=f.created_at,
            updated_at=f.updated_at,
            deleted_at=f.deleted_at,
            last_accessed_at=f.last_accessed_at,
            current=FileVersionOut.build(current) if current is not None else None,
            allowed_actions=allowed_actions or [],
            audit=AuditRef.build(audit_event),
        )


class FileListOut(BaseModel):
    items: list[FileOut]
    total: int
    limit: int
    offset: int


class VersionListOut(BaseModel):
    file_id: uuid.UUID
    current_version: int
    versions: list[FileVersionOut]
    audit: AuditRef | None = None


class VersionIntegrityOut(BaseModel):
    version: int
    status: str
    content: str
    anchor: str
    evidence: str
    expected_sha256: str
    actual_sha256: str | None
    anchor_chain_index: int


class IntegrityReportOut(BaseModel):
    file_id: uuid.UUID
    status: str
    versions: list[VersionIntegrityOut]
    audit: AuditRef


class GrantOut(BaseModel):
    id: uuid.UUID
    file_id: uuid.UUID
    grantee_id: uuid.UUID | None
    grantee_role: Role | None
    permissions: list[Permission]
    granted_by: uuid.UUID
    reason: str | None
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    revoked_by: uuid.UUID | None
    audit_chain_index: int
    revoked_audit_chain_index: int | None

    @classmethod
    def build(cls, g: FilePermission) -> "GrantOut":
        return cls(
            id=g.id,
            file_id=g.file_id,
            grantee_id=g.grantee_id,
            grantee_role=Role(g.grantee_role) if g.grantee_role else None,
            permissions=[Permission(p) for p in g.permissions],
            granted_by=g.granted_by,
            reason=g.reason,
            created_at=g.created_at,
            expires_at=g.expires_at,
            revoked_at=g.revoked_at,
            revoked_by=g.revoked_by,
            audit_chain_index=g.audit_chain_index,
            revoked_audit_chain_index=g.revoked_audit_chain_index,
        )


class GrantListOut(BaseModel):
    file_id: uuid.UUID
    grants: list[GrantOut]


class GrantResultOut(BaseModel):
    grant: GrantOut
    audit: AuditRef
