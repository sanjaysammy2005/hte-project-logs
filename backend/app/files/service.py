"""Secure file lifecycle and sharing (ZERO_TRUST_FILE_MODULE §9, §11, §12, §13).

Every operation follows the same shape:

    load (row-locked for mutations) → enforcer.require*() → chained event → mutate → one commit

This module contains no authorization rules. It asks ``PolicyEnforcer`` (app/access/enforcer.py),
which asks the pure policy (app/access/policy.py) and records the decision in the audit chain.

* **No change without its audit event.** An ALLOW is recorded in the *same transaction* as the
  change, so a change that rolls back leaves no event and an event never describes a change
  that did not happen. A DENY is committed on its own: the operation never ran.
* **File IDs from the client are only lookup keys**; possession of an ID grants nothing.
* **Lock order** is fixed: the file row (SELECT … FOR UPDATE) first, then the audit stream's
  advisory lock (inside append_event). Versions are never overwritten: a replacement names the
  version it replaces (``base_version``) and gets the next number.
* **Content** is validated before it reaches storage, stored under a server-generated key, and
  re-hashed before every download; mismatching bytes are never served.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, BinaryIO

from sqlalchemy import Select, case, func, select
from sqlalchemy.orm import Session

from app.access.audit import Actor, AuditTarget, audit_name
from app.access.enforcer import INLINE_EXTENSIONS, PolicyEnforcer
from app.access.model import Action, Classification, IntegrityStatus, Role
from app.access.policy import (
    AccountFacts,
    decide,
    decide_grant,
    decide_revoke,
    decide_role_grant,
    decide_transfer,
    update_actions,
)
from app.access.policy_file import AccessPolicy
from app.core.config import Settings
from app.core.errors import APIError
from app.db.models import AuditEvent, File, FilePermission, FileVersion, Operator
from app.files.integrity import IntegrityFailure, VersionIntegrity, check_version, read_verified
from app.files.schemas import FileCreateIn, FileUpdateIn, GrantCreateIn, VersionCreateIn
from app.files.storage import FileTooLargeError, StorageBackend, StoredBlob
from app.files.validation import (
    FilenameError,
    FileTypeError,
    SafeFilename,
    clean_filename,
    verify_content,
)
from app.provenance.rules import TransitionRules

METADATA_VISIBLE = "METADATA_VISIBLE"


@dataclass(frozen=True)
class ListQuery:
    scope: str = "all"  # all | mine | shared | recent | trash
    q: str | None = None
    classifications: tuple[Classification, ...] = ()
    extension: str | None = None
    owner_id: uuid.UUID | None = None
    uploader_id: uuid.UUID | None = None
    created_from: datetime | None = None
    created_to: datetime | None = None
    sort: str = "updated_at"
    order: str = "desc"
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class FileView:
    file: File
    current: FileVersion | None
    allowed_actions: list[Action]
    audit_event: AuditEvent | None = None


@dataclass(frozen=True)
class Content:
    data: bytes
    mime_type: str
    filename: str
    inline: bool
    audit_event: AuditEvent


@dataclass(frozen=True)
class IntegrityReport:
    file: File
    status: IntegrityStatus
    versions: list[VersionIntegrity]
    audit_event: AuditEvent


@dataclass(frozen=True)
class GrantResult:
    grant: FilePermission
    audit_event: AuditEvent


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class FileService:
    def __init__(
        self,
        db: Session,
        storage: StorageBackend,
        settings: Settings,
        policy: AccessPolicy,
        rules: TransitionRules,
        actor: Actor,
        clock: Callable[[], datetime],
    ) -> None:
        self.db = db
        self.storage = storage
        self.settings = settings
        self.policy = policy
        self.actor = actor
        self.clock = clock
        self.access = PolicyEnforcer(db, policy, rules, actor, clock)

    # --- loading -------------------------------------------------------------------------------

    def _load(self, file_id: uuid.UUID, lock: bool = False) -> File | None:
        query = select(File).where(
            File.id == file_id, File.origin != "lab", File.purged_at.is_(None)
        )
        if lock:
            query = query.with_for_update()
        return self.db.scalars(query).first()

    def _current(self, file: File) -> FileVersion:
        return self._version(file, file.current_version)  # type: ignore[return-value]

    def _version(self, file: File, number: int) -> FileVersion | None:
        return self.db.scalars(
            select(FileVersion).where(
                FileVersion.file_id == file.id, FileVersion.version_number == number
            )
        ).first()

    def _view(
        self, file: File, version: FileVersion | None, event: AuditEvent | None = None
    ) -> FileView:
        return FileView(file, version, self.access.allowed_actions(file), event)

    # --- upload validation -----------------------------------------------------------------------

    def _validated_upload(
        self, filename: str | None, source: BinaryIO, size: int | None
    ) -> tuple[SafeFilename, str]:
        """Name, size and content checks. Nothing reaches storage before these pass."""
        try:
            name = clean_filename(
                filename or "", self.settings.allowed_extensions, from_upload=True
            )
        except FilenameError as exc:
            status = 415 if exc.code == "UNSUPPORTED_FILE_TYPE" else 422
            raise APIError(status, exc.code, str(exc)) from exc
        if size is None or size > self.settings.max_upload_bytes:
            raise APIError(
                413,
                "FILE_TOO_LARGE",
                f"Files may be at most {self.settings.max_upload_bytes} bytes",
                {"max_bytes": self.settings.max_upload_bytes},
            )
        try:
            rule = verify_content(source, name.extension)
        except FileTypeError as exc:
            status = 422 if exc.code == "EMPTY_FILE" else 415
            raise APIError(status, exc.code, str(exc)) from exc
        source.seek(0)
        return name, rule.mime_type

    def _store(self, source: BinaryIO) -> StoredBlob:
        try:
            return self.storage.put(source, self.settings.max_upload_bytes)
        except FileTooLargeError as exc:  # pragma: no cover - the size was checked just before
            raise APIError(
                413, "FILE_TOO_LARGE", str(exc), {"max_bytes": self.settings.max_upload_bytes}
            ) from exc
        except OSError as exc:
            raise APIError(503, "STORAGE_UNAVAILABLE", "File storage is unavailable") from exc

    def _discard(self, blob: StoredBlob) -> None:
        self.db.rollback()
        try:
            self.storage.delete(blob.key)
        except OSError:  # pragma: no cover - an orphan blob is harmless (never referenced)
            pass

    def _new_version_row(
        self,
        file: File,
        number: int,
        blob: StoredBlob,
        mime: str,
        original_filename: str,
        event: AuditEvent,
        change_reason: str | None = None,
        restored_from: int | None = None,
    ) -> FileVersion:
        version = FileVersion(
            file_id=file.id,
            version_number=number,
            storage_key=blob.key,
            sha256=blob.sha256,
            size_bytes=blob.size_bytes,
            mime_type=mime,
            original_filename=original_filename,
            uploaded_by=self.actor.operator.id,
            change_reason=change_reason,
            restored_from_version=restored_from,
            audit_stream_id=event.stream_id,
            audit_chain_index=event.chain_index,
        )
        self.db.add(version)
        self.db.flush()
        return version

    # --- create and read -------------------------------------------------------------------------

    def upload(
        self, filename: str | None, source: BinaryIO, size: int | None, meta: FileCreateIn
    ) -> FileView:
        decision = self.access.require(Action.CREATE, None, None)
        name, mime = self._validated_upload(filename, source, size)
        blob = self._store(source)
        file_id = uuid.uuid4()
        department = self.actor.operator.department
        try:
            target = AuditTarget(file_id, meta.classification, name.name)
            event = self.access.record_allow(
                "FILE_UPLOAD", Action.CREATE, decision, target,
                version=1, sha256=blob.sha256.hex(), size_bytes=blob.size_bytes, mime_type=mime,
                department=department,
            )  # fmt: skip
            me = self.actor.operator.id
            file = File(
                id=file_id,
                display_name=name.name,
                extension=name.extension,
                mime_type=mime,
                classification=meta.classification.value,
                owner_id=me,
                created_by=me,
                current_version=1,
                description=meta.description or None,
                department=department,
            )
            self.db.add(file)
            self.db.flush()
            version = self._new_version_row(file, 1, blob, mime, name.name, event)
            self.db.commit()
        except BaseException:
            self._discard(blob)
            raise
        return self._view(file, version, event)

    def list_files(self, query: ListQuery) -> tuple[list[FileView], int]:
        """Files the caller may discover, filtered, sorted and paged. Listing is not chained."""
        me = self.actor.operator.id
        stmt: Select = select(File).where(
            File.origin != "lab", File.purged_at.is_(None), self.access.visibility_clause()
        )
        stmt = stmt.where(
            File.deleted_at.is_not(None) if query.scope == "trash" else File.deleted_at.is_(None)
        )
        if query.scope == "mine":
            stmt = stmt.where(File.owner_id == me)
        elif query.scope == "shared":
            stmt = stmt.where(File.id.in_(self.access.granted_file_ids()), File.owner_id != me)
        elif query.scope == "recent":
            stmt = stmt.where(File.last_accessed_at.is_not(None))

        if query.q:
            stmt = stmt.where(File.display_name.ilike(f"%{_like_escape(query.q)}%", escape="\\"))
        if query.classifications:
            stmt = stmt.where(File.classification.in_([c.value for c in query.classifications]))
        if query.extension:
            stmt = stmt.where(File.extension == query.extension)
        if query.owner_id:
            stmt = stmt.where(File.owner_id == query.owner_id)
        if query.uploader_id:
            stmt = stmt.where(File.created_by == query.uploader_id)
        if query.created_from:
            stmt = stmt.where(File.created_at >= query.created_from)
        if query.created_to:
            stmt = stmt.where(File.created_at <= query.created_to)

        total = self.db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        size = (
            select(FileVersion.size_bytes)
            .where(
                FileVersion.file_id == File.id, FileVersion.version_number == File.current_version
            )
            .scalar_subquery()
        )
        rank = case({c.value: c.rank for c in Classification}, value=File.classification)
        sort_key = {
            "name": func.lower(File.display_name),
            "created_at": File.created_at,
            "updated_at": File.updated_at,
            "size": size,
            "classification": rank,
            "last_accessed": File.last_accessed_at,
        }[query.sort]
        if query.scope == "recent":
            sort_key = File.last_accessed_at
        ordered = (
            sort_key.desc().nulls_last() if query.order == "desc" else sort_key.asc().nulls_last()
        )
        rows = list(
            self.db.scalars(stmt.order_by(ordered, File.id).limit(query.limit).offset(query.offset))
        )
        grants = self.access.grants(f.id for f in rows)
        versions = {
            (v.file_id, v.version_number): v
            for v in self.db.scalars(
                select(FileVersion).where(FileVersion.file_id.in_([f.id for f in rows]))
            )
        }
        views = [
            FileView(
                f,
                versions.get((f.id, f.current_version)),
                self.access.allowed_actions(f, grants.get(f.id, frozenset())),
            )
            for f in rows
        ]
        return views, total

    def _metadata_view_event(self, file: File, scope: str) -> AuditEvent | None:
        """Chain metadata views of files whose level requires it (RESTRICTED+ by default)."""
        if not self.policy.levels[Classification(file.classification)].audit_metadata_views:
            return None
        body = self.access.payload(
            self.access.target(file), Action.VIEW, None,
            decision="ALLOW", reason_code=METADATA_VISIBLE, rule="metadata_visibility",
            scope=scope,
        )  # fmt: skip
        event = self.access.record("FILE_VIEW", body)
        self.db.commit()
        return event

    def detail(self, file_id: uuid.UUID) -> FileView:
        file = self.access.require_visible(file_id, self._load(file_id), "metadata")
        event = self._metadata_view_event(file, "metadata")
        return self._view(file, self._current(file), event)

    def versions(self, file_id: uuid.UUID) -> tuple[File, list[FileVersion], AuditEvent | None]:
        file = self.access.require_visible(file_id, self._load(file_id), "versions")
        event = self._metadata_view_event(file, "versions")
        rows = list(
            self.db.scalars(
                select(FileVersion)
                .where(FileVersion.file_id == file.id)
                .order_by(FileVersion.version_number.desc())
            )
        )
        return file, rows, event

    def _integrity_failure(
        self, file: File, version: FileVersion, failure: IntegrityFailure, trigger: Action
    ) -> APIError:
        """Record a blocked read/restore as FILE_INTEGRITY_FAILURE and return the 409."""
        self.db.rollback()
        body = self.access.payload(
            self.access.target(file), trigger, None,
            decision="BLOCKED", reason_code=failure.status.value, version=version.version_number,
            expected_sha256=bytes(version.sha256).hex(), actual_sha256=failure.actual_sha256,
            trigger=trigger.value,
        )  # fmt: skip
        event = self.access.record("FILE_INTEGRITY_FAILURE", body)
        self.db.commit()
        return APIError(
            409,
            "INTEGRITY_FAILURE",
            "The stored content does not match its recorded SHA-256; it was not served.",
            {
                "status": failure.status.value,
                "version": version.version_number,
                "audit": {"stream_id": str(event.stream_id), "chain_index": event.chain_index},
            },
        )

    def content(self, file_id: uuid.UUID, inline: bool, version_number: int | None) -> Content:
        action = Action.VIEW if inline else Action.DOWNLOAD
        file = self._load(file_id)
        decision = self.access.require(action, file_id, file)
        assert file is not None
        if inline and file.extension not in INLINE_EXTENSIONS:
            raise APIError(
                415, "INLINE_NOT_SUPPORTED", f".{file.extension} files can only be downloaded"
            )
        version = self._version(file, version_number or file.current_version)
        if version is None:
            raise APIError(404, "VERSION_NOT_FOUND", "No such version of this file")
        try:
            data = read_verified(self.storage, version)  # verify-before-serve (L1)
        except IntegrityFailure as failure:
            raise self._integrity_failure(file, version, failure, action) from failure
        event = self.access.record_allow(
            "FILE_VIEW" if inline else "FILE_DOWNLOAD", action, decision, self.access.target(file),
            version=version.version_number, sha256=bytes(version.sha256).hex(),
            size_bytes=version.size_bytes, verified=True,
        )  # fmt: skip
        file.last_accessed_at = self.clock()
        self.db.commit()
        return Content(data, version.mime_type, file.display_name, inline, event)

    # --- change --------------------------------------------------------------------------------

    def update(self, file_id: uuid.UUID, body: FileUpdateIn) -> FileView:
        file = self._load(file_id, lock=True)
        if file is None:
            self.access.require(Action.UPDATE, file_id, None)  # always raises (404, chained)
        assert file is not None
        old_level = Classification(file.classification)
        new_name = body.display_name if body.display_name not in (None, file.display_name) else None
        new_description = (
            (body.description or None) if body.description is not None else file.description
        )
        description_changed = new_description != file.description
        new_level = body.classification if body.classification not in (None, old_level) else None

        actions = update_actions(old_level, new_level, new_name is not None, description_changed)
        decisions = [(a, self.access.require(a, file_id, file)) for a in actions]
        # Input checks come after authorization, so they cannot reveal anything about a file
        # the caller may not access.
        if not decisions:
            self.access.require_visible(file_id, file, "metadata")
            self.db.rollback()
            return self._view(file, self._current(file))
        if Action.MANAGE_PERMISSIONS in actions and not body.reason:
            raise APIError(422, "REASON_REQUIRED", "A classification downgrade needs a reason")
        if new_name is not None and clean_filename(new_name).extension != file.extension:
            raise APIError(
                422,
                "EXTENSION_CHANGE_NOT_ALLOWED",
                f"The name must keep the .{file.extension} extension; the file type is fixed.",
            )

        # Redact using the stricter of the old and new classification.
        strict = max(old_level, new_level or old_level, key=lambda c: c.rank)
        target = AuditTarget(file.id, strict, file.display_name)
        last_event = None
        for action, decision in decisions:
            if action is Action.RENAME:
                last_event = self.access.record_allow(
                    "FILE_RENAME", action, decision, target,
                    old_name=audit_name(self.policy, strict, file.display_name),
                    new_name=audit_name(self.policy, strict, new_name),
                )  # fmt: skip
            else:
                changes: dict[str, Any] = {}
                if description_changed:
                    changes["description"] = True
                if new_level is not None:
                    changes["classification"] = {"from": old_level.value, "to": new_level.value}
                # A classification change alters who may access the file: an access-policy change.
                event_type = "FILE_ACCESS_POLICY_CHANGED" if new_level else "FILE_UPDATE"
                last_event = self.access.record_allow(
                    event_type, action, decision, target,
                    changes=changes, reason=body.reason,
                    downgrade=action is Action.MANAGE_PERMISSIONS,
                    previous_state={"classification": old_level.value},
                    new_state={"classification": (new_level or old_level).value},
                )  # fmt: skip
        if new_name is not None:
            file.display_name = new_name
        file.description = new_description
        if new_level is not None:
            file.classification = new_level.value
        file.updated_at = self.clock()
        self.db.commit()
        return self._view(file, self._current(file), last_event)

    def delete(self, file_id: uuid.UUID) -> AuditEvent:
        file = self._load(file_id, lock=True)
        decision = self.access.require(Action.DELETE, file_id, file)
        assert file is not None
        event = self.access.record_allow(
            "FILE_DELETE", Action.DELETE, decision, self.access.target(file)
        )
        file.deleted_at = self.clock()
        file.deleted_by = self.actor.operator.id
        self.db.commit()
        return event

    @staticmethod
    def _check_base(file: File, base_version: int) -> None:
        if base_version != file.current_version:
            raise APIError(
                409,
                "VERSION_CONFLICT",
                "The file changed since you last saw it; reload and try again.",
                {"current_version": file.current_version, "base_version": base_version},
            )

    def new_version(
        self,
        file_id: uuid.UUID,
        filename: str | None,
        source: BinaryIO,
        size: int | None,
        meta: VersionCreateIn,
    ) -> FileView:
        file = self._load(file_id, lock=True)
        decision = self.access.require(Action.UPLOAD, file_id, file)
        assert file is not None
        self._check_base(file, meta.base_version)
        name, mime = self._validated_upload(filename, source, size)
        if name.extension != file.extension:
            raise APIError(
                415, "EXTENSION_MISMATCH", f"A new version must also be a .{file.extension} file"
            )
        blob = self._store(source)
        number = file.current_version + 1
        try:
            event = self.access.record_allow(
                "FILE_VERSION_CREATED", Action.UPLOAD, decision, self.access.target(file),
                version=number, previous_version=file.current_version,
                sha256=blob.sha256.hex(), size_bytes=blob.size_bytes, mime_type=mime,
                change_reason=meta.change_reason,
            )  # fmt: skip
            version = self._new_version_row(
                file, number, blob, mime, name.name, event, change_reason=meta.change_reason
            )
            file.current_version, file.mime_type, file.updated_at = number, mime, self.clock()
            self.db.commit()
        except BaseException:
            self._discard(blob)
            raise
        return self._view(file, version, event)

    def restore(
        self, file_id: uuid.UUID, number: int, base_version: int, reason: str | None
    ) -> FileView:
        file = self._load(file_id, lock=True)
        decision = self.access.require(Action.RESTORE, file_id, file)
        assert file is not None
        self._check_base(file, base_version)
        old = self._version(file, number)
        if old is None:
            raise APIError(404, "VERSION_NOT_FOUND", "No such version of this file")
        if number == file.current_version:
            raise APIError(409, "ALREADY_CURRENT", "That version is already the current one")
        try:
            read_verified(self.storage, old)  # never restore content that no longer matches
        except IntegrityFailure as failure:
            raise self._integrity_failure(file, old, failure, Action.RESTORE) from failure

        new_number = file.current_version + 1
        event = self.access.record_allow(
            "FILE_VERSION_RESTORED", Action.RESTORE, decision, self.access.target(file),
            version=new_number, previous_version=file.current_version, restored_from=number,
            sha256=bytes(old.sha256).hex(), size_bytes=old.size_bytes, reason=reason,
        )  # fmt: skip
        blob = StoredBlob(old.storage_key, bytes(old.sha256), old.size_bytes)
        version = self._new_version_row(
            file, new_number, blob, old.mime_type, old.original_filename, event,
            change_reason=reason, restored_from=number,
        )  # fmt: skip
        file.current_version = new_number
        file.mime_type = old.mime_type
        file.updated_at = self.clock()
        self.db.commit()
        return self._view(file, version, event)

    def verify(self, file_id: uuid.UUID, version_number: int | None) -> IntegrityReport:
        file = self._load(file_id)
        decision = self.access.require(Action.VERIFY, file_id, file)
        assert file is not None
        query = select(FileVersion).where(FileVersion.file_id == file.id)
        if version_number is not None:
            query = query.where(FileVersion.version_number == version_number)
        rows = list(self.db.scalars(query.order_by(FileVersion.version_number)))
        if not rows:
            raise APIError(404, "VERSION_NOT_FOUND", "No such version of this file")

        results = [check_version(self.db, self.storage, file, v) for v in rows]
        status = next(
            (r.status for r in results if r.status is not IntegrityStatus.INTACT),
            IntegrityStatus.INTACT,
        )
        intact = status is IntegrityStatus.INTACT
        event = self.access.record_allow(
            "FILE_INTEGRITY_CHECK" if intact else "FILE_INTEGRITY_FAILURE",
            Action.VERIFY, decision, self.access.target(file),
            status=status.value,
            versions=[
                {"version": r.version, "status": r.status.value, "content": r.content,
                 "anchor": r.anchor, "evidence": r.evidence}
                for r in results
            ],
        )  # fmt: skip
        now = self.clock()
        for row, result in zip(rows, results, strict=True):
            row.last_verified_at, row.last_integrity_status = now, result.status.value
        self.db.commit()
        return IntegrityReport(file, status, results, event)

    # --- sharing and permission management -----------------------------------------------------
    #
    # Event types: a grant to a user is a share (FILE_SHARED / FILE_SHARE_REVOKED); a grant to a
    # role is a permission assignment (FILE_PERMISSION_GRANTED / FILE_PERMISSION_REVOKED);
    # ownership transfer and classification changes are FILE_ACCESS_POLICY_CHANGED. Each event
    # names the target, the permissions, the previous and the new state, and the decision; the
    # chained context adds actor, session and timestamp.

    def _account(self, operator_id: uuid.UUID) -> tuple[Operator | None, AccountFacts]:
        account = self.db.get(Operator, operator_id)
        if account is None:
            # Unknown users are simply ineligible; the denial does not say whether they exist.
            return None, AccountFacts(operator_id, Role.INGESTOR, False)
        return account, AccountFacts(account.id, Role(account.role), account.is_active)

    @staticmethod
    def _target_of(row: FilePermission) -> dict[str, Any]:
        if row.grantee_role is not None:
            return {"type": "role", "role": row.grantee_role}
        return {"type": "user", "id": str(row.grantee_id)}

    @staticmethod
    def _state(row: FilePermission | None) -> dict[str, Any]:
        if row is None:
            return {"grant_id": None, "permissions": []}
        return {
            "grant_id": str(row.id),
            "permissions": list(row.permissions),
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        }

    def list_grants(self, file_id: uuid.UUID) -> tuple[File, list[FilePermission]]:
        """Current (active) grants. Owners and permission managers see all of them; anyone else
        who can see the file sees only grants they issued or that reach them."""
        file = self.access.require_visible(file_id, self._load(file_id), "permissions")
        query = select(FilePermission).where(
            FilePermission.file_id == file.id, FilePermission.revoked_at.is_(None)
        )
        if not self._can_see_all_grants(file):
            me = self.actor.operator
            query = query.where(
                (FilePermission.granted_by == me.id)
                | (FilePermission.grantee_id == me.id)
                | (FilePermission.grantee_role == me.role)
            )
        rows = list(self.db.scalars(query.order_by(FilePermission.created_at)))
        self._metadata_view_event(file, "permissions")
        return file, rows

    def _can_see_all_grants(self, file: File) -> bool:
        return (
            file.owner_id == self.actor.operator.id
            or self.access.decide(Action.MANAGE_PERMISSIONS, file).allowed
        )

    def grant_history(self, file_id: uuid.UUID) -> tuple[File, list[FilePermission]]:
        """Every grant ever made on the file, including revoked and superseded ones, each with
        the chain index of the event that created it and of the event that revoked it."""
        file = self.access.require_visible(file_id, self._load(file_id), "permission_history")
        if not self._can_see_all_grants(file):
            self.access.require(Action.MANAGE_PERMISSIONS, file_id, file)  # raises (chained)
        rows = list(
            self.db.scalars(
                select(FilePermission)
                .where(FilePermission.file_id == file.id)
                .order_by(FilePermission.created_at, FilePermission.id)
            )
        )
        self._metadata_view_event(file, "permission_history")
        return file, rows

    def grant(self, file_id: uuid.UUID, body: GrantCreateIn) -> GrantResult:
        """Create a grant, or replace the target's active grant (previous state is recorded)."""
        file = self._load(file_id, lock=True)
        if file is None:
            self.access.require(Action.SHARE, file_id, None)  # always raises (404, chained)
        assert file is not None
        permissions = frozenset(body.permissions)
        facts, grants, context = self.access.file_inputs(file)
        if body.grantee_role is not None:
            target_info: dict[str, Any] = {"type": "role", "role": body.grantee_role.value}
            decision = decide_role_grant(
                self.policy, self.access.principal, facts, grants, context,
                body.grantee_role, permissions,
            )  # fmt: skip
            action, granted = Action.MANAGE_PERMISSIONS, "FILE_PERMISSION_GRANTED"
            same_target = FilePermission.grantee_role == body.grantee_role.value
        else:
            grantee, grantee_facts = self._account(body.grantee_id)  # type: ignore[arg-type]
            target_info = {
                "type": "user",
                "id": str(body.grantee_id),
                "username": grantee.username if grantee else None,
            }
            decision = decide_grant(
                self.policy, self.access.principal, facts, grants, context, grantee_facts,
                permissions,
            )  # fmt: skip
            action, granted = Action.SHARE, "FILE_SHARED"
            same_target = FilePermission.grantee_id == body.grantee_id

        target = self.access.target(file)
        requested = {"grantee": target_info, "permissions": sorted(body.permissions)}
        self.access.require_decision(decision, action, target, **requested)
        level = self.policy.levels[Classification(file.classification)]
        if level.share_reason_required and not body.reason:
            raise APIError(
                422, "REASON_REQUIRED", f"Sharing {file.classification} files needs a reason"
            )
        previous = self.db.scalars(
            select(FilePermission)
            .where(
                FilePermission.file_id == file.id, same_target, FilePermission.revoked_at.is_(None)
            )
            .with_for_update()
        ).first()
        row = FilePermission(
            id=uuid.uuid4(),
            file_id=file.id,
            grantee_id=body.grantee_id,
            grantee_role=body.grantee_role.value if body.grantee_role else None,
            permissions=sorted(body.permissions),
            granted_by=self.actor.operator.id,
            reason=body.reason,
            expires_at=body.expires_at,
        )
        event = self.access.record_allow(
            granted, action, decision, target, **requested,
            change="MODIFY" if previous else "GRANT",
            previous_state=self._state(previous), new_state=self._state(row),
            reason=body.reason,
        )  # fmt: skip
        if previous is not None:  # superseded, never edited: the history stays complete
            previous.revoked_at = self.clock()
            previous.revoked_by = self.actor.operator.id
            previous.revoked_audit_chain_index = event.chain_index
            self.db.flush()
        row.audit_stream_id, row.audit_chain_index = event.stream_id, event.chain_index
        self.db.add(row)
        self.db.commit()
        return GrantResult(row, event)

    def revoke(self, file_id: uuid.UUID, grant_id: uuid.UUID) -> GrantResult:
        file = self._load(file_id, lock=True)
        if file is None:
            self.access.require(Action.MANAGE_PERMISSIONS, file_id, None)  # raises (404)
        assert file is not None
        row = self.db.scalars(
            select(FilePermission)
            .where(FilePermission.id == grant_id, FilePermission.file_id == file.id)
            .with_for_update()
        ).first()
        facts, grants, context = self.access.file_inputs(file)
        decision = decide_revoke(
            self.policy, self.access.principal, facts, grants, context,
            row.granted_by if row else uuid.UUID(int=0),
        )  # fmt: skip
        if row is not None and row.grantee_role is not None:
            # Role grants are created by permission managers only, so only they remove them.
            decision = decide(
                self.policy, self.access.principal, Action.MANAGE_PERMISSIONS, facts, grants,
                context,
            )  # fmt: skip
        target = self.access.target(file)
        self.access.require_decision(
            decision, Action.MANAGE_PERMISSIONS, target, grant_id=str(grant_id), change="REVOKE"
        )
        # Authorized; only now say whether the grant exists (it is scoped to this file).
        if row is None:
            raise APIError(404, "GRANT_NOT_FOUND", "No such grant on this file")
        if row.revoked_at is not None:
            raise APIError(409, "GRANT_ALREADY_REVOKED", "This grant was already revoked")
        event_type = "FILE_PERMISSION_REVOKED" if row.grantee_role else "FILE_SHARE_REVOKED"
        event = self.access.record_allow(
            event_type, Action.MANAGE_PERMISSIONS, decision, target,
            change="REVOKE", grantee=self._target_of(row), permissions=list(row.permissions),
            previous_state=self._state(row), new_state=self._state(None),
        )  # fmt: skip
        row.revoked_at, row.revoked_by = self.clock(), self.actor.operator.id
        row.revoked_audit_chain_index = event.chain_index
        self.db.commit()
        return GrantResult(row, event)

    def transfer_owner(self, file_id: uuid.UUID, new_owner_id: uuid.UUID, reason: str) -> FileView:
        file = self._load(file_id, lock=True)
        if file is None:
            self.access.require(Action.MANAGE_PERMISSIONS, file_id, None)  # raises (404)
        assert file is not None
        new_owner, owner_facts = self._account(new_owner_id)
        facts, grants, context = self.access.file_inputs(file)
        decision = decide_transfer(
            self.policy, self.access.principal, facts, grants, context, owner_facts
        )
        target = self.access.target(file)
        details = {
            "change": "OWNER_TRANSFER",
            "grantee": {"type": "user", "id": str(new_owner_id)},
        }
        self.access.require_decision(decision, Action.MANAGE_PERMISSIONS, target, **details)
        event = self.access.record_allow(
            "FILE_ACCESS_POLICY_CHANGED", Action.MANAGE_PERMISSIONS, decision, target, **details,
            previous_state={"owner_id": str(file.owner_id)},
            new_state={"owner_id": str(new_owner_id)}, reason=reason,
        )  # fmt: skip
        assert new_owner is not None  # eligibility was part of the decision
        file.owner_id = new_owner.id
        file.updated_at = self.clock()
        self.db.commit()
        return self._view(file, self._current(file), event)
