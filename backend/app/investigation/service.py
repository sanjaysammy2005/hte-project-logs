"""File security investigation (ZERO_TRUST_FILE_MODULE §29).

The chained ``audit_events`` of the ``system`` stream are the only audit trail used here; there
is no second log. Everything in this module is read-only: it searches events, explains their
place in the hash chain and Merkle batches, re-verifies them, and correlates file versions with
the events that anchor them.

Two different security conditions are kept apart:

* **FILE INTEGRITY FAILURE** — a file's stored bytes, or its stored SHA-256, no longer agree
  with what an *intact* audit event recorded (layers L1/L2 of §12.2).
* **AUDIT LOG INTEGRITY FAILURE** — the audit evidence itself fails verification: an event's
  hash, its links to neighbours, its Merkle batch, or the stream as a whole (layer L3 and the
  paper's verification engine).

A file can be damaged while the log is intact (someone edited the blob), and the log can be
damaged while files are intact (someone edited an event). Both can happen together.
"""

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Select, and_, func, select
from sqlalchemy.orm import Session

from app.auth.service import get_system_stream
from app.batching.service import StreamInconsistentError, batch_for, proof_for
from app.crypto.canonical import CanonicalizationError, format_timestamp
from app.crypto.chain import compute_entry_hash
from app.crypto.merkle import merkle_root, verify_proof
from app.db.models import AuditEvent, File, FileVersion, LogStream
from app.files.storage import BlobNotFoundError, InvalidStorageKeyError, StorageBackend
from app.ingestion.service import to_chained
from app.provenance.checks import check_provenance
from app.provenance.rules import TransitionRules
from app.verification.engine import build_report, load_stream

FILE_INTEGRITY_FAILURE = "FILE_INTEGRITY_FAILURE"
AUDIT_LOG_INTEGRITY_FAILURE = "AUDIT_LOG_INTEGRITY_FAILURE"

# Investigation categories → event types (all are chained platform events).
CATEGORIES: dict[str, tuple[str, ...]] = {
    "denied": ("FILE_ACCESS_DENIED",),
    "unauthenticated": ("UNAUTHENTICATED_ACCESS",),
    "integrity": ("FILE_INTEGRITY_FAILURE", "FILE_INTEGRITY_CHECK"),
    "permissions": (
        "FILE_SHARED",
        "FILE_SHARE_REVOKED",
        "FILE_PERMISSION_GRANTED",
        "FILE_PERMISSION_REVOKED",
        "FILE_ACCESS_POLICY_CHANGED",
    ),
    "deletion": ("FILE_DELETE", "FILE_PURGE"),
    "restoration": ("FILE_VERSION_RESTORED", "FILE_UNDELETE"),
    "replacement": ("FILE_VERSION_CREATED",),
    "access": ("FILE_VIEW", "FILE_DOWNLOAD"),
    "authentication": ("REAUTHENTICATION", "REAUTHENTICATION_FAILED", "SECURITY_VIOLATION"),
}
SECURITY_EVENT_TYPES = tuple(sorted({t for types in CATEGORIES.values() for t in types} | {
    "FILE_UPLOAD", "FILE_RENAME", "FILE_UPDATE",
}))  # fmt: skip


@dataclass(frozen=True)
class EventQuery:
    user: str | None = None
    file_id: uuid.UUID | None = None
    action: str | None = None
    decision: str | None = None
    classification: str | None = None
    event_types: tuple[str, ...] = ()
    category: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    before_chain_index: int | None = None  # cursor: newest first
    limit: int = 50


def _payload(key: str):
    return AuditEvent.event_payload[key].astext


class Investigation:
    def __init__(self, db: Session, storage: StorageBackend, rules: TransitionRules) -> None:
        self.db = db
        self.storage = storage
        self.rules = rules
        self.stream: LogStream = get_system_stream(db)

    # --- search -----------------------------------------------------------------------------------

    def _base(self) -> Select:
        return select(AuditEvent).where(AuditEvent.stream_id == self.stream.id)

    def search(self, q: EventQuery) -> tuple[list[AuditEvent], int | None]:
        stmt = self._base()
        types = set(q.event_types) or set(SECURITY_EVENT_TYPES)
        if q.category:
            types &= set(CATEGORIES[q.category])
        stmt = stmt.where(AuditEvent.event_type.in_(sorted(types)))
        if q.user:
            stmt = stmt.where(AuditEvent.actor_user_id == q.user)
        if q.file_id:
            stmt = stmt.where(_payload("file_id") == str(q.file_id))
        if q.action:
            stmt = stmt.where(_payload("action") == q.action)
        if q.decision:
            stmt = stmt.where(_payload("decision") == q.decision)
        if q.classification:
            stmt = stmt.where(_payload("classification") == q.classification)
        if q.since:
            stmt = stmt.where(AuditEvent.event_timestamp >= q.since)
        if q.until:
            stmt = stmt.where(AuditEvent.event_timestamp <= q.until)
        if q.before_chain_index:
            stmt = stmt.where(AuditEvent.chain_index < q.before_chain_index)
        rows = list(
            self.db.scalars(stmt.order_by(AuditEvent.chain_index.desc()).limit(q.limit + 1))
        )
        cursor = rows[q.limit - 1].chain_index if len(rows) > q.limit else None
        return rows[: q.limit], cursor

    def event(self, chain_index: int) -> AuditEvent | None:
        return self.db.scalars(self._base().where(AuditEvent.chain_index == chain_index)).first()

    # --- one event: chain, batch, provenance ------------------------------------------------------

    def chain_relationship(self, event: AuditEvent) -> dict[str, Any]:
        predecessor = self.event(event.chain_index - 1) if event.chain_index > 1 else None
        successor = self.event(event.chain_index + 1)
        expected_prev = (
            bytes(predecessor.entry_hash) if predecessor else bytes(self.stream.genesis_hash)
        )
        try:
            recomputed = compute_entry_hash(to_chained(event).record, bytes(event.prev_hash))
            recomputed_hex: str | None = recomputed.hex()
        except CanonicalizationError:
            recomputed_hex = None
        hash_ok = recomputed_hex == bytes(event.entry_hash).hex()
        has_predecessor = predecessor is not None or event.chain_index == 1
        link_ok = has_predecessor and bytes(event.prev_hash) == expected_prev
        successor_ok = (
            None if successor is None else bytes(successor.prev_hash) == bytes(event.entry_hash)
        )
        status = "VALID" if hash_ok and link_ok and successor_ok is not False else "BROKEN"
        return {
            "status": status,
            "stored_hash": bytes(event.entry_hash).hex(),
            "recomputed_hash": recomputed_hex,
            "hash_matches": hash_ok,
            "prev_hash": bytes(event.prev_hash).hex(),
            "predecessor": {
                "chain_index": predecessor.chain_index if predecessor else None,
                "entry_hash": expected_prev.hex(),
                "is_genesis": predecessor is None and event.chain_index == 1,
                "missing": predecessor is None and event.chain_index > 1,
            },
            "link_matches": link_ok,
            "successor": None
            if successor is None
            else {
                "chain_index": successor.chain_index,
                "prev_hash": bytes(successor.prev_hash).hex(),
                "links_back": successor_ok,
            },
        }

    def merkle_status(self, event: AuditEvent) -> dict[str, Any]:
        batch = batch_for(self.db, self.stream, event.chain_index)
        if batch is None:
            return {"status": "UNSEALED", "batch": None}
        info = {
            "batch_id": str(batch.id),
            "batch_index": batch.batch_index,
            "first_chain_index": batch.first_chain_index,
            "last_chain_index": batch.last_chain_index,
            "leaf_count": batch.leaf_count,
            "stored_root": bytes(batch.merkle_root).hex(),
        }
        rows = list(
            self.db.scalars(
                self._base()
                .where(
                    AuditEvent.chain_index >= batch.first_chain_index,
                    AuditEvent.chain_index <= batch.last_chain_index,
                )
                .order_by(AuditEvent.chain_index)
            )
        )
        if len(rows) != batch.leaf_count:
            return {"status": "RANGE_INCONSISTENT", "batch": info, "records_present": len(rows)}
        try:
            leaves = [compute_entry_hash(to_chained(r).record, bytes(r.prev_hash)) for r in rows]
        except CanonicalizationError:
            return {"status": "ROOT_MISMATCH", "batch": info, "recomputed_root": None}
        recomputed_root = merkle_root(leaves)
        root_ok = recomputed_root == bytes(batch.merkle_root)
        try:
            leaf, proof = proof_for(self.db, self.stream, batch, event.chain_index)
            proof_ok = verify_proof(
                leaves[event.chain_index - batch.first_chain_index], proof, bytes(batch.merkle_root)
            )
            proof_out = [{"sibling": s.sibling.hex(), "position": s.position} for s in proof]
        except StreamInconsistentError:
            proof_ok, proof_out = False, []
        return {
            "status": "VALID" if root_ok and proof_ok else "ROOT_MISMATCH",
            "batch": info,
            "recomputed_root": recomputed_root.hex(),
            "proof": proof_out,
            "proof_valid": proof_ok,
        }

    def provenance_status(self, event: AuditEvent) -> dict[str, Any]:
        """The paper's five checks for this event within its session (sessionless: N/A)."""
        if event.session_id is None:
            return {"status": "NOT_APPLICABLE", "findings": []}
        session = list(
            self.db.scalars(
                self._base()
                .where(AuditEvent.session_id == event.session_id)
                .order_by(AuditEvent.chain_index)
            )
        )
        result = check_provenance([to_chained(r) for r in session], self.rules)
        mine = [
            {"check": str(f.check), "expected": f.expected, "actual": f.actual}
            for f in result.findings
            if f.chain_index == event.chain_index and str(f.check) != "PROV_TIMESTAMP_ORDER"
        ]
        return {
            "status": "VALID" if not mine else "BROKEN",
            "session_events": len(session),
            "findings": mine,
        }

    def verify_event(self, event: AuditEvent) -> dict[str, Any]:
        chain = self.chain_relationship(event)
        merkle = self.merkle_status(event)
        provenance = self.provenance_status(event)
        broken = (
            chain["status"] != "VALID"
            or merkle["status"] in ("ROOT_MISMATCH", "RANGE_INCONSISTENT")
            or provenance["status"] == "BROKEN"
        )
        return {
            "chain_index": event.chain_index,
            "status": AUDIT_LOG_INTEGRITY_FAILURE if broken else "VALID",
            "chain": chain,
            "merkle": merkle,
            "provenance": provenance,
            "note": "Unsealed events are protected by the hash chain only."
            if merkle["status"] == "UNSEALED"
            else None,
        }

    # --- files ------------------------------------------------------------------------------------

    def file(self, file_id: uuid.UUID) -> File | None:
        return self.db.get(File, file_id)

    def file_versions(self, file: File) -> list[FileVersion]:
        return list(
            self.db.scalars(
                select(FileVersion)
                .where(FileVersion.file_id == file.id)
                .order_by(FileVersion.version_number)
            )
        )

    def file_timeline(self, file_id: uuid.UUID, limit: int = 500) -> list[AuditEvent]:
        return list(
            self.db.scalars(
                self._base()
                .where(_payload("file_id") == str(file_id))
                .order_by(AuditEvent.chain_index)
                .limit(limit)
            )
        )

    def file_integrity(self, file: File) -> dict[str, Any]:
        """Investigate one file: what its bytes, its stored hash and its anchoring audit events
        say, kept apart as file integrity versus audit-log integrity."""
        versions = []
        for v in self.file_versions(file):
            expected = bytes(v.sha256).hex()
            actual, content = self._blob_hash(v)
            anchor = (
                self.event(v.audit_chain_index) if v.audit_stream_id == self.stream.id else None
            )
            anchored = (anchor.event_payload or {}).get("sha256") if anchor else None
            anchor_report = self.verify_event(anchor) if anchor else None
            anchor_ok = anchor_report is not None and anchor_report["status"] == "VALID"
            matches_anchor = (
                anchor is not None
                and anchored == expected
                and (anchor.event_payload or {}).get("file_id") == str(file.id)
                and (anchor.event_payload or {}).get("version") == v.version_number
            )
            if content != "OK":
                file_status = content  # CONTENT_MISMATCH / BLOB_MISSING
            elif anchor_ok and not matches_anchor:
                file_status = "METADATA_MISMATCH"  # DB hash disagrees with an intact anchor
            else:
                file_status = "INTACT"
            versions.append(
                {
                    "version": v.version_number,
                    "expected_sha256": expected,  # what the database says
                    "anchored_sha256": anchored,  # what the chained event recorded
                    "actual_sha256": actual,  # what the stored bytes hash to now
                    "file_status": file_status,
                    "anchor_chain_index": v.audit_chain_index,
                    "anchor_status": (
                        "MISSING"
                        if anchor is None
                        else "VALID"
                        if anchor_ok
                        else AUDIT_LOG_INTEGRITY_FAILURE
                    ),
                    "anchor_chain_status": anchor_report["chain"]["status"]
                    if anchor_report
                    else None,
                    "anchor_merkle_status": anchor_report["merkle"]["status"]
                    if anchor_report
                    else None,
                }
            )
        file_failures = [v for v in versions if v["file_status"] != "INTACT"]
        audit_failures = [v for v in versions if v["anchor_status"] != "VALID"]
        stream = self.stream_status()
        first_file = file_failures[0] if file_failures else None
        return {
            "file_id": str(file.id),
            "display_name": file.display_name,
            "classification": file.classification,
            "file_integrity": {
                "status": FILE_INTEGRITY_FAILURE if file_failures else "INTACT",
                "first_affected_version": first_file["version"] if first_file else None,
                # The event that recorded the hash the file no longer matches.
                "first_affected_audit_event": first_file["anchor_chain_index"]
                if first_file
                else None,
            },
            "audit_log_integrity": {
                "status": AUDIT_LOG_INTEGRITY_FAILURE
                if audit_failures or stream["status"] != "VALID"
                else "VALID",
                "anchors_failing": [v["anchor_chain_index"] for v in audit_failures],
                "stream": stream,
            },
            "versions": versions,
        }

    def _blob_hash(self, v: FileVersion) -> tuple[str | None, str]:
        try:
            with self.storage.open(v.storage_key) as blob:
                data = blob.read(v.size_bytes + 1)
        except (BlobNotFoundError, InvalidStorageKeyError):
            return None, "BLOB_MISSING"
        actual = hashlib.sha256(data).hexdigest()
        ok = actual == bytes(v.sha256).hex() and len(data) == v.size_bytes
        return actual, "OK" if ok else "CONTENT_MISMATCH"

    def stream_status(self) -> dict[str, Any]:
        """Full verification of the system stream (not persisted): the paper's engine."""
        records, batches = load_stream(self.db, self.stream)
        report = build_report(records, batches, bytes(self.stream.genesis_hash), self.rules)
        first = report.first_failure
        return {
            "status": report.status,
            "records_checked": report.records_checked,
            "unbatched_records": report.unbatched_records,
            "failed_by_check": report.failed_by_check,
            "first_affected_audit_event": first.chain_index if first else None,
            "first_failed_check": first.check if first else None,
            "first_failing_batch_index": first.batch_index if first else None,
        }

    # --- findings (heuristics) --------------------------------------------------------------------

    def findings(self, since: datetime, until: datetime, threshold: int) -> dict[str, Any]:
        """Patterns worth a look. Heuristics over chained events, not threat detection."""
        window = and_(
            AuditEvent.stream_id == self.stream.id,
            AuditEvent.event_timestamp >= since,
            AuditEvent.event_timestamp <= until,
        )

        def per_user(event_type: str, extra=None) -> list[dict[str, Any]]:
            cond = and_(window, AuditEvent.event_type == event_type)
            if extra is not None:
                cond = and_(cond, extra)
            rows = self.db.execute(
                select(
                    AuditEvent.actor_user_id,
                    func.count(),
                    func.count(func.distinct(_payload("file_id"))),
                    func.min(AuditEvent.event_timestamp),
                    func.max(AuditEvent.event_timestamp),
                    func.min(AuditEvent.chain_index),
                )
                .where(cond)
                .group_by(AuditEvent.actor_user_id)
                .having(func.count() >= threshold)
                .order_by(func.count().desc())
            ).all()
            return [
                {
                    "user": user,
                    "count": count,
                    "distinct_files": files,
                    "first_seen": format_timestamp(first),
                    "last_seen": format_timestamp(last),
                    "first_chain_index": first_index,
                }
                for user, count, files, first, last, first_index in rows
            ]

        def events(cond) -> list[dict[str, Any]]:
            rows = self.db.scalars(
                self._base().where(window, cond).order_by(AuditEvent.chain_index)
            )
            return [summary(e) for e in rows]

        return {
            "window": {"since": format_timestamp(since), "until": format_timestamp(until)},
            "threshold": threshold,
            "repeated_denials": per_user("FILE_ACCESS_DENIED"),
            "unauthenticated_attempts": per_user("UNAUTHENTICATED_ACCESS"),
            "high_frequency_downloads": per_user("FILE_DOWNLOAD"),
            "probing_unknown_or_hidden_files": per_user(
                "FILE_ACCESS_DENIED",
                AuditEvent.event_payload["signals"]["discoverable"].astext == "false",
            ),
            "integrity_failures": events(AuditEvent.event_type == "FILE_INTEGRITY_FAILURE"),
            "break_glass_self_grants": events(
                and_(
                    AuditEvent.event_type == "FILE_SHARED",
                    AuditEvent.event_payload["signals"]["self_grant"].astext == "true",
                )
            ),
            "classification_downgrades": events(
                and_(
                    AuditEvent.event_type == "FILE_ACCESS_POLICY_CHANGED",
                    _payload("downgrade") == "true",
                )
            ),
            "deletions": events(AuditEvent.event_type.in_(CATEGORIES["deletion"])),
            "failed_reauthentications": events(AuditEvent.event_type == "REAUTHENTICATION_FAILED"),
            "provenance_violations": events(AuditEvent.event_type == "SECURITY_VIOLATION"),
        }


def summary(e: AuditEvent) -> dict[str, Any]:
    p = e.event_payload or {}
    return {
        "chain_index": e.chain_index,
        "event_type": e.event_type,
        "timestamp": format_timestamp(e.event_timestamp),
        "user": e.actor_user_id,
        "session_id": e.session_id,
        "file_id": p.get("file_id"),
        "filename": p.get("filename"),
        "classification": p.get("classification"),
        "action": p.get("action"),
        "decision": p.get("decision"),
        "reason_code": p.get("reason_code"),
        "rule": p.get("rule"),
    }


def default_window(now: datetime, hours: int = 24) -> tuple[datetime, datetime]:
    return now - timedelta(hours=hours), now
