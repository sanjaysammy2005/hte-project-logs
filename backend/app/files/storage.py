"""Storage abstraction for file contents (ZERO_TRUST_FILE_MODULE §6).

The rest of the application depends only on ``StorageBackend``. ``LocalFileStorage`` keeps
blobs on a local (Docker-mounted) directory; an S3-compatible backend could implement the same
four methods later.

Path safety does not rely on cleaning user input: a storage key is always a server-generated
UUID (32 lowercase hex characters), every key is checked against that pattern before a path is
built, and the resolved path must lie inside the storage root. User filenames never reach here.
"""

import hashlib
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

KEY_PATTERN = re.compile(r"[0-9a-f]{32}")
CHUNK_BYTES = 64 * 1024
_TMP_DIR = ".tmp"
_FILE_MODE = 0o640
_DIR_MODE = 0o750


class StorageError(Exception):
    """Base class for storage failures."""


class InvalidStorageKeyError(StorageError):
    """The key is not a server-generated key, or resolves outside the storage root."""


class BlobNotFoundError(StorageError):
    pass


class FileTooLargeError(StorageError):
    def __init__(self, max_bytes: int) -> None:
        super().__init__(f"file exceeds the maximum size of {max_bytes} bytes")
        self.max_bytes = max_bytes


@dataclass(frozen=True)
class StoredBlob:
    key: str
    sha256: bytes  # 32 raw bytes, computed over exactly the bytes written
    size_bytes: int


class StorageBackend(Protocol):
    def put(self, source: BinaryIO, max_bytes: int) -> StoredBlob: ...

    def open(self, key: str) -> BinaryIO: ...

    def exists(self, key: str) -> bool: ...

    def delete(self, key: str) -> None: ...


class LocalFileStorage:
    """Blobs at ``root/<key[:2]>/<key>``; writes are atomic (temp file + rename)."""

    def __init__(self, root: Path) -> None:
        root.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        self.root = root.resolve(strict=True)
        self._tmp = self.root / _TMP_DIR
        self._tmp.mkdir(mode=_DIR_MODE, exist_ok=True)

    def _path(self, key: str) -> Path:
        if not isinstance(key, str) or KEY_PATTERN.fullmatch(key) is None:
            raise InvalidStorageKeyError("invalid storage key")
        path = self.root / key[:2] / key
        # Defence in depth: a symlinked shard directory must not lead outside the root.
        if not path.parent.resolve().is_relative_to(self.root):
            raise InvalidStorageKeyError("storage key resolves outside the storage root")
        return path

    def put(self, source: BinaryIO, max_bytes: int) -> StoredBlob:
        """Stream ``source`` into a new blob, hashing and counting as it goes.

        Raises FileTooLargeError (nothing is kept) once more than ``max_bytes`` arrive; the
        declared size of an upload is never trusted.
        """
        key = uuid.uuid4().hex
        hasher = hashlib.sha256()
        size = 0
        tmp_path = self._tmp / secrets.token_hex(16)
        fd = os.open(
            tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), _FILE_MODE
        )
        try:
            with os.fdopen(fd, "wb") as out:
                while chunk := source.read(CHUNK_BYTES):
                    size += len(chunk)
                    if size > max_bytes:
                        raise FileTooLargeError(max_bytes)
                    hasher.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            final = self._path(key)
            final.parent.mkdir(mode=_DIR_MODE, exist_ok=True)
            os.replace(tmp_path, final)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        return StoredBlob(key, hasher.digest(), size)

    def open(self, key: str) -> BinaryIO:
        path = self._path(key)
        try:
            return path.open("rb")
        except FileNotFoundError as exc:
            raise BlobNotFoundError("blob not found") from exc

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def delete(self, key: str) -> None:
        """Remove a blob (used only by purge). Deleting a missing blob is not an error."""
        self._path(key).unlink(missing_ok=True)


def digest(source: BinaryIO) -> tuple[bytes, int]:
    """SHA-256 and size of everything readable from ``source`` (for integrity checks)."""
    hasher = hashlib.sha256()
    size = 0
    while chunk := source.read(CHUNK_BYTES):
        size += len(chunk)
        hasher.update(chunk)
    return hasher.digest(), size
