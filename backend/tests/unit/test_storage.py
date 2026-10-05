"""ZT-F3: local storage backend: confinement, atomic writes, size limit, hashing (§6)."""

import hashlib
import io
import os
import stat
from pathlib import Path

import pytest

from app.files.storage import (
    BlobNotFoundError,
    FileTooLargeError,
    InvalidStorageKeyError,
    LocalFileStorage,
    digest,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions and symlinks")


@pytest.fixture
def storage(tmp_path: Path) -> LocalFileStorage:
    return LocalFileStorage(tmp_path / "store")


def files_under(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def test_put_then_open_round_trip(storage: LocalFileStorage) -> None:
    data = os.urandom(200_000)  # several chunks
    blob = storage.put(io.BytesIO(data), max_bytes=1_000_000)

    assert blob.sha256 == hashlib.sha256(data).digest()  # independent oracle
    assert blob.size_bytes == len(data)
    with storage.open(blob.key) as stored:
        assert stored.read() == data
    assert storage.exists(blob.key)


def test_keys_are_random_server_generated_hex(storage: LocalFileStorage) -> None:
    a = storage.put(io.BytesIO(b"same"), 10)
    b = storage.put(io.BytesIO(b"same"), 10)
    assert a.key != b.key  # no content addressing: identical uploads stay separate
    assert len(a.key) == 32 and set(a.key) <= set("0123456789abcdef")
    assert (storage.root / a.key[:2] / a.key).is_file()


def test_exactly_max_bytes_is_accepted(storage: LocalFileStorage) -> None:
    assert storage.put(io.BytesIO(b"x" * 100), max_bytes=100).size_bytes == 100


def test_oversized_upload_aborted_and_nothing_kept(storage: LocalFileStorage) -> None:
    with pytest.raises(FileTooLargeError) as error:
        storage.put(io.BytesIO(b"x" * 200_001), max_bytes=200_000)
    assert error.value.max_bytes == 200_000
    assert files_under(storage.root) == []


def test_failing_source_leaves_no_partial_file(storage: LocalFileStorage) -> None:
    class Broken(io.RawIOBase):
        calls = 0

        def read(self, size: int = -1) -> bytes:
            self.calls += 1
            if self.calls > 2:
                raise OSError("client disconnected")
            return b"x" * 1024

    with pytest.raises(OSError):
        storage.put(Broken(), max_bytes=10_000)  # type: ignore[arg-type]
    assert files_under(storage.root) == []


@pytest.mark.parametrize(
    "key",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "..",
        "",
        "0" * 31,
        "0" * 33,
        "A" * 32,  # uppercase is not a generated key
        "0" * 31 + "/",
        "0" * 32 + "\n",  # trailing newline must not slip past the pattern
        "g" * 32,
        "../" + "0" * 29,
    ],
)
def test_non_generated_keys_rejected_everywhere(storage: LocalFileStorage, key: str) -> None:
    for operation in (storage.open, storage.exists, storage.delete):
        with pytest.raises(InvalidStorageKeyError):
            operation(key)


def test_non_string_key_rejected(storage: LocalFileStorage) -> None:
    with pytest.raises(InvalidStorageKeyError):
        storage.open(None)  # type: ignore[arg-type]


def test_missing_blob(storage: LocalFileStorage) -> None:
    key = "0" * 32
    assert storage.exists(key) is False
    with pytest.raises(BlobNotFoundError):
        storage.open(key)


def test_delete_removes_blob_and_is_idempotent(storage: LocalFileStorage) -> None:
    blob = storage.put(io.BytesIO(b"bye"), 10)
    storage.delete(blob.key)
    storage.delete(blob.key)
    assert not storage.exists(blob.key)


def test_digest_matches_hashlib(storage: LocalFileStorage) -> None:
    data = os.urandom(150_000)
    blob = storage.put(io.BytesIO(data), len(data))
    with storage.open(blob.key) as stored:
        assert digest(stored) == (hashlib.sha256(data).digest(), len(data))


@posix_only
def test_blobs_are_not_world_readable(storage: LocalFileStorage) -> None:
    blob = storage.put(io.BytesIO(b"secret"), 10)
    path = storage.root / blob.key[:2] / blob.key
    assert stat.S_IMODE(path.stat().st_mode) & 0o007 == 0
    assert stat.S_IMODE(path.parent.stat().st_mode) & 0o007 == 0


@posix_only
def test_symlinked_shard_cannot_escape_root(storage: LocalFileStorage, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    key = "ab" + "0" * 30
    (outside / key).write_bytes(b"not yours")
    (storage.root / "ab").symlink_to(outside, target_is_directory=True)

    with pytest.raises(InvalidStorageKeyError):
        storage.open(key)


def test_root_is_created_if_missing(tmp_path: Path) -> None:
    root = tmp_path / "a" / "b"
    LocalFileStorage(root)
    assert root.is_dir() and (root / ".tmp").is_dir()
