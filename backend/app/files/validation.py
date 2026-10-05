"""Filename sanitising and content-type validation (ZERO_TRUST_FILE_MODULE §16.2–§16.3).

Pure functions: no database, no configuration import. Callers pass the allowed extensions.

Two rules carry the security weight:

1. A filename is only ever a *display label*. It never becomes part of a filesystem path
   (storage keys are server-generated, see ``storage.py``), so sanitising here protects the
   people who later see or download the name, not the server's filesystem.
2. The extension is never trusted on its own. The file's bytes must carry the signature of
   that extension's format; the client's Content-Type header is ignored entirely.
"""

import codecs
import unicodedata
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

MAX_FILENAME_BYTES = 255
HEAD_BYTES = 8192
CHUNK_BYTES = 64 * 1024
MAX_ZIP_ENTRIES = 10_000

# Unicode categories never allowed in a filename: controls, format characters (this includes
# bidi overrides such as U+202E and zero-width characters), surrogates, private use, unassigned,
# and line/paragraph separators.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
# Characters that are invalid in Windows filenames; rejected so downloads save cleanly anywhere.
_FORBIDDEN_CHARS = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


class FilenameError(ValueError):
    """The filename cannot be used. ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class FileTypeError(ValueError):
    """The content is not an allowed file of the claimed type."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class FileTypeRule:
    mime_type: str
    family: str  # how the content is checked: pdf, png, jpeg, ole2, ooxml, text


# Every extension that can ever be enabled. Configuration may enable a subset; enabling an
# extension without a rule here is a startup error (app/core/config.py).
FILE_TYPES: dict[str, FileTypeRule] = {
    "txt": FileTypeRule("text/plain", "text"),
    "csv": FileTypeRule("text/csv", "text"),
    "pdf": FileTypeRule("application/pdf", "pdf"),
    "png": FileTypeRule("image/png", "png"),
    "jpg": FileTypeRule("image/jpeg", "jpeg"),
    "jpeg": FileTypeRule("image/jpeg", "jpeg"),
    "doc": FileTypeRule("application/msword", "ole2"),
    "xls": FileTypeRule("application/vnd.ms-excel", "ole2"),
    "ppt": FileTypeRule("application/vnd.ms-powerpoint", "ole2"),
    "docx": FileTypeRule(
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "ooxml"
    ),
    "xlsx": FileTypeRule(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "ooxml"
    ),
    "pptx": FileTypeRule(
        "application/vnd.openxmlformats-officedocument.presentationml.presentation", "ooxml"
    ),
}

_SIGNATURES = {
    "pdf": b"%PDF-",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "ole2": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    "ooxml": b"PK\x03\x04",
}
# The part folder that identifies each OOXML document kind.
_OOXML_PART = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}


@dataclass(frozen=True)
class SafeFilename:
    name: str  # NFC, validated; safe to display and to send in Content-Disposition (encoded)
    extension: str  # lowercase, without the dot


def clean_filename(
    raw: object, allowed_extensions: frozenset[str] | None = None, *, from_upload: bool = False
) -> SafeFilename:
    """Validate a filename and return it in NFC form with its lowercase extension.

    ``from_upload=True`` keeps only the part after the last ``/`` or ``\\`` (some clients send
    a full local path); otherwise a separator is an error. ``allowed_extensions=None`` skips
    the allowlist check (used when the caller compares with a file's fixed extension instead).
    """
    if not isinstance(raw, str):
        raise FilenameError("INVALID_FILENAME", "filename must be text")
    name = raw
    if from_upload:
        name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = unicodedata.normalize("NFC", name).strip(" ")

    if not name or name in (".", ".."):
        raise FilenameError("INVALID_FILENAME", "filename is empty")
    for ch in name:
        if ch in _FORBIDDEN_CHARS:
            raise FilenameError("INVALID_FILENAME", f"filename contains forbidden character {ch!r}")
        if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES:
            raise FilenameError(
                "INVALID_FILENAME",
                f"filename contains a control or invisible character U+{ord(ch):04X}",
            )
    if name.startswith("."):
        raise FilenameError("INVALID_FILENAME", "filename must not start with a dot")
    if name.endswith((".", " ")):
        raise FilenameError("INVALID_FILENAME", "filename must not end with a dot or space")
    if len(name.encode("utf-8")) > MAX_FILENAME_BYTES:
        raise FilenameError("INVALID_FILENAME", f"filename exceeds {MAX_FILENAME_BYTES} bytes")
    if name.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_RESERVED:
        raise FilenameError("INVALID_FILENAME", "filename is a reserved device name")

    stem, dot, extension = name.rpartition(".")
    if not dot or not stem:
        raise FilenameError("MISSING_EXTENSION", "filename must have an extension")
    extension = extension.lower()
    if allowed_extensions is not None and extension not in allowed_extensions:
        raise FilenameError("UNSUPPORTED_FILE_TYPE", f"files of type .{extension} are not allowed")
    return SafeFilename(name, extension)


def verify_content(source: BinaryIO, extension: str) -> FileTypeRule:
    """Check that the bytes in ``source`` are a file of type ``extension``.

    ``source`` must be seekable (an upload's spooled temp file or a stored blob); it is read
    from the start and left at an unspecified position. Returns the server-side type rule,
    whose MIME type is the one ever served for this file.
    """
    rule = FILE_TYPES.get(extension)
    if rule is None:
        raise FileTypeError("UNSUPPORTED_FILE_TYPE", f"no content rule for .{extension}")
    source.seek(0)
    head = source.read(HEAD_BYTES)
    if not head:
        raise FileTypeError("EMPTY_FILE", "file is empty")

    if rule.family == "text":
        _check_text(source, head)
    else:
        if not head.startswith(_SIGNATURES[rule.family]):
            raise FileTypeError(
                "FILE_TYPE_MISMATCH", f"content does not match the .{extension} format"
            )
        if rule.family == "ooxml":
            _check_ooxml(source, extension)
    return rule


def _check_text(source: BinaryIO, head: bytes) -> None:
    """Plain text: valid UTF-8 (a BOM is allowed) with no NUL bytes anywhere."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    chunk = head
    try:
        while chunk:
            if b"\x00" in chunk:
                raise FileTypeError("FILE_TYPE_MISMATCH", "text file contains binary data")
            decoder.decode(chunk)
            chunk = source.read(CHUNK_BYTES)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError as exc:
        raise FileTypeError("FILE_TYPE_MISMATCH", "text file is not valid UTF-8") from exc


def _check_ooxml(source: BinaryIO, extension: str) -> None:
    """Office Open XML: read the ZIP directory only (no decompression) and check its parts."""
    source.seek(0)
    try:
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, ValueError, OSError) as exc:
        raise FileTypeError("FILE_TYPE_MISMATCH", "document archive is corrupt") from exc
    if len(names) > MAX_ZIP_ENTRIES:
        raise FileTypeError("FILE_TYPE_MISMATCH", "document has too many parts")
    if "[Content_Types].xml" not in names:
        raise FileTypeError("FILE_TYPE_MISMATCH", "not an Office Open XML document")
    if not any(n.startswith(_OOXML_PART[extension]) for n in names):
        raise FileTypeError("FILE_TYPE_MISMATCH", f"content is not a .{extension} document")
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        raise FileTypeError("MACROS_NOT_ALLOWED", "documents containing macros are not allowed")
