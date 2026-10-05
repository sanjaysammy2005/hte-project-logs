"""ZT-F2: filename sanitising and content-type validation (ZERO_TRUST_FILE_MODULE §16.2–§16.3).

Samples are built in memory, so no binary fixtures are committed and none are ever executed.
"""

import io
import zipfile

import pytest

from app.files.validation import (
    FILE_TYPES,
    MAX_ZIP_ENTRIES,
    FilenameError,
    FileTypeError,
    clean_filename,
    verify_content,
)
from tests.file_samples import CSV, DOCX, EXE, JPEG, OLE2, PDF, PNG, PPTX, TXT, XLSX, ooxml

ALL = frozenset(FILE_TYPES)


# --- one valid sample per supported extension -------------------------------------------

VALID = {
    "pdf": PDF, "png": PNG, "jpg": JPEG, "jpeg": JPEG,
    "doc": OLE2, "xls": OLE2, "ppt": OLE2,
    "docx": DOCX, "xlsx": XLSX, "pptx": PPTX,
    "txt": TXT, "csv": CSV,
}  # fmt: skip


def check(data: bytes, extension: str):
    return verify_content(io.BytesIO(data), extension)


# --- filenames ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "name", "extension"),
    [
        ("Q3 report.pdf", "Q3 report.pdf", "pdf"),
        ("Budget.XLSX", "Budget.XLSX", "xlsx"),  # display name kept, extension lowercased
        ("résumé (final).docx", "résumé (final).docx", "docx"),
        ("  padded.txt  ", "padded.txt", "txt"),
        ("archive.tar.pdf", "archive.tar.pdf", "pdf"),  # judged by the last extension
    ],
)
def test_valid_filenames(raw: str, name: str, extension: str) -> None:
    cleaned = clean_filename(raw, ALL)
    assert (cleaned.name, cleaned.extension) == (name, extension)


def test_nfc_and_nfd_spellings_are_identical() -> None:
    composed, decomposed = "caf" + chr(0xE9) + ".txt", "cafe" + chr(0x301) + ".txt"
    assert clean_filename(composed, ALL).name == clean_filename(decomposed, ALL).name == composed


@pytest.mark.parametrize(
    "raw",
    [
        "../../etc/passwd.txt",  # traversal
        "..\\..\\windows\\win.ini.txt",
        "/etc/shadow.txt",  # absolute paths
        "C:\\Users\\x\\a.txt",
        "reports/q3.pdf",  # any separator, when not an upload
        "",
        ".",
        "..",
        ".htaccess.txt",  # leading dot
        "report.pdf.",  # trailing dot (Windows strips it)
        "a\x00b.txt",  # NUL
        "a\nb.txt",  # control character
        # Built with chr(): `ruff format` would turn \u escapes into invisible literal characters.
        "invoice" + chr(0x202E) + "fdp.exe",  # right-to-left override spoof
        "in" + chr(0x200B) + "voice.pdf",  # zero-width space
        "CON.txt",  # reserved device names
        "nul.pdf",
        "com1 .docx",
        'quote".txt',  # Windows-invalid characters
        "star*.txt",
        "a" * 252 + ".txt",  # 256 bytes
        "é" * 126 + ".txt",  # 256 bytes in UTF-8 although only 130 characters
    ],
)
def test_malicious_or_invalid_filenames_rejected(raw: str) -> None:
    with pytest.raises(FilenameError) as error:
        clean_filename(raw, ALL)
    assert error.value.code == "INVALID_FILENAME"


def test_length_limit_is_counted_in_bytes() -> None:
    assert clean_filename("a" * 251 + ".txt", ALL).name  # exactly 255 bytes
    with pytest.raises(FilenameError):
        clean_filename("é" * 126 + ".txt", ALL)


@pytest.mark.parametrize("raw", ["README", "noext.", "report.pdf.exe", "page.html", "image.svg"])
def test_missing_or_disallowed_extensions_rejected(raw: str) -> None:
    with pytest.raises(FilenameError) as error:
        clean_filename(raw, ALL)
    assert error.value.code in {"MISSING_EXTENSION", "UNSUPPORTED_FILE_TYPE", "INVALID_FILENAME"}


def test_allowlist_is_respected() -> None:
    with pytest.raises(FilenameError) as error:
        clean_filename("photo.png", frozenset({"pdf"}))
    assert error.value.code == "UNSUPPORTED_FILE_TYPE"
    assert clean_filename("photo.png", None).extension == "png"  # allowlist check skipped


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("C:\\Users\\alice\\Desktop\\plan.docx", "plan.docx"),
        ("/home/bob/../../plan.docx", "plan.docx"),
        ("folder/sub\\plan.docx", "plan.docx"),
    ],
)
def test_uploads_keep_only_the_basename(raw: str, expected: str) -> None:
    assert clean_filename(raw, ALL, from_upload=True).name == expected


@pytest.mark.parametrize("raw", ["dir/..", "dir/", "x/.hidden.txt"])
def test_upload_basename_is_still_validated(raw: str) -> None:
    with pytest.raises(FilenameError):
        clean_filename(raw, ALL, from_upload=True)


def test_non_text_filename_rejected() -> None:
    with pytest.raises(FilenameError):
        clean_filename(b"file.txt", ALL)  # type: ignore[arg-type]


# --- content -----------------------------------------------------------------------------------


@pytest.mark.parametrize("extension", sorted(VALID))
def test_every_supported_type_accepted_with_server_mime(extension: str) -> None:
    rule = check(VALID[extension], extension)
    assert rule.mime_type == FILE_TYPES[extension].mime_type


def test_every_supported_extension_has_a_sample() -> None:
    assert set(VALID) == set(FILE_TYPES)


@pytest.mark.parametrize(
    ("data", "extension"),
    [
        (PNG, "pdf"),  # image renamed to .pdf
        (PDF, "png"),
        (EXE, "docx"),  # executable renamed to a document
        (EXE, "pdf"),
        (JPEG, "png"),
        (OLE2, "docx"),  # legacy format claiming to be OOXML
        (DOCX, "doc"),
        (b"<html><script>alert(1)</script></html>", "pdf"),
        (b"%PDX-1.7", "pdf"),
    ],
)
def test_spoofed_types_rejected(data: bytes, extension: str) -> None:
    with pytest.raises(FileTypeError) as error:
        check(data, extension)
    assert error.value.code == "FILE_TYPE_MISMATCH"


@pytest.mark.parametrize(("data", "extension"), [(DOCX, "xlsx"), (XLSX, "pptx"), (PPTX, "docx")])
def test_ooxml_kind_must_match_extension(data: bytes, extension: str) -> None:
    with pytest.raises(FileTypeError):
        check(data, extension)


def test_plain_zip_is_not_ooxml() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", "<doc/>")  # no [Content_Types].xml
    with pytest.raises(FileTypeError):
        check(buffer.getvalue(), "docx")


def test_corrupt_zip_with_valid_signature_rejected() -> None:
    with pytest.raises(FileTypeError) as error:
        check(b"PK\x03\x04" + b"\x00" * 100, "docx")
    assert error.value.code == "FILE_TYPE_MISMATCH"


def test_macro_enabled_document_rejected() -> None:
    with pytest.raises(FileTypeError) as error:
        check(ooxml("word/", {"word/vbaProject.bin": b"\x00" * 10}), "docx")
    assert error.value.code == "MACROS_NOT_ALLOWED"


def test_archive_with_too_many_entries_rejected() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        for i in range(MAX_ZIP_ENTRIES):
            archive.writestr(f"word/p{i}.xml", "")
    with pytest.raises(FileTypeError):
        check(buffer.getvalue(), "docx")


def test_ooxml_check_reads_directory_only() -> None:
    """A highly compressible member (zip-bomb shape) is never decompressed."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", b"\x00" * (50 * 1024 * 1024))
    assert len(buffer.getvalue()) < 1024 * 1024
    assert check(buffer.getvalue(), "docx").family == "ooxml"


@pytest.mark.parametrize(
    "data",
    [
        b"hello\x00world",  # NUL in the first block
        b"a" * 100_000 + b"\x00",  # NUL far beyond the first block
        b"\xff\xfe\x00\x00",  # UTF-32/16-style binary
        b"caf\xe9",  # Latin-1, not UTF-8
        b"ok" + b"\xe2\x82",  # truncated multi-byte sequence at the end
        EXE,
    ],
)
def test_binary_or_non_utf8_text_rejected(data: bytes) -> None:
    with pytest.raises(FileTypeError):
        check(data, "txt")


def test_multibyte_character_split_across_chunks_is_valid() -> None:
    data = b"a" * 8191 + "€".encode() + b"tail"  # '€' straddles the first read boundary
    assert check(data, "txt").family == "text"


@pytest.mark.parametrize("extension", ["txt", "pdf", "png", "docx"])
def test_empty_files_rejected(extension: str) -> None:
    with pytest.raises(FileTypeError) as error:
        check(b"", extension)
    assert error.value.code == "EMPTY_FILE"


def test_unknown_extension_rejected() -> None:
    with pytest.raises(FileTypeError) as error:
        check(PDF, "exe")
    assert error.value.code == "UNSUPPORTED_FILE_TYPE"


def test_polyglot_is_judged_by_its_claimed_type() -> None:
    """A file that is both a valid PDF prefix and has trailing ZIP data is a PDF, nothing more:
    the server never serves it as anything but application/pdf."""
    assert check(PDF + DOCX, "pdf").mime_type == "application/pdf"
    with pytest.raises(FileTypeError):
        check(PDF + DOCX, "docx")
