"""In-memory sample files for file-module tests. Nothing here is ever executed."""

import io
import zipfile


def ooxml(part: str, extra: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(f"{part}document.xml", "<doc/>")
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


PDF = b"%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 20
JPEG = b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF" + b"\x00" * 20
OLE2 = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
EXE = b"MZ\x90\x00" + b"\x00" * 60 + b"This program cannot be run in DOS mode"
DOCX, XLSX, PPTX = ooxml("word/"), ooxml("xl/"), ooxml("ppt/")
TXT = "Quarterly notes – café ✓\n".encode()
CSV = b"\xef\xbb\xbfname,amount\nA,1\n"
