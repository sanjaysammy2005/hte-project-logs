"""Reject oversized uploads before the body is read (ZERO_TRUST_FILE_MODULE §16.4).

FastAPI parses multipart bodies (spooling files to disk) *before* any endpoint dependency
runs, so the size limit must be enforced earlier, here, from the Content-Length header.
Requests without a length (e.g. chunked) are refused. The header is not trusted beyond this
point: the file part's real size is checked again and bytes are counted while storing.
"""

import json
import re
from collections.abc import Awaitable, Callable
from typing import Any

from app.core.config import get_settings

# Room for multipart boundaries and the small form fields next to the file.
MULTIPART_OVERHEAD = 64 * 1024
UPLOAD_PATHS = re.compile(r"^/api/v1/files(/[0-9a-fA-F-]{36}/versions)?/?$")

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


async def _reject(send: Send, status: int, code: str, message: str, details: dict) -> None:
    body = json.dumps({"error": {"code": code, "message": message, "details": details}}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class UploadLimitMiddleware:
    def __init__(self, app: Callable[[Scope, Receive, Send], Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and scope["method"] == "POST"
            and UPLOAD_PATHS.match(scope["path"])
        ):
            max_bytes = get_settings().max_upload_bytes
            headers = dict(scope["headers"])
            length = headers.get(b"content-length")
            if length is None or not length.isdigit():
                await _reject(
                    send, 411, "LENGTH_REQUIRED", "Uploads must declare a Content-Length", {}
                )
                return
            if int(length) > max_bytes + MULTIPART_OVERHEAD:
                await _reject(
                    send,
                    413,
                    "FILE_TOO_LARGE",
                    f"Files may be at most {max_bytes} bytes",
                    {"max_bytes": max_bytes},
                )
                return
        await self.app(scope, receive, send)
