"""Independent reference implementation of hash scheme tl-v1, used as a test oracle.

It shares NO code with ``app/`` and uses only the Python standard library. It is written
differently from the production code on purpose (hand-written JSON serialiser, bytearray
building, isoformat-based timestamps), so a mistake in one is unlikely to be repeated in the
other. It also contains a decoder, which proves the encoding can be parsed back unambiguously.

Records are plain dicts with the timestamp as an ISO 8601 string, e.g.:

    {"event_type": "FILE_OPEN", "event_payload": {"resource": "/a"},
     "actor_user_id": "U101", "session_id": "S5001", "prev_event_type": "AUTHENTICATION",
     "session_seq": 3, "event_timestamp": "2026-10-04T10:15:32.000000Z"}

Run directly to print the published vectors, or with ``--write PATH`` to regenerate them:

    python tests/reference_tl_v1.py
"""

import hashlib
import json
import sys
import unicodedata
from datetime import UTC, datetime

GENESIS = b"\x00" * 32

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _json_string(text: str) -> str:
    parts = ['"']
    for ch in text:
        if ch in _SHORT_ESCAPES:
            parts.append(_SHORT_ESCAPES[ch])
        elif ord(ch) < 0x20:
            parts.append(f"\\u{ord(ch):04x}")
        else:
            parts.append(ch)
    parts.append('"')
    return "".join(parts)


def _json_value(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _json_string(_nfc(value))
    if isinstance(value, dict):
        items = sorted(((_nfc(k), v) for k, v in value.items()), key=lambda kv: kv[0])
        return "{" + ",".join(_json_string(k) + ":" + _json_value(v) for k, v in items) + "}"
    if isinstance(value, list | tuple):
        return "[" + ",".join(_json_value(v) for v in value) + "]"
    raise TypeError(f"unsupported value {value!r}")


def _field(text: str) -> bytes:
    data = _nfc(text).encode("utf-8")
    return len(data).to_bytes(4, "big") + data


def _optional(text: str | None) -> bytes:
    return b"\x00" if text is None else b"\x01" + _field(text)


def _timestamp(iso_text: str) -> str:
    moment = datetime.fromisoformat(iso_text).astimezone(UTC)
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def hash_input(record: dict, prev_hash: bytes) -> bytes:
    seq = record["session_seq"]
    buffer = bytearray()
    buffer += _field(record["event_type"])
    buffer += _field(_json_value(record["event_payload"]))
    buffer += _optional(record["actor_user_id"])
    buffer += _optional(record["session_id"])
    buffer += _optional(record["prev_event_type"])
    buffer += _optional(None if seq is None else str(seq))
    buffer += _field(_timestamp(record["event_timestamp"]))
    buffer += prev_hash
    return bytes(buffer)


def entry_hash(record: dict, prev_hash: bytes) -> bytes:
    return hashlib.sha256(hash_input(record, prev_hash)).digest()


def decode_hash_input(data: bytes) -> dict:
    """Parse tl-v1 hash-input bytes back into their text fields. Raises ValueError if malformed."""
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise ValueError("truncated input")
        chunk = data[pos : pos + n]
        pos += n
        return chunk

    def read_field() -> str:
        return take(int.from_bytes(take(4), "big")).decode("utf-8")

    def read_optional() -> str | None:
        marker = take(1)
        if marker == b"\x00":
            return None
        if marker == b"\x01":
            return read_field()
        raise ValueError(f"bad optional marker {marker!r}")

    decoded = {
        "event_type": read_field(),
        "payload_json": read_field(),
        "actor_user_id": read_optional(),
        "session_id": read_optional(),
        "prev_event_type": read_optional(),
        "session_seq": read_optional(),
        "timestamp": read_field(),
        "prev_hash": take(32),
    }
    if pos != len(data):
        raise ValueError("trailing bytes after hash input")
    return decoded


# Published vectors. Record 3 reproduces the paper's Table III example (U101, S5001,
# Open File after Authentication, sequence 3, 10:15:32). Record 4 is sessionless. Record 5
# uses a +05:30 offset and a decomposed "é" to exercise timestamp and NFC normalisation.
VECTOR_INPUTS = [
    {
        "event_type": "LOGIN",
        "event_payload": {"outcome": "success", "ip_address": "10.0.0.12"},
        "actor_user_id": "U101",
        "session_id": "S5001",
        "prev_event_type": "__START__",
        "session_seq": 1,
        "event_timestamp": "2026-10-04T10:15:30.000000Z",
    },
    {
        "event_type": "AUTHENTICATION",
        "event_payload": {"method": "password", "outcome": "success"},
        "actor_user_id": "U101",
        "session_id": "S5001",
        "prev_event_type": "LOGIN",
        "session_seq": 2,
        "event_timestamp": "2026-10-04T10:15:31.250000Z",
    },
    {
        "event_type": "FILE_OPEN",
        "event_payload": {"resource": "/reports/q3.xlsx"},
        "actor_user_id": "U101",
        "session_id": "S5001",
        "prev_event_type": "AUTHENTICATION",
        "session_seq": 3,
        "event_timestamp": "2026-10-04T10:15:32.000000Z",
    },
    {
        "event_type": "IP_SECURITY_EVENT",
        "event_payload": {
            "ip_address": "203.0.113.7",
            "reason": "blocked: repeated failures",
            "attempts": 5,
        },
        "actor_user_id": None,
        "session_id": None,
        "prev_event_type": None,
        "session_seq": None,
        "event_timestamp": "2026-10-04T10:15:33.500000Z",
    },
    {
        "event_type": "FILE_EDIT",
        "event_payload": {
            "resource": "/reports/café.xlsx",
            "details": {"bytes_changed": 120, "backup": True, "note": None},
        },
        "actor_user_id": "U101",
        "session_id": "S5001",
        "prev_event_type": "FILE_OPEN",
        "session_seq": 4,
        "event_timestamp": "2026-10-04T15:45:34.000001+05:30",
    },
]


def build_vectors() -> dict:
    records = []
    prev = GENESIS
    for index, record in enumerate(VECTOR_INPUTS, start=1):
        data = hash_input(record, prev)
        digest = hashlib.sha256(data).digest()
        records.append(
            {
                "chain_index": index,
                "input": record,
                "prev_hash": prev.hex(),
                "hash_input_hex": data.hex(),
                "entry_hash": digest.hex(),
            }
        )
        prev = digest
    return {"scheme": "tl-v1", "genesis_hash": GENESIS.hex(), "records": records}


if __name__ == "__main__":
    vectors = build_vectors()
    text = json.dumps(vectors, indent=2, ensure_ascii=True) + "\n"
    if len(sys.argv) == 3 and sys.argv[1] == "--write":
        with open(sys.argv[2], "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        for entry in vectors["records"]:
            print(entry["chain_index"], entry["input"]["event_type"], entry["entry_hash"])
