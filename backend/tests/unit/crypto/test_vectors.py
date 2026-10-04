"""T2.11: published tl-v1 test vectors and differential testing against the reference."""

import json
import random
from pathlib import Path

import pytest

from app.crypto.chain import GENESIS_HASH, build_chain, hash_input, verify_chain
from tests import reference_tl_v1 as reference
from tests.factories import random_record, record_from_dict, record_to_dict

VECTORS_PATH = Path(__file__).resolve().parents[2] / "vectors" / "tl-v1.json"


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def test_published_vectors_match_reference_implementation(vectors: dict) -> None:
    """Guards against the vector file going stale or being edited by hand."""
    assert vectors == reference.build_vectors()


def test_production_code_reproduces_published_vectors(vectors: dict) -> None:
    assert vectors["scheme"] == "tl-v1"
    assert bytes.fromhex(vectors["genesis_hash"]) == GENESIS_HASH

    chain = build_chain(record_from_dict(entry["input"]) for entry in vectors["records"])

    for item, entry in zip(chain, vectors["records"], strict=True):
        assert item.chain_index == entry["chain_index"]
        assert item.prev_hash.hex() == entry["prev_hash"]
        assert hash_input(item.record, item.prev_hash).hex() == entry["hash_input_hex"]
        assert item.entry_hash.hex() == entry["entry_hash"]
    assert verify_chain(chain).is_valid


def test_paper_table_iii_vector_fields(vectors: dict) -> None:
    """Record 3 is the paper's Table III example: U101, S5001, Open File after Authentication."""
    decoded = reference.decode_hash_input(bytes.fromhex(vectors["records"][2]["hash_input_hex"]))

    assert decoded["event_type"] == "FILE_OPEN"
    assert decoded["actor_user_id"] == "U101"
    assert decoded["session_id"] == "S5001"
    assert decoded["prev_event_type"] == "AUTHENTICATION"
    assert decoded["session_seq"] == "3"
    assert decoded["timestamp"] == "2026-10-04T10:15:32.000000Z"


def test_production_matches_reference_on_1000_random_records() -> None:
    rng = random.Random(1999)  # Schneier & Kelsey's year, for no reason other than a fixed seed
    for i in range(1000):
        record = random_record(rng, offset_seconds=i)
        prev = rng.randbytes(32)

        assert hash_input(record, prev) == reference.hash_input(record_to_dict(record), prev), i
