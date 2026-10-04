"""T3.1–T3.7: Merkle root, membership proofs and the duplicate-leaf weakness."""

import hashlib
import math
from dataclasses import replace

import pytest

from app.crypto.merkle import (
    MerkleCheck,
    MerkleError,
    ProofStep,
    check_batch,
    membership_proof,
    merkle_root,
    verify_proof,
)

SIZES = [1, 2, 3, 4, 5, 7, 8, 9]


def _leaves(m: int) -> list[bytes]:
    return [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(m)]


def _reference_root(nodes: list[bytes]) -> bytes:
    """Independent recursive definition of paper Eq. 2 (written separately from app code)."""
    if len(nodes) == 1:
        return nodes[0]
    padded = nodes + [nodes[-1]] if len(nodes) % 2 else nodes
    parents = [
        hashlib.sha256(a + b).digest() for a, b in zip(padded[::2], padded[1::2], strict=True)
    ]
    return _reference_root(parents)


def _h(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(a + b).digest()


# --- T3.1–T3.3: roots ------------------------------------------------------------------------


def test_single_leaf_root_is_the_leaf() -> None:
    leaf = _leaves(1)[0]

    assert merkle_root([leaf]) == leaf


@pytest.mark.parametrize("m", SIZES)
def test_root_matches_independent_reference(m: int) -> None:
    assert merkle_root(_leaves(m)) == _reference_root(_leaves(m))


def test_hand_computed_roots_for_small_batches() -> None:
    a, b, c, d, e = _leaves(5)

    assert merkle_root([a, b]) == _h(a, b)
    assert merkle_root([a, b, c]) == _h(_h(a, b), _h(c, c))  # odd level duplicates c
    assert merkle_root([a, b, c, d]) == _h(_h(a, b), _h(c, d))
    ab_cd = _h(_h(a, b), _h(c, d))
    ee_ee = _h(_h(e, e), _h(e, e))
    assert merkle_root([a, b, c, d, e]) == _h(ab_cd, ee_ee)


@pytest.mark.parametrize("bad", [[], [b"short"], [bytes(32), bytes(33)], ["00" * 32]])
def test_invalid_leaves_rejected(bad: list) -> None:
    with pytest.raises(MerkleError):
        merkle_root(bad)


# --- T3.4: proofs ----------------------------------------------------------------------------


@pytest.mark.parametrize("m", SIZES)
def test_every_leaf_has_a_valid_proof_of_log_length(m: int) -> None:
    leaves = _leaves(m)
    root = merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        proof = membership_proof(leaves, index)

        assert verify_proof(leaf, proof, root), (m, index)
        assert len(proof) == math.ceil(math.log2(m)), (m, index)


@pytest.mark.parametrize("index", [-1, 3])
def test_proof_index_outside_batch_rejected(index: int) -> None:
    with pytest.raises(MerkleError):
        membership_proof(_leaves(3), index)


# --- T3.5 / T3.6: tampering ------------------------------------------------------------------


@pytest.mark.parametrize("m", SIZES)
def test_altering_any_leaf_changes_root_and_breaks_its_old_proof(m: int) -> None:
    leaves = _leaves(m)
    root = merkle_root(leaves)
    for index in range(m):
        proof = membership_proof(leaves, index)
        altered = list(leaves)
        altered[index] = hashlib.sha256(b"tampered" + leaves[index]).digest()

        assert merkle_root(altered) != root
        assert not verify_proof(altered[index], proof, root)


def test_proof_with_tampered_sibling_or_side_fails() -> None:
    leaves = _leaves(8)
    root = merkle_root(leaves)
    proof = membership_proof(leaves, 5)

    bad_sibling = [replace(proof[0], sibling=bytes(32)), *proof[1:]]
    flipped = [replace(proof[0], position="left" if proof[0].position == "right" else "right")]
    flipped += proof[1:]

    assert not verify_proof(leaves[5], bad_sibling, root)
    assert not verify_proof(leaves[5], flipped, root)
    assert not verify_proof(leaves[5], proof[:-1], root)


@pytest.mark.parametrize(
    ("leaf", "proof"),
    [
        (b"short", []),
        (bytes(32), [ProofStep(b"short", "right")]),
        (bytes(32), [ProofStep(bytes(32), "up")]),  # type: ignore[arg-type]
    ],
)
def test_malformed_proof_input_returns_false(leaf: bytes, proof: list[ProofStep]) -> None:
    assert verify_proof(leaf, proof, bytes(32)) is False


# --- T3.7: duplicate-last-leaf weakness and the leaf-count check -----------------------------


def test_duplicated_last_leaf_gives_same_root_but_fails_leaf_count_check() -> None:
    a, b, c = _leaves(3)
    root = merkle_root([a, b, c])

    # Known weakness of the paper's padding rule (VERIFICATION §5.4)...
    assert merkle_root([a, b, c, c]) == root
    # ...closed by comparing against the stored leaf count.
    assert check_batch([a, b, c], stored_leaf_count=3, stored_root=root) == []
    assert check_batch([a, b, c, c], stored_leaf_count=3, stored_root=root) == [
        MerkleCheck.MERKLE_RANGE
    ]


def test_check_batch_reports_root_and_range_failures() -> None:
    leaves = _leaves(4)
    root = merkle_root(leaves)

    assert check_batch(leaves[:3], 4, root) == [MerkleCheck.MERKLE_RANGE, MerkleCheck.MERKLE_ROOT]
    assert check_batch(leaves, 4, bytes(32)) == [MerkleCheck.MERKLE_ROOT]
    assert check_batch([], 4, root) == [MerkleCheck.MERKLE_RANGE, MerkleCheck.MERKLE_ROOT]
