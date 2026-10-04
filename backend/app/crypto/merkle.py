"""Merkle-tree batch integrity (paper §VI-D, Eq. 2), scheme ``paper-dup-v1``.

    leaves  = entry hashes H_n of the batch, in chain order
    parent  = SHA-256(left || right)          (32 raw bytes each)
    odd level: the last node is duplicated    (paper)
    one leaf: the root is the leaf itself     [Rec, Q10]

Duplicating the last node means [a, b, c] and [a, b, c, c] share a root, so batch
verification also checks the stored leaf count (MERKLE_RANGE) [Rec, Q14].
"""

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

MERKLE_SCHEME = "paper-dup-v1"
_HASH_LENGTH = 32


class MerkleError(ValueError):
    """Invalid input to tree construction."""


class MerkleCheck(StrEnum):
    MERKLE_RANGE = "MERKLE_RANGE"
    MERKLE_ROOT = "MERKLE_ROOT"


@dataclass(frozen=True)
class ProofStep:
    """A sibling hash and which side of the running hash it sits on."""

    sibling: bytes
    position: Literal["left", "right"]


def _parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def _validated(leaves: Sequence[bytes]) -> list[bytes]:
    if not leaves:
        raise MerkleError("a batch must contain at least one leaf")
    for leaf in leaves:
        if not isinstance(leaf, bytes) or len(leaf) != _HASH_LENGTH:
            raise MerkleError(f"every leaf must be exactly {_HASH_LENGTH} bytes")
    return list(leaves)


def _next_level(level: list[bytes]) -> list[bytes]:
    if len(level) % 2:
        level = [*level, level[-1]]
    return [_parent(level[i], level[i + 1]) for i in range(0, len(level), 2)]


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    level = _validated(leaves)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def membership_proof(leaves: Sequence[bytes], index: int) -> list[ProofStep]:
    """Sibling hashes from leaf ``index`` up to the root: ⌈log2 m⌉ steps."""
    level = _validated(leaves)
    if not 0 <= index < len(level):
        raise MerkleError(f"leaf index {index} is outside the batch")
    proof: list[ProofStep] = []
    while len(level) > 1:
        if index % 2:
            proof.append(ProofStep(level[index - 1], "left"))
        else:
            # A duplicated last node is its own sibling.
            sibling = level[index + 1] if index + 1 < len(level) else level[index]
            proof.append(ProofStep(sibling, "right"))
        level = _next_level(level)
        index //= 2
    return proof


def verify_proof(leaf: bytes, proof: Sequence[ProofStep], root: bytes) -> bool:
    """Fold the proof from the leaf; malformed input verifies as False rather than raising."""
    if not isinstance(leaf, bytes) or len(leaf) != _HASH_LENGTH:
        return False
    current = leaf
    for step in proof:
        if not isinstance(step.sibling, bytes) or len(step.sibling) != _HASH_LENGTH:
            return False
        if step.position == "left":
            current = _parent(step.sibling, current)
        elif step.position == "right":
            current = _parent(current, step.sibling)
        else:
            return False
    return current == root


def check_batch(
    leaves: Sequence[bytes], stored_leaf_count: int, stored_root: bytes
) -> list[MerkleCheck]:
    """Failed checks for one sealed batch (empty list = intact)."""
    failures: list[MerkleCheck] = []
    if len(leaves) != stored_leaf_count:
        failures.append(MerkleCheck.MERKLE_RANGE)
    if not leaves or merkle_root(leaves) != stored_root:
        failures.append(MerkleCheck.MERKLE_ROOT)
    return failures
