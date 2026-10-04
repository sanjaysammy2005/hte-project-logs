"""Pure cryptographic core: canonical encoding, hash chain and (Phase 3) Merkle trees.

Nothing in this package touches the database or FastAPI, so it can be tested in isolation and
is shared unchanged by ingestion (which computes hashes) and verification (which re-checks them).
"""
