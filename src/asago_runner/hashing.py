"""Hashing helpers used across evidence records."""

from __future__ import annotations

import hashlib
from pathlib import Path

BLOCK_SIZE = 1024 * 1024


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 hex digest of a file's bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(BLOCK_SIZE)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of a byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Return the SHA-256 hex digest of UTF-8 text (no newline normalisation)."""
    return sha256_bytes(text.encode("utf-8"))
