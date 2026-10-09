"""Byte-for-byte comparison of a rebuilt image with the original.

Every platform's pipeline ends here: a disassembly counts only when the
project it emits rebuilds the exact image it came from.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


class VerificationError(RuntimeError):
    """The rebuilt image differs from the original."""


def first_difference(left: bytes, right: bytes) -> int | None:
    for index, (first, second) in enumerate(zip(left, right)):
        if first != second:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def verify_exact(original: Path, rebuilt: Path) -> dict[str, object]:
    original_bytes = original.read_bytes()
    rebuilt_bytes = rebuilt.read_bytes()
    difference = first_difference(original_bytes, rebuilt_bytes)
    result: dict[str, object] = {
        "schema_version": 1,
        "status": "exact" if difference is None else "mismatch",
        "original_size": len(original_bytes),
        "rebuilt_size": len(rebuilt_bytes),
        "original_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "rebuilt_sha256": hashlib.sha256(rebuilt_bytes).hexdigest(),
        "first_difference": difference,
    }
    if difference is not None:
        raise VerificationError(
            f"rebuilt image differs at file offset {difference:#x}: "
            f"{result['original_sha256']} != {result['rebuilt_sha256']}"
        )
    return result
