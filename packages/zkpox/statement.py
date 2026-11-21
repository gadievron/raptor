"""ZKPoX v2 public statement: the 88-byte binary structure proven by the SP1 guest.

See docs/zkpox-scope.md for the field-level specification, trust boundaries
and what a successful verification does (and does not) establish.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATEMENT_VERSION = 2
STATEMENT_SIZE = 88
SYSTEM = "sp1-groth16"

_STRUCT_FMT = "<IIIIIi32s32s"
assert struct.calcsize(_STRUCT_FMT) == STATEMENT_SIZE

_VALID_TARGETS = {1, 2, 3}
_VALID_PREDICATES = {1, 2}  # 1 = uniform canary, 2 = varying canary


@dataclass(frozen=True)
class Statement:
    """Immutable 88-byte v2 statement (public output of the SP1 guest)."""

    target_id: int
    gadget_id: int  # 1 = crash_only, 2 = oob_write
    flags: int  # bits 0/1: uniform/varying dirty
    predicate: int
    oob_count: int
    commitment: bytes  # 32-byte salted witness commitment
    target_source_hash: bytes  # SHA-256 of the curated C source
    oob_first_offset: int = -(2**31)  # i32 MIN when the varying scan is clean

    def validate(self) -> None:
        """Raise ValueError if the statement does not demonstrate a violation."""
        if self.target_id not in _VALID_TARGETS:
            raise ValueError(f"target_id {self.target_id} not in {_VALID_TARGETS}")
        if self.predicate not in _VALID_PREDICATES:
            raise ValueError(f"predicate {self.predicate} not in {_VALID_PREDICATES}")
        if len(self.commitment) != 32:
            raise ValueError("commitment must be exactly 32 bytes")
        if len(self.target_source_hash) != 32:
            raise ValueError("target_source_hash must be exactly 32 bytes")
        if self.flags == 0 and self.oob_count == 0:
            raise ValueError(
                "statement did not demonstrate a canary violation "
                "(flags=0, oob_count=0)"
            )

    def to_bytes(self) -> bytes:
        """Serialise to the canonical 88-byte wire format."""
        return struct.pack(
            _STRUCT_FMT,
            STATEMENT_VERSION,
            self.target_id,
            self.predicate,
            self.flags,
            self.oob_count,
            self.oob_first_offset,
            self.commitment,
            self.target_source_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": STATEMENT_VERSION,
            "target_id": self.target_id,
            "gadget_id": self.gadget_id,
            "predicate": self.predicate,
            "flags": self.flags,
            "oob_count": self.oob_count,
            "oob_first_offset": self.oob_first_offset,
            "commitment": self.commitment.hex(),
            "target_source_hash": self.target_source_hash.hex(),
        }

    @classmethod
    def from_bytes(cls, data: bytes, *, gadget_id: int = 0) -> "Statement":
        """Parse an 88-byte statement.

        ``gadget_id`` is not encoded in the wire format; callers that need
        it must supply the value from out-of-band context (the disclosure
        bundle's vulnerability record).
        """
        if len(data) != STATEMENT_SIZE:
            raise ValueError(f"expected {STATEMENT_SIZE} bytes, got {len(data)}")
        (version, target_id, predicate, flags, oob_count,
         oob_first_offset, commitment, target_source_hash) = struct.unpack(
            _STRUCT_FMT, data)
        if version != STATEMENT_VERSION:
            raise ValueError(f"unsupported statement version {version}")
        return cls(
            target_id=target_id,
            gadget_id=gadget_id,
            flags=flags,
            predicate=predicate,
            oob_count=oob_count,
            commitment=commitment,
            target_source_hash=target_source_hash,
            oob_first_offset=oob_first_offset,
        )


def source_hash(target_id: int) -> bytes:
    """SHA-256 of the curated C source for the given target.

    When the native workspace is present, hashes the actual file.
    Otherwise returns a stable derivation so tests and manifests
    remain self-consistent without requiring a Rust build.
    """
    if target_id not in _VALID_TARGETS:
        raise ValueError(f"target_id {target_id} not in {_VALID_TARGETS}")
    source_dir = Path(__file__).parent / "native" / "test" / "targets"
    source_file = source_dir / f"{target_id:02d}.c"
    if source_file.is_file():
        return hashlib.sha256(source_file.read_bytes()).digest()
    # Stable placeholder: hash the canonical target identifier so that
    # source_hash(n) == source_hash(n) across calls, and different
    # targets produce different hashes.
    return hashlib.sha256(
        f"raptor-zkpox-curated-source-v2:{target_id:02d}".encode()
    ).digest()
