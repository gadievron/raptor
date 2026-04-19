"""Shared validators for binary-analysis inputs passed into subprocess tools.

Consolidates the hex-address regex and byte-count bound so GDB, LLDB, and
addr2line code paths can't drift apart. GDB scripts are newline-delimited,
so \\n in any string field is an injection vector — every such field should
route through here.
"""

import re

# 1-16 hex digits fits every real architecture (64-bit max). Rejecting
# unbounded length is defence-in-depth, not exploit-prevention.
_HEX_ADDRESS_RE = re.compile(r'^0x[0-9a-fA-F]{1,16}$')

# 4 KB: well above any realistic `x/Nxb` caller, small enough to prevent
# a bad int from embedding megabytes of output request into a GDB script.
_MAX_EXAMINE_BYTES = 4096


def is_valid_hex_address(address) -> bool:
    """Non-raising check for best-effort callers (e.g. symbol resolvers)."""
    return isinstance(address, str) and bool(_HEX_ADDRESS_RE.match(address))


def validate_hex_address(address, *, param_name: str = "address") -> None:
    """Raise ValueError if address isn't 0x<1-16 hex digits>.

    Non-str inputs are rejected up front so callers see one exception type.
    """
    if not isinstance(address, str):
        raise ValueError(
            f"Invalid {param_name} {address!r}: expected str, "
            f"got {type(address).__name__}."
        )
    if not _HEX_ADDRESS_RE.match(address):
        raise ValueError(
            f"Invalid {param_name} {address!r}: expected 0x<1-16 hex digits>. "
            "Arbitrary strings are rejected to prevent GDB script injection."
        )


def validate_byte_count(num_bytes, *, param_name: str = "num_bytes") -> None:
    """Raise ValueError if num_bytes isn't an int in [1, _MAX_EXAMINE_BYTES].

    Guards the f-string path in examine_memory(): a str like "64\\nshell id"
    passed as num_bytes would otherwise be embedded verbatim into a GDB script.
    bool is an int subclass in Python, so reject it explicitly.
    """
    if isinstance(num_bytes, bool) or not isinstance(num_bytes, int):
        raise ValueError(
            f"Invalid {param_name} {num_bytes!r}: expected int, "
            f"got {type(num_bytes).__name__}."
        )
    if num_bytes < 1 or num_bytes > _MAX_EXAMINE_BYTES:
        raise ValueError(
            f"Invalid {param_name} {num_bytes}: must be between 1 "
            f"and {_MAX_EXAMINE_BYTES}."
        )
