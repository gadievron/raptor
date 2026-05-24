"""Source-side input taxonomy for trust-boundary reasoning.

This module is intentionally separate from :mod:`core.function_taxonomy`.
Function taxonomy drives sink/import/fuzz-priority signals, where ubiquitous
calls such as ``read`` are often deliberately omitted. Input taxonomy is
source-code oriented: when a concrete call site is visible, those same calls
are useful L1 evidence for /understand and /validate prompt context.
"""

from __future__ import annotations

from typing import Dict, FrozenSet

TRUST_L1_ATTACKER_CONTROLLED = "L1"

# fd-level reads: ubiquitous in binaries, but meaningful as source-code
# L1 taint origins when RAPTOR sees the call site.
FD_READ_FUNCS: FrozenSet[str] = frozenset({
    "read",
    "readv",
    "pread",
    "preadv",
})

# Socket/network ingress.
SOCKET_READ_FUNCS: FrozenSet[str] = frozenset({
    "recv",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "SSL_read",
    "BIO_read",
})

# Stream / line-oriented ingress. Kept source-side only; this does not imply
# import-table fuzz-priority semantics.
STREAM_INPUT_FUNCS: FrozenSet[str] = frozenset({
    "fgets",
    "fgetws",
    "getline",
    "getdelim",
    "scanf",
    "fscanf",
})

# Process/environment boundary inputs.
ENV_INPUT_FUNCS: FrozenSet[str] = frozenset({
    "getenv",
})

# Kernel/user boundary reads. ``copy_to_user``/``put_user`` are outbound and
# intentionally not source observations here.
KERNEL_USER_INPUT_FUNCS: FrozenSet[str] = frozenset({
    "copy_from_user",
    "get_user",
    "strncpy_from_user",
    "strnlen_user",
})

# Device-control entry points often carry attacker-supplied request structs or
# command values. These are weaker than explicit buffer reads but still useful
# L1 context in driver code.
DEVICE_CONTROL_INPUT_FUNCS: FrozenSet[str] = frozenset({
    "ioctl",
    "unlocked_ioctl",
    "compat_ioctl",
})

def _kind_map(names: FrozenSet[str], kind: str) -> Dict[str, str]:
    return {name: kind for name in sorted(names)}


C_L1_SOURCE_CALLS: Dict[str, str] = {
    **_kind_map(FD_READ_FUNCS, "fd"),
    **_kind_map(SOCKET_READ_FUNCS, "socket"),
    **_kind_map(STREAM_INPUT_FUNCS, "stream"),
    **_kind_map(ENV_INPUT_FUNCS, "env"),
    **_kind_map(KERNEL_USER_INPUT_FUNCS, "kernel_user"),
    **_kind_map(DEVICE_CONTROL_INPUT_FUNCS, "device_control"),
}

# Names that are not function calls but should be surfaced when source code
# uses process/environment vectors directly.
ARGV_SOURCE_NAMES: FrozenSet[str] = frozenset({"argv"})
ENV_SOURCE_NAMES: FrozenSet[str] = frozenset({"envp", "environ"})
