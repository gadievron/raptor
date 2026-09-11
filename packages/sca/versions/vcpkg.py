"""vcpkg version comparator.

vcpkg ports carry dotted-numeric versions (``1.2.3``) or date
versions (``2021-06-01``), optionally followed by ``#N`` — the
port-version, bumped when the port's packaging changes without an
upstream release.

Ordering: numeric components (split on ``.`` and ``-``) compare
pairwise with missing components as 0; equal bases compare on the
port-version. Non-numeric components raise ``ValueError`` (normalised
to ``VersionError`` by the dispatcher) — vcpkg's ``version-string``
scheme is explicitly unordered, so guessing would be wrong.
"""

from __future__ import annotations

import re

_SPLIT_RE = re.compile(r"[.-]")

# Digit-run cap keeps ``int()`` off hostile-length runs.
_MAX_COMPONENT_DIGITS = 32


def _parse(version: str) -> tuple[list[int], int]:
    v = version.strip()
    base, sep, port = v.partition("#")
    if not base:
        msg = f"not a vcpkg version: {version!r}"
        raise ValueError(msg)
    if sep:
        if not port.isdigit() or len(port) > _MAX_COMPONENT_DIGITS:
            msg = f"invalid vcpkg port-version in {version!r}"
            raise ValueError(msg)
        port_version = int(port)
    else:
        port_version = 0
    if base.startswith("v"):
        base = base[1:]
    nums: list[int] = []
    for part in _SPLIT_RE.split(base):
        if not part.isdigit() or len(part) > _MAX_COMPONENT_DIGITS:
            msg = f"not a vcpkg version: {version!r}"
            raise ValueError(msg)
        nums.append(int(part))
    return nums, port_version


def compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a < b``, ``a == b``, ``a > b``."""
    if a == b:
        return 0
    na, porta = _parse(a)
    nb, portb = _parse(b)
    length = max(len(na), len(nb))
    for i in range(length):
        xa = na[i] if i < len(na) else 0
        xb = nb[i] if i < len(nb) else 0
        if xa != xb:
            return -1 if xa < xb else 1
    if porta != portb:
        return -1 if porta < portb else 1
    return 0


__all__ = ["compare"]
