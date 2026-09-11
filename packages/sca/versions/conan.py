"""Conan (ConanCenter) version comparator.

Conan versions are semver-ish but looser: any number of dot-separated
components, each a digit run with an optional letter tail
(``1.1.1t``, ``2.13.0``, ``1.2.3.4``), plus optional semver-style
pre-release (``-rc1``) and build metadata (``+b2``, ignored).

Ordering:

  1. Main components compare pairwise: numeric part first, then the
     letter tail lexically (``1.1.1k < 1.1.1t``). A missing component
     compares as ``0`` with no tail (``1.2 == 1.2.0``, ``1.2 < 1.2.1``).
  2. A version with a pre-release sorts before the same version
     without one; two pre-releases compare identifier by identifier
     (numeric < alphanumeric, semver-style).

Shapes outside this grammar raise ``ValueError`` (normalised to
``VersionError`` by the dispatcher) so range matchers skip rather
than guess.
"""

from __future__ import annotations

import re

# Digit runs bounded so hostile-length runs never reach ``int()``.
_COMPONENT_RE = re.compile(r"^(\d{1,32})([A-Za-z]{0,16})$")


def _parse(version: str) -> tuple[list[tuple[int, str]], list[str] | None]:
    v = version.strip()
    if v.startswith("v"):
        v = v[1:]
    if not v:
        msg = "empty Conan version"
        raise ValueError(msg)
    v = v.split("+", 1)[0]                 # build metadata ignored
    main, sep, pre = v.partition("-")
    components: list[tuple[int, str]] = []
    for part in main.split("."):
        m = _COMPONENT_RE.match(part)
        if not m:
            msg = f"not a Conan version: {version!r}"
            raise ValueError(msg)
        components.append((int(m.group(1)), m.group(2)))
    prerelease = pre.split(".") if sep else None
    if sep and not pre:
        msg = f"not a Conan version: {version!r}"
        raise ValueError(msg)
    return components, prerelease


def _cmp_ident(a: str, b: str) -> int:
    a_num, b_num = a.isdigit(), b.isdigit()
    if a_num and b_num:
        # String-numeric compare (no int(): identifiers are unbounded).
        as_, bs = a.lstrip("0"), b.lstrip("0")
        if len(as_) != len(bs):
            return -1 if len(as_) < len(bs) else 1
        return 0 if as_ == bs else (-1 if as_ < bs else 1)
    if a_num != b_num:
        return -1 if a_num else 1          # numeric < alphanumeric
    return 0 if a == b else (-1 if a < b else 1)


def compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 for ``a < b``, ``a == b``, ``a > b``."""
    if a == b:
        return 0
    ca, pa = _parse(a)
    cb, pb = _parse(b)
    length = max(len(ca), len(cb))
    for i in range(length):
        na, ta = ca[i] if i < len(ca) else (0, "")
        nb, tb = cb[i] if i < len(cb) else (0, "")
        if na != nb:
            return -1 if na < nb else 1
        if ta != tb:
            return -1 if ta < tb else 1
    if (pa is None) != (pb is None):
        return 1 if pa is None else -1     # pre-release sorts first
    if pa is not None and pb is not None:
        for ia, ib in zip(pa, pb, strict=False):
            c = _cmp_ident(ia, ib)
            if c != 0:
                return c
        if len(pa) != len(pb):
            return -1 if len(pa) < len(pb) else 1
    return 0


__all__ = ["compare"]
