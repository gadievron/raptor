"""PEP 425 wheel filename parser + platform-tag decoder.

A wheel filename has the shape::

    {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl

We need the platform-tag in particular to decide compat:

  * ``any``                 — pure Python, installable everywhere
  * ``manylinux_X_Y_<arch>`` — needs glibc ≥ X.Y on ``<arch>``
  * ``manylinux2014_<arch>`` — alias for ``manylinux_2_17_<arch>``
  * ``manylinux2010_<arch>`` — alias for ``manylinux_2_12_<arch>``
  * ``manylinux1_<arch>``   — alias for ``manylinux_2_5_<arch>``
  * ``musllinux_X_Y_<arch>`` — needs musl ≥ X.Y on ``<arch>``
  * ``macosx_X_Y_<arch>``    — macOS X.Y on ``<arch>``
  * ``win_amd64``           — Windows x86_64
  * ``win32``               — Windows i686
  * ``linux_<arch>``         — raw linux, no libc constraint specified

Multiple platform tags can appear joined by ``.`` (a single wheel
file that's compat with multiple platforms — e.g. the macosx
``universal2`` shape uses
``macosx_11_0_arm64.macosx_11_0_x86_64``).

We don't try to handle pre-PEP-425 wheels (very old packages
without proper tags) — those are rare in modern projects.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from packages.sca.platform_matrix.glibc_db import LibcVersion

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WheelTag:
    """Decoded platform tag from a wheel filename."""

    arch: Optional[str]                # ``x86_64`` / ``aarch64`` / ``any`` / …
    libc: Optional[LibcVersion]        # glibc/musl version requirement
    os: str                            # ``linux`` / ``macosx`` / ``windows`` / ``any``
    raw: str                           # original platform-tag string
    # ``macosx_X_Y_<arch>`` tags encode the minimum macOS version
    # the wheel was built against. A wheel tagged ``macosx_11_0_arm64``
    # installs on macOS 11+ and is rejected by pip on macOS 10.x. We
    # capture it as ``(11, 0)`` so the compat checker can refuse a
    # too-new wheel against a project pinned to an older macOS
    # runner. ``None`` for non-macOS tags.
    macos_version: Optional[Tuple[int, int]] = None


# Architecture portion of platform tags. ``i686`` / ``i386`` / ``amd64``
# all appear; canonicalise.
_PLATFORM_ARCH_ALIASES = {
    "x86_64": "x86_64", "amd64": "x86_64",
    "aarch64": "aarch64", "arm64": "aarch64",
    "armv7l": "armv7l",
    "i686": "i686", "i386": "i686",
    "ppc64le": "ppc64le", "ppc64": "ppc64",
    "s390x": "s390x",
    "universal2": "any",       # macosx universal — covers x86_64+arm64
}


# manylinux legacy aliases. The bare names map to specific
# manylinux_X_Y_<arch> equivalents per PEP 600.
_MANYLINUX_LEGACY = {
    "manylinux1":    (2, 5),
    "manylinux2010": (2, 12),
    "manylinux2014": (2, 17),
}


_MANYLINUX_NEW_RE = re.compile(r"^manylinux_(\d+)_(\d+)_(.+)$")
_MUSLLINUX_RE = re.compile(r"^musllinux_(\d+)_(\d+)_(.+)$")
_MACOSX_RE = re.compile(r"^macosx_(\d+)_(\d+)_(.+)$")
_WIN_RE = re.compile(r"^(win_amd64|win32)$")
_LINUX_BARE_RE = re.compile(r"^linux_(.+)$")
_MANYLINUX_LEGACY_RE = re.compile(
    r"^(manylinux1|manylinux2010|manylinux2014)_(.+)$"
)


def _parse_single_platform_tag(tag: str) -> WheelTag:
    """Parse one platform-tag component (no ``.``-separated joins).

    Returns a :class:`WheelTag` whose ``raw`` retains the input
    for diagnostic display.
    """
    if tag == "any":
        return WheelTag(arch="any", libc=None, os="any", raw=tag)

    # manylinux_X_Y_<arch>
    m = _MANYLINUX_NEW_RE.match(tag)
    if m:
        major, minor, arch = m.group(1), m.group(2), m.group(3)
        return WheelTag(
            arch=_PLATFORM_ARCH_ALIASES.get(arch, arch),
            libc=LibcVersion("glibc", (int(major), int(minor))),
            os="linux", raw=tag,
        )

    # manylinux2014_<arch> etc.
    m = _MANYLINUX_LEGACY_RE.match(tag)
    if m:
        name, arch = m.group(1), m.group(2)
        gv = _MANYLINUX_LEGACY[name]
        return WheelTag(
            arch=_PLATFORM_ARCH_ALIASES.get(arch, arch),
            libc=LibcVersion("glibc", gv),
            os="linux", raw=tag,
        )

    # musllinux_X_Y_<arch>
    m = _MUSLLINUX_RE.match(tag)
    if m:
        major, minor, arch = m.group(1), m.group(2), m.group(3)
        return WheelTag(
            arch=_PLATFORM_ARCH_ALIASES.get(arch, arch),
            libc=LibcVersion("musl", (int(major), int(minor))),
            os="linux", raw=tag,
        )

    # macosx_X_Y_<arch>
    m = _MACOSX_RE.match(tag)
    if m:
        major, minor, arch = m.group(1), m.group(2), m.group(3)
        return WheelTag(
            arch=_PLATFORM_ARCH_ALIASES.get(arch, arch),
            libc=None, os="macosx", raw=tag,
            macos_version=(int(major), int(minor)),
        )

    # Windows
    m = _WIN_RE.match(tag)
    if m:
        if tag == "win_amd64":
            return WheelTag(arch="x86_64", libc=None, os="windows", raw=tag)
        return WheelTag(arch="i686", libc=None, os="windows", raw=tag)

    # linux_<arch> — raw linux tag, no libc constraint declared
    m = _LINUX_BARE_RE.match(tag)
    if m:
        arch = m.group(1)
        return WheelTag(
            arch=_PLATFORM_ARCH_ALIASES.get(arch, arch),
            libc=None, os="linux", raw=tag,
        )

    # Unknown platform tag — pass through with no constraints.
    logger.debug("wheel_tags: unknown platform tag %r", tag)
    return WheelTag(arch=None, libc=None, os="unknown", raw=tag)


def parse_wheel_filename(filename: str) -> List[WheelTag]:
    """Parse a wheel filename like ``z3_solver-4.16.0.0-py3-none-
    manylinux_2_38_aarch64.whl`` and return a list of
    :class:`WheelTag` (one per ``.``-joined platform component).

    Returns ``[]`` when the filename doesn't match the PEP 425
    wheel shape — caller treats that as "no constraints declared,
    assume universal".
    """
    if not filename.endswith(".whl"):
        return []
    stem = filename[:-len(".whl")]
    parts = stem.split("-")
    # PEP 425: 5 or 6 parts after the split.
    #   5 — no build-tag:   name-version-python-abi-platform
    #   6 — with build-tag: name-version-build-python-abi-platform
    if len(parts) < 5:
        return []
    platform_tag_joined = parts[-1]
    # The platform position can be a ``.``-joined set of tags.
    platform_tags = platform_tag_joined.split(".")
    return [_parse_single_platform_tag(t) for t in platform_tags]
