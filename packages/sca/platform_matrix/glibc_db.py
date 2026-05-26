"""Distro-image → libc version lookup tables.

Two families: ``glibc`` (Debian/Ubuntu/Fedora/RHEL/AL202X derivatives,
the python:X-Y-bookworm style devcontainer images) and ``musl``
(Alpine, distroless-musl). The libc family AND the version number
both matter: a ``manylinux_2_38`` wheel needs glibc ≥ 2.38; a
``musllinux_1_2`` wheel needs musl ≥ 1.2.

Coverage is the dominant Python-base / GHA-runner subset; less
common images (Photon, Clear Linux, etc.) fall through to the
fallback heuristics in :mod:`packages.sca.platform_matrix.matrix`.

If an image isn't in the table we return ``None`` rather than
guess — wrong glibc info is worse than no glibc info.

Adding rows: cross-reference https://distrowatch.com/ or the
distro's own glibc package version. For Python's official images,
the ``python:<py-ver>-<distro-codename>`` form follows the
underlying distro's glibc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class LibcVersion:
    """A libc family + version pair, e.g. ``LibcVersion("glibc", (2, 36))``.

    Versions are tuples for lexical comparison — ``(2, 36) < (2, 39)``
    is the obvious win over string comparison (which gets ``"2.10"``
    < ``"2.9"`` wrong)."""

    family: str            # "glibc" | "musl"
    version: Tuple[int, ...]

    def as_str(self) -> str:
        return f"{self.family} {'.'.join(str(p) for p in self.version)}"


# Distro release → libc family + version.
#
# Sources / spot-checks:
# - https://www.debian.org/releases/ + glibc package version
# - https://wiki.ubuntu.com/Releases + glibc
# - https://endoflife.date/almalinux + glibc
# - alpinelinux.org/releases + musl package version
#
# Format: "distro:codename" → LibcVersion
_DISTRO_LIBC: Dict[str, LibcVersion] = {
    # Debian
    "debian:buster":   LibcVersion("glibc", (2, 28)),  # 10
    "debian:bullseye": LibcVersion("glibc", (2, 31)),  # 11
    "debian:bookworm": LibcVersion("glibc", (2, 36)),  # 12
    "debian:trixie":   LibcVersion("glibc", (2, 39)),  # 13
    # Ubuntu
    "ubuntu:20.04":    LibcVersion("glibc", (2, 31)),
    "ubuntu:focal":    LibcVersion("glibc", (2, 31)),
    "ubuntu:22.04":    LibcVersion("glibc", (2, 35)),
    "ubuntu:jammy":    LibcVersion("glibc", (2, 35)),
    "ubuntu:24.04":    LibcVersion("glibc", (2, 39)),
    "ubuntu:noble":    LibcVersion("glibc", (2, 39)),
    # Alpine (musl)
    "alpine:3.16":     LibcVersion("musl", (1, 2, 3)),
    "alpine:3.17":     LibcVersion("musl", (1, 2, 3)),
    "alpine:3.18":     LibcVersion("musl", (1, 2, 4)),
    "alpine:3.19":     LibcVersion("musl", (1, 2, 4)),
    "alpine:3.20":     LibcVersion("musl", (1, 2, 5)),
    # AlmaLinux / Rocky / RHEL
    "almalinux:8":     LibcVersion("glibc", (2, 28)),
    "almalinux:9":     LibcVersion("glibc", (2, 34)),
    "rockylinux:8":    LibcVersion("glibc", (2, 28)),
    "rockylinux:9":    LibcVersion("glibc", (2, 34)),
    "redhat/ubi8":     LibcVersion("glibc", (2, 28)),
    "redhat/ubi9":     LibcVersion("glibc", (2, 34)),
    # Fedora
    "fedora:39":       LibcVersion("glibc", (2, 38)),
    "fedora:40":       LibcVersion("glibc", (2, 39)),
    "fedora:41":       LibcVersion("glibc", (2, 40)),
    "fedora:42":       LibcVersion("glibc", (2, 41)),
}


# GHA runner image → libc. Runners are Ubuntu-based.
_RUNNER_LIBC: Dict[str, LibcVersion] = {
    "ubuntu-20.04":    LibcVersion("glibc", (2, 31)),
    "ubuntu-22.04":    LibcVersion("glibc", (2, 35)),
    "ubuntu-24.04":    LibcVersion("glibc", (2, 39)),
    # The floating ``ubuntu-latest`` rolls forward; today it points
    # at 24.04. We use the newer floor since wheel compatibility is
    # "the wheel needs >= this", so picking the newer side
    # under-flags compat issues (a wheel that works on 24.04 might
    # not work on 22.04). Operators using ubuntu-latest accept the
    # rolling-target trade.
    "ubuntu-latest":   LibcVersion("glibc", (2, 39)),
    # Windows / macOS — return None; wheels for those have win_amd64
    # or macosx_* tags, no libc concept.
}


def lookup_distro_libc(distro_ref: str) -> Optional[LibcVersion]:
    """Look up a libc version for a distro reference like
    ``debian:bookworm``. Returns None when unknown.

    Tolerates the common Python-image shape
    ``python:<py-ver>-<distro-codename>`` by stripping the Python-
    version prefix and recognising the trailing distro codename.
    Examples:
      * ``python:3.12-bookworm`` → glibc 2.36 (Debian 12)
      * ``python:3.13-slim-bookworm`` → glibc 2.36
      * ``python:3.13-alpine3.19`` → musl 1.2.4
    """
    if distro_ref in _DISTRO_LIBC:
        return _DISTRO_LIBC[distro_ref]

    # ``python:3.12-bookworm``, ``python:3.13-slim-bookworm``,
    # ``python:3.13-alpine3.19`` — split on "-" / ":" and check
    # each suffix segment against the codename map.
    parts = distro_ref.replace(":", "-").split("-")
    for part in parts:
        # ``alpine3.19`` form → ``alpine:3.19``
        if part.startswith("alpine") and len(part) > len("alpine"):
            ver = part[len("alpine"):]
            key = f"alpine:{ver}"
            if key in _DISTRO_LIBC:
                return _DISTRO_LIBC[key]
        # Codename-only Debian variants: bookworm, bullseye, …
        for distro in ("debian", "ubuntu"):
            key = f"{distro}:{part}"
            if key in _DISTRO_LIBC:
                return _DISTRO_LIBC[key]

    return None


def lookup_runner_libc(runner_ref: str) -> Optional[LibcVersion]:
    """Look up libc for a GHA ``runs-on:`` value. Returns None for
    Windows/macOS runners (no libc applicable)."""
    return _RUNNER_LIBC.get(runner_ref)


def known_distros() -> Dict[str, LibcVersion]:
    """Public read-only view of the distro table — used by tests +
    diagnostic output."""
    return dict(_DISTRO_LIBC)
