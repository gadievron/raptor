"""Wheel-matrix builder + compat cross-check engine.

For each ``(arch, libc)`` in the project's platform matrix, find
the best-installable wheel from the candidate's PyPI release.
Categorise each (project_pair, wheel) outcome:

  * ``ok`` — there's at least one wheel that fits
  * ``arch_gap`` — wheels exist but none for this arch (e.g.
    a package that ships x86_64 wheels only)
  * ``libc_too_new`` — wheel for the right arch exists but
    requires a newer libc than the project's base image
    supplies (the canonical z3-solver==4.16.0.0 case)
  * ``sdist_only`` — no platform-specific wheel, only ``any``
    or sdist; needs build environment in the install path
  * ``uninstallable`` — no wheel AND no sdist

The verdict ladder for emitting findings:
  ok           → no finding
  sdist_only   → info-tier hygiene note
  libc_too_new → high-tier hygiene finding (the canonical bite)
  arch_gap     → medium-tier hygiene finding
  uninstallable→ high-tier hygiene finding
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple

from packages.sca.platform_matrix import PlatformPair, ProjectPlatformMatrix
from packages.sca.platform_matrix.glibc_db import LibcVersion
from packages.sca.wheel_compat.wheel_tags import (
    WheelTag, parse_wheel_filename,
)

logger = logging.getLogger(__name__)


# Possible compat verdicts for one (platform_pair, package_version).
@dataclass(frozen=True)
class CompatVerdict:
    """One compat decision: for this (arch, libc) project pair,
    given the wheel set for this (name, version), what's the
    outcome?"""

    pair: PlatformPair
    verdict: str                       # "ok" | "arch_gap" | "libc_too_new" | …
    reason: str                        # human-readable
    matching_wheel: Optional[str] = None  # filename of best fit when ok


@dataclass
class WheelMatrix:
    """The set of platform constraints a ``(pkg, version)`` ships
    wheels for, plus the sdist-availability flag."""

    name: str
    version: str
    wheel_tags: List[WheelTag]
    has_sdist: bool

    def __bool__(self) -> bool:
        return bool(self.wheel_tags) or self.has_sdist


def wheel_matrix_for_version(
    pypi_client, name: str, version: str,
) -> Optional[WheelMatrix]:
    """Build the wheel matrix for ``name==version`` by fetching
    its PyPI metadata + parsing each release-file's wheel name.

    Returns None when PyPI doesn't have the (name, version)
    combination — the bumper distinguishes "no compat data" from
    "compat data says this is broken" via this return value.
    """
    try:
        meta = pypi_client.get_metadata(name)
    except Exception as e:                                  # noqa: BLE001
        logger.debug(
            "wheel_compat: PyPI fetch failed for %s: %s", name, e,
        )
        return None
    if not isinstance(meta, dict):
        return None
    releases = meta.get("releases") or {}
    files = releases.get(version)
    if not isinstance(files, list) or not files:
        return None

    wheel_tags: List[WheelTag] = []
    has_sdist = False
    for f in files:
        filename = f.get("filename") if isinstance(f, dict) else None
        if not isinstance(filename, str):
            continue
        if filename.endswith(".tar.gz") or filename.endswith(".zip"):
            has_sdist = True
            continue
        if filename.endswith(".whl"):
            wheel_tags.extend(parse_wheel_filename(filename))

    return WheelMatrix(
        name=name, version=version,
        wheel_tags=wheel_tags, has_sdist=has_sdist,
    )


def _best_match(
    pair: PlatformPair, wheel_tags: List[WheelTag],
) -> Optional[WheelTag]:
    """For one (arch, libc) project pair, return the wheel-tag
    that best satisfies it, or None if none does.

    "Best" means: same arch (or ``any``), same OS family, libc
    requirement satisfied by the project's libc version. We don't
    rank between multiple matches — the first match is enough to
    decide "ok".
    """
    candidates = []
    for w in wheel_tags:
        if w.arch == "any" and w.os == "any":
            candidates.append(w)
            continue
        if w.arch != pair.arch:
            continue
        # OS-family check. macOS / Windows tags don't satisfy a
        # Linux project pair and vice-versa. The platform_matrix
        # only currently emits Linux pairs (with libc) or
        # libc=None for Windows/macOS pairs.
        if pair.libc is None:
            # Project pair is non-Linux — wheel must match the OS.
            # We don't distinguish macOS / Windows in PlatformPair
            # today; fall through and let arch match decide.
            if w.os == "windows":
                candidates.append(w)
                continue
            if w.os == "macosx":
                # macOS version gating: a project pinned to macos-13
                # (pair.macos_version=(13, 0)) can install
                # ``macosx_11_0_arm64`` wheels but NOT
                # ``macosx_14_0_arm64`` wheels. When pair.macos_version
                # is set + wheel declares a tag version, reject too-new
                # wheels. When EITHER side is missing version info,
                # fall through to "arch match decides" (the existing
                # lenient behaviour).
                if (pair.macos_version is not None
                        and w.macos_version is not None
                        and w.macos_version > pair.macos_version):
                    # Wheel requires a NEWER macOS than the project
                    # accepts — not a fit.
                    continue
                candidates.append(w)
            continue
        # Linux pair → wheel must be Linux + libc family + version OK.
        if w.os != "linux":
            continue
        if w.libc is None:
            # Raw ``linux_x86_64`` tag — no libc constraint declared.
            # Treat as OK (the wheel might still fail at runtime but
            # we have no signal to gate on).
            candidates.append(w)
            continue
        if w.libc.family != pair.libc.family:
            continue
        if w.libc.version > pair.libc.version:
            # Wheel requires NEWER libc than project provides → not a fit.
            continue
        candidates.append(w)

    return candidates[0] if candidates else None


def _verdict_for_pair(
    pair: PlatformPair, wm: WheelMatrix,
) -> CompatVerdict:
    """Decide the compat verdict for one project pair against one
    wheel matrix."""
    # Has any wheel at all? Check `any` first (pure-python pkgs).
    if not wm.wheel_tags and wm.has_sdist:
        return CompatVerdict(
            pair=pair, verdict="sdist_only",
            reason=(
                f"{wm.name}=={wm.version} ships no wheels; "
                f"install requires a build environment "
                f"(compilers, headers) on {pair.as_str()}"
            ),
        )
    if not wm.wheel_tags and not wm.has_sdist:
        return CompatVerdict(
            pair=pair, verdict="uninstallable",
            reason=(
                f"{wm.name}=={wm.version} has no wheels and no "
                f"sdist on PyPI for {pair.as_str()}"
            ),
        )

    match = _best_match(pair, wm.wheel_tags)
    if match is not None:
        return CompatVerdict(
            pair=pair, verdict="ok",
            reason="installable wheel found",
            matching_wheel=match.raw,
        )

    # No wheel matched this pair — dig deeper to give a useful
    # diagnostic. Check if any wheel exists for the arch (then it's
    # a libc / OS mismatch); else it's arch_gap.
    same_arch = [w for w in wm.wheel_tags if w.arch == pair.arch]
    if not same_arch:
        if wm.has_sdist:
            return CompatVerdict(
                pair=pair, verdict="sdist_only",
                reason=(
                    f"{wm.name}=={wm.version} has wheels for other "
                    f"arches but none for {pair.arch}; install on "
                    f"{pair.as_str()} requires sdist build"
                ),
            )
        return CompatVerdict(
            pair=pair, verdict="arch_gap",
            reason=(
                f"{wm.name}=={wm.version} has no wheels for "
                f"{pair.arch} and no sdist; not installable on "
                f"{pair.as_str()}"
            ),
        )

    # Same-arch wheels exist; closest mismatch is libc.
    if pair.libc is not None:
        same_family = [
            w for w in same_arch
            if w.libc is not None and w.libc.family == pair.libc.family
        ]
        if same_family:
            min_libc = min(
                same_family, key=lambda w: w.libc.version,
            )
            return CompatVerdict(
                pair=pair, verdict="libc_too_new",
                reason=(
                    f"{wm.name}=={wm.version}'s {pair.arch} wheels "
                    f"require {min_libc.libc.as_str()} or newer; "
                    f"project pair has only {pair.libc.as_str()}"
                ),
                matching_wheel=min_libc.raw,
            )

    # macOS version gating: project on macos-13 vs a dep that only
    # ships macosx_14+_arm64 wheels. Mirrors the libc_too_new logic
    # above. Only fires when the project explicitly declares a
    # macOS version (GHA macos-N runner) AND every same-arch macOS
    # wheel requires a newer version.
    if pair.macos_version is not None:
        same_macos = [
            w for w in same_arch
            if w.os == "macosx" and w.macos_version is not None
        ]
        if same_macos:
            min_required = min(
                same_macos, key=lambda w: w.macos_version,
            )
            if min_required.macos_version > pair.macos_version:
                return CompatVerdict(
                    pair=pair, verdict="macos_too_new",
                    reason=(
                        f"{wm.name}=={wm.version}'s {pair.arch} wheels "
                        f"require macOS "
                        f"{min_required.macos_version[0]}.{min_required.macos_version[1]} "
                        f"or newer; project pair targets macOS "
                        f"{pair.macos_version[0]}.{pair.macos_version[1]}"
                    ),
                    matching_wheel=min_required.raw,
                )

    # Fallback — no libc info or different family; surface generic.
    if wm.has_sdist:
        # Alpine / musl projects hitting a dep that only ships
        # manylinux (glibc) wheels are the dominant cross-family
        # case. The default generic message ("sdist available but
        # requires build environment") is correct but unactionable;
        # add an Alpine-specific build-tools hint when we recognise
        # the shape so operators get a clear next step.
        is_alpine_glibc_only = (
            pair.libc is not None and pair.libc.family == "musl"
            and any(
                w.libc is not None and w.libc.family == "glibc"
                for w in same_arch
            )
        )
        if is_alpine_glibc_only:
            reason = (
                f"{wm.name}=={wm.version} ships manylinux (glibc) "
                f"wheels for {pair.arch} but no musllinux wheel "
                f"for {pair.as_str()}. sdist available; on Alpine "
                f"add ``apk add build-base python3-dev`` to your "
                f"Dockerfile to enable source build, or switch "
                f"base to a glibc image (``python:3.X-bookworm``)."
            )
        else:
            reason = (
                f"{wm.name}=={wm.version}'s {pair.arch} wheels "
                f"don't match {pair.as_str()}; sdist available "
                f"but requires build environment"
            )
        return CompatVerdict(
            pair=pair, verdict="sdist_only",
            reason=reason,
        )
    return CompatVerdict(
        pair=pair, verdict="arch_gap",
        reason=(
            f"{wm.name}=={wm.version} has no wheel compatible "
            f"with {pair.as_str()}"
        ),
    )


def check_compat(
    matrix: ProjectPlatformMatrix,
    wm: WheelMatrix,
) -> List[CompatVerdict]:
    """For every project pair, decide the compat verdict against
    the wheel matrix."""
    return [_verdict_for_pair(pair, wm) for pair in matrix]


# Per-process recommendation cache. ``find_compatible_version`` is
# the priciest call in the wheel-compat scan path — walks up to 20
# versions of PyPI release history, fetching wheel metadata for each.
# When the same dep shows up in multiple manifests within one scan
# (``requirements.txt`` + ``requirements-dev.txt`` + ``pyproject.toml``
# all pinning ``numpy==1.x``), the second + third invocations recompute
# the same answer. Key omits ``PlatformPair.source`` (diagnostic-only
# text that varies between matrix builds but doesn't affect the
# recommendation).
_RECOMMENDATION_CACHE: Dict[
    Tuple[str, FrozenSet[Tuple[str, Optional["LibcVersion"]]]],
    Optional[str],
] = {}


def _matrix_cache_key(matrix: ProjectPlatformMatrix) -> FrozenSet[
    Tuple[str, Optional[LibcVersion], Optional[Tuple[int, int]]]
]:
    """Build a cache key that ignores ``PlatformPair.source``.

    Two matrices with the same ``{(arch, libc, macos_version)}`` set
    produce the same recommendation regardless of which Dockerfile /
    GHA / etc. each pair was discovered from.

    ``macos_version`` MUST be in the key — a project on macos-13 and
    one on macos-14 have different acceptable-wheel windows
    (macos-13 rejects ``macosx_14_arm64`` wheels). Sharing a cache
    entry would mis-recommend.
    """
    return frozenset(
        (p.arch, p.libc, p.macos_version) for p in matrix.pairs
    )


def clear_recommendation_cache() -> None:
    """Reset the per-process recommendation cache.

    Test utility + escape hatch for long-running services that
    refresh PyPI metadata mid-process. Not called by production
    scan paths — the cache lifetime is correctly process-scoped.
    """
    _RECOMMENDATION_CACHE.clear()


def find_compatible_version(
    pypi_client,
    name: str,
    matrix: ProjectPlatformMatrix,
    *,
    max_versions_walked: int = 20,
) -> Optional[str]:
    """Walk a package's PyPI release history newest → oldest and
    return the highest version with NO platform-compat findings
    against ``matrix``. Returns None if no compatible version is
    found within the walk window.

    Bounded walk (``max_versions_walked``): packages with long
    release histories (numpy, requests, …) shouldn't trigger a
    300-version walk just to find a compatible point. 20 versions
    covers ~6-12 months of typical release cadence — enough to
    find a workaround pin without unbounded PyPI traffic.

    Pre-release versions (``b1``, ``rc2``, ``dev``) are skipped —
    operators wanting a recommendation almost always want stable.

    Cached per ``(name, matrix-shape)`` for the process lifetime;
    a scan with the same dep pinned across multiple manifests pays
    the PyPI walk once.
    """
    cache_key = (name, _matrix_cache_key(matrix))
    if cache_key in _RECOMMENDATION_CACHE:
        return _RECOMMENDATION_CACHE[cache_key]

    try:
        meta = pypi_client.get_metadata(name)
    except Exception as e:                                  # noqa: BLE001
        logger.debug(
            "wheel_compat: find_compatible_version: PyPI fetch failed "
            "for %s: %s", name, e,
        )
        # Don't cache the failure — a transient network error
        # shouldn't pin the result for the rest of the process.
        return None
    if not isinstance(meta, dict):
        return None
    releases = meta.get("releases") or {}
    if not isinstance(releases, dict):
        return None

    stable = [
        v for v in releases.keys()
        if _is_stable_version(v)
    ]
    stable.sort(key=_version_key, reverse=True)

    for version in stable[:max_versions_walked]:
        wm = wheel_matrix_for_version(pypi_client, name, version)
        if wm is None:
            continue
        verdicts = check_compat(matrix, wm)
        if all(v.verdict == "ok" for v in verdicts):
            _RECOMMENDATION_CACHE[cache_key] = version
            return version
    # No compatible version found within the walk window. Cache the
    # negative result too — the next caller would walk the same
    # exhausted history.
    _RECOMMENDATION_CACHE[cache_key] = None
    return None


_STABLE_VERSION_RE = __import__("re").compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$"
)


def _is_stable_version(v: str) -> bool:
    """True when ``v`` is a stable-semver-ish version. Mirrors
    the filter used by ``core.upstream_latest._version_filter``
    so pre-releases / .devN / +local / rc / b1 / a1 are all
    rejected."""
    return bool(_STABLE_VERSION_RE.match(v))


def _version_key(v: str) -> tuple:
    """Numeric-component sort key. Treats missing components as 0."""
    m = _STABLE_VERSION_RE.match(v)
    if not m:
        return (0,)
    return tuple(int(p) if p else 0 for p in m.groups())
