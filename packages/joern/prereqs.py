"""Joern prerequisite checks — CLI resolution, JVM, version gating."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from core.run.toolprobe import probe

_JOERN_NAMES = ("joern", "joern-cli")
_JOERN_PARSE_BIN = "joern-parse"
# Oldest supported release: first joern release of 2026.  Older
# releases (including all v3.x) use pre-v4 CPGQL API idioms that
# RAPTOR's queries no longer accommodate.
MIN_JOERN_VERSION = (4, 0, 458)
MIN_JAVA_VERSION = 11

_resolved_joern: str | None = None
_joern_resolved: bool = False

_resolved_joern_parse: str | None = None
_joern_parse_resolved: bool = False


# Both resolvers cache the REAL path (os.path.realpath of the which()
# result): joern installs put symlink launchers on PATH while the
# actual scripts live in the joern-cli install dir next to the jars
# they need. The sandbox's mount-ns visibility check realpaths cmd[0],
# so exec'ing the un-realpath'd symlink silently downgrades the run to
# the Landlock-only fallback tier (selftest-05 scanner precedent:
# exec tools via their real path).
def _joern_path() -> str | None:
    global _resolved_joern, _joern_resolved
    if not _joern_resolved:
        for name in _JOERN_NAMES:
            found = shutil.which(name)
            if found:
                _resolved_joern = os.path.realpath(found)
                break
        _joern_resolved = True
    return _resolved_joern


def _joern_parse_path() -> str | None:
    global _resolved_joern_parse, _joern_parse_resolved
    if not _joern_parse_resolved:
        found = shutil.which(_JOERN_PARSE_BIN)
        _resolved_joern_parse = os.path.realpath(found) if found else None
        _joern_parse_resolved = True
    return _resolved_joern_parse


def reset_path_cache() -> None:
    """Clear cached paths. Call between tests that patch shutil.which."""
    global _resolved_joern, _joern_resolved
    global _resolved_joern_parse, _joern_parse_resolved
    _resolved_joern = None
    _joern_resolved = False
    _resolved_joern_parse = None
    _joern_parse_resolved = False


def is_available() -> bool:
    """True if joern (or joern-cli) and joern-parse are on PATH."""
    return (
        _joern_path() is not None
        and shutil.which(_JOERN_PARSE_BIN) is not None
    )


def _version_from_dist(joern: str) -> str | None:
    """Read the version from the distribution's own jar names.

    Recent joern releases dropped the ``--version`` flag, and scraping
    the REPL banner costs a full JVM boot.  The ``lib/`` dir next to
    the launcher carries the version in every jar name
    (``io.joern.joern-cli-<version>.jar``) — read it for free.
    """
    lib = Path(joern).resolve().parent / "lib"
    try:
        for jar in lib.glob("io.joern.joern-cli-*.jar"):
            m = re.match(r"io\.joern\.joern-cli-(\d+\S*)\.jar", jar.name)
            if m:
                return m.group(1)
    except OSError:
        pass
    return None


def version() -> str | None:
    """Return the joern version string, or None if unavailable."""
    if not is_available():
        return None
    dist_version = _version_from_dist(_joern_path() or "joern")
    if dist_version:
        return dist_version
    try:
        from core.config import RaptorConfig
        proc = subprocess.run(
            [_joern_path() or "joern", "--version"],
            capture_output=True, text=True, timeout=30,
            check=False,
            env=RaptorConfig.get_safe_env(),
        )
        # joern >= 4.x has no --version flag: it launches the REPL, which
        # prints jline warnings and a banner containing "Version: X.Y.Z".
        # Older releases print the bare version on the first line. Scan for
        # whichever appears rather than trusting line order.
        for line in proc.stdout.splitlines():
            m = re.search(r"Version:\s*(v?\d+\S*)", line)
            if m:
                return m.group(1)
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            if re.match(r"v?\d+\.\d+", stripped):
                return stripped
        return None
    except (subprocess.TimeoutExpired, OSError):
        return None


def version_tuple() -> tuple[int, ...] | None:
    """Parse major.minor.patch from the joern version string.

    Patch defaults to 0 when absent so comparisons against the
    three-component MIN_JOERN_VERSION stay well-defined.
    """
    v = version()
    if not v:
        return None
    m = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?", v)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def meets_min_version() -> bool:
    """True iff joern is at least MIN_JOERN_VERSION."""
    vt = version_tuple()
    return vt is not None and vt >= MIN_JOERN_VERSION


def _java_version() -> int | None:
    """Return the major Java version, or None.

    Probes via core.run.toolprobe (sanitised env, resolved-path
    exec). java prints its version to stderr — scan both streams.
    """
    info = probe("java", args=("-version",), timeout=10)
    if info is None:
        return None
    combined = info.stdout + info.stderr
    m = re.search(r'"(\d+)(?:\.(\d+))?', combined)
    if m:
        major = int(m.group(1))
        if major == 1 and m.group(2):
            return int(m.group(2))
        return major
    return None


def check_prereqs() -> list[str]:
    """Return list of missing prerequisites (empty = all met)."""
    missing: list[str] = []

    if _joern_path() is None:
        missing.append("joern-cli not found on PATH")
    if shutil.which(_JOERN_PARSE_BIN) is None:
        missing.append("joern-parse not found on PATH")

    java_ver = _java_version()
    if java_ver is None:
        missing.append("java not found on PATH (JVM required)")
    elif java_ver < MIN_JAVA_VERSION:
        missing.append(
            f"java {java_ver} < required {MIN_JAVA_VERSION}"
        )

    if not missing and not meets_min_version():
        v = version() or "unknown"
        required = ".".join(str(p) for p in MIN_JOERN_VERSION)
        missing.append(f"joern version {v} < required {required}")

    try:
        from core.sandbox import run as _sandbox_run  # noqa: F401
    except ImportError:
        missing.append("core.sandbox not available (required for untrusted source)")

    return missing
