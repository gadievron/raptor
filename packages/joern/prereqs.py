"""Joern prerequisite checks — CLI resolution, JVM, version gating."""

from __future__ import annotations

import logging
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


# Mirrors core.sandbox.python_paths._SYSTEM_PREFIXES: dirs already in
# the mount-ns baseline bind set need no tool_paths declaration.
# (test_tool_paths pins the two tuples equal so drift is test-visible.)
_SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/", "/sbin/")

_resolved_java: str | None = None
_java_resolved: bool = False


def _java_path() -> str | None:
    """Realpath of the ``java`` the launcher scripts will exec, cached
    beside the launcher resolutions so one spawn's declaration cannot
    diverge from the next after a mid-run PATH mutation."""
    global _resolved_java, _java_resolved
    if not _java_resolved:
        found = shutil.which("java")
        _resolved_java = os.path.realpath(found) if found else None
        _java_resolved = True
    return _resolved_java


def _java_declared_root(java_real: str) -> str | None:
    """The directory a non-system ``java`` earns in the sandbox bind set.

    ``<root>/bin/java`` is the JDK layout, but climbing two levels
    blindly is dangerous: a wrapper at ``~/bin/java`` climbs to ``$HOME``
    itself, a version-manager shim under ``~/.local/bin`` climbs to
    ``~/.local`` — either would bind a credential-bearing tree read-only
    into a sandbox that parses hostile source (and, under the strict
    profile, union it into the Landlock read allowlist). So the climb is
    earned, not assumed: the candidate root must carry a JDK shape marker
    (``release`` file, ``jmods/``, or ``lib/modules``) and must not be
    ``$HOME`` or an ancestor of it. Anything else falls back to declaring
    only the ``bin/`` dir (never ``$HOME`` itself), loudly.
    """
    bin_dir = os.path.realpath(str(Path(java_real).parent))
    root = os.path.realpath(str(Path(bin_dir).parent))
    home = os.path.realpath(os.path.expanduser("~"))
    rootp, homep = Path(root), Path(home)
    jdk_shaped = ((rootp / "release").is_file()
                  or (rootp / "jmods").is_dir()
                  or (rootp / "lib" / "modules").is_file())
    home_or_above = root == home or homep.is_relative_to(rootp)
    if jdk_shaped and not home_or_above:
        return root
    if bin_dir == home or Path(bin_dir) in homep.parents:
        logging.getLogger(__name__).warning(
            "joern tool_paths: java at %s resolves under a root too broad "
            "to declare (%s); not binding it — a sandboxed joern call may "
            "demote if this java is required", java_real, root)
        return None
    logging.getLogger(__name__).warning(
        "joern tool_paths: %s is not JDK-shaped (or is $HOME-adjacent); "
        "declaring only the bin dir %s", root, bin_dir)
    return bin_dir


def _under_system_prefix(path: str) -> bool:
    return any(
        path == prefix.rstrip("/") or path.startswith(prefix)
        for prefix in _SYSTEM_PREFIXES
    )


def joern_tool_paths() -> list[str]:
    """Sandbox read-allowed roots for the Joern toolchain.

    Joern is routinely installed outside the system dirs (a coursier or
    tarball unpack under the operator's home), which puts its launchers
    outside the sandbox's mount-ns bind tree: without a ``tool_paths``
    declaration every sandboxed ``joern-parse``/``joern`` call demotes to
    the mountless namespace backend (host paths visible by name).
    Declaring the install roots keeps those calls on the bind-tree lane.

    Covered roots, deduplicated, system-prefix entries dropped (they are
    already in the bind tree):

    - the parent dir of each resolved launcher (``joern-cli/`` — the
      launcher scripts, ``lib/`` jars, and ``bin/`` re-exec helpers all
      live under it; resolvers already cache the realpath, see above)
    - for a non-system ``java`` (the launcher scripts exec it from
      PATH; a user-local JDK — sdkman, tarball — would otherwise fail
      at exec inside mount-ns): the JDK root, but only when it earns
      the climb — see ``_java_declared_root``.
    """
    candidates: list[str] = []
    for launcher in (_joern_path(), _joern_parse_path()):
        if launcher:
            candidates.append(str(Path(launcher).parent))
    java = _java_path()
    if java and not _under_system_prefix(java):
        root = _java_declared_root(java)
        if root:
            candidates.append(root)
    paths: list[str] = []
    for raw in candidates:
        resolved = os.path.realpath(raw)
        if (os.path.isabs(resolved) and os.path.isdir(resolved)
                and not _under_system_prefix(resolved)
                and resolved not in paths):
            paths.append(resolved)
    return paths


def reset_path_cache() -> None:
    """Clear cached paths. Call between tests that patch shutil.which."""
    global _resolved_joern, _joern_resolved
    global _resolved_joern_parse, _joern_parse_resolved
    global _resolved_java, _java_resolved
    _resolved_joern = None
    _joern_resolved = False
    _resolved_joern_parse = None
    _joern_parse_resolved = False
    _resolved_java = None
    _java_resolved = False


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
            # \d\S* — \S subsumes the digit run (same language, no
            # overlapping repeats)
            m = re.match(r"io\.joern\.joern-cli-(\d\S*)\.jar", jar.name)
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
