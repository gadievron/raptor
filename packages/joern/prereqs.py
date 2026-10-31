"""Joern prerequisite checks — CLI resolution, JVM, version gating."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
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


def _homebrew_install_root(launcher: str) -> Path | None:
    """Recognize an installed Joern keg, not arbitrary adjacent directories."""
    path = Path(launcher)
    if path.parent.name != "bin":
        return None
    root = path.parent.parent
    if root.name == "libexec":
        root = root.parent
    if (root.parent.name != "joern" or root.parent.parent.name != "Cellar"
            or not (root / "INSTALL_RECEIPT.json").is_file()
            or not (root / "libexec/lib").is_dir()):
        return None
    return root


def _homebrew_receipt(root: Path) -> dict:
    try:
        descriptor = os.open(root / "INSTALL_RECEIPT.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return {}
            data = stream.read(65537)
        if len(data) > 65536:
            return {}
        value = json.loads(data)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, RecursionError):
        return {}


def _homebrew_entry(launcher: str, name: str) -> str | None:
    root = _homebrew_install_root(launcher)
    if root is not None:
        candidate = root / "libexec/bin" / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
    return None


def _homebrew_version(launcher: str) -> str | None:
    root = _homebrew_install_root(launcher)
    if root is None:
        return None
    source = _homebrew_receipt(root).get("source")
    if not isinstance(source, dict) or source.get("spec") != "stable":
        return None
    versions = source.get("versions")
    value = versions.get("stable") if isinstance(versions, dict) else None
    # A timestamped HEAD banner is not a semantic release number. A stable
    # Homebrew receipt records the source release used to build these JARs.
    return value if isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value) else None


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
                real = os.path.realpath(found)
                _resolved_joern = (_homebrew_entry(real, "repl-bridge")
                                   or _homebrew_entry(real, "joern-cli") or real)
                break
        _joern_resolved = True
    return _resolved_joern


def _joern_parse_path() -> str | None:
    global _resolved_joern_parse, _joern_parse_resolved
    if not _joern_parse_resolved:
        found = shutil.which(_JOERN_PARSE_BIN)
        if found:
            real = os.path.realpath(found)
            _resolved_joern_parse = _homebrew_entry(real, "joern-parse") or real
        else:
            launcher = _joern_path()
            _resolved_joern_parse = _homebrew_entry(launcher, "joern-parse") if launcher else None
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
        launcher = _joern_path()
        if launcher and _homebrew_install_root(launcher) is not None:
            # Homebrew wrappers choose JAVA_HOME on both Linux and macOS.
            # Resolve that choice explicitly before bypassing the wrapper.
            selected = os.environ.get("JAVA_HOME")
            if selected:
                _resolved_java = _java_in_home(selected)
            else:
                home = _homebrew_java_home(launcher)
                _resolved_java = str(home / "bin/java") if home is not None else None
            if _resolved_java is None:
                logging.getLogger(__name__).warning(
                    "Joern Homebrew JDK unavailable; check JAVA_HOME and the installed OpenJDK dependency")
        elif sys.platform == "darwin" and (found == "/usr/bin/java" or _resolved_java == "/usr/bin/java"):
            _resolved_java = _darwin_java_path()
        _java_resolved = True
    return _resolved_java


def _jdk_home(java: str) -> Path | None:
    """Return a verified JDK layout, never infer JAVA_HOME from a shim."""
    path = Path(java).resolve()
    root = path.parent.parent
    if path.parent.name == "bin" and (
        (root / "release").is_file() or (root / "jmods").is_dir()
        or (root / "lib/modules").is_file()
    ):
        return root
    return None


def _java_in_home(selected: str) -> str | None:
    try:
        root = Path(selected)
        if not root.is_absolute():
            return None
        for candidate in (root / "bin/java", root / "openjdk.jdk/Contents/Home/bin/java"):
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                continue
            java = candidate.resolve(strict=True)
            if str(java) != "/usr/bin/java" and _jdk_home(str(java)) is not None:
                return str(java)
    except (OSError, ValueError, RuntimeError):
        pass
    return None


def _homebrew_java_home(launcher: str) -> Path | None:
    root = _homebrew_install_root(launcher)
    if root is None:
        return None
    dependencies = _homebrew_receipt(root).get("runtime_dependencies")
    if not isinstance(dependencies, list):
        return None
    # Prefer the formula's declared JDK over unrelated transitive runtimes.
    direct = [entry for entry in dependencies if isinstance(entry, dict)
              and entry.get("declared_directly") is True]
    names = []
    for entry in direct or dependencies:
        name = entry.get("full_name") if isinstance(entry, dict) else entry
        if isinstance(name, str) and re.fullmatch(r"openjdk(?:@\d+)?", name) and name not in names:
            names.append(name)
    if len(names) != 1:
        # Ambiguous receipts cannot establish the wrapper's JDK choice.
        # An explicit JAVA_HOME remains available to the operator.
        return None
    prefix = root.parent.parent.parent / "opt" / names[0]
    for candidate in (prefix / "libexec", prefix):
        java = _java_in_home(str(candidate))
        if java is not None:
            return _jdk_home(java)
    return None


def _darwin_java_path() -> str | None:
    # Apple's system launcher needs services blocked by worker confinement.
    # Resolve the JDK before sandboxing instead of treating /usr as JAVA_HOME.
    selected = os.environ.get("JAVA_HOME")
    if not selected:
        from core.config import RaptorConfig
        try:
            result = subprocess.run(
                ["/usr/libexec/java_home"], capture_output=True, text=True,
                timeout=5, env=RaptorConfig.get_safe_env(),
            )
            if result.returncode != 0:
                return None
            selected = result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return None
    java = _java_in_home(selected)
    if java is not None:
        return java
    logging.getLogger(__name__).warning(
        "Joern requires a real JDK on macOS; correct JAVA_HOME or put the JDK bin directory on PATH")
    return None


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


def _joern_declared_root(launcher_real: str) -> str:
    """The directory a resolved Joern launcher earns in the sandbox bind set.

    Real tarball installs put launchers in ``joern-cli/bin/`` while the
    JARs live in ``joern-cli/lib/``.  Declaring only ``bin/`` (the
    launcher's parent) is safe but incomplete — the JVM can't find its
    class JARs and fails with ClassNotFoundException inside mount-ns.

    The climb from ``bin/`` to the distribution root is earned, not
    assumed: the candidate must carry a Joern shape marker (``lib/``
    subdir or ``c2cpg.sh``) and must not be ``$HOME`` or an ancestor.
    When the climb isn't earned the launcher's parent dir (safe
    fallback) is returned.
    """
    bin_dir = os.path.realpath(str(Path(launcher_real).parent))
    if Path(bin_dir).name != "bin":
        return bin_dir

    root = os.path.realpath(str(Path(bin_dir).parent))
    home = os.path.realpath(os.path.expanduser("~"))
    rootp, homep = Path(root), Path(home)

    joern_shaped = ((rootp / "lib").is_dir()
                    or (rootp / "c2cpg.sh").is_file())
    home_or_above = root == home or homep.is_relative_to(rootp)

    if joern_shaped and not home_or_above:
        return root

    if home_or_above:
        logging.getLogger(__name__).warning(
            "joern tool_paths: launcher at %s resolves under a root too "
            "broad to declare (%s); declaring only the bin dir",
            launcher_real, root)
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
            candidates.append(_joern_declared_root(launcher))
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
    """True if the CLI and parser resolve from PATH or a verified Homebrew keg."""
    return (
        _joern_path() is not None
        and _joern_parse_path() is not None
    )


def _version_from_dist(joern: str) -> str | None:
    """Read the version from the distribution's own jar names.

    Recent joern releases dropped the ``--version`` flag, and scraping
    the REPL banner costs a full JVM boot.  The ``lib/`` dir next to
    the launcher carries the version in every jar name
    (``io.joern.joern-cli-<version>.jar``) — read it for free.
    """
    launcher = Path(joern).resolve()
    root = launcher.parent.parent if launcher.parent.name == "bin" else launcher.parent
    lib = root / "lib"
    try:
        for jar in lib.glob("io.joern.joern-cli-*.jar"):
            # \d\S* — \S subsumes the digit run (same language, no
            # overlapping repeats)
            m = re.match(r"io\.joern\.joern-cli-(\d\S*)\.jar", jar.name)
            if m:
                return m.group(1)
    except OSError:
        pass
    return _homebrew_version(str(launcher))


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
    java = _java_path()
    if java is None:
        return None
    info = probe(java, args=("-version",), timeout=10)
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
    if _joern_parse_path() is None:
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
