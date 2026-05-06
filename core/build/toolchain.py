"""Toolchain-home env-var auto-detection for build subprocesses.

The sandbox's `get_safe_env()` keeps a tight allowlist that deliberately
excludes language-specific vars like `JAVA_HOME`, `GOROOT`,
`DOTNET_ROOT`, `RUSTUP_HOME`. Expanding the allowlist globally would
broaden exposure for every non-that-language user (prompt-injection
amplification — see PR #210 threat-model notes).

Instead, each build-system entry in
`packages/codeql/build_detector.BUILD_SYSTEMS` declares an
`env_detect: List[str]` naming the vars it needs. At build time, this
module resolves each name by filesystem probing — never by reading
`os.environ` (which would re-admit the operator's shell quirks we're
trying to keep out of the sandbox).

Detection strategy per var:

  JAVA_HOME     1. /usr/lib/jvm/default-java (Debian/Ubuntu symlink)
                2. readlink -f $(which java) → strip /bin/java
                3. /usr/libexec/java_home (macOS — when supported)

  GOROOT        readlink -f $(which go) → strip /bin/go

  DOTNET_ROOT   readlink -f $(which dotnet) → strip /bin

  RUSTUP_HOME   1. ~/.rustup if present
                2. `rustup show home` output (if rustup on PATH)

Helpers return None when nothing resolves. Callers log a WARNING
naming the missing toolchain, then let the build tool surface its
own error (cryptic but authoritative).
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional

logger = logging.getLogger(__name__)


def _resolve_from_which(cmd: str, strip_suffix: str) -> Optional[str]:
    """Locate `cmd` on PATH, readlink to the real binary, strip a
    trailing path suffix to reveal the install root.

    Example: cmd="java", strip_suffix="bin/java" on a host where
    `/usr/bin/java` is a symlink chain leading to
    `/usr/lib/jvm/java-17-openjdk-amd64/bin/java` — returns the path
    `/usr/lib/jvm/java-17-openjdk-amd64`.

    Returns None if cmd isn't on PATH or the real path doesn't end
    with the expected suffix (defensive — avoids building a bogus
    "toolchain home" from a wrapper script in an unrelated dir).
    """
    found = shutil.which(cmd)
    if not found:
        return None
    try:
        real = os.path.realpath(found)
    except OSError:
        return None
    # Normalise suffix for endswith comparison
    suffix = "/" + strip_suffix.lstrip("/")
    if not real.endswith(suffix):
        return None
    home = real[: -len(suffix)]
    return home or None


def detect_JAVA_HOME() -> Optional[str]:
    """Resolve JAVA_HOME from the host. See module docstring for order."""
    import sys as _sys
    # 1. Debian/Ubuntu convention
    default_java = "/usr/lib/jvm/default-java"
    if os.path.isdir(default_java):
        return default_java
    # 2. macOS's canonical helper. MUST run BEFORE the which-java
    # heuristic on Darwin: `/usr/bin/java` is Apple's stub that
    # exists even when no JDK is installed, so `which java` returns
    # `/usr/bin/java` → strip /bin/java → JAVA_HOME = `/usr`. Setting
    # `JAVA_HOME=/usr` makes the stub recursively re-exec itself
    # (it finds `/usr/bin/javac` = the stub itself = infinite loop)
    # and ANY subprocess that invokes javac under that env hangs
    # indefinitely. Apple's java_home is the authoritative source on
    # macOS — defer to it. Caught by macOS dogfooding of
    # packages/codeql build synthesis.
    if _sys.platform == "darwin":
        macos_helper = "/usr/libexec/java_home"
        if os.path.isfile(macos_helper) and os.access(macos_helper, os.X_OK):
            try:
                import subprocess
                r = subprocess.run(
                    [macos_helper], capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0 and r.stdout.strip():
                    candidate = r.stdout.strip()
                    if os.path.isdir(candidate):
                        return candidate
            except (OSError, subprocess.SubprocessError):
                pass
        # macOS without a JDK: don't fall through to the which-java
        # heuristic — would hit the stub-loop trap above. Return None
        # and let the caller's build tool surface the missing-
        # toolchain error.
        return None
    # 3. From `which java` (Linux). Reject `/usr` itself as a
    # defensive check: any host where the resolved java install
    # root collapses to `/usr` is misconfigured (would hit the
    # stub-loop on macOS, surely wrong on Linux too).
    home = _resolve_from_which("java", "bin/java")
    if home and home != "/usr" and os.path.isdir(home):
        return home
    return None


def detect_GOROOT() -> Optional[str]:
    """Resolve GOROOT: readlink of `which go`, strip /bin/go."""
    home = _resolve_from_which("go", "bin/go")
    if home and os.path.isdir(home):
        return home
    return None


def detect_DOTNET_ROOT() -> Optional[str]:
    """Resolve DOTNET_ROOT: dotnet is installed with `dotnet` at the
    root, not under a bin/ subdir on most distros — strip only the
    trailing filename.

    Refuses the filesystem root ``/`` and the user's ``$HOME``:
      * ``/`` happens when dotnet is installed AS `/dotnet` (some
        minimal container layouts). Setting `DOTNET_ROOT=/` makes
        dotnet scan the entire filesystem for SDKs and can
        legitimately try to write workload metadata into ``/``.
      * ``$HOME`` happens when a custom layout puts the dotnet
        binary directly in the user's home (`~/dotnet`).
        DOTNET_ROOT then refers to the whole home directory —
        dotnet writes workload state and tooling cache into the
        home root instead of a scoped install dir.
    """
    found = shutil.which("dotnet")
    if not found:
        return None
    try:
        real = os.path.realpath(found)
    except OSError:
        return None
    root = os.path.dirname(real)
    if not root or not os.path.isdir(root):
        return None
    # Refuse the filesystem root and HOME exactly.
    # `os.path.normpath` rather than `os.path.realpath` for the HOME
    # comparison: realpath was already invoked above on the original
    # binary, so `root` already reflects symlink resolution. Re-running
    # realpath here would unnecessarily stat HOME and complicate the
    # tests that mock `os.path.realpath` to return a fixed value
    # regardless of input.
    if root == os.sep:
        return None
    home = os.environ.get("HOME")
    if home and os.path.normpath(root) == os.path.normpath(home):
        return None
    return root


def detect_RUSTUP_HOME() -> Optional[str]:
    """Resolve RUSTUP_HOME. Default is ~/.rustup when rustup is
    installed via rustup-init. Don't probe ~ without checking — some
    hosts have no real home dir (containers, CI). Use
    `rustup show home` as the authoritative source when rustup is
    available.
    """
    # 1. Ask rustup directly if on PATH
    rustup_bin = shutil.which("rustup")
    if rustup_bin:
        try:
            import subprocess
            r = subprocess.run(
                [rustup_bin, "show", "home"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                candidate = r.stdout.strip()
                if os.path.isdir(candidate):
                    return candidate
        except (OSError, subprocess.SubprocessError):
            pass
    # 2. Fallback: ~/.rustup if it's a real dir
    home_env = os.environ.get("HOME")
    if home_env:
        candidate = os.path.join(home_env, ".rustup")
        if os.path.isdir(candidate):
            return candidate
    return None


# Registry of detectors keyed by env-var name. Schema-populating code
# in build_detector.py names the env vars it wants via strings; we
# resolve to callables here. Keeping this as a dict (not getattr on
# module) makes it explicit what's supported and lets tests iterate
# the set.
DETECTORS: Dict[str, Callable[[], Optional[str]]] = {
    "JAVA_HOME": detect_JAVA_HOME,
    "GOROOT": detect_GOROOT,
    "DOTNET_ROOT": detect_DOTNET_ROOT,
    "RUSTUP_HOME": detect_RUSTUP_HOME,
}


def apply_toolchain_env(env: Dict[str, str],
                        var_names: Iterable[str]) -> Dict[str, str]:
    """Merge auto-detected toolchain env vars into `env` in place, return it.

    For each name in `var_names`, call the matching detector in
    `DETECTORS` and set env[name] to the returned value if non-None.
    If a name isn't in DETECTORS, raise ValueError (schema bug — fail
    loud so a typo in `env_detect` doesn't become a silent no-op).
    If a detector returns None, log a WARNING naming the missing
    toolchain and continue (the caller's build tool will surface its
    own error; our warning gives operators a pointer to the missing
    piece).
    """
    for name in var_names:
        if name not in DETECTORS:
            raise ValueError(
                f"core/build/toolchain.py: no detector for env_detect "
                f"entry {name!r}. Add a detect_{name}() helper or "
                f"remove the name from BUILD_SYSTEMS.env_detect."
            )
        # Treat any detector exception as "not found" rather than
        # propagating — a detector crash on an exotic distro (odd
        # filesystem, broken shutil.which) should NOT take out the
        # whole build. The warning below tells operators what happened.
        try:
            value = DETECTORS[name]()
        except Exception as e:
            logger.warning(
                f"build toolchain: detector for {name} raised "
                f"{type(e).__name__}: {e} — treating as not found."
            )
            value = None
        if value is None:
            logger.warning(
                f"build toolchain: {name} not found on this host — "
                f"the build step will likely fail with a missing-"
                f"toolchain error. Install the toolchain or set "
                f"{name} explicitly via --build-env-file (future flag) "
                f"/ via your shell and the sandbox's env= kwarg."
            )
            continue
        env[name] = value
        logger.debug(f"build toolchain: {name}={value}")
    return env
