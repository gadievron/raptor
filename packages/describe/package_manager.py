"""Package-manager-aware install advice.

Two layers:

1. **PM detection + raw install-command formatting**
   (``detect_package_manager`` + ``format_install_hint``) —
   the primitive. Operator's PM detected from PATH; install
   verb formatted for that PM (apt / dnf / pacman / apk /
   zypper / brew). Pre-fix every hint hardcoded
   ``sudo apt install …``, wrong-by-construction off
   Debian/Ubuntu.

2. **Per-tool install advice**
   (``InstallAdvice`` + ``format_install_advice``) — the
   policy layer. Different tools install different ways:

   * distro-PM (autoconf, automake, libtoolize, spatch, gdb)
   * pipx (semgrep — CLI tool, isolated env)
   * static URL (codeql — not in distro repos; GH Releases)
   * platform-restricted (rr — Linux-only; no brew)
   * per-PM package-name override (afl-fuzz — apt: afl++,
     dnf: american-fuzzy-lop, brew: afl-fuzz)

   ``format_install_advice("rr")`` knows rr is Linux-only and
   surfaces the project URL instead of a wrong ``brew install
   rr`` on macOS. ``format_install_advice("semgrep")`` knows
   it's not in distro repos and surfaces ``pipx install
   semgrep``. Both /describe and /doctor consume this surface.
"""

from __future__ import annotations

import functools
import os
import platform as _platform
import shutil
from dataclasses import dataclass
from typing import Dict, List, Optional


# Package managers we recognise, in detection order. Order is
# significant for the "first wins" rule — if a system has both
# (e.g. brew installed on a Linux box), the Linux native PM
# leads because system-level tool dependencies typically come
# from there, not the user-local PM.
_KNOWN_PMS = (
    "apt", "dnf", "yum", "pacman", "apk", "zypper", "brew",
)


# Per-PM package-name overrides for binaries whose package
# name differs across distros. Empty today — every binary
# /describe currently checks (autoconf / automake / libtool /
# libtoolize / coccinelle) has the same package name on
# apt / dnf / pacman / apk / zypper / brew. Extend with
# ``{"binary": {"pm": "package-name"}}`` when a divergent case
# materialises.
_PER_PM_PKG_OVERRIDES: dict = {}


@functools.lru_cache(maxsize=1)
def detect_package_manager() -> Optional[str]:
    """Return the first installed PM from ``_KNOWN_PMS``, or
    None when no recognised PM is on PATH. Cached per-process
    since the answer doesn't change mid-run.
    """
    for pm in _KNOWN_PMS:
        if shutil.which(pm):
            return pm
    return None


def _sudo_prefix() -> str:
    """``"sudo "`` for a normal-user invocation, empty string
    when already root. Docker base images (slim/distroless)
    often run as root with no ``sudo`` binary installed; a
    pastable ``sudo apt install foo`` line then fails with
    ``sudo: command not found``. ``os.geteuid() == 0`` covers
    Linux/macOS root; on Windows ``geteuid`` doesn't exist and
    we degrade to "sudo" prefix (incorrect on Windows but
    Windows isn't a supported RAPTOR host anyway)."""
    try:
        if os.geteuid() == 0:  # type: ignore[attr-defined]
            return ""
    except AttributeError:
        pass
    return "sudo "


def format_install_hint(packages: List[str]) -> str:
    """Return an operator-pastable install command for the
    detected PM, or a generic message when no PM is found.

    Examples::

        format_install_hint(["libtool"])
        → "sudo apt install libtool"      (Debian/Ubuntu)
        → "sudo dnf install libtool"      (Fedora/RHEL)
        → "sudo pacman -S libtool"        (Arch)
        → "brew install libtool"          (macOS)
        → "apt install libtool"           (root in container, no sudo)
        → "install libtool via your system package manager"
                                          (no recognised PM)
    """
    pm = detect_package_manager()
    pkgs = " ".join(_resolve_pkg(p, pm) for p in packages)
    sudo = _sudo_prefix()

    if pm == "apt":
        return f"{sudo}apt install {pkgs}"
    if pm in ("dnf", "yum"):
        return f"{sudo}{pm} install {pkgs}"
    if pm == "pacman":
        return f"{sudo}pacman -S {pkgs}"
    if pm == "zypper":
        return f"{sudo}zypper install {pkgs}"
    if pm == "apk":
        return f"{sudo}apk add {pkgs}"
    if pm == "brew":
        # brew refuses to run as root regardless; no sudo
        # prefix needed even when EUID==0 (brew itself errors
        # in that case, which is the right surface).
        return f"brew install {pkgs}"
    return f"install {pkgs} via your system package manager"


def _resolve_pkg(pkg: str, pm: Optional[str]) -> str:
    """Look up the per-PM override for ``pkg`` if one exists,
    else pass through unchanged."""
    overrides = _PER_PM_PKG_OVERRIDES.get(pkg)
    if overrides and pm and pm in overrides:
        return overrides[pm]
    return pkg


# ---------------------------------------------------------------------------
# Python-environment-aware install path for the ``pipx`` / ``pip`` kinds
# ---------------------------------------------------------------------------

# Pipx install command per PM, used when pipx itself isn't on PATH.
# Names match what each PM ships in current releases:
#   apt  — Ubuntu 23.04+ / Debian 12+ ship ``pipx`` as the package name.
#          Older releases require ``python3 -m pip install --user pipx``
#          (we leave that case to the operator — they'll see the apt
#          error and Google for two seconds).
#   pacman — package is namespaced as ``python-pipx`` per Arch convention.
#   everything else — bare ``pipx``.
# Pipx package name per PM (some distros namespace differently).
# The install command is built at call time via format_install_hint
# so the EUID==0 / no-sudo path is honoured uniformly.
_PIPX_PKG_PER_PM: Dict[str, str] = {
    "apt": "pipx",
    "dnf": "pipx",
    "yum": "pipx",
    "pacman": "python-pipx",
    "apk": "pipx",
    "zypper": "pipx",
    "brew": "pipx",
}


def _format_python_cli_install(package: str) -> str:
    """Render an install command for a Python CLI tool (``semgrep``
    et al.), preferring whatever Python environment the operator
    is actually in:

    1. **Active venv** (``VIRTUAL_ENV`` set) — ``pip install pkg``
       works inside a venv with no PEP 668 issue.
    2. **Active conda env** (``CONDA_DEFAULT_ENV`` set) — ``conda
       install -c conda-forge pkg``.
    3. **uv on PATH** — ``uv tool install pkg`` (the equivalent of
       ``pipx install`` for the uv toolchain).
    4. **pipx on PATH** — ``pipx install pkg``.
    5. **pipx NOT on PATH** — chain the bootstrap:
       ``<pm-install-pipx> && pipx ensurepath && pipx install pkg``.
       ``ensurepath`` is included because a fresh pipx install
       requires it to put ``~/.local/bin`` on PATH; new operators
       forget this and the next command fails with "command not
       found: <tool>" until they re-login.
    6. **No PM, no env** — generic fallback message.

    The detection order matches what an operator would actually
    want: their currently-activated env wins over a globally
    available tool. Each branch is correct on PEP 668 systems —
    we never suggest a path that the OS-managed Python would
    block.
    """
    # 1. Active venv — pip works inside the venv even on PEP 668
    #    systems because the venv's pip writes to the venv, not the
    #    system site-packages. Pre-fix the hint blindly said pipx
    #    even when the operator was in a venv where pip would work.
    if os.environ.get("VIRTUAL_ENV"):
        return f"pip install {package}"

    # 2. Active conda env. conda-forge is the canonical channel for
    #    third-party tools; conda's default channel often lacks
    #    them (semgrep isn't in defaults at this time).
    if os.environ.get("CONDA_DEFAULT_ENV"):
        return f"conda install -c conda-forge {package}"

    # 3. uv — modern (2024+) replacement for pipx/venv. If the
    #    operator has it, they want the uv command (consistent
    #    toolchain).
    if shutil.which("uv"):
        return f"uv tool install {package}"

    # 4. pipx already installed → straightforward.
    if shutil.which("pipx"):
        return f"pipx install {package}"

    # 5. pipx missing → bootstrap chain. format_install_hint
    #    handles per-PM verb + EUID==0 sudo suppression
    #    (Docker root images don't have sudo).
    pm = detect_package_manager()
    pipx_pkg = _PIPX_PKG_PER_PM.get(pm or "") if pm else None
    if pipx_pkg:
        pipx_install = format_install_hint([pipx_pkg])
        return (
            f"{pipx_install} && pipx ensurepath && pipx install {package}"
        )

    # 6. No PM and no env — the operator's setup is non-standard;
    #    point them at the canonical pipx docs and let them choose
    #    their poison (venv / pip --user / pyenv etc).
    return (
        f"install pipx first (see https://pipx.pypa.io/stable/installation/), "
        f"then: pipx install {package}"
    )


# ---------------------------------------------------------------------------
# Per-tool install advice — kind-dispatched policy layer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InstallAdvice:
    """How to install a tool.

    ``kind`` dispatches the formatter:

    * ``distro_pm`` — distro package manager. ``pm_packages`` is an
      optional per-PM override map; when None, the binary name is
      used as the package name on every PM. When a single PM's
      override exists but the operator's PM isn't in the map, the
      formatter falls back to the binary name (best-effort).
    * ``pipx`` — pipx install (preferred over pip for CLI tools so
      the install lands in an isolated venv).
    * ``pip`` — pip install (for libraries / when pipx is overkill).
    * ``static_url`` — not in any distro / language PM; operator
      installs from a project URL. Used for codeql (GH Releases).
    * ``linux_only`` — Linux-only tool. On Linux falls back to
      ``distro_pm`` semantics; off Linux surfaces an unavailable
      message + ``docs_url``.

    ``docs_url`` is rendered after the install command as a
    parenthetical pointer ("see https://…") for the operator who
    wants build-from-source instructions or version-specific advice.

    ``mac_caveat`` is appended ONLY when running on macOS — for
    tools whose install command works but whose runtime has a
    Mac-specific gotcha (gdb's codesigning rabbit hole; afl-fuzz's
    incomplete Apple Silicon support). Pre-fix the install hint
    rendered the same on every platform; an operator on macOS hit
    the gotcha after the install succeeded, wasting Google time.
    """
    kind: str    # "distro_pm" | "pipx" | "pip" | "static_url" | "linux_only"
    pm_packages: Optional[Dict[str, str]] = None
    package: Optional[str] = None
    static_url: Optional[str] = None
    docs_url: Optional[str] = None
    mac_caveat: Optional[str] = None


# Registry — binary name → InstallAdvice. Binary names match what
# ``shutil.which`` (and ``RaptorConfig.TOOL_DEPS[*]['binary']``)
# checks for, so callers pass the same name they probed with.
_INSTALL_ADVICE: Dict[str, InstallAdvice] = {
    # --- autotools chain (consumed by tool_readiness) ---
    "autoreconf": InstallAdvice(
        kind="distro_pm",
        pm_packages={
            "apt": "autoconf", "dnf": "autoconf", "yum": "autoconf",
            "pacman": "autoconf", "apk": "autoconf",
            "zypper": "autoconf", "brew": "autoconf",
        },
    ),
    "automake": InstallAdvice(kind="distro_pm"),
    "libtoolize": InstallAdvice(
        kind="distro_pm",
        # Binary ships in the ``libtool`` package on every PM.
        pm_packages={
            "apt": "libtool", "dnf": "libtool", "yum": "libtool",
            "pacman": "libtool", "apk": "libtool",
            "zypper": "libtool", "brew": "libtool",
        },
    ),
    # --- /doctor-checked binaries ---
    "gdb": InstallAdvice(
        kind="distro_pm",
        mac_caveat=(
            "macOS: gdb needs codesigning to control processes — "
            "consider lldb instead (`xcrun lldb`)"
        ),
    ),
    "spatch": InstallAdvice(
        kind="distro_pm",
        pm_packages={
            "apt": "coccinelle", "dnf": "coccinelle",
            "yum": "coccinelle", "pacman": "coccinelle",
            "apk": "coccinelle", "zypper": "coccinelle",
            "brew": "coccinelle",
        },
        docs_url="https://coccinelle.gitlabpages.inria.fr/website/",
    ),
    "rr": InstallAdvice(
        kind="linux_only",
        # Linux package names: apt: rr ✓ / dnf: rr ✓ / pacman: rr (AUR)
        pm_packages={"apt": "rr", "dnf": "rr", "pacman": "rr"},
        docs_url="https://rr-project.org/",
    ),
    "afl-fuzz": InstallAdvice(
        kind="distro_pm",
        # Genuinely divergent package names per PM.
        pm_packages={
            "apt": "afl++", "dnf": "american-fuzzy-lop",
            "pacman": "afl++", "brew": "afl-fuzz",
        },
        docs_url="https://aflplus.plus/",
        mac_caveat=(
            "macOS: incomplete Apple Silicon support upstream; "
            "x86_64 Macs work, M-series degraded"
        ),
    ),
    "codeql": InstallAdvice(
        kind="static_url",
        static_url=(
            "https://github.com/github/codeql-cli-binaries/releases"
        ),
    ),
    "semgrep": InstallAdvice(
        kind="pipx",
        package="semgrep",
        docs_url="https://semgrep.dev/docs/getting-started/quickstart",
    ),
}


def format_install_advice(binary: str) -> str:
    """Operator-actionable install line for ``binary``. Falls
    back to the generic "install via your system package
    manager" message when the binary isn't in the registry.

    Examples::

        format_install_advice("libtoolize")
            → "sudo apt install libtool"      (Ubuntu)
            → "sudo dnf install libtool"      (Fedora)
            → "brew install libtool"          (macOS)

        format_install_advice("semgrep")
            → "pipx install semgrep
               (see https://semgrep.dev/docs/getting-started/quickstart)"

        format_install_advice("codeql")
            → "see https://github.com/github/codeql-cli-binaries/releases"

        format_install_advice("rr")  on Linux
            → "sudo apt install rr (see https://rr-project.org/)"
        format_install_advice("rr")  on macOS
            → "rr is Linux-only (see https://rr-project.org/)"
    """
    advice = _INSTALL_ADVICE.get(binary)
    if advice is None:
        # Unknown tool — generic fallback through the primitive.
        return format_install_hint([binary])

    docs_suffix = (
        f" (see {advice.docs_url})" if advice.docs_url else ""
    )
    # Mac-specific caveat appended only on macOS. Suppresses on
    # Linux even when set, so tools with mac_caveat data don't
    # noise up the more-common Linux operator surface. Goes
    # before docs_suffix so the order reads "install command —
    # caveat — see-also URL".
    mac_suffix = (
        f" — {advice.mac_caveat}"
        if advice.mac_caveat and _platform.system() == "Darwin"
        else ""
    )

    if advice.kind == "distro_pm":
        pm = detect_package_manager()
        pkg = (advice.pm_packages or {}).get(pm or "", binary)
        return f"{format_install_hint([pkg])}{mac_suffix}{docs_suffix}"

    if advice.kind == "pipx":
        cmd = _format_python_cli_install(advice.package or binary)
        return f"{cmd}{mac_suffix}{docs_suffix}"

    if advice.kind == "pip":
        # Same env-aware path as pipx — a library install in a
        # PEP 668 system is the same problem as a CLI install:
        # need a venv/conda/uv/--user-via-pipx context for pip to
        # actually work.
        cmd = _format_python_cli_install(advice.package or binary)
        return f"{cmd}{mac_suffix}{docs_suffix}"

    if advice.kind == "static_url":
        return f"see {advice.static_url}{mac_suffix}{docs_suffix}"

    if advice.kind == "linux_only":
        if _platform.system() == "Linux":
            pm = detect_package_manager()
            pkg = (advice.pm_packages or {}).get(pm or "", binary)
            return f"{format_install_hint([pkg])}{docs_suffix}"
        return f"{binary} is Linux-only{docs_suffix}"

    # Unknown kind — degrade to the generic primitive.
    return format_install_hint([binary])


__all__ = [
    "InstallAdvice",
    "detect_package_manager",
    "format_install_advice",
    "format_install_hint",
]
