"""Target-applicability checks for /describe (QoL #14c).

**Scope boundary with /doctor:** /doctor answers "is RAPTOR set
up on this host" — tool binaries on PATH, API keys present,
output dir writable. /describe answers "given THIS target, will
the tools find anything and what will the run look like."
These should not duplicate. When a host-level prerequisite is
absent (binary missing, no LLM config), /describe reports it as
"deferred to ``raptor doctor``" rather than rendering its own
parallel diagnostic.

Checks here focus on target-applicability:

* CodeQL — IF binary present, are the build-system deps
  installed for the target's detected build system? A CodeQL
  DB build for an autotools target fails when ``autoreconf`` /
  ``libtool`` are missing; /describe names them up-front.
* Coccinelle — would the shipped rule pack fire on the target?
  (cocci's rules are C-specific; honest "will 0-fire on a
  Python target" warning beats silent uselessness.)
* Binary oracle — does the target have build artefacts the
  oracle would consume (after build), or will it activate
  post-build?

LLM-dispatcher configuration + bare tool presence are NOT
checked here — those are /doctor's domain. When a tool is
missing entirely we render a single deferral line pointing at
/doctor rather than re-implementing host diagnostics.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import List, Optional

from packages.describe.target_shape import TargetShape


@dataclass(frozen=True)
class ToolCheck:
    """One per-tool readiness signal. ``status`` drives the
    renderer's symbol (✓ / ⚠ / ✗ / ?) and the overall pass/fail
    rollup. ``hint`` is operator-actionable text shown only when
    status is not ``ok``.

    Status values:
      * ``ok``    — tool is present and applicable to the target
      * ``warn``  — present but limited (missing build dep, wrong
                    rule pack for the language, no build artefacts
                    yet, etc.)
      * ``fail``  — required tool absent
      * ``unknown`` — check couldn't determine state (probe
                    raised, ambiguous signals, etc.); honest
                    "we don't know" rather than a falsely-cheerful
                    default. Operator sees ``?`` and a hint to
                    run ``raptor doctor`` for deeper inspection.
    """
    name: str
    status: str  # "ok" | "warn" | "fail" | "unknown"
    version: Optional[str]
    detail: str
    hint: Optional[str] = None


# Build-system → list of binaries the target's build will need.
# Drives the CodeQL DB-build readiness check: if the target's
# build system is autotools and ``autoreconf`` isn't on PATH,
# the operator gets a specific install hint instead of "CodeQL
# might fail" hand-waving.
_BUILD_SYSTEM_DEPS = {
    # ``libtoolize`` not ``libtool``: the Debian ``libtool``
    # package ships ``libtoolize`` (the binary autoreconf
    # actually invokes during bootstrap) but doesn't always
    # ship a bare ``libtool`` command. Checking ``libtool``
    # gave false-positive "missing" warnings on systems with
    # the package fully installed.
    "autotools": ["autoreconf", "automake", "libtoolize"],
    "cmake": ["cmake"],
    "meson": ["meson", "ninja"],
    "make": ["make"],
    "maven": ["mvn"],
    "gradle": ["gradle"],
    "poetry": ["poetry"],
    "pip": ["pip"],
    "npm": ["npm"],
    "yarn": ["yarn"],
    "cargo": ["cargo"],
    "go": ["go"],
}

def _format_build_deps_hint(missing_deps: List[str]) -> str:
    """Group missing build deps by their per-PM package name +
    install verb so the operator gets ONE pastable install
    command per shared install path (rather than N sudo prompts
    for three packages in the same PM).

    Three autotools deps missing on Ubuntu render as:

        sudo apt install autoconf automake libtool

    Same three on macOS:

        brew install autoconf automake libtool

    Mixed install kinds (e.g. one is pipx, two are distro_pm)
    fall back to per-binary advice joined with "; ".
    """
    from packages.describe.package_manager import (
        _INSTALL_ADVICE, detect_package_manager, format_install_advice,
        format_install_hint,
    )

    # Group by (kind, pm) so distro_pm deps for the same PM
    # collapse into one install command; everything else falls
    # through per-binary.
    pm = detect_package_manager()
    distro_pkgs: List[str] = []
    other_hints: List[str] = []
    for dep in missing_deps:
        adv = _INSTALL_ADVICE.get(dep)
        if adv and adv.kind == "distro_pm":
            pkg = (adv.pm_packages or {}).get(pm or "", dep)
            distro_pkgs.append(pkg)
        else:
            other_hints.append(format_install_advice(dep))

    parts: List[str] = []
    if distro_pkgs:
        # De-dupe pkg names — multiple binaries (autoreconf +
        # automake share no package, but autoreconf is from
        # ``autoconf`` and any future dep mapping the same way
        # wouldn't double-print).
        seen = set()
        dedup_pkgs = [
            p for p in distro_pkgs
            if not (p in seen or seen.add(p))
        ]
        parts.append(format_install_hint(dedup_pkgs))
    parts.extend(other_hints)
    return "; ".join(parts)


def check_tool_readiness(shape: TargetShape) -> List[ToolCheck]:
    """Return target-applicability checks for ``shape``.
    Per-tool helpers may return None when the check doesn't
    apply (binary oracle on header-only library, cocci on
    Python target where we don't surface the binary-missing
    case because /doctor owns it); those are filtered out.

    Host-level checks (LLM dispatcher, raw binary presence)
    are NOT included — those live in ``raptor doctor``. The
    renderer adds a footer pointing the operator there."""
    checks: List[Optional[ToolCheck]] = [
        _check_codeql(shape),
        _check_coccinelle(shape),
        _check_binary_oracle(shape),
    ]
    return [c for c in checks if c is not None]


# ---------------------------------------------------------------------------
# Per-tool checks
# ---------------------------------------------------------------------------


def _doctor_deferral(tool_name: str) -> ToolCheck:
    """Render the standard 'host-level — see /doctor' line for a
    tool that's not on PATH. /describe doesn't duplicate /doctor's
    install hints; one short pointer is enough."""
    return ToolCheck(
        name=tool_name,
        status="unknown",
        version=None,
        detail="host check deferred",
        hint="run `raptor doctor` to diagnose host setup",
    )


def _check_codeql(shape: TargetShape) -> Optional[ToolCheck]:
    """Target-applicability for CodeQL: given that the binary
    exists, will the target's detected build system actually
    build under codeql's database step? Names the missing dep
    and the install command up-front.

    When the binary is absent we defer to /doctor (host-level)
    rather than render install instructions here."""
    if not shutil.which("codeql"):
        return _doctor_deferral("CodeQL")
    version = _bin_version("codeql")
    # Build-deps check for the target's primary-language build.
    missing_deps: List[str] = []
    if shape.primary_language and shape.primary_language in shape.build_systems:
        bs = shape.build_systems[shape.primary_language]
        required = _BUILD_SYSTEM_DEPS.get(bs, [])
        for dep in required:
            if not shutil.which(dep):
                missing_deps.append(dep)
        if missing_deps:
            hint = _format_build_deps_hint(missing_deps)
            return ToolCheck(
                name="CodeQL",
                status="warn",
                version=version,
                detail=(
                    f"DB build needs {', '.join(missing_deps)} for "
                    f"{bs} build system"
                ),
                hint=hint,
            )
    return ToolCheck(
        name="CodeQL",
        status="ok",
        version=version,
        detail=(
            f"build deps ok for {shape.build_systems.get(shape.primary_language or '', 'this target')}"
        ),
    )


def _check_coccinelle(shape: TargetShape) -> Optional[ToolCheck]:
    """Target-applicability for Coccinelle: will the shipped
    rule pack actually fire? Cocci's rules are C-specific —
    honest "will 0-fire on Python" warning beats silent
    uselessness.

    Binary absence defers to /doctor (host-level)."""
    if not shutil.which("spatch"):
        return _doctor_deferral("Coccinelle")
    version = _bin_version("spatch")
    # Cocci is C-only today. If primary language isn't C/C++,
    # warn that it'll run but find nothing.
    if shape.primary_language not in (None, "cpp"):
        return ToolCheck(
            name="Coccinelle",
            status="warn",
            version=version,
            detail=(
                f"rule pack is C-only — will run on "
                f"{shape.primary_language} target but fire 0 rules"
            ),
            hint=None,
        )
    return ToolCheck(
        name="Coccinelle",
        status="ok",
        version=version,
        detail="C rule pack applicable to target",
    )


def _check_binary_oracle(shape: TargetShape) -> Optional[ToolCheck]:
    """Binary-oracle reachability is opt-out on /agentic / /codeql.
    Check whether the target has build artefacts in the
    auto-detect dirs — if not, the oracle will be inactive
    unless the operator builds first."""
    # Native languages only — Python / JS / Go-build targets
    # don't produce the ELF artefacts the oracle parses.
    if shape.primary_language not in ("cpp", "rust", "go"):
        return None
    target = shape.target_path
    common_build_dirs = (
        "build", "target/release", "target/debug",
        "bazel-bin", "cmake-build-debug", "cmake-build-release",
    )
    has_artefacts = any(
        (target / d).exists() for d in common_build_dirs
    )
    if has_artefacts:
        return ToolCheck(
            name="Binary oracle",
            status="ok",
            version=None,
            detail="build artefacts present in common locations",
        )
    return ToolCheck(
        name="Binary oracle",
        status="warn",
        version=None,
        detail="no build artefacts found — will activate after build",
        hint=None,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bin_version(binary: str) -> Optional[str]:
    """Best-effort ``--version`` extraction. Returns None on
    binary missing / non-zero exit / parse failure — caller
    renders without a version suffix."""
    if not shutil.which(binary):
        return None
    import subprocess
    for flag in ("--version", "-V", "version"):
        try:
            res = subprocess.run(
                [binary, flag],
                capture_output=True, text=True, timeout=5,
            )
            if res.returncode == 0 and res.stdout:
                # First line; strip whitespace + leading tool name.
                first = res.stdout.splitlines()[0].strip()
                # Extract just the version token if the line is
                # "tool-name X.Y.Z [other stuff]". Strip
                # trailing punctuation so "2.23.8." (CodeQL's
                # release-line shape) renders as "2.23.8".
                parts = first.split()
                for tok in parts:
                    if tok and tok[0].isdigit():
                        return tok.rstrip(".,;:")
                return first[:60].rstrip(".,;:")
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


__all__ = ["ToolCheck", "check_tool_readiness"]
