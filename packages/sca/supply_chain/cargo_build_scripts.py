"""Cargo build.rs detector — analog to npm's install_hooks check.

Rust crates can ship a ``build.rs`` script at the crate root
that's executed at ``cargo build`` time. Like npm's postinstall
hooks, this is an untrusted-code-execution surface during what
operators think is a "build" step.

For each Cargo manifest under the target, read the build script
Cargo would execute — ``[package] build = "<path>"`` when declared
(any filename; ``build = false`` disables build scripts entirely),
else the sibling ``build.rs`` — and apply the shared
:mod:`_hook_patterns` substrate.  Emits only when a real signal
fires — dangerous shell shape, credential read, or the C+G
self-replication conjunction.  Mere presence of ``build.rs`` is
NOT signal (nearly every published crate has one for
auto-generated bindings, version stamping, etc.); flagging on
presence would FP-flood every cargo project.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from ..models import (
    Confidence, Dependency, Manifest,
)
from ..parsers import _safe_read
from ..parsers._base import PARSE_ESCAPE_ERRORS
from . import _hook_patterns, _own_host
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CargoBuildScriptFinding:
    dependency: Dependency
    severity: str
    confidence: Confidence
    detail: str


def scan_manifests(
    manifests: Iterable[Manifest],
    deps: Iterable[Dependency],
) -> list[CargoBuildScriptFinding]:
    """Walk every Cargo.toml; for each, scan sibling build.rs with
    the shared hook-pattern substrate."""
    out: list[CargoBuildScriptFinding] = []
    deps_list = list(deps)
    for m in manifests:
        if m.path.name != "Cargo.toml" or m.is_lockfile:
            continue
        host = _host_dep(deps_list, m)
        build_script, declared_missing = _resolve_build_script(m)
        if declared_missing is not None:
            # ``[package] build = "..."`` names a script that isn't in
            # the tree.  Cargo would fail this build outright, so the
            # declaration is either broken packaging or a tree that
            # materialises the script at build time — either way the
            # HOOK surface can't be inspected statically.  Emit its
            # own low row rather than silently skipping the crate.
            out.append(CargoBuildScriptFinding(
                dependency=host,
                severity="low",
                confidence=Confidence(
                    "medium",
                    reason=(
                        "Cargo.toml declares a build script that does "
                        "not exist in the tree"
                    ),
                ),
                detail=(
                    f"``[package] build = {declared_missing!r}`` names "
                    "a build script missing from the crate tree — the "
                    "install-time execution surface cannot be "
                    "inspected statically"
                ),
            ))
            continue
        if build_script is None:
            continue
        body = _safe_read.read_bounded(build_script, follow_symlinks=False)
        if body is None:
            continue
        analysis = _hook_patterns.analyse_body(body)
        worm_conjunction = (
            analysis.reads_credentials and analysis.has_publish_action
        )
        worm_shape = (
            worm_conjunction
            and not _hook_patterns.is_attested_publish_helper(host)
        )
        if analysis.reasons:
            why = ", ".join(analysis.reasons)
            out.append(CargoBuildScriptFinding(
                dependency=host,
                severity="high",
                confidence=Confidence(
                    "high",
                    reason="build.rs matches known-dangerous pattern",
                ),
                detail=(
                    f"Cargo build script executes at ``cargo build`` "
                    f"time; reason: {why}; body preview: {body[:200]!r}"
                ),
            ))
        elif worm_shape:
            out.append(CargoBuildScriptFinding(
                dependency=host,
                severity="high",
                confidence=Confidence(
                    "high",
                    reason=(
                        "build.rs reads credentials AND invokes a "
                        "publish action (self-replication shape)"
                    ),
                ),
                detail=(
                    "Cargo build script reads publish credentials "
                    "AND invokes a publish action — Iron Worm-class "
                    f"shape; body preview: {body[:200]!r}"
                ),
            ))
        elif worm_conjunction:
            # Worm conjunction fired but the host is an ATTESTED
            # publish helper — suppress the HIGH promotion, but keep
            # a low-severity row (parity with the npm adapter's
            # fall-through) so the HOOK family survives for the
            # composite chokepoint and the suppression stays visible
            # to operators instead of silently deleting the signal.
            out.append(CargoBuildScriptFinding(
                dependency=host,
                severity="low",
                confidence=Confidence(
                    "medium",
                    reason=(
                        "build.rs reads credentials and invokes a "
                        "publish action, but the crate is an attested "
                        "publish helper — worm-shape promotion "
                        "suppressed"
                    ),
                ),
                detail=(
                    "Cargo build script reads publish credentials AND "
                    "invokes a publish action; host is an attested "
                    "publish helper so the self-replication promotion "
                    f"is suppressed; body preview: {body[:200]!r}"
                ),
            ))
        # Mere-presence row REMOVED — every published crate has a
        # build.rs.  Emitting on presence floods reports without
        # adding signal.
    return out


def _resolve_build_script(m: Manifest) -> tuple[Path | None, str | None]:
    """Resolve which build script Cargo would execute for this crate.

    Returns ``(script_path, declared_missing)``:

      * ``[package] build = "<path>"`` → that file.  Cargo runs ANY
        script the key names — renaming the script away from
        ``build.rs`` was the cheapest possible evasion of this
        detector while the code only looked for the sibling file.
        The declared path is containment-checked against the crate
        directory; a missing or escaping path comes back as
        ``(None, <declared value>)`` so the caller can emit its own
        signal instead of silently skipping the crate.
      * ``[package] build = false`` → ``(None, None)`` — this
        disables build scripts INCLUDING ``build.rs``
        auto-detection, so there is nothing that executes.
      * no ``build`` key → the sibling ``build.rs`` when present.
    """
    crate_dir = m.path.parent
    declared = _declared_build_value(m.path)
    if declared is False:
        return None, None
    if isinstance(declared, str):
        candidate = crate_dir / declared
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(crate_dir.resolve())
        except (OSError, ValueError):
            return None, declared
        if not resolved.is_file():
            return None, declared
        return resolved, None
    build_rs = crate_dir / "build.rs"
    if build_rs.exists():
        return build_rs, None
    return None, None


def _declared_build_value(manifest_path: Path) -> object:
    """The raw ``[package].build`` value (str / False / None).
    Unparseable manifests degrade to None — the sibling-``build.rs``
    default — never to a crash."""
    try:
        import tomllib                # Python 3.11+
    except ModuleNotFoundError:       # pragma: no cover
        import tomli as tomllib       # type: ignore[no-redef]
    text = _safe_read.read_bounded(manifest_path, follow_symlinks=False)
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, *PARSE_ESCAPE_ERRORS):  # hostile-input escape classes
        return None
    package = data.get("package")
    if not isinstance(package, dict):
        return None
    build = package.get("build")
    if build is False or isinstance(build, str):
        return build
    return None


def _host_dep(deps: list[Dependency], m: Manifest) -> Dependency:
    """Anchor the finding on the crate's OWN name from Cargo.toml
    ``[package].name`` (placeholder when absent) — ``build.rs`` is
    the crate's own code, so attributing it to whichever dep the
    parser emitted first named an innocent third party and keyed
    the publish-helper worm-shape suppression on the wrong name."""
    del deps
    return _own_host.resolve_own_host(
        m,
        reason="placeholder for cargo-build-script finding host",
        placeholder_name="<project>",
    )
