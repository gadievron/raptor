"""Cargo build.rs detector — analog to npm's install_hooks check.

Rust crates can ship a ``build.rs`` script at the crate root
that's executed at ``cargo build`` time. Like npm's postinstall
hooks, this is an untrusted-code-execution surface during what
operators think is a "build" step.

Scope today is the project-tree side only:
  * For each Cargo manifest under the target, look for a sibling
    ``build.rs``
  * If present, emit an informational
    ``sca:supply_chain:install_hook_suspicious`` finding so
    operators see the surface exists

Future enhancements (TRIGGER-gated):
  * Detect dangerous patterns in ``build.rs`` bodies (curl|sh,
    download-and-exec, etc.) — same heuristic as install_hooks.py
  * For each DEPENDENCY, query crates.io for ``build`` declaration
    in its Cargo.toml (currently no public-API surface for that)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, List

from ..models import (
    Confidence, Dependency, Manifest,
)

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
) -> List[CargoBuildScriptFinding]:
    """Walk every Cargo.toml; for each, check for sibling build.rs."""
    out: List[CargoBuildScriptFinding] = []
    deps_list = list(deps)
    for m in manifests:
        if m.path.name != "Cargo.toml" or m.is_lockfile:
            continue
        build_rs = m.path.parent / "build.rs"
        if not build_rs.exists():
            continue
        host = _host_dep(deps_list, m)
        # Read first 4KB of the script for the detail line —
        # gives operators a quick preview of what's inside.
        try:
            preview = build_rs.read_text(
                encoding="utf-8", errors="replace"
            )[:200]
        except OSError:
            preview = ""
        out.append(CargoBuildScriptFinding(
            dependency=host,
            severity="info",
            confidence=Confidence(
                "high", reason="build.rs present at crate root",
            ),
            detail=(
                f"Cargo build script {build_rs.name} executes at "
                f"``cargo build`` time. Operators should audit "
                f"its contents — like npm postinstall, this is a "
                f"supply-chain surface. Preview: {preview!r}"
            ),
        ))
    return out


def _host_dep(deps: List[Dependency], m: Manifest) -> Dependency:
    """Find a Dependency to anchor the finding on — first
    Cargo-eco dep from the same dir, else a synthetic one."""
    for d in deps:
        if d.ecosystem == "Cargo" and d.declared_in == m.path:
            return d
    # Synthetic anchor — no real dep to point at.
    from packages.sca.models import PinStyle
    return Dependency(
        ecosystem="Cargo",
        name="<project>",
        version=None,
        declared_in=m.path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "high", reason="synthetic project anchor",
        ),
    )
