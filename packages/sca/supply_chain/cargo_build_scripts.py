"""Cargo build.rs detector — analog to npm's install_hooks check.

Rust crates can ship a ``build.rs`` script at the crate root
that's executed at ``cargo build`` time. Like npm's postinstall
hooks, this is an untrusted-code-execution surface during what
operators think is a "build" step.

For each Cargo manifest under the target, read its sibling
``build.rs`` (when present) and apply the shared
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
from typing import Iterable, List

from ..models import (
    Confidence, Dependency, Manifest,
)
from . import _hook_patterns

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
    """Walk every Cargo.toml; for each, scan sibling build.rs with
    the shared hook-pattern substrate."""
    out: List[CargoBuildScriptFinding] = []
    deps_list = list(deps)
    for m in manifests:
        if m.path.name != "Cargo.toml" or m.is_lockfile:
            continue
        build_rs = m.path.parent / "build.rs"
        if not build_rs.exists():
            continue
        try:
            body = build_rs.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        analysis = _hook_patterns.analyse_body(body)
        host = _host_dep(deps_list, m)
        worm_shape = (
            analysis.reads_credentials
            and analysis.has_publish_action
            and not _hook_patterns.is_publish_helper(host)
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
        # Mere-presence row REMOVED — every published crate has a
        # build.rs.  Emitting on presence floods reports without
        # adding signal.
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
