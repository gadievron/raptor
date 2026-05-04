"""LLM upgrade impact analysis for dependency version bumps.

Given a proposed upgrade (old_version → new_version), the package's
CHANGELOG/migration notes, and a mechanical grep of call sites in the
project, the LLM classifies the upgrade as safe / minor_migration /
major_migration and lists specific breaking-change call sites with
suggested fixes.

**Mechanical override:** the call-site list from ``grep`` is
authoritative — the LLM cannot invent call sites, only reason about
ones found mechanically.  The CHANGELOG is attacker-controlled content
in the supply-chain threat model.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional

from ..models import Dependency
from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .prompts import UPGRADE_IMPACT_SYSTEM
from .schemas import UpgradeImpactVerdict

logger = logging.getLogger(__name__)

_MAX_CHANGELOG_CHARS = 10_000
_MAX_CALLSITE_CHARS = 30_000


def assess_upgrade_impact(
    client,
    dep: Dependency,
    new_version: str,
    target: Path,
    changelog: str = "",
) -> Optional[UpgradeImpactVerdict]:
    """Assess the impact of upgrading a dependency.

    Args:
        client: LLMClient instance.
        dep: The dependency being upgraded (with current version).
        new_version: The proposed new version.
        target: Project root for call-site grep.
        changelog: CHANGELOG/migration notes text (may be empty).

    Returns:
        UpgradeImpactVerdict or None if the LLM is unavailable.
    """
    if not dep.version or dep.version == new_version:
        return None

    call_sites = _grep_call_sites(target, dep)
    if not call_sites:
        return UpgradeImpactVerdict(
            verdict="safe",
            confidence="medium",
            summary=f"No call sites found for {dep.name} — upgrade is safe",
        )

    blocks: list[UntrustedBlock] = []

    callsite_text = "\n".join(call_sites)[:_MAX_CALLSITE_CHARS]
    blocks.append(UntrustedBlock(
        content=callsite_text,
        kind="CALL_SITES",
        origin=f"{dep.ecosystem}/{dep.name} call sites in project",
    ))

    if changelog:
        blocks.append(UntrustedBlock(
            content=changelog[:_MAX_CHANGELOG_CHARS],
            kind="CHANGELOG",
            origin=f"{dep.ecosystem}/{dep.name} changelog",
        ))

    result: StageResult = run_stage(
        client=client,
        system=UPGRADE_IMPACT_SYSTEM,
        untrusted_blocks=tuple(blocks),
        slots={
            "package_name": TaintedString(value=dep.name, trust="untrusted"),
            "ecosystem": TaintedString(value=dep.ecosystem, trust="trusted"),
            "old_version": TaintedString(value=dep.version, trust="untrusted"),
            "new_version": TaintedString(value=new_version, trust="untrusted"),
        },
        schema_cls=UpgradeImpactVerdict,
        task_type="sca_upgrade_impact",
    )

    if result.error or result.model is None:
        logger.debug("sca.llm.upgrade_impact: %s failed: %s",
                      dep.name, result.error)
        return None

    verdict: UpgradeImpactVerdict = result.model  # type: ignore[assignment]
    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})
    return verdict


def _grep_call_sites(target: Path, dep: Dependency) -> List[str]:
    """Find call sites for a dependency in the project source.

    Returns lines in 'file:line: content' format.
    """
    import_patterns = _import_patterns(dep)
    if not import_patterns:
        return []

    results: List[str] = []
    extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
                  ".rs", ".rb", ".php", ".cs"}
    skip_dirs = {"node_modules", "vendor", ".git", "__pycache__",
                 "target", "build", "dist", ".venv", "venv"}

    for root, dirs, files in target.walk():
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if Path(fname).suffix not in extensions:
                continue
            fpath = root / fname
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            for i, line in enumerate(text.splitlines(), 1):
                for pat in import_patterns:
                    if pat.search(line):
                        rel = fpath.relative_to(target)
                        results.append(f"{rel}:{i}: {line.rstrip()[:200]}")
                        break
            if len(results) > 500:
                break
        if len(results) > 500:
            break

    return results


def _import_patterns(dep: Dependency) -> List[re.Pattern]:
    """Build regex patterns to find import/usage of a dependency."""
    name = dep.name
    patterns = []

    if dep.ecosystem == "PyPI":
        module = name.replace("-", "_").replace(".", "_")
        patterns.append(re.compile(rf"\b(?:import|from)\s+{re.escape(module)}\b"))
    elif dep.ecosystem == "npm":
        bare = name.split("/")[-1] if "/" in name else name
        patterns.append(re.compile(rf"""(?:require\s*\(\s*|from\s+)['"]({re.escape(name)})"""))
        if bare != name:
            patterns.append(re.compile(rf"""(?:require\s*\(\s*|from\s+)['"]({re.escape(bare)})"""))
    elif dep.ecosystem in ("Maven", "Gradle"):
        parts = name.split(":")
        if len(parts) == 2:
            patterns.append(re.compile(rf"\bimport\s+{re.escape(parts[0])}\."))
    elif dep.ecosystem == "Go":
        patterns.append(re.compile(rf'"{re.escape(name)}'))
    elif dep.ecosystem == "Cargo":
        patterns.append(re.compile(rf"\buse\s+{re.escape(name.replace('-', '_'))}"))
    elif dep.ecosystem == "RubyGems":
        patterns.append(re.compile(rf"\brequire\s+['\"]({re.escape(name)})"))

    return patterns
