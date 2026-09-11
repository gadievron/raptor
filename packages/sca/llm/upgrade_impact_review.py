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
import os
import re
from pathlib import Path

from core.llm.scorecard import (
    fast_tier_model_name,
    prefilter_decision,
    record_prefilter_outcome,
)
from core.llm.task_types import TaskType

from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .prompts import UPGRADE_IMPACT_PREFILTER_SYSTEM, UPGRADE_IMPACT_SYSTEM
from .schemas import UpgradeImpactPrefilter, UpgradeImpactVerdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import Dependency

logger = logging.getLogger(__name__)

_MAX_CHANGELOG_CHARS = 10_000
_MAX_CALLSITE_CHARS = 30_000


def _cheap_safe_check(
    client, dep: Dependency, new_version: str, changelog: str,
) -> UpgradeImpactPrefilter | None:
    """Ask the fast-tier model whether this upgrade is clearly safe.
    Returns ``None`` on call failure (caller treats as "no signal"
    and runs full analysis). The prompt deliberately under-specifies
    the call-site list — the cheap model decides on changelog and
    semver alone, leaving call-site reasoning to the full review."""
    blocks: list[UntrustedBlock] = []
    if changelog:
        blocks.append(UntrustedBlock(
            content=changelog[:_MAX_CHANGELOG_CHARS],
            kind="CHANGELOG",
            origin=f"{dep.ecosystem}/{dep.name} changelog",
        ))
    result: StageResult = run_stage(
        client=client,
        system=UPGRADE_IMPACT_PREFILTER_SYSTEM,
        untrusted_blocks=tuple(blocks),
        slots={
            "package_name": TaintedString(value=dep.name, trust="untrusted"),
            "ecosystem": TaintedString(value=dep.ecosystem, trust="trusted"),
            "old_version": TaintedString(value=dep.version or "", trust="untrusted"),
            "new_version": TaintedString(value=new_version, trust="untrusted"),
        },
        schema_cls=UpgradeImpactPrefilter,
        task_type=TaskType.VERDICT_BINARY,
    )
    if result.error or result.model is None:
        logger.debug(
            "sca.llm.upgrade_impact: prefilter failed: %s", result.error,
        )
        return None
    return result.model  # type: ignore[return-value]


def _short_circuit_safe_result(
    _dep: Dependency, reasoning: str,
) -> UpgradeImpactVerdict:
    """Build a safe-verdict UpgradeImpactVerdict from a cheap-tier
    ``clear_safe`` outcome. Confidence is medium, not high — the
    cheap model is a filter, not the authority. Operators reading
    the result see the cheap reasoning in the summary so they can
    spot-check obvious-safe classifications."""
    return UpgradeImpactVerdict(
        verdict="safe",
        confidence="medium",
        summary=(
            f"Fast-tier prefilter: {reasoning}"[:500] if reasoning
            else "Fast-tier prefilter classified upgrade as safe"
        ),
    )


def assess_upgrade_impact(
    client,
    dep: Dependency,
    new_version: str,
    target: Path,
    changelog: str = "",
) -> UpgradeImpactVerdict | None:
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
        # Zero grep hits is a heuristic result, not proof of non-use:
        # the import patterns are best-effort per ecosystem and miss
        # dynamic imports, re-exports, and unconventional module names.
        # Report "safe" but at low confidence with an honest summary
        # rather than a confident verdict.
        return UpgradeImpactVerdict(
            verdict="safe",
            confidence="low",
            summary=(
                f"Heuristic import grep found no call sites for "
                f"{dep.name}; usage may exist via patterns the grep "
                f"cannot see — verify before relying on this verdict"
            ),
        )

    # Fast-tier prefilter. Asks the cheap model "is this upgrade
    # clearly safe?" and consults the scorecard for whether to trust
    # this (decision_class, model) cell enough to short-circuit on
    # the cheap verdict. Decision class is keyed by ecosystem since
    # changelog conventions and stability profiles differ
    # significantly between (e.g.) PyPI and npm.
    decision_class = f"sca:major_bump:{dep.ecosystem}"
    fast_model_name = fast_tier_model_name(client.config)
    cheap = _cheap_safe_check(client, dep, new_version, changelog)
    # Defensive: tests sometimes stub ``run_stage`` to return the same
    # MagicMock for both the cheap and full calls, so ``cheap`` may
    # not actually be an :class:`UpgradeImpactPrefilter`. ``getattr``
    # with defaults keeps the wiring robust against that without
    # forcing every test to know about the prefilter shape.
    cheap_says_safe = (
        cheap is not None
        and getattr(cheap, "verdict", None) == "clear_safe"
    )
    cheap_reasoning = (
        getattr(cheap, "reasoning", "") if cheap is not None else ""
    )

    decision = prefilter_decision(
        getattr(client, "scorecard", None),
        decision_class=decision_class,
        model=fast_model_name,
        cheap_says_fp=cheap_says_safe,    # "FP" for our gate = "safe" here
    )
    if decision.short_circuit:
        logger.info(
            "sca.llm.upgrade_impact: fast-tier short-circuit on %s "
            "(cheap verdict trusted by scorecard)", decision_class,
        )
        return _short_circuit_safe_result(dep, cheap_reasoning)

    # Run full review.
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
        task_type=TaskType.ANALYSE,
    )

    if result.error or result.model is None:
        logger.debug("sca.llm.upgrade_impact: %s failed: %s",
                      dep.name, result.error)
        return None

    verdict: UpgradeImpactVerdict = result.model  # type: ignore[assignment]
    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})

    # Record cheap-vs-full agreement for the scorecard. ``full_says_fp``
    # for major-bump = full said "safe". Same shape as codeql's FP
    # gate (cheap_says_fp + full_says_fp).
    full_says_safe = verdict.verdict == "safe"
    record_prefilter_outcome(
        getattr(client, "scorecard", None),
        decision_class=decision_class,
        model=fast_model_name,
        cheap_says_fp=cheap_says_safe,
        full_says_fp=full_says_safe,
        cheap_reasoning=cheap_reasoning,
        full_reasoning=verdict.summary,
    )
    return verdict


def _grep_call_sites(target: Path, dep: Dependency) -> list[str]:
    """Find call sites for a dependency in the project source.

    Returns lines in 'file:line: content' format.
    """
    import_patterns = _import_patterns(dep)
    if not import_patterns:
        return []

    from ..discovery import EXCLUDED_DIR_NAMES
    results: list[str] = []
    extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
                  ".rs", ".rb", ".php", ".cs"}
    skip_dirs = EXCLUDED_DIR_NAMES

    for root, dirs, files in os.walk(target, onerror=lambda _e: None):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        root_path = Path(root)
        for fname in files:
            if Path(fname).suffix not in extensions:
                continue
            fpath = root_path / fname
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001, S112 — unreadable file: skip, grep is best-effort
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


def _import_patterns(dep: Dependency) -> list[re.Pattern]:
    """Build regex patterns to find import/usage of a dependency.

    Ecosystem name-mapping quirks are delegated to the reachability
    layer's resolvers so the grep looks for what source code actually
    writes, not the registry-facing package name:

    - PyPI distribution names diverge from import-module names
      (``pyyaml`` → ``import yaml``) — candidates come from
      :func:`packages.sca.reachability.python._candidate_modules`
      (curated map + PEP 503/8 heuristics).
    - Maven groupIds diverge from Java package prefixes
      (``com.google.guava`` → ``com.google.common``) — prefixes come
      from :func:`packages.sca.reachability.maven._candidate_prefixes`
      (curated map + groupId heuristics).
    - Packagist names are lowercase but PHP ``use`` statements are
      PascalCase and case-sensitive (``symfony/console`` →
      ``use Symfony\\Component\\Console\\...``) — match the PascalCase
      vendor namespace case-insensitively.
    """
    name = dep.name
    patterns = []

    if dep.ecosystem == "PyPI":
        from ..reachability.python import _candidate_modules
        for module in _candidate_modules(name):
            patterns.append(
                re.compile(rf"\b(?:import|from)\s+{re.escape(module)}\b"),
            )
    elif dep.ecosystem == "npm":
        bare = name.split("/")[-1] if "/" in name else name
        patterns.append(re.compile(rf"""(?:require\s*\(\s*|from\s+)['"]({re.escape(name)})"""))
        if bare != name:
            patterns.append(re.compile(rf"""(?:require\s*\(\s*|from\s+)['"]({re.escape(bare)})"""))
    elif dep.ecosystem in ("Maven", "Gradle"):
        from ..reachability.maven import _candidate_prefixes
        for prefix in _candidate_prefixes(name):
            patterns.append(re.compile(
                rf"\bimport\s+(?:static\s+)?{re.escape(prefix)}\.",
            ))
    elif dep.ecosystem == "Go":
        patterns.append(re.compile(rf'"{re.escape(name)}'))
    elif dep.ecosystem == "Cargo":
        patterns.append(re.compile(rf"\buse\s+{re.escape(name.replace('-', '_'))}"))
    elif dep.ecosystem == "RubyGems":
        patterns.append(re.compile(rf"\brequire\s+['\"]({re.escape(name)})"))
    elif dep.ecosystem == "NuGet":
        patterns.append(re.compile(rf"\busing\s+{re.escape(name)}\b"))
    elif dep.ecosystem == "Packagist":
        vendor = name.split("/", 1)[0]
        from ..reachability.composer import _to_pascal
        vendor_pascal = _to_pascal(vendor)
        # Vendor-namespace match only: the second PSR-4 segment often
        # differs from the composer package name (symfony/console maps
        # to Symfony\Component\Console). Case-insensitive because the
        # composer name is lowercase while PHP code is PascalCase.
        patterns.append(re.compile(
            rf"\buse\s+{re.escape(vendor_pascal)}\\", re.IGNORECASE,
        ))

    return patterns
