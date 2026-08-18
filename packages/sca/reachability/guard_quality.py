"""Call-site guard quality analysis for SCA reachability.

For deps with ``likely_called`` verdict + CVE advisories, this module
inspects the project source around each call site to determine whether
the vulnerable function call is protected by adequate guards (auth
checks, bounds validation, type checks, etc.).

Post-processing enrichment that runs after the function-level
reachability tiers. Does NOT change the reachability verdict — it adds
a guard quality signal that the findings layer can incorporate into
risk scoring.

Layers used:
  - condition_extraction (Layer 0, tree-sitter) — always runs
  - condition_adequacy (Layer 1) — always runs
  - condition_binding (Layer 2) — always runs
  - condition_cpg (Layer 3, Joern) — only when joern_server is passed
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Reachability

logger = logging.getLogger(__name__)


@dataclass
class CallSiteGuardAnalysis:
    """Guard analysis for one call site (one evidence entry)."""

    evidence_entry: str
    sink_api: str
    guards_found: int
    unconditional: bool
    adequacy_verdict: str
    has_bound_guard: bool
    all_decorative: bool
    guard_details: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "evidence": self.evidence_entry,
            "sink_api": self.sink_api,
            "guards_found": self.guards_found,
            "unconditional": self.unconditional,
            "adequacy": self.adequacy_verdict,
            "has_bound_guard": self.has_bound_guard,
            "all_decorative": self.all_decorative,
        }
        if self.guard_details:
            d["guard_details"] = self.guard_details
        return d


@dataclass
class GuardQualityResult:
    """Aggregate guard quality for all call sites of one dep."""

    dep_key: str
    call_sites: list[CallSiteGuardAnalysis]
    any_unguarded: bool
    any_inadequate: bool
    all_adequately_guarded: bool
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dep_key": self.dep_key,
            "call_sites": [cs.to_dict() for cs in self.call_sites],
            "any_unguarded": self.any_unguarded,
            "any_inadequate": self.any_inadequate,
            "all_adequately_guarded": self.all_adequately_guarded,
            "summary": self.summary,
        }


def analyze_call_site_guards(
    reachability: dict[str, Reachability],
    target: Path,
    *,
    cve_dep_keys: set[str] | None = None,
    affected_functions: dict[str, list[str]] | None = None,
    joern_server: Any | None = None,
    out_dir: Any | None = None,
) -> dict[str, GuardQualityResult]:
    """Analyze guard quality at call sites for likely_called deps.

    Args:
        reachability: dep_key -> Reachability from scan()
        target: project root directory
        cve_dep_keys: dep keys that have CVE advisories
        affected_functions: dep_key -> [function_name, ...] from OSV
        joern_server: optional JoernServer for Layer 3 analysis
        out_dir: run output dir for loading IRIS project sanitisers.
            When provided, IRIS-confirmed sanitisers are used to
            enhance guard recognition.  ``None`` is safe — stock
            guard categories only.

    Returns:
        dep_key -> GuardQualityResult for each analyzed dep.
        Empty dict when no deps qualify or the condition stack is
        unavailable.
    """
    if not cve_dep_keys or not affected_functions:
        return {}

    try:
        from core.audit.condition_adequacy import assess_guard_adequacy
        from core.audit.condition_binding import check_guard_binding
        from core.audit.condition_extraction import extract_sink_guards
    except ImportError:
        logger.debug(
            "guard_quality: core.audit.condition_* not importable; "
            "skipping guard enrichment"
        )
        return {}

    # Load IRIS-confirmed sanitisers (graceful: empty set on failure).
    # The IRIS store loader self-catches malformed/missing store files;
    # only store-path resolution can legitimately fail here (OSError).
    iris_sanitisers: set[str] = set()
    if out_dir is not None:
        try:
            from core.iris.api import get_project_sanitisers
            iris_sanitisers = set(get_project_sanitisers(out_dir=out_dir))
        except OSError as e:
            logger.warning(
                "guard_quality: IRIS sanitiser load failed (%s) — "
                "scoring without project-confirmed sanitisers", e,
            )

    results: dict[str, GuardQualityResult] = {}

    for dep_key, reach in reachability.items():
        if reach.verdict != "likely_called":
            continue
        if dep_key not in cve_dep_keys:
            continue
        if not reach.evidence:
            continue

        funcs = affected_functions.get(dep_key, [])
        if not funcs:
            continue

        result = _analyze_dep_call_sites(
            dep_key,
            reach.evidence,
            funcs,
            target,
            joern_server=joern_server,
            iris_sanitisers=iris_sanitisers,
            _extract=extract_sink_guards,
            _adequacy=assess_guard_adequacy,
            _binding=check_guard_binding,
        )
        if result is not None:
            results[dep_key] = result

    return results


def _analyze_dep_call_sites(
    dep_key: str,
    evidence: list[str],
    affected_functions: list[str],
    target: Path,
    *,
    joern_server: Any | None = None,
    iris_sanitisers: set[str] | None = None,
    _extract=None,
    _adequacy=None,
    _binding=None,
) -> GuardQualityResult | None:
    """Analyze all call sites for one dep."""
    call_sites: list[CallSiteGuardAnalysis] = []
    source_cache: dict[str, str] = {}

    for entry in evidence[:10]:
        path, line = _parse_evidence(entry)
        if path is None or line is None:
            continue

        source_path = target / path
        if path not in source_cache:
            try:
                source_cache[path] = source_path.read_text(
                    encoding="utf-8", errors="replace",
                )
            except OSError:
                continue
        source = source_cache[path]

        guards = _extract(source, path, sink_lines=[line])
        if not guards:
            call_sites.append(CallSiteGuardAnalysis(
                evidence_entry=entry,
                sink_api=(
                    affected_functions[0]
                    if affected_functions
                    else "unknown"
                ),
                guards_found=0,
                unconditional=True,
                adequacy_verdict="insufficient",
                has_bound_guard=False,
                all_decorative=True,
            ))
            continue

        for sg in guards:
            adequacy = _adequacy(sg.sink_api, sg.guards)
            binding = _binding(source, sg)

            guard_details = [g.to_dict() for g in sg.guards]
            if joern_server is not None:
                _enrich_cpg(sg, joern_server, guard_details)

            # Annotate guards that call IRIS-confirmed sanitisers
            if iris_sanitisers:
                for gd in guard_details:
                    text = gd.get("text", "")
                    matched = [s for s in iris_sanitisers if s in text]
                    if matched:
                        gd["iris_sanitiser_match"] = matched

            call_sites.append(CallSiteGuardAnalysis(
                evidence_entry=entry,
                sink_api=sg.sink_api,
                guards_found=sg.guard_count,
                unconditional=sg.unconditional,
                adequacy_verdict=adequacy.verdict.value,
                has_bound_guard=binding.has_any_bound_guard,
                all_decorative=binding.all_guards_decorative,
                guard_details=guard_details,
            ))

    if not call_sites:
        return None

    any_unguarded = any(cs.unconditional for cs in call_sites)
    any_inadequate = any(
        cs.adequacy_verdict in ("insufficient", "irrelevant")
        for cs in call_sites
    )
    all_adequate = all(
        cs.adequacy_verdict == "sufficient" and cs.has_bound_guard
        for cs in call_sites
    )

    total = len(call_sites)
    unguarded = sum(1 for cs in call_sites if cs.unconditional)
    adequate = sum(
        1 for cs in call_sites
        if cs.adequacy_verdict == "sufficient" and cs.has_bound_guard
    )

    if all_adequate:
        summary = f"all {total} call site(s) adequately guarded"
    elif any_unguarded:
        summary = (
            f"{unguarded}/{total} call site(s) unconditional; "
            f"{adequate}/{total} adequately guarded"
        )
    else:
        summary = f"{adequate}/{total} call site(s) adequately guarded"

    return GuardQualityResult(
        dep_key=dep_key,
        call_sites=call_sites,
        any_unguarded=any_unguarded,
        any_inadequate=any_inadequate,
        all_adequately_guarded=all_adequate,
        summary=summary,
    )


def _enrich_cpg(
    sg: Any,
    joern_server: Any,
    guard_details: list[dict[str, Any]],
) -> None:
    """Optionally enrich guard details with CPG verification.

    ``verify_guard_relevance_cpg`` degrades per-guard internally
    (query failures land in ``cr.error``) and returns ``[]`` without
    a server, so no handler is needed here — an exception escaping
    it is a wiring bug (or a safety-contract violation) and must
    propagate.
    """
    from core.audit.condition_cpg import verify_guard_relevance_cpg

    cpg_results = verify_guard_relevance_cpg(
        sg, joern_server=joern_server,
    )
    errored = sum(1 for cr in cpg_results if cr.error)
    if errored:
        logger.debug(
            "guard_quality: %d/%d CPG guard checks errored — "
            "guard evidence degraded", errored, len(cpg_results),
        )
    for cr in cpg_results:
        guard_details.append({
            "cpg_verified": cr.verified_relevant,
            "data_dep_bound": cr.data_dep_bound,
        })


def _parse_evidence(entry: str) -> tuple:
    """Parse a ``path:line`` evidence string.

    Uses rfind to handle paths containing colons (Windows drive
    letters, though uncommon in this context).
    """
    idx = entry.rfind(":")
    if idx <= 0:
        return None, None
    try:
        return entry[:idx], int(entry[idx + 1:])
    except ValueError:
        return None, None


__all__ = [
    "CallSiteGuardAnalysis",
    "GuardQualityResult",
    "analyze_call_site_guards",
]
