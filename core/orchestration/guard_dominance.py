"""Guard-dominance as a refute/corroborate channel beyond /audit (P23).

Reuses ``core.audit.joern_verify.run_guard_dominance_check`` — the
CFG-dominance query with vacuity guards and identifier-consistency
controls built in — for consumers outside /audit's tool chains:

* /validate's pre-LLM demoter (``apply_to_findings``): a condition on
  the claimed identifier dominating every matched sink call site
  mechanically refutes a "missing check" finding; its attack paths are
  soft-demoted with an explicit receipt. No dominating guard is
  corroboration recorded as evidence.
* /agentic's pre-LLM refuter (``refute_finding``): same check per
  finding; a refuted claim skips the LLM call with the receipt in the
  analysis record — explicit disqualifier semantics, never a silent
  verdict.
* constraint propagation's dominance tier lives in
  ``core.audit.propagation`` (needs the audit-side Constraint types)
  and shares the same underlying query.

Server lifecycle: ``acquire_warm_server`` starts a JoernServer only
when a cached CPG already exists for the target (the same warm-CPG
pattern as /agentic's reachability prepass) — nothing here ever builds
a CPG. Degrades to ``None`` when joern is absent or the CPG is cold;
every consumer treats ``None`` as "channel unavailable".
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Per-run cap on dominance queries outside /audit: each is a Joern
# REPL round-trip.
GUARD_DOMINANCE_CAP = 20

# Findings must LOOK like a missing-check claim before we spend a
# query — "missing/unchecked/unvalidated/without ... check/validation"
# prose in the reasoning text.
_MISSING_CHECK_HINT_RE = re.compile(
    r"missing|unchecked|unvalidated|unsanitized|unsanitised|"
    r"without\s+(?:\w+\s+){0,3}(?:check|validat)|"
    r"no\s+(?:\w+\s+){0,3}(?:check|validat)",
    re.IGNORECASE,
)


def acquire_warm_server(target: Path, *run_dirs: Path) -> Any | None:
    """Start a Joern server ONLY when a cached CPG exists for *target*.

    ``run_dirs`` are candidate cache roots (run dir, project dir) —
    each is probed for ``joern-cpg/`` via the standard cache loader.
    Returns a started server with the CPG imported, or ``None``
    (joern missing, no fresh cache, startup failure). Caller owns the
    lifecycle (``server.stop()``).
    """
    try:
        from packages.joern.prereqs import is_available
        if not is_available():
            return None
        from packages.joern.runner import load_cached_cpg
        cpg = None
        for candidate in run_dirs:
            if candidate is None:
                continue
            cpg = load_cached_cpg(Path(target), Path(candidate))
            if cpg is not None:
                break
        if cpg is None:
            return None
        from packages.joern.server import JoernServer
        server = JoernServer()
        server.start()
        if not server.import_cpg(cpg.path):
            server.stop()
            return None
        logger.info("guard-dominance: Joern server started with cached CPG")
        return server
    except Exception:
        logger.debug("guard-dominance: warm server unavailable",
                     exc_info=True)
        return None


def _finding_claim_text(finding: dict[str, Any]) -> str:
    parts = [
        finding.get("candidate_reasoning") or "",
        finding.get("dataflow_summary") or "",
        finding.get("message") or "",
        finding.get("hypothesis") or "",
    ]
    return " ".join(p for p in parts if p)


def _candidate_sinks(finding: dict[str, Any]) -> list[str]:
    sinks: list[str] = []
    cwe = finding.get("cwe_id") or finding.get("cwe") or ""
    if cwe:
        try:
            from core.audit.cwe_dispatch import sinks_for_cwe
            sinks.extend(sinks_for_cwe(cwe))
        except ImportError:
            pass
    try:
        from core.audit.joern_verify import _DEFAULT_GUARD_SINKS, normalize_cwe
        sinks.extend(_DEFAULT_GUARD_SINKS.get(normalize_cwe(cwe), []))
    except ImportError:
        pass
    return sinks


def missing_check_binding(
    finding: dict[str, Any],
) -> tuple[str, str] | None:
    """Bind ``(identifier, sink)`` for a missing-check-shaped finding.

    Returns ``None`` unless the claim text reads as a missing-check
    claim AND both the identifier and the sink bind to it
    (identifier-consistency control: no binding, no query).
    """
    text = _finding_claim_text(finding)
    if not text or not _MISSING_CHECK_HINT_RE.search(text):
        return None
    try:
        from core.audit.joern_verify import extract_guard_target
    except ImportError:
        return None
    ident, sink = extract_guard_target(text, _candidate_sinks(finding))
    if not ident or not sink:
        return None
    return ident, sink


def _finding_coords(finding: dict[str, Any]) -> tuple[str, str] | None:
    file_path = finding.get("file") or finding.get("file_path") or ""
    function = (
        finding.get("function")
        or (finding.get("metadata") or {}).get("function_name")
        or (finding.get("metadata") or {}).get("name")
        or ""
    )
    if not file_path or not function:
        return None
    return file_path, function


def check_finding(
    finding: dict[str, Any],
    target: Path,
    server: Any,
    *,
    timeout: int | None = None,
) -> Any | None:
    """Run the dominance query for one finding. Returns the
    ``SweepResult`` (outcome confirmed / refuted / inconclusive /
    error) or ``None`` when the finding doesn't bind."""
    binding = missing_check_binding(finding)
    coords = _finding_coords(finding)
    if binding is None or coords is None:
        return None
    ident, sink = binding
    file_path, function = coords
    from core.audit.joern_verify import run_guard_dominance_check
    return run_guard_dominance_check(
        target_path=Path(target),
        file_path=file_path,
        function_name=function,
        identifier=ident,
        sink_call=sink,
        server=server,
        timeout=timeout,
    )


def refute_finding(
    finding: dict[str, Any],
    target: Path,
    server: Any,
    *,
    timeout: int | None = None,
) -> dict[str, Any] | None:
    """/agentic pre-LLM refuter: returns a receipt dict when the
    missing-check claim is mechanically refuted, else ``None``.

    The receipt carries the dominator evidence so the skip is an
    explicit disqualifier, never a silent verdict.
    """
    result = check_finding(finding, target, server, timeout=timeout)
    if result is None or result.outcome != "refuted":
        return None
    details = result.details or {}
    return {
        "outcome": "refuted",
        "rule_id": result.rule_id,
        "reason": details.get("reason", "dominating check found"),
        "dominators": details.get("dominators", []),
    }


def apply_to_findings(
    findings: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]],
    target: Path,
    server: Any,
    *,
    cap: int = GUARD_DOMINANCE_CAP,
    timeout: int | None = None,
) -> dict[str, int]:
    """/validate demoter: dominance-check every missing-check finding.

    * ``refuted`` — receipt recorded on the finding
      (``guard_dominance``), and every attack path anchored to it is
      soft-demoted (proximity clamp + ``joern:guard-dominance``
      blocker). Never suppression: finding and paths stay in the
      report for the Stage D ruling.
    * ``confirmed`` — unguarded sink sites recorded as corroboration.
    * inconclusive / error — nothing recorded.

    Returns ``{"checked", "refuted", "corroborated", "demoted_paths"}``.
    """
    stats = {"checked": 0, "refuted": 0, "corroborated": 0,
             "demoted_paths": 0}

    paths_by_finding: dict[str, list[dict[str, Any]]] = {}
    for path in attack_paths or []:
        if not isinstance(path, dict):
            continue
        fid = path.get("finding_id") or path.get("finding")
        if isinstance(fid, str) and fid:
            paths_by_finding.setdefault(fid, []).append(path)

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if finding.get("status") == "disproven":
            continue
        if (finding.get("ruling") or {}).get("status") == "ruled_out":
            continue
        if finding.get("manual_override"):
            continue
        if finding.get("guard_dominance"):
            continue  # already checked
        if stats["checked"] >= cap:
            break
        result = check_finding(finding, target, server, timeout=timeout)
        if result is None:
            continue
        stats["checked"] += 1

        if result.outcome == "refuted":
            stats["refuted"] += 1
            details = result.details or {}
            reason = details.get("reason", "dominating check found")
            finding["guard_dominance"] = {
                "outcome": "refuted",
                "reason": reason,
                "dominators": details.get("dominators", []),
            }
            blocker = f"joern:guard-dominance — {reason}"
            for path in paths_by_finding.get(finding.get("id", ""), []):
                _clamp(path, blocker)
                stats["demoted_paths"] += 1
        elif result.outcome == "confirmed":
            stats["corroborated"] += 1
            finding["guard_dominance"] = {
                "outcome": "confirmed",
                "unguarded": result.matches or [],
            }

    return stats


def _clamp(path: dict[str, Any], blocker: str) -> None:
    """Shared soft-demotion semantics (proximity only ever lowered)."""
    try:
        from packages.exploitability_validation.reachability import (
            _apply_clamp,
        )
        _apply_clamp(path, blocker)
        return
    except ImportError:
        pass
    original = path.get("proximity")
    if isinstance(original, bool):
        original = None
    path["proximity"] = (
        min(original, 1) if isinstance(original, (int, float)) else 1
    )
    blockers = path.get("blockers")
    if not isinstance(blockers, list):
        blockers = []
    if blocker and blocker not in blockers:
        blockers.append(blocker)
    path["blockers"] = blockers


__all__ = [
    "GUARD_DOMINANCE_CAP",
    "acquire_warm_server",
    "apply_to_findings",
    "check_finding",
    "missing_check_binding",
    "refute_finding",
]
