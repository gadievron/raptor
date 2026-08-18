"""IRIS-style CodeQL dataflow validation for /audit hypotheses.

When the LLM claims "input flows from source to sink" but no
existing CodeQL finding confirms the path, generate a targeted
CodeQL query to test the claim. Uses the existing CodeQL
augmented-run substrate.

Integration:
- review_fn generates a hypothesis with evidence_tool="codeql"
- orchestrator calls validate_dataflow_claim() with the hypothesis
- Result strengthens or refutes the finding

This converts ungrounded LLM opinions into tool-verified dataflow.

SMT path pruning: before a synthesized query's SARIF matches count as
confirmation, each match's thread-flow path is run through the SMT
path-feasibility machinery (same substrate /agentic's Tier 4 uses —
``packages.exploit_feasibility.smt_path.validate_path`` over
``core.smt_solver.path_feasibility``). Branch conditions are harvested
mechanically from the guards enclosing each path step; a match whose
every conditioned path is UNSAT is an incidental (vacuous-checker)
match and is pruned with a receipt. Complements condition_smt.py:
that checks hypothesis conditions, this checks per-dataflow-path
satisfiability.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._util import is_valid_identifier

logger = logging.getLogger(__name__)


@dataclass
class DataflowClaim:
    source_file: str
    source_function: str
    sink_file: str
    sink_function: str
    source_type: str = ""
    sink_type: str = ""
    description: str = ""


@dataclass
class ValidationResult:
    claim: DataflowClaim
    confirmed: bool | None = None
    sarif_matches: int = 0
    reasoning: str = ""
    error: str = ""
    query_text: str = ""
    smt_pruned: int = 0
    smt_receipts: list[dict[str, Any]] = field(default_factory=list)


_CPP_IDENT_RE = re.compile(
    r"^~?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:::[A-Za-z_~][A-Za-z0-9_]*)*"
    r"(?:<[A-Za-z0-9_:,\s*&]*>)?$"
)


def _validate_identifier(name: str, label: str) -> None:
    if not name:
        raise ValueError(f"{label} must be non-empty")
    if not is_valid_identifier(name) and not _CPP_IDENT_RE.match(name):
        raise ValueError(
            f"{label} must be a valid identifier (got {name!r})"
        )


def generate_taint_query(claim: DataflowClaim, *, language: str = "cpp") -> str:
    """Generate a targeted CodeQL taint-tracking query for a claim.

    Produces a minimal QL query that checks whether data flows from
    the claimed source to the claimed sink. Currently supports C/C++
    (language="cpp"). Raises ValueError for unsupported languages
    or invalid function names.
    """
    _validate_identifier(claim.source_function, "source_function")
    _validate_identifier(claim.sink_function, "sink_function")

    if language != "cpp":
        raise ValueError(f"unsupported language for CodeQL validation: {language}")

    source_fn = claim.source_function
    sink_fn = claim.sink_function

    return f"""\
/**
 * @name Audit hypothesis: dataflow {source_fn} -> {sink_fn}
 * @description Tests whether data flows from {source_fn} to {sink_fn}
 * @kind path-problem
 * @id raptor/audit-hypothesis
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

module AuditHypothesisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node source) {{
    exists(FunctionCall fc |
      fc.getTarget().getName() = "{source_fn}" and
      source.asExpr() = fc
    )
    or
    exists(Function f |
      f.getName() = "{source_fn}" and
      source.asParameter() = f.getAParameter()
    )
  }}

  predicate isSink(DataFlow::Node sink) {{
    exists(FunctionCall fc |
      fc.getTarget().getName() = "{sink_fn}" and
      sink.asExpr() = fc.getAnArgument()
    )
  }}
}}

module AuditHypothesisFlow = TaintTracking::Global<AuditHypothesisConfig>;

from AuditHypothesisFlow::PathNode source, AuditHypothesisFlow::PathNode sink
where AuditHypothesisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Data flows from {source_fn} to {sink_fn}"
"""


def validate_dataflow_claim(
    claim: DataflowClaim,
    *,
    db_path: Path | None = None,
    codeql_bin: str = "codeql",
    timeout_seconds: int = 300,
    target_path: Path | None = None,
) -> ValidationResult:
    """Run a CodeQL query to validate a dataflow claim.

    Generates a taint-tracking query for the claim, runs it against
    the CodeQL database, and checks whether any paths are found.
    When ``target_path`` is given, each match's thread-flow path is
    additionally SMT-checked (branch-condition satisfiability); a
    match whose paths are all provably infeasible is pruned before it
    can confirm the claim — with per-path receipts on the result.
    """
    if db_path is None:
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error="no CodeQL database path provided",
        )

    if not db_path.exists():
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error=f"CodeQL database not found: {db_path}",
        )

    try:
        query_text = generate_taint_query(claim)
    except ValueError as exc:
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error=str(exc),
        )

    try:
        from core.dataflow.codeql_augmented_run import analyze
    except ImportError:
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error="codeql_augmented_run not available",
            query_text=query_text,
        )

    try:
        with tempfile.TemporaryDirectory(prefix="audit-codeql-") as tmpdir:
            tmpdir_path = Path(tmpdir)
            query_file = tmpdir_path / "audit-hypothesis.ql"
            query_file.write_text(query_text)
            output_path = tmpdir_path / "results.sarif"

            result = analyze(
                db_path=db_path,
                queries=[str(query_file)],
                output_path=output_path,
                codeql_bin=codeql_bin,
                timeout_seconds=timeout_seconds,
            )

            if result.sarif_path.exists():
                sarif_data = json.loads(result.sarif_path.read_text())
                match_count = _count_sarif_results(sarif_data)
                smt_pruned = 0
                smt_receipts: list[dict[str, Any]] = []
                if match_count > 0 and target_path is not None:
                    try:
                        match_count, smt_pruned, smt_receipts = (
                            _smt_prune_sarif_matches(
                                sarif_data, target_path,
                            )
                        )
                    except Exception:
                        logger.debug(
                            "smt prune pass failed", exc_info=True,
                        )
                if match_count > 0:
                    reasoning = f"CodeQL found {match_count} dataflow path(s)"
                    if smt_pruned:
                        reasoning += (
                            f" ({smt_pruned} match(es) pruned:"
                            " path conditions unsatisfiable)"
                        )
                elif smt_pruned:
                    reasoning = (
                        f"CodeQL matched but SMT proved all {smt_pruned}"
                        " match path(s) infeasible — vacuous checker"
                        " match"
                    )
                else:
                    reasoning = "CodeQL found no dataflow paths"
                return ValidationResult(
                    claim=claim,
                    confirmed=match_count > 0,
                    sarif_matches=match_count,
                    reasoning=reasoning,
                    query_text=query_text,
                    smt_pruned=smt_pruned,
                    smt_receipts=smt_receipts,
                )
            else:
                return ValidationResult(
                    claim=claim,
                    confirmed=None,
                    error="no SARIF output produced",
                    query_text=query_text,
                )

    except Exception as exc:  # noqa: BLE001 — degrade to inconclusive
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error=str(exc),
            query_text=query_text,
        )


def _count_sarif_results(sarif: dict[str, Any]) -> int:
    """Count the number of results with codeFlows in SARIF output."""
    count = 0
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if result.get("codeFlows"):
                count += 1
    return count


# ── SMT path pruning ─────────────────────────────────────────────────
# Bounded like /agentic's Tier 4: few paths per match, few steps per
# path, few conditions per solver call, short per-call timeout. The
# solver wrapper degrades to feasible=None when z3 is absent — unknown
# never prunes.
_MAX_SMT_PATHS_PER_RESULT = 3
_MAX_SMT_PATH_STEPS = 20
_MAX_SMT_CONDITIONS = 16
_SMT_PRUNE_TIMEOUT_MS = 2000
_GUARD_LOOKBACK_LINES = 3

_GUARD_KW_RE = re.compile(r"\b(if|while|for)\s*\(")


def _balanced_paren_group(text: str, open_idx: int) -> str | None:
    """Content of the paren group opening at ``open_idx`` (single line)."""
    depth = 0
    start = None
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == "(":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:i]
    return None


def _guard_condition_on_line(text: str) -> str | None:
    """Branch condition on a source line, or None.

    ``if (...)`` / ``while (...)`` take the whole (balanced) group;
    ``for (init; cond; step)`` takes the middle clause. Purely
    textual and single-line — multi-line conditions are skipped
    rather than guessed.
    """
    m = _GUARD_KW_RE.search(text)
    if not m:
        return None
    group = _balanced_paren_group(text, m.end() - 1)
    if group is None:
        return None
    if m.group(1) == "for":
        parts = group.split(";")
        group = parts[1] if len(parts) == 3 else ""
    group = group.strip()
    return group or None


def _sarif_result_paths(
    result: dict[str, Any],
) -> list[list[tuple]]:
    """(uri, line) step lists for a SARIF result's thread flows."""
    paths: list[list[tuple]] = []
    for cf in result.get("codeFlows", []):
        for tf in cf.get("threadFlows", []):
            steps: list[tuple] = []
            for loc in tf.get("locations", [])[:_MAX_SMT_PATH_STEPS]:
                phys = (
                    loc.get("location", {}).get("physicalLocation", {})
                )
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
                if uri and isinstance(line, int) and line > 0:
                    steps.append((uri, line))
            if steps:
                paths.append(steps)
            if len(paths) >= _MAX_SMT_PATHS_PER_RESULT:
                return paths
    return paths


def _load_source_lines(
    uri: str,
    target_path: Path,
    cache: dict[str, list[str] | None],
) -> list[str] | None:
    if uri in cache:
        return cache[uri]
    lines: list[str] | None = None
    try:
        rel = uri.lstrip("/")
        candidate = (target_path / rel).resolve()
        # Path-containment: SARIF uris are attacker-influenced text.
        if (
            str(candidate).startswith(str(Path(target_path).resolve()))
            and candidate.is_file()
        ):
            lines = candidate.read_text(errors="replace").splitlines()
    except (OSError, ValueError):
        lines = None
    cache[uri] = lines
    return lines


def _path_conditions(
    steps: list[tuple],
    target_path: Path,
    cache: dict[str, list[str] | None],
) -> list[dict[str, Any]]:
    """Harvest enclosing-guard conditions along one thread-flow path."""
    conditions: list[dict[str, Any]] = []
    seen: set = set()
    for step_index, (uri, line) in enumerate(steps):
        lines = _load_source_lines(uri, target_path, cache)
        if not lines or line > len(lines):
            continue
        for j in range(line, max(line - 1 - _GUARD_LOOKBACK_LINES, 0), -1):
            cond = _guard_condition_on_line(lines[j - 1])
            if cond:
                if cond not in seen:
                    seen.add(cond)
                    conditions.append({
                        "text": cond,
                        "step_index": step_index,
                        "negated": False,
                    })
                break
        if len(conditions) >= _MAX_SMT_CONDITIONS:
            break
    return conditions


def _smt_prune_sarif_matches(
    sarif: dict[str, Any],
    target_path: Path,
) -> tuple:
    """SMT-check each match's path conditions; prune UNSAT-only matches.

    Returns ``(surviving_count, pruned_count, receipts)``. A match is
    pruned only when every thread-flow path yielded conditions AND the
    solver proved every one of them jointly unsatisfiable — an
    incidental match of a vacuous checker. Unknown/unavailable/
    condition-free paths always keep the match (fail-open).
    """
    try:
        from packages.exploit_feasibility.smt_path import validate_path
    except ImportError:
        return _count_sarif_results(sarif), 0, []

    kept = 0
    pruned = 0
    receipts: list[dict[str, Any]] = []
    cache: dict[str, list[str] | None] = {}

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if not result.get("codeFlows"):
                continue
            paths = _sarif_result_paths(result)
            path_receipts: list[dict[str, Any]] = []
            all_unsat = bool(paths)
            for steps in paths:
                conditions = _path_conditions(steps, target_path, cache)
                if not conditions:
                    all_unsat = False
                    continue
                try:
                    res = validate_path(
                        conditions,
                        profile="uint64",
                        timeout_ms=_SMT_PRUNE_TIMEOUT_MS,
                    )
                except Exception:
                    logger.debug("smt path prune failed", exc_info=True)
                    all_unsat = False
                    continue
                if res.get("feasible") is False:
                    path_receipts.append({
                        "conditions": conditions,
                        "reasoning": res.get("reasoning", ""),
                        "unsatisfied": res.get("unsatisfied", []),
                    })
                else:
                    all_unsat = False

            if all_unsat and path_receipts:
                pruned += 1
                loc = (
                    result.get("locations", [{}])[0]
                    .get("physicalLocation", {})
                )
                receipts.append({
                    "file": (
                        loc.get("artifactLocation", {}).get("uri", "")
                    ),
                    "line": loc.get("region", {}).get("startLine", 0),
                    "rule_id": result.get("ruleId", ""),
                    "verdict": "smt_path_infeasible",
                    "paths": path_receipts,
                })
            else:
                kept += 1

    return kept, pruned, receipts


def extract_claims_from_review(
    review_result: dict[str, Any],
) -> list[DataflowClaim]:
    """Extract dataflow claims from a review result.

    Looks for structured claim data in the review result. The LLM
    should populate these fields when evidence_tool="codeql":
    - dataflow_source: {file, function}
    - dataflow_sink: {file, function}
    """
    claims = []

    source = review_result.get("dataflow_source", {})
    sink = review_result.get("dataflow_sink", {})

    if source and sink and source.get("function") and sink.get("function"):
        claims.append(DataflowClaim(
            source_file=source.get("file", review_result.get("file", "")),
            source_function=source.get("function", ""),
            sink_file=sink.get("file", review_result.get("file", "")),
            sink_function=sink.get("function", ""),
            source_type=source.get("type", ""),
            sink_type=sink.get("type", ""),
            description=review_result.get("hypothesis", ""),
        ))

    return claims
