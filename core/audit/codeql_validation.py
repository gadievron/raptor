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
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    confirmed: Optional[bool] = None
    sarif_matches: int = 0
    reasoning: str = ""
    error: str = ""
    query_text: str = ""


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
    db_path: Optional[Path] = None,
    codeql_bin: str = "codeql",
    timeout_seconds: int = 300,
) -> ValidationResult:
    """Run a CodeQL query to validate a dataflow claim.

    Generates a taint-tracking query for the claim, runs it against
    the CodeQL database, and checks whether any paths are found.
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
                return ValidationResult(
                    claim=claim,
                    confirmed=match_count > 0,
                    sarif_matches=match_count,
                    reasoning=(
                        f"CodeQL found {match_count} dataflow path(s)"
                        if match_count > 0
                        else "CodeQL found no dataflow paths"
                    ),
                    query_text=query_text,
                )
            else:
                return ValidationResult(
                    claim=claim,
                    confirmed=None,
                    error="no SARIF output produced",
                    query_text=query_text,
                )

    except Exception as exc:
        return ValidationResult(
            claim=claim,
            confirmed=None,
            error=str(exc),
            query_text=query_text,
        )


def _count_sarif_results(sarif: Dict[str, Any]) -> int:
    """Count the number of results with codeFlows in SARIF output."""
    count = 0
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if result.get("codeFlows"):
                count += 1
    return count


def extract_claims_from_review(
    review_result: Dict[str, Any],
) -> List[DataflowClaim]:
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
