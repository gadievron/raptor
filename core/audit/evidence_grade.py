"""Evidence grading for /audit findings.

Each piece of evidence injected into the review context carries a source
tag and confidence level. Source tags distinguish mechanical extraction
(verifiable, deterministic) from LLM inference (probabilistic). Confidence
levels gate injection priority — HIGH evidence is never shed from the
prompt, LOW evidence is shed first under budget pressure.

Grading happens at two levels:
1. Per-evidence-item: each signal (taint flow, Joern result, spec
   deviation) gets a source tag and confidence.
2. Per-finding: a finding's overall confidence is the strongest
   evidence in its chain.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class EvidenceSource(str, enum.Enum):
    """Where a piece of evidence came from."""

    TREE_SITTER = "mechanical:tree_sitter"
    TAINT_APPROX = "mechanical:taint_approx"
    CALL_GRAPH = "mechanical:call_graph"
    JOERN = "mechanical:joern"
    SEMGREP = "mechanical:semgrep"
    CODEQL = "mechanical:codeql"
    COCCINELLE = "mechanical:coccinelle"
    SMT = "mechanical:smt"
    BINARY_ORACLE = "mechanical:binary_oracle"
    TYPESTATE = "mechanical:typestate"
    NEGATIVE_SPACE = "mechanical:negative_space"
    PREFILTER = "mechanical:prefilter"
    LLM_INFERRED = "llm:inferred"
    LLM_SPEC = "llm:spec"
    LLM_CORROBORATED = "llm:corroborated"
    DYNAMIC_SANITIZER = "dynamic:sanitizer"
    DYNAMIC_FRIDA = "dynamic:frida"
    DYNAMIC_CRASH = "dynamic:crash"
    DARK_VERIFY = "mechanical:dark_verify"
    COMPILATION = "mechanical:compilation"


class Confidence(str, enum.Enum):
    """Confidence level for evidence injection priority."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_SOURCE_CONFIDENCE: Dict[EvidenceSource, Confidence] = {
    EvidenceSource.TREE_SITTER: Confidence.HIGH,
    EvidenceSource.TAINT_APPROX: Confidence.HIGH,
    EvidenceSource.CALL_GRAPH: Confidence.HIGH,
    EvidenceSource.JOERN: Confidence.HIGH,
    EvidenceSource.SEMGREP: Confidence.HIGH,
    EvidenceSource.CODEQL: Confidence.HIGH,
    EvidenceSource.COCCINELLE: Confidence.HIGH,
    EvidenceSource.SMT: Confidence.HIGH,
    EvidenceSource.BINARY_ORACLE: Confidence.HIGH,
    EvidenceSource.TYPESTATE: Confidence.MEDIUM,
    EvidenceSource.NEGATIVE_SPACE: Confidence.MEDIUM,
    EvidenceSource.PREFILTER: Confidence.MEDIUM,
    EvidenceSource.LLM_INFERRED: Confidence.LOW,
    EvidenceSource.LLM_SPEC: Confidence.LOW,
    EvidenceSource.LLM_CORROBORATED: Confidence.MEDIUM,
    EvidenceSource.DYNAMIC_SANITIZER: Confidence.HIGH,
    EvidenceSource.DYNAMIC_FRIDA: Confidence.HIGH,
    EvidenceSource.DYNAMIC_CRASH: Confidence.MEDIUM,
    EvidenceSource.DARK_VERIFY: Confidence.HIGH,
    EvidenceSource.COMPILATION: Confidence.MEDIUM,
}

VALID_EVIDENCE_TOOLS: frozenset = frozenset({
    "semgrep", "coccinelle", "codeql", "smt", "joern",
    "compilation", "dynamic:sanitizer", "dynamic:crash", "frida:runtime",
    "dark_verify:confirmed", "dark_verify:refuted",
})

_TOOL_NAMESPACES = frozenset(VALID_EVIDENCE_TOOLS | {
    "prefilter", "critique", "sweep", "sarif_cache", "triage",
    "dynamic", "frida", "dark_verify",
})


def _is_single_tool_evidence(part: str) -> bool:
    """Check one atomic stamp (no ``+`` separator)."""
    if not part or part == "none":
        return False
    root = part.split(":")[0] if ":" in part else part
    return root in _TOOL_NAMESPACES or part in _TOOL_NAMESPACES


def is_tool_evidence(stamp: str) -> bool:
    """Return True if *stamp* was set by an actual tool run, not an LLM claim.

    Matches canonical stamps (``"dynamic:sanitizer"``, ``"semgrep"``, etc.),
    namespaced composites (``"semgrep:rule-123"``, ``"critique:prefilter:id"``),
    and ``+``-joined multi-tool stamps (``"semgrep+joern"``).
    """
    if not stamp or stamp == "none":
        return False
    parts = stamp.split("+") if "+" in stamp else [stamp]
    return all(_is_single_tool_evidence(p) for p in parts)


_LLM_ONLY_EVIDENCE = frozenset({
    "manual", "manual code review", "manual review", "code review",
    "llm", "llm review", "none", "n/a", "",
})

LLM_CLAIM_PREFIX = "llm-claimed:"


def sanitize_llm_evidence_tool(raw: str) -> str:
    """Normalise an evidence_tool value that came from the LLM.

    Values meaning "no tool" collapse to empty string.  Everything else
    is namespaced under ``llm-claimed:`` so it cannot satisfy
    :func:`is_tool_evidence`.  A real receipt overwrites it later via
    ``_stamp_evidence`` once a tool has actually run.
    """
    value = (raw or "").strip()
    if not value or value.lower() in _LLM_ONLY_EVIDENCE:
        return ""
    if value.startswith(LLM_CLAIM_PREFIX):
        return value
    return f"{LLM_CLAIM_PREFIX}{value}"


_RECEIPT_MAP: Dict[str, tuple] = {
    "dynamic:sanitizer": (EvidenceSource.DYNAMIC_SANITIZER, "confirmed by dynamic sanitizer"),
    "dynamic:crash": (EvidenceSource.DYNAMIC_CRASH, "non-zero exit without sanitizer confirmation"),
    "frida": (EvidenceSource.DYNAMIC_FRIDA, "confirmed by Frida runtime observation"),
    "joern": (EvidenceSource.JOERN, "confirmed by Joern CPG analysis"),
    "semgrep": (EvidenceSource.SEMGREP, "confirmed by Semgrep pattern match"),
    "codeql": (EvidenceSource.CODEQL, "confirmed by CodeQL analysis"),
    "coccinelle": (EvidenceSource.COCCINELLE, "confirmed by Coccinelle"),
    "smt": (EvidenceSource.SMT, "path feasibility confirmed by SMT solver"),
    "dark_verify:confirmed": (EvidenceSource.DARK_VERIFY, "confirmed by executed dark witness"),
    "dark_verify:refuted": (EvidenceSource.DARK_VERIFY, "refuted by executed dark witness"),
    "dark_verify": (EvidenceSource.DARK_VERIFY, "dark verification witness"),
    "compilation": (EvidenceSource.COMPILATION, "confirmed by compilation and execution"),
    "critique": (EvidenceSource.PREFILTER, "confirmed by critique prefilter"),
    "sarif_cache": (EvidenceSource.SEMGREP, "matched prior SARIF result"),
}

_CONFIDENCE_PRIORITY: Dict[Confidence, int] = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}


@dataclass
class GradedEvidence:
    """A single piece of evidence with source attribution and confidence."""

    source: EvidenceSource
    confidence: Confidence
    description: str
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "source": self.source.value,
            "confidence": self.confidence.value,
            "description": self.description,
        }
        if self.detail:
            d["detail"] = self.detail
        return d

    @property
    def priority(self) -> int:
        return _CONFIDENCE_PRIORITY.get(self.confidence, 2)


def default_confidence(source: EvidenceSource) -> Confidence:
    """Return the default confidence for an evidence source."""
    return _SOURCE_CONFIDENCE.get(source, Confidence.LOW)


def grade_evidence(
    source: EvidenceSource,
    description: str,
    *,
    detail: Optional[str] = None,
    confidence_override: Optional[Confidence] = None,
) -> GradedEvidence:
    """Create a graded evidence item."""
    conf = confidence_override or default_confidence(source)
    return GradedEvidence(
        source=source,
        confidence=conf,
        description=description,
        detail=detail,
    )


def finding_confidence(chain: List[GradedEvidence]) -> Confidence:
    """Compute overall confidence for a finding from its evidence chain.

    The finding's confidence is the highest confidence in the chain.
    If the chain has both mechanical and LLM evidence pointing at the
    same issue, the LLM evidence upgrades to MEDIUM (corroborated).
    """
    if not chain:
        return Confidence.LOW

    has_mechanical = any(
        e.source.value.startswith("mechanical:")
        or e.source.value.startswith("dynamic:")
        for e in chain
    )
    has_llm = any(
        e.source.value.startswith("llm:")
        for e in chain
    )

    best = Confidence.LOW
    for e in chain:
        conf = e.confidence
        if has_mechanical and has_llm and conf == Confidence.LOW:
            conf = Confidence.MEDIUM
        if _CONFIDENCE_PRIORITY[conf] < _CONFIDENCE_PRIORITY[best]:
            best = conf
    return best


def grade_evidence_record(record: Any) -> List[GradedEvidence]:
    """Convert an EvidenceRecord into a list of GradedEvidence items.

    Maps each populated field of the existing EvidenceRecord to graded
    evidence with appropriate source tags.
    """
    items: List[GradedEvidence] = []

    if getattr(record, "taint_approx", None) is not None:
        approx = record.taint_approx
        df = approx.get("dangerous_flows", {}) if isinstance(approx, dict) else getattr(approx, "dangerous_flows", {})
        if df:
            items.append(grade_evidence(
                EvidenceSource.TAINT_APPROX,
                f"{len(df)} tainted parameter flows",
            ))

    if getattr(record, "taint_summary", None) is not None:
        items.append(grade_evidence(
            EvidenceSource.TAINT_APPROX,
            "CFG path-sensitive taint flow",
        ))

    flows = getattr(record, "joern_flows", [])
    if flows:
        items.append(grade_evidence(
            EvidenceSource.JOERN,
            f"{len(flows)} Joern CPG flows",
        ))

    imported = getattr(record, "imported_joern_flows", [])
    if imported:
        items.append(grade_evidence(
            EvidenceSource.JOERN,
            f"{len(imported)} imported Joern flows",
        ))

    unguarded = getattr(record, "joern_unguarded_sinks", [])
    if unguarded:
        items.append(grade_evidence(
            EvidenceSource.JOERN,
            f"{len(unguarded)} unguarded sinks",
        ))

    codeql = getattr(record, "codeql_alerts", [])
    if codeql:
        items.append(grade_evidence(
            EvidenceSource.CODEQL,
            f"{len(codeql)} CodeQL alerts",
        ))

    semgrep = getattr(record, "semgrep_hits", [])
    if semgrep:
        items.append(grade_evidence(
            EvidenceSource.SEMGREP,
            f"{len(semgrep)} Semgrep matches",
        ))

    if getattr(record, "negative_space", None):
        ns = record.negative_space
        items.append(grade_evidence(
            EvidenceSource.NEGATIVE_SPACE,
            f"{len(ns)} convention deviations from sibling functions",
        ))

    if getattr(record, "sink_unreachable", False):
        items.append(grade_evidence(
            EvidenceSource.CALL_GRAPH,
            "sink unreachable from entry points",
        ))

    if getattr(record, "binary_sink_edges", None):
        items.append(grade_evidence(
            EvidenceSource.BINARY_ORACLE,
            f"{len(record.binary_sink_edges)} binary call edges to sinks",
        ))

    sink_args = getattr(record, "joern_sink_args", [])
    if sink_args:
        items.append(grade_evidence(
            EvidenceSource.JOERN,
            f"{len(sink_args)} sink argument flows",
        ))

    if getattr(record, "context_map_sink", None) is not None:
        items.append(grade_evidence(
            EvidenceSource.CALL_GRAPH,
            "context-map sink match",
        ))

    if getattr(record, "transitive_taint", None) is not None:
        items.append(grade_evidence(
            EvidenceSource.TAINT_APPROX,
            "transitive taint propagation",
        ))

    if getattr(record, "prefilter", None) is not None:
        items.append(grade_evidence(
            EvidenceSource.PREFILTER,
            "prefilter match",
        ))

    app_sinks = getattr(record, "app_sink_targets", [])
    if app_sinks:
        items.append(grade_evidence(
            EvidenceSource.CALL_GRAPH,
            f"{len(app_sinks)} application sink targets",
        ))

    sanitizers = getattr(record, "sanitizer_calls", [])
    if sanitizers:
        items.append(grade_evidence(
            EvidenceSource.TAINT_APPROX,
            f"{len(sanitizers)} sanitizer calls",
        ))

    if getattr(record, "binary_surface_category", None):
        items.append(grade_evidence(
            EvidenceSource.BINARY_ORACLE,
            f"surface category: {record.binary_surface_category}",
        ))

    if getattr(record, "binary_parser_boundary", False):
        items.append(grade_evidence(
            EvidenceSource.BINARY_ORACLE,
            "parser boundary function",
        ))

    layer0 = getattr(record, "binary_layer0_findings", [])
    if layer0:
        items.append(grade_evidence(
            EvidenceSource.BINARY_ORACLE,
            f"{len(layer0)} layer-0 binary findings",
        ))

    return items


def grade_review_result(
    review_result: Optional[Dict[str, Any]],
    evidence_tool: str = "",
) -> List[GradedEvidence]:
    """Extract graded evidence from an LLM review result."""
    items: List[GradedEvidence] = []

    rr = review_result or {}

    hypothesis = rr.get("hypothesis", "")
    if hypothesis:
        items.append(grade_evidence(
            EvidenceSource.LLM_INFERRED,
            hypothesis[:200],
        ))

    spec_dev = rr.get("spec_deviation")
    if spec_dev and spec_dev.get("deviation"):
        items.append(grade_evidence(
            EvidenceSource.LLM_SPEC,
            f"spec deviation: {spec_dev['deviation'][:150]}",
        ))

    ts_viol = rr.get("typestate_violation")
    if ts_viol and ts_viol.get("confirmed"):
        items.append(grade_evidence(
            EvidenceSource.TYPESTATE,
            f"{ts_viol.get('violation_kind', 'violation')} on {ts_viol.get('type_name', '?')}",
            confidence_override=Confidence.HIGH,
        ))

    if evidence_tool and is_tool_evidence(evidence_tool):
        parts = evidence_tool.split("+") if "+" in evidence_tool else [evidence_tool]
        seen: set = set()
        for part in parts:
            namespace = part.split(":")[0] if ":" in part else part
            entry = _RECEIPT_MAP.get(part) or _RECEIPT_MAP.get(namespace)
            if entry and entry[0] not in seen:
                seen.add(entry[0])
                source, description = entry
                items.append(grade_evidence(source, description))

    return items


def format_evidence_chain(chain: List[GradedEvidence]) -> str:
    """Render an evidence chain as human-readable text."""
    if not chain:
        return ""

    lines = ["### Evidence chain"]
    for e in sorted(chain, key=lambda x: x.priority):
        tag = e.source.value.split(":")[-1]
        conf = e.confidence.value.upper()
        lines.append(f"- [{conf}] ({tag}) {e.description}")
        if e.detail:
            lines.append(f"  {e.detail}")
    return "\n".join(lines)
