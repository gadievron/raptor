"""IRIS-pattern taint specification synthesis.

The LLM reads functions identified as potential sources, sinks, sanitisers,
or propagators, and generates structured taint specifications.  These specs
teach Joern/CodeQL the project's vocabulary so mechanical tools find flows
they'd miss with stock rules.

Named after the IRIS paper (ICLR 2025) which demonstrated that LLM-inferred
taint specifications doubled CodeQL's finding count vs stock rules.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from core.evidence import EvidenceTier

logger = logging.getLogger(__name__)

_SECURITY_NAME_PATTERNS = frozenset({
    "auth", "authenticate", "authorize", "login", "logout",
    "sanitize", "sanitise", "escape", "encode", "decode",
    "validate", "verify", "check", "filter", "clean", "purify",
    "encrypt", "decrypt", "hash", "sign",
    "parse", "deserialize", "unserialize", "unmarshal",
    "read", "recv", "fetch", "load", "get", "input",
    "write", "send", "output", "emit", "render", "execute",
    "query", "eval", "exec", "run", "system", "popen",
    "open", "close", "connect", "bind", "listen",
})


@dataclass
class TaintSpec:
    """A project-specific taint specification for one function."""

    function: str
    file: str
    role: str
    taint_classes: list[str] = field(default_factory=list)
    params_affected: list[int] = field(default_factory=list)
    return_tainted: bool = False
    confidence: float = 0.5
    evidence_tier: EvidenceTier = EvidenceTier.HEURISTIC
    # Provenance label ("heuristic", "operator_confirmed", ...).
    # Mirrors core.iris.specs.TaintSpec so the two spec shapes stay
    # interchangeable across the refine loop / store merge seam.
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "function": self.function,
            "file": self.file,
            "role": self.role,
            "taint_classes": self.taint_classes,
            "params_affected": self.params_affected,
            "return_tainted": self.return_tainted,
            "confidence": self.confidence,
            "evidence_tier": self.evidence_tier.value,
        }
        if self.source:
            d["source"] = self.source
        return d


@dataclass
class CandidateFunction:
    """A function identified as a candidate for taint spec synthesis."""

    function: str
    file: str
    source: str = ""
    reason: str = ""
    callee_of_taint_chain: bool = False
    has_security_name: bool = False
    line_start: int = 0
    line_end: int = 0


def identify_candidates(
    gaps: list[dict[str, Any]],
    *,
    taint_chain_callees: set | None = None,
    stock_sinks: set | None = None,
    stock_sources: set | None = None,
) -> list[CandidateFunction]:
    """Identify functions that are candidates for taint spec synthesis.

    Candidates are functions that:
    - Appear as callees in taint chains but aren't stock sinks/sources
    - Have security-related names (auth, sanitize, validate, etc.)
    - Show taint propagation in their Joern summary (param flows to return)
    """
    chain_callees = taint_chain_callees or set()
    known_sinks = stock_sinks or set()
    known_sources = stock_sources or set()
    candidates = []

    for gap in gaps:
        name = gap.get("name", "")
        key = f"{gap['file']}:{name}"
        name_lower = name.lower()

        is_chain_callee = key in chain_callees and key not in known_sinks and key not in known_sources
        has_sec_name = any(pat in name_lower for pat in _SECURITY_NAME_PATTERNS)

        if is_chain_callee or has_sec_name:
            candidates.append(CandidateFunction(
                function=name,
                file=gap["file"],
                source=gap.get("source", ""),
                reason="taint chain callee" if is_chain_callee else f"name matches: {name_lower}",
                callee_of_taint_chain=is_chain_callee,
                has_security_name=has_sec_name,
                line_start=gap.get("line_start", 0) or 0,
                line_end=gap.get("line_end", 0) or 0,
            ))

    return candidates


def parse_spec_response(raw: str) -> list[TaintSpec]:
    """Parse structured taint specs from an LLM response.

    Expects JSON objects with role, function, taint_classes, etc.
    Tolerant of markdown fencing and multiple objects.
    """
    specs = []

    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        cleaned = "\n".join(lines)

    for line in cleaned.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            spec = _parse_one_spec(data)
            if spec:
                specs.append(spec)
        except json.JSONDecodeError:
            continue

    if not specs:
        try:
            data = json.loads(cleaned)
            if isinstance(data, list):
                for item in data:
                    spec = _parse_one_spec(item)
                    if spec:
                        specs.append(spec)
            elif isinstance(data, dict):
                spec = _parse_one_spec(data)
                if spec:
                    specs.append(spec)
        except json.JSONDecodeError:
            pass

    return specs


def _parse_one_spec(data: dict[str, Any]) -> TaintSpec | None:
    """Parse a single spec from a dict."""
    role = data.get("role", "")
    if role not in ("source", "sink", "sanitiser", "sanitizer", "propagator"):
        return None
    if role == "sanitizer":
        role = "sanitiser"
    return TaintSpec(
        function=data.get("function", ""),
        file=data.get("file", ""),
        role=role,
        taint_classes=data.get("taint_classes", []),
        params_affected=data.get("params_affected", []),
        return_tainted=data.get("return_tainted", False),
        confidence=data.get("confidence", 0.5),
    )


def compile_joern_config(specs: list[TaintSpec]) -> str:
    """Generate CPGQL source/sink/sanitiser definitions from specs.

    The output is a Scala snippet that can be prepended to Joern queries
    to teach the CPG about project-specific taint vocabulary.
    """
    lines = [
        "// Project-specific taint specs (IRIS-synthesised)",
        "// Generated by core.audit.iris_specs",
        "",
    ]

    sources = [s for s in specs if s.role == "source"]
    sinks = [s for s in specs if s.role == "sink"]
    sanitisers = [s for s in specs if s.role == "sanitiser"]

    if sources:
        names = [_escape_scala(s.function) for s in sources]
        pattern = "^(" + "|".join(names) + ")$"
        lines.append(f'val projectSources = cpg.call.name("{pattern}").argument')
        lines.append("")

    if sinks:
        names = [_escape_scala(s.function) for s in sinks]
        pattern = "^(" + "|".join(names) + ")$"
        lines.append(f'val projectSinks = cpg.call.name("{pattern}").argument')
        lines.append("")

    if sanitisers:
        names = [_escape_scala(s.function) for s in sanitisers]
        pattern = "^(" + "|".join(names) + ")$"
        lines.append(f'val projectSanitisers = cpg.call.name("{pattern}")')
        lines.append("")

    propagators = [s for s in specs if s.role == "propagator"]
    if propagators:
        names = [_escape_scala(s.function) for s in propagators]
        pattern = "^(" + "|".join(names) + ")$"
        lines.append(f'val projectPropagators = cpg.call.name("{pattern}")')
        lines.append("")

    return "\n".join(lines)


def compile_codeql_config(specs: list[TaintSpec]) -> str:
    """Generate CodeQL extensible predicate definitions from specs.

    Produces a QL module that extends the taint-tracking library with
    project-specific sources, sinks, and sanitisers via the standard
    extensible predicate mechanism.
    """
    lines = [
        "// Project-specific taint specs (IRIS-synthesised)",
        "// Generated by core.audit.iris_specs",
        "",
        "import semmle.code.cpp.dataflow.TaintTracking",
        "",
    ]

    sources = [s for s in specs if s.role == "source"]
    sinks = [s for s in specs if s.role == "sink"]
    sanitisers = [s for s in specs if s.role == "sanitiser"]

    if sources:
        lines.append("class ProjectSource extends DataFlow::Node {")
        lines.append("  ProjectSource() {")
        predicates = []
        for s in sources:
            safe_name = _escape_codeql(s.function)
            predicates.append(
                f'    this.(DataFlow::CallNode).getTarget().hasName("{safe_name}")'
            )
        lines.append(" or\n".join(predicates))
        lines.append("  }")
        lines.append("}")
        lines.append("")

    if sinks:
        lines.append("class ProjectSink extends DataFlow::Node {")
        lines.append("  ProjectSink() {")
        predicates = []
        for s in sinks:
            safe_name = _escape_codeql(s.function)
            predicates.append(
                f'    this.(DataFlow::CallNode).getTarget().hasName("{safe_name}")'
            )
        lines.append(" or\n".join(predicates))
        lines.append("  }")
        lines.append("}")
        lines.append("")

    if sanitisers:
        lines.append("class ProjectBarrier extends DataFlow::Node {")
        lines.append("  ProjectBarrier() {")
        predicates = []
        for s in sanitisers:
            safe_name = _escape_codeql(s.function)
            predicates.append(
                f'    this.(DataFlow::CallNode).getTarget().hasName("{safe_name}")'
            )
        lines.append(" or\n".join(predicates))
        lines.append("  }")
        lines.append("}")
        lines.append("")

    propagators = [s for s in specs if s.role == "propagator"]
    if propagators:
        lines.append("class ProjectAdditionalTaintStep extends TaintTracking::AdditionalTaintStep {")
        lines.append("  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {")
        predicates = []
        for s in propagators:
            safe_name = _escape_codeql(s.function)
            predicates.append(
                f'    exists(DataFlow::CallNode c | c.getTarget().hasName("{safe_name}") '
                f"and pred = c.getAnArgument() and succ = c)"
            )
        lines.append(" or\n".join(predicates))
        lines.append("  }")
        lines.append("}")
        lines.append("")

    return "\n".join(lines)


def _escape_codeql(name: str) -> str:
    """Escape a function name for use in a CodeQL string literal."""
    name = name.replace("\n", "").replace("\r", "").replace("\0", "")
    return name.replace("\\", "\\\\").replace('"', '\\"')


def _escape_scala(name: str) -> str:
    """Escape a function name for use in a Joern/Java regex pattern.

    The result is embedded in a Scala double-quoted string literal,
    so we must escape both regex metacharacters AND Scala string
    characters (backslash and double-quote).
    """
    escaped = re.escape(name)
    return escaped.replace("\\", "\\\\").replace('"', '\\"')


def specs_to_json(specs: list[TaintSpec]) -> str:
    """Serialise specs to JSON for caching."""
    return json.dumps([s.to_dict() for s in specs], indent=2)


def specs_from_json(raw: str) -> list[TaintSpec]:
    """Deserialise specs from cached JSON."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    specs = []
    for item in data:
        try:
            tier = EvidenceTier(item.get("evidence_tier", "heuristic"))
        except ValueError:
            tier = EvidenceTier.HEURISTIC
        specs.append(TaintSpec(
            function=item.get("function", ""),
            file=item.get("file", ""),
            role=item.get("role", ""),
            taint_classes=item.get("taint_classes", []),
            params_affected=item.get("params_affected", []),
            return_tainted=item.get("return_tainted", False),
            confidence=item.get("confidence", 0.5),
            evidence_tier=tier,
            source=item.get("source", ""),
        ))
    return specs
