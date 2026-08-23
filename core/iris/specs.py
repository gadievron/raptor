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
        file = gap.get("file", "")
        if not file or not name:
            continue
        key = f"{file}:{name}"
        name_lower = name.lower()

        if key in known_sinks or key in known_sources:
            continue
        is_chain_callee = key in chain_callees
        has_sec_name = any(pat in name_lower for pat in _SECURITY_NAME_PATTERNS)

        if is_chain_callee or has_sec_name:
            candidates.append(CandidateFunction(
                function=name,
                file=file,
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
    # Strip fences: find the first ``` and last ```, keep only between
    fence_start = cleaned.find("```")
    if fence_start >= 0:
        after_fence = cleaned[fence_start:]
        lines = after_fence.splitlines()
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        cleaned = "\n".join(lines)

    for line in cleaned.splitlines():
        line = line.strip()
        if not line or (not line.startswith("{") and not line.startswith("[")):
            continue
        try:
            data = json.loads(line)
            if isinstance(data, list):
                for item in data:
                    try:
                        s = _parse_one_spec(item)
                    except (ValueError, TypeError):
                        continue
                    if s:
                        specs.append(s)
            else:
                spec = _parse_one_spec(data)
                if spec:
                    specs.append(spec)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue

    if not specs:
        try:
            data = json.loads(cleaned)
            if isinstance(data, list):
                for item in data:
                    try:
                        spec = _parse_one_spec(item)
                    except (ValueError, TypeError):
                        continue
                    if spec:
                        specs.append(spec)
            elif isinstance(data, dict):
                spec = _parse_one_spec(data)
                if spec:
                    specs.append(spec)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    return specs


def _safe_confidence(val: Any) -> float:
    try:
        return max(0.0, min(1.0, float(val)))
    except (ValueError, TypeError):
        return 0.5


_VALID_ROLES = frozenset({"source", "sink", "sanitiser", "sanitizer", "propagator"})


def _parse_one_spec(data: Any) -> TaintSpec | None:
    """Parse a single spec from a dict."""
    if not isinstance(data, dict):
        return None
    role = data.get("role", "")
    if role not in _VALID_ROLES:
        return None
    if role == "sanitizer":
        role = "sanitiser"
    function = data.get("function", "")
    if not isinstance(function, str) or not function:
        return None
    file = data.get("file", "")
    if not isinstance(file, str):
        file = ""
    taint_classes = data.get("taint_classes", [])
    if isinstance(taint_classes, str):
        taint_classes = [taint_classes]
    raw_params = data.get("params_affected", [])
    if isinstance(raw_params, (int, float)):
        params_affected = [int(raw_params)]
    elif isinstance(raw_params, list):
        params_affected = []
        for x in raw_params:
            try:
                params_affected.append(int(x))
            except (TypeError, ValueError):
                continue
    else:
        params_affected = []
    return TaintSpec(
        function=function,
        file=file,
        role=role,
        taint_classes=taint_classes if isinstance(taint_classes, list) else [],
        params_affected=params_affected,
        return_tainted=data.get("return_tainted", False),
        confidence=_safe_confidence(data.get("confidence", 0.5)),
    )


def compile_joern_config(specs: list[TaintSpec]) -> str:
    """Generate CPGQL source/sink/sanitiser definitions from specs.

    The output is a Scala snippet that can be prepended to Joern queries
    to teach the CPG about project-specific taint vocabulary.
    """
    lines = [
        "// Project-specific taint specs (IRIS-synthesised)",
        "// Generated by core.iris.specs",
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


_CODEQL_LANG_IMPORTS: dict[str, tuple] = {
    "cpp": (
        "semmle.code.cpp.dataflow.DataFlow",
        "semmle.code.cpp.dataflow.TaintTracking",
    ),
    "java": (
        "semmle.code.java.dataflow.DataFlow",
        "semmle.code.java.dataflow.TaintTracking",
    ),
    "javascript": (
        "semmle.javascript.dataflow.DataFlow",
        "semmle.javascript.dataflow.TaintTracking",
    ),
    "python": (
        "semmle.python.dataflow.new.DataFlow",
        "semmle.python.dataflow.new.TaintTracking",
    ),
    "csharp": (
        "semmle.code.csharp.dataflow.DataFlow",
        "semmle.code.csharp.dataflow.TaintTracking",
    ),
    "go": (
        "semmle.go.dataflow.DataFlow",
        "semmle.go.dataflow.TaintTracking",
    ),
    "ruby": (
        "codeql.ruby.dataflow.DataFlow",
        "codeql.ruby.dataflow.TaintTracking",
    ),
}


def _source_predicate(specs: list[TaintSpec]) -> str:
    """Build a disjunction matching source function calls."""
    parts = []
    for s in specs:
        safe = _escape_codeql(s.function)
        parts.append(
            f'    n.(DataFlow::CallNode).getTarget().hasName("{safe}")'
        )
    return " or\n".join(parts)


def _barrier_predicate(specs: list[TaintSpec]) -> str:
    """Build a disjunction matching sanitiser call nodes as barriers."""
    parts = []
    for s in specs:
        safe = _escape_codeql(s.function)
        parts.append(
            f'    exists(DataFlow::CallNode c | '
            f'c.getTarget().hasName("{safe}") and n = c)'
        )
    return " or\n".join(parts)


def _sink_predicate(specs: list[TaintSpec]) -> str:
    """Build a disjunction matching arguments of sink function calls."""
    parts = []
    for s in specs:
        safe = _escape_codeql(s.function)
        parts.append(
            f'    exists(DataFlow::CallNode c | '
            f'c.getTarget().hasName("{safe}") and n = c.getAnArgument())'
        )
    return " or\n".join(parts)


def _propagator_predicate(specs: list[TaintSpec]) -> str:
    """Build a disjunction of additional taint steps through propagator calls."""
    parts = []
    for s in specs:
        safe = _escape_codeql(s.function)
        parts.append(
            f'    exists(DataFlow::CallNode c | '
            f'c.getTarget().hasName("{safe}") '
            f"and pred = c.getAnArgument() and succ = c)"
        )
    return " or\n".join(parts)


def compile_codeql_config(specs: list[TaintSpec], *, language: str = "cpp") -> str:
    """Generate a runnable CodeQL taint-tracking query from specs.

    Uses the module-based ``DataFlow::ConfigSig`` +
    ``TaintTracking::Global<Config>`` API (current CodeQL).  When both
    sources and sinks are present, produces a full taint-tracking
    path-problem query.  When only sinks are present, produces a
    simpler query reporting all matching call sites.
    """
    df_import, tt_import = _CODEQL_LANG_IMPORTS.get(
        language, _CODEQL_LANG_IMPORTS["cpp"],
    )

    sources = [s for s in specs if s.role == "source"]
    sinks = [s for s in specs if s.role == "sink"]
    sanitisers = [s for s in specs if s.role == "sanitiser"]
    propagators = [s for s in specs if s.role == "propagator"]

    if not sinks:
        return ""

    kind = "path-problem" if (sources and sinks) else "problem"
    lines = [
        "/**",
        " * @name IRIS project-specific taint tracking",
        " * @description Finds tainted data flows through IRIS-synthesised specs",
        f" * @kind {kind}",
        " * @problem.severity error",
        f" * @id raptor/iris/{language}/project-specs",
        " * @tags security",
        " */",
        "",
        f"import {df_import}",
        f"import {tt_import}",
        "",
    ]

    if sources and sinks:
        lines.append("private module Config implements DataFlow::ConfigSig {")
        lines.append("  predicate isSource(DataFlow::Node n) {")
        lines.append(_source_predicate(sources))
        lines.append("  }")
        lines.append("")
        lines.append("  predicate isSink(DataFlow::Node n) {")
        lines.append(_sink_predicate(sinks))
        lines.append("  }")
        if sanitisers:
            lines.append("")
            lines.append("  predicate isBarrier(DataFlow::Node n) {")
            lines.append(_barrier_predicate(sanitisers))
            lines.append("  }")
        if propagators:
            lines.append("")
            lines.append("  predicate isAdditionalTaintStep"
                         "(DataFlow::Node pred, DataFlow::Node succ) {")
            lines.append(_propagator_predicate(propagators))
            lines.append("  }")
        lines.append("}")
        lines.append("")
        lines.append("module Flow = TaintTracking::Global<Config>;")
        lines.append("")
        lines.append("import Flow::PathGraph")
        lines.append("")
        lines.append("from Flow::PathNode source, Flow::PathNode sink")
        lines.append("where Flow::flowPath(source, sink)")
        lines.append('select sink.getNode(), source, sink,')
        lines.append('  "IRIS: tainted data from $@ reaches project-specific sink",')
        lines.append('  source.getNode(), "this source"')
    elif sinks:
        lines.append("from DataFlow::Node sink")
        lines.append("where")
        sink_parts = []
        for s in sinks:
            safe = _escape_codeql(s.function)
            sink_parts.append(
                f'    exists(DataFlow::CallNode c | '
                f'c.getTarget().hasName("{safe}") and sink = c.getAnArgument())'
            )
        lines.append(" or\n".join(sink_parts))
        lines.append('select sink, "Argument to IRIS-identified project sink"')

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
    return _specs_from_list(data)


_VALID_STORE_ROLES = frozenset({"source", "sink", "sanitiser", "propagator"})


def _specs_from_list(items: list[dict[str, Any]]) -> list[TaintSpec]:
    """Build TaintSpec objects from a list of dicts."""
    specs = []
    for item in items:
        if not isinstance(item, dict):
            continue
        function = item.get("function", "")
        if not isinstance(function, str) or not function:
            continue
        role = item.get("role", "")
        if role not in _VALID_STORE_ROLES:
            continue
        try:
            tier = EvidenceTier(item.get("evidence_tier", "heuristic"))
        except ValueError:
            tier = EvidenceTier.HEURISTIC
        tc = item.get("taint_classes", [])
        if isinstance(tc, str):
            taint_classes = [tc]
        elif isinstance(tc, list):
            taint_classes = tc
        else:
            taint_classes = []
        pa = item.get("params_affected", [])
        if isinstance(pa, (int, float)) or isinstance(pa, str) and pa.isdigit():
            params_affected = [int(pa)]
        elif isinstance(pa, list):
            params_affected = []
            for x in pa:
                try:
                    params_affected.append(int(x))
                except (TypeError, ValueError):
                    continue
        else:
            params_affected = []
        specs.append(TaintSpec(
            function=function,
            file=item.get("file", "") if isinstance(item.get("file"), str) else "",
            role=role,
            taint_classes=taint_classes,
            params_affected=params_affected,
            return_tainted=item.get("return_tainted", False),
            confidence=_safe_confidence(item.get("confidence", 0.5)),
            evidence_tier=tier,
            source=item.get("source", ""),
        ))
    return specs
