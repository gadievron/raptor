"""IRIS-pattern taint specification synthesis.

The LLM reads functions identified as potential sources, sinks, sanitisers,
or propagators, and generates structured taint specifications.  These specs
teach Joern/CodeQL the project's vocabulary so mechanical tools find flows
they'd miss with stock rules.

Named after the IRIS paper (ICLR 2025) which demonstrated that LLM-inferred
taint specifications doubled CodeQL's finding count vs stock rules.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from core.evidence import EvidenceTier
from core.orchestration.llm_json import strip_json_fences
from core.json import dumps_artifact

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
    # A fence may follow prose: drop everything before the first one,
    # then take that fenced block's payload.
    fence_start = cleaned.find("```")
    if fence_start >= 0:
        cleaned = strip_json_fences(cleaned[fence_start:])

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


# Per-language QL fragments for the generated query. The three helper
# predicates are the ONLY language-specific surface — everything else
# in the generated query (Config module, Flow instantiation, select /
# message building) is language-independent, so a new language is one
# registry row, not a new query shape.
#
# Why per-language helpers instead of one ``DataFlow::CallNode``
# pattern: ``DataFlow::CallNode`` only exists in the JS/Go/Ruby
# libraries (and only Go's has ``getTarget()``).  cpp/java/csharp
# match calls through ``Node.asExpr()`` on their AST call class;
# python matches through ``CallCfgNode``.  A single spelling can NEVER
# compile across languages — each row below is compile-verified
# against its stock ``codeql/<lang>-all`` pack (the e2e closure test
# recompiles them against the locally cached packs).
#
# Helper contract (identical across languages):
#   irisCallResult(n, name) — n is the result value of a call to a
#     function/method named ``name`` (source + sanitiser-barrier form)
#   irisCallArg(n, name)    — n is an argument of such a call (sink form)
#   irisCallStep(pred, succ, name) — pred is an argument and succ the
#     result of such a call (propagator taint step)


@dataclass(frozen=True)
class _LangQL:
    """Language row: import lines + the three helper predicates."""

    imports: tuple[str, ...]
    helpers: str


_CPP_STYLE_HELPERS = """\
predicate irisCallResult(DataFlow::Node n, string name) {{
  n.asExpr().({call_cls}).{target}.hasName(name)
}}

predicate irisCallArg(DataFlow::Node n, string name) {{
  exists({call_cls} c | c.{target}.hasName(name) and n.asExpr() = c.getAnArgument())
}}

predicate irisCallStep(DataFlow::Node pred, DataFlow::Node succ, string name) {{
  exists({call_cls} c |
    c.{target}.hasName(name) and
    pred.asExpr() = c.getAnArgument() and
    succ.asExpr() = c
  )
}}"""

_CALLNODE_STYLE_HELPERS = """\
predicate irisCallTo({call_node} c, string name) {{
  {match}
}}

predicate irisCallResult(DataFlow::Node n, string name) {{ irisCallTo(n, name) }}

predicate irisCallArg(DataFlow::Node n, string name) {{
  exists({call_node} c | irisCallTo(c, name) and n = c.{arg})
}}

predicate irisCallStep(DataFlow::Node pred, DataFlow::Node succ, string name) {{
  exists({call_node} c | irisCallTo(c, name) and pred = c.{arg} and succ = c)
}}"""

_CODEQL_LANG_QL: dict[str, _LangQL] = {
    "cpp": _LangQL(
        imports=(
            "import cpp",
            "import semmle.code.cpp.dataflow.new.DataFlow",
            "import semmle.code.cpp.dataflow.new.TaintTracking",
        ),
        helpers=_CPP_STYLE_HELPERS.format(
            call_cls="Call", target="getTarget()",
        ),
    ),
    "java": _LangQL(
        imports=(
            "import java",
            "import semmle.code.java.dataflow.DataFlow",
            "import semmle.code.java.dataflow.TaintTracking",
        ),
        helpers=_CPP_STYLE_HELPERS.format(
            call_cls="MethodCall", target="getMethod()",
        ),
    ),
    "csharp": _LangQL(
        imports=(
            "import csharp",
            "import semmle.code.csharp.dataflow.DataFlow",
            "import semmle.code.csharp.dataflow.TaintTracking",
        ),
        helpers=_CPP_STYLE_HELPERS.format(
            call_cls="MethodCall", target="getTarget()",
        ),
    ),
    "python": _LangQL(
        imports=(
            "import python",
            "import semmle.python.dataflow.new.DataFlow",
            "import semmle.python.dataflow.new.TaintTracking",
        ),
        helpers=_CALLNODE_STYLE_HELPERS.format(
            call_node="DataFlow::CallCfgNode",
            match=(
                "c.getFunction().asCfgNode().(NameNode).getId() = name\n"
                "  or\n"
                "  c.getFunction().asCfgNode().(AttrNode).getName() = name"
            ),
            arg="getArg(_)",
        ),
    ),
    "javascript": _LangQL(
        imports=("import javascript",),
        helpers=_CALLNODE_STYLE_HELPERS.format(
            call_node="DataFlow::CallNode",
            match="c.getCalleeName() = name",
            arg="getAnArgument()",
        ),
    ),
    "go": _LangQL(
        imports=("import go",),
        helpers=_CALLNODE_STYLE_HELPERS.format(
            call_node="DataFlow::CallNode",
            match="c.getTarget().getName() = name",
            arg="getAnArgument()",
        ),
    ),
    "ruby": _LangQL(
        imports=(
            "import codeql.ruby.DataFlow",
            "import codeql.ruby.TaintTracking",
        ),
        helpers=_CALLNODE_STYLE_HELPERS.format(
            call_node="DataFlow::CallNode",
            match="c.getMethodName() = name",
            arg="getArgument(_)",
        ),
    ),
}

#: Languages ``compile_codeql_config`` can generate a compilable query
#: for (CodeQL canonical names). Callers gate on this BEFORE compiling;
#: an unsupported language raises rather than silently producing a
#: query for the wrong language's library.
CODEQL_QUERY_LANGUAGES: frozenset[str] = frozenset(_CODEQL_LANG_QL)


def _name_disjunction(
    specs: list[TaintSpec], template: str,
) -> str:
    """Disjunction of ``template`` instantiated per spec function name."""
    parts = [
        "    " + template.format(name=_escape_codeql(s.function))
        for s in specs
    ]
    return " or\n".join(parts)


def compile_codeql_config(specs: list[TaintSpec], *, language: str = "cpp") -> str:
    """Generate a runnable CodeQL taint-tracking query from specs.

    Uses the module-based ``DataFlow::ConfigSig`` +
    ``TaintTracking::Global<Config>`` API (current CodeQL).  When both
    sources and sinks are present, produces a full taint-tracking
    path-problem query.  When only sinks are present, produces a
    simpler query reporting all matching call sites.

    ``language`` must be a member of ``CODEQL_QUERY_LANGUAGES``
    (CodeQL canonical names); anything else raises ``ValueError``.
    Fail-closed by design: the pre-registry version silently fell back
    to the cpp imports for unknown languages and emitted call-matching
    QL that existed in no language's library — every generated query
    failed to compile and the confirmation lane was dead while
    reporting per-round tool errors only.
    """
    lang_ql = _CODEQL_LANG_QL.get(language)
    if lang_ql is None:
        supported = ", ".join(sorted(_CODEQL_LANG_QL))
        msg = (
            f"unsupported CodeQL query language {language!r} "
            f"(supported: {supported})"
        )
        raise ValueError(msg)

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
        *lang_ql.imports,
        "",
        lang_ql.helpers,
        "",
    ]

    if sources and sinks:
        lines.append("private module Config implements DataFlow::ConfigSig {")
        lines.append("  predicate isSource(DataFlow::Node n) {")
        lines.append(_name_disjunction(
            sources, 'irisCallResult(n, "{name}")'))
        lines.append("  }")
        lines.append("")
        lines.append("  predicate isSink(DataFlow::Node n) {")
        lines.append(_name_disjunction(
            sinks, 'irisCallArg(n, "{name}")'))
        lines.append("  }")
        if sanitisers:
            lines.append("")
            lines.append("  predicate isBarrier(DataFlow::Node n) {")
            lines.append(_name_disjunction(
                sanitisers, 'irisCallResult(n, "{name}")'))
            lines.append("  }")
        if propagators:
            lines.append("")
            # ConfigSig's member is isAdditionalFlowStep (the old
            # class-based API's isAdditionalTaintStep does not exist
            # in the module API and fails compilation).
            lines.append("  predicate isAdditionalFlowStep"
                         "(DataFlow::Node pred, DataFlow::Node succ) {")
            lines.append(_name_disjunction(
                propagators, 'irisCallStep(pred, succ, "{name}")'))
            lines.append("  }")
        lines.append("}")
        lines.append("")
        lines.append("module Flow = TaintTracking::Global<Config>;")
        lines.append("")
        lines.append("import Flow::PathGraph")
        lines.append("")
        # The result message MUST carry a machine-joinable identity
        # for the matched source/sink specs: the runner's confirmation
        # match-back (core.iris.codeql_runner._match_to_spec_keys)
        # extracts the `[src=<token> sink=<token>]` suffix and maps
        # each token back to its spec via spec_message_token. Fixed
        # messages made confirmed_keys always empty — no XREF_BACKED
        # promotion, no scorecard outcome, ever. Tokens (not free-text
        # function names) are the join: names are LLM-derived from the
        # studied repo, so a spec named after message boilerplate
        # ("data", "sink") or a same-named spec in another file/role
        # would false-confirm off a name search. Each token is bound
        # from the same irisCall* name constraint its Config predicate
        # uses; the human-readable name rides along for the operator.
        src_parts = []
        for s in sources:
            safe = _escape_codeql(s.function)
            tok = spec_message_token(s)
            src_parts.append(
                f'    (irisCallResult(source.getNode(), "{safe}") '
                f'and srcName = "{safe}" and srcKey = "{tok}")'
            )
        snk_parts = []
        for s in sinks:
            safe = _escape_codeql(s.function)
            tok = spec_message_token(s)
            snk_parts.append(
                f'    (irisCallArg(sink.getNode(), "{safe}") '
                f'and snkName = "{safe}" and snkKey = "{tok}")'
            )
        lines.append("from Flow::PathNode source, Flow::PathNode sink, "
                     "string srcName, string srcKey, "
                     "string snkName, string snkKey")
        lines.append("where")
        lines.append("  Flow::flowPath(source, sink) and")
        lines.append("  (")
        lines.append(" or\n".join(src_parts))
        lines.append("  ) and")
        lines.append("  (")
        lines.append(" or\n".join(snk_parts))
        lines.append("  )")
        lines.append('select sink.getNode(), source, sink,')
        lines.append('  "IRIS: tainted data from $@ reaches '
                     'project-specific sink " + snkName')
        lines.append('    + " [src=" + srcKey + " sink=" + snkKey + "]",')
        lines.append('  source.getNode(), srcName')
    elif sinks:
        # Same match-back contract as the path-problem branch: the
        # message must carry the sink spec's join token.
        lines.append("from DataFlow::Node sink, string snkName, "
                     "string snkKey")
        lines.append("where")
        sink_parts = []
        for s in sinks:
            safe = _escape_codeql(s.function)
            tok = spec_message_token(s)
            sink_parts.append(
                f'    (irisCallArg(sink, "{safe}") '
                f'and snkName = "{safe}" and snkKey = "{tok}")'
            )
        lines.append(" or\n".join(sink_parts))
        lines.append('select sink, "Argument to IRIS-identified '
                     'project sink " + snkName')
        lines.append('    + " [sink=" + snkKey + "]"')

    return "\n".join(lines)


def spec_message_token(spec: TaintSpec) -> str:
    """Stable join token binding a generated-query result to its spec.

    Hash of the spec's full identity — the same ``file\\0function\\
    0role`` triple ``store._spec_key`` uses — so same-named specs in
    different files/roles get distinct tokens and cannot cross-bleed
    a confirmation. Emitted into query result messages as
    ``src=<token>`` / ``sink=<token>`` by ``compile_codeql_config``;
    ``codeql_runner._match_to_spec_keys`` maps it back. 48 bits over
    a per-run spec list (tens of rows) — collision-safe for the join.
    Hex-only, so it needs no CodeQL string escaping.
    """
    identity = f"{spec.file}\0{spec.function}\0{spec.role}"
    return hashlib.sha256(identity.encode()).hexdigest()[:12]


def _escape_codeql(name: str) -> str:
    """Escape a function name for use in a CodeQL string literal."""
    name = name.replace("\n", "").replace("\r", "").replace("\0", "")
    return name.replace("\\", "\\\\").replace('"', '\\"')


def _escape_scala(name: str) -> str:
    """Escape a function name for use in a Joern/Java regex pattern.

    The result is embedded in a Scala double-quoted string literal,
    so we must escape both regex metacharacters AND Scala string
    characters (backslash and double-quote). Control characters are
    stripped first (mirroring _escape_codeql): re.escape keeps a raw
    newline as-is, which would break the single-line Scala literal —
    one malformed LLM-derived spec name then kills the whole generated
    Joern config compile.
    """
    name = name.replace("\n", "").replace("\r", "").replace("\0", "")
    escaped = re.escape(name)
    return escaped.replace("\\", "\\\\").replace('"', '\\"')


def specs_to_json(specs: list[TaintSpec]) -> str:
    """Serialise specs to JSON for caching."""
    return dumps_artifact([s.to_dict() for s in specs])


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
