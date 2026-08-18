"""Joern no-execution verification channels for /audit hypotheses.

Two mechanical verifiers on the live Joern CPG server:

* **Guard-dominance** — for "missing check" hypotheses (missing
  bounds / null / auth check on identifier X before sink Y).  A CPGQL
  query determines whether a control-structure condition mentioning X
  DOMINATES the claimed sink call site (every path from function entry
  to the sink evaluates the check).  A dominating check mechanically
  REFUTES the "missing check" hypothesis, with the dominator node as
  evidence.  No dominating check is confirm-capable only when the sink
  and identifier both match the hypothesis (identifier-consistency
  negative control, same discipline as sweep.py's semgrep controls).

* **Flow reachability** — for taint-style hypotheses ("attacker data
  from X reaches Y").  A ``reachableByFlows`` query from the named
  source to the named sink within the function (or across the file).
  A flow with matching identifiers confirms with the flow path as
  evidence; no flow on a well-formed query refutes only when the CPG
  actually covered the function — if the function is not in the CPG
  the outcome is inconclusive, never refuted (vacuity guard).

Security posture matches ``packages/joern``: the scanned repo is
untrusted and nothing from it executes.  Queries are RAPTOR-authored
CPGQL with every substituted value validated against the identifier
allowlist and Scala-escaped; results come back over the loopback-only
server API.  When Joern is unavailable the outcome is ``error`` with a
clear reason — never a crash, never a fabricated verdict.

Returns :class:`core.audit.sweep.SweepResult`-compatible outcomes.
Evidence stamps are namespaced ``joern:guard-dominance`` /
``joern:flow``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ._util import is_valid_identifier
from .sweep import SweepResult, _check_path_containment

logger = logging.getLogger(__name__)

GUARD_DOMINANCE_STAMP = "joern:guard-dominance"
FLOW_STAMP = "joern:flow"

# CWE families dispatched to each channel (wired via
# orchestrator._cwe_fallback_chain).
GUARD_DOMINANCE_CWES = frozenset({
    # CWE-121: stack variant of the 120/122/787 buffer family.
    "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-476",
    # P10 web families: "missing validation before sink" shapes — a
    # dominating check on the hypothesis identifier refutes, an
    # unguarded sink site confirms.
    "CWE-22", "CWE-23", "CWE-502", "CWE-918", "CWE-611", "CWE-601",
    "CWE-77",
})
FLOW_CWES = frozenset({
    "CWE-20", "CWE-74", "CWE-78", "CWE-89", "CWE-79",
    # CWE-130: length-parameter inconsistency — the recv-length →
    # parse/copy flow question (sinks come from cwe_dispatch).
    "CWE-130",
    # CWE-908: uninitialised-resource disclosure — the uninitialised
    # object → copy-out sink flow question (sinks from cwe_dispatch;
    # the joern live-query receipts on this family's promoted finding
    # were exactly these memcpy flows).
    "CWE-908",
    # P10 web families: source→sink reachability is verification-grade
    # for all of these (sinks come from cwe_dispatch).
    "CWE-22", "CWE-23", "CWE-502", "CWE-918", "CWE-611", "CWE-601",
    "CWE-77", "CWE-94", "CWE-95", "CWE-1321",
})

# Fallback sink lists for CWEs without a sink-carrying cwe_dispatch
# entry (CWE-476 is joern=False there; CWE-20/74 have no entry at
# all).  Deref-adjacent libc calls stand in for "sink the pointer
# must be checked before"; the injection families get the classic
# copy/exec/format sinks.
_DEFAULT_GUARD_SINKS: dict[str, list[str]] = {
    "CWE-476": ["memcpy", "memmove", "memset", "strcpy", "strncpy",
                "strlen", "free"],
    "CWE-20": ["memcpy", "strcpy", "strncpy", "sprintf", "system",
               "popen"],
    "CWE-74": ["system", "popen", "execve", "execl", "sprintf",
               "printf"],
}

_DEFAULT_QUERY_TIMEOUT_S = 300

# Output-protocol sentinels (kept distinct from packages/joern's
# JOERN_FLOW / JOERN_DARK markers, which the server parser also reads).
_GD_FUNC = "RAPTOR_GD_FUNC:"
_GD_SINKS = "RAPTOR_GD_SINKS:"
_GD_UNGUARDED = "RAPTOR_GD_UNGUARDED:"
_GD_GUARDED = "RAPTOR_GD_GUARDED:"
_FLOW_FUNC = "RAPTOR_FLOW_FUNC:"
_FLOW_SRC = "RAPTOR_FLOW_SRC:"
_FLOW_SNK = "RAPTOR_FLOW_SNK:"
_FLOW_COUNT = "RAPTOR_FLOW_COUNT:"


def normalize_cwe(cwe: str) -> str:
    """Normalise ``"120"`` / ``"cwe-120"`` → ``"CWE-120"``."""
    normalized = (cwe or "").upper().strip()
    if normalized and not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return normalized


def default_query_timeout() -> int:
    """Resolve the query timeout from the central Joern tunables."""
    try:
        from packages.joern.tunables import JoernTunables
        return JoernTunables.from_tuning().query_timeout_s
    except Exception:  # noqa: BLE001 — tuning backends vary; any failure means "use default"
        return _DEFAULT_QUERY_TIMEOUT_S


# ── chain-entry helpers (consumed by orchestrator._cwe_fallback_chain) ──


def guard_chain_entry(cwe: str) -> dict[str, Any] | None:
    """Tool-chain entry for the guard-dominance channel, or None."""
    norm = normalize_cwe(cwe)
    if norm not in GUARD_DOMINANCE_CWES:
        return None
    sinks = _sinks_for(norm)
    if not sinks:
        return None
    return {"type": "joern_guard", "config": {"sinks": sinks}}


def flow_chain_entry(cwe: str) -> dict[str, Any] | None:
    """Tool-chain entry for the flow-reachability channel, or None."""
    norm = normalize_cwe(cwe)
    if norm not in FLOW_CWES:
        return None
    sinks = _sinks_for(norm)
    if not sinks:
        return None
    return {"type": "joern_flow", "config": {"sinks": sinks}}


def _sinks_for(norm_cwe: str) -> list[str]:
    sinks: list[str] = []
    try:
        from .cwe_dispatch import sinks_for_cwe
        sinks = sinks_for_cwe(norm_cwe)
    except ImportError:
        pass
    if not sinks:
        sinks = _DEFAULT_GUARD_SINKS.get(norm_cwe, [])
    return sinks


# ── hypothesis extraction ────────────────────────────────────────────

_BACKTICK_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_GUARD_IDENT_PATTERNS = (
    # "missing bounds check on `len` before memcpy"
    re.compile(
        r"(?:check|validation|bounds[- ]check|null[- ]check)\s+"
        r"(?:on|of|for|against)\s+[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?",
        re.IGNORECASE,
    ),
    # "`len` is not checked / never validated"
    re.compile(
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?\s+is\s+"
        r"(?:not|never)\s+(?:checked|validated|verified|bounded)",
        re.IGNORECASE,
    ),
    # "unchecked `len`" / "unvalidated size"
    re.compile(
        r"\b(?:unchecked|unvalidated|unbounded)\s+"
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?",
        re.IGNORECASE,
    ),
)

_FLOW_PATTERNS = (
    # "from `argv` reaches/flows to/into `system`"
    re.compile(
        r"from\s+[`'\"]?([A-Za-z_][A-Za-z0-9_]*)(?:\(\))?[`'\"]?\s+"
        r".{0,80}?\b(?:reach(?:es)?|flows?(?:\s+(?:to|into))?|"
        r"propagates?\s+to|to|into)\s+"
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_.]*)(?:\(\))?[`'\"]?",
        re.IGNORECASE,
    ),
    # "`buf` reaches `system`" / "`buf` flows into `system`"
    re.compile(
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?\s+"
        r"(?:reach(?:es)?|flows?\s+(?:to|into)|is\s+passed\s+to)\s+"
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_.]*)(?:\(\))?[`'\"]?",
        re.IGNORECASE,
    ),
)

# Prose words that regex capture groups must never treat as code
# identifiers (mirrors sweep.py's stop-word discipline).
_STOP_WORDS = frozenset({
    "a", "an", "and", "any", "are", "attacker", "be", "before",
    "buffer", "by", "call", "check", "checked", "checks", "data",
    "for", "from", "function", "in", "input", "into", "is", "it",
    "missing", "no", "not", "of", "on", "or", "pointer", "reaches",
    "sink", "that", "the", "then", "this", "to", "user",
    "value", "which", "with", "without",
})


def _plausible_identifier(name: str | None) -> str | None:
    if not name:
        return None
    if name.lower() in _STOP_WORDS:
        return None
    if not is_valid_identifier(name):
        return None
    return name


def extract_guard_target(
    hypothesis: str,
    candidate_sinks: list[str],
) -> tuple[str | None, str | None]:
    """Extract (identifier, sink) for a guard-dominance check.

    The sink must be one of *candidate_sinks* (or a callee named
    right after "before") appearing verbatim in the hypothesis; the
    identifier is the checked variable named by the hypothesis.
    Returns ``(None, None)`` when either cannot be bound — the
    identifier-consistency negative control: no binding, no verdict.
    """
    hyp = hypothesis or ""

    sink: str | None = None
    for cand in candidate_sinks:
        bare = cand.split(".")[-1]
        if re.search(rf"\b{re.escape(bare)}\b", hyp):
            sink = bare
            break
    if sink is None:
        m = re.search(
            r"before\s+(?:the\s+)?(?:call\s+to\s+)?"
            r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?",
            hyp, re.IGNORECASE,
        )
        if m:
            sink = _plausible_identifier(m.group(1))

    ident: str | None = None
    for pat in _GUARD_IDENT_PATTERNS:
        m = pat.search(hyp)
        if m:
            ident = _plausible_identifier(m.group(1))
            if ident and ident != sink:
                break
            ident = None
    if ident is None:
        for cand in _BACKTICK_RE.findall(hyp):
            cand = _plausible_identifier(cand)
            if cand and cand != sink:
                ident = cand
                break

    if not sink or not ident or sink == ident:
        return (None, None)
    return (ident, sink)


def extract_flow_endpoints(
    hypothesis: str,
    candidate_sinks: list[str],
) -> tuple[str | None, str | None]:
    """Extract (source identifier, sink call) for a flow check.

    Source is the tainted variable / parameter the hypothesis names;
    sink is a call name (matched against *candidate_sinks* when the
    prose pattern doesn't name one).  Returns ``(None, None)`` when
    either endpoint cannot be bound to the hypothesis text.
    """
    hyp = hypothesis or ""

    for pat in _FLOW_PATTERNS:
        m = pat.search(hyp)
        if m:
            source = _plausible_identifier(m.group(1))
            sink_raw = m.group(2) or ""
            sink = _plausible_identifier(sink_raw.split(".")[-1])
            if source and sink and source != sink:
                return (source, sink)

    # Fallback: a candidate sink named in the hypothesis plus a
    # backticked identifier that isn't the sink.
    sink = None
    for cand in candidate_sinks:
        bare = cand.split(".")[-1]
        if re.search(rf"\b{re.escape(bare)}\b", hyp):
            sink = bare
            break
    if sink:
        for cand in _BACKTICK_RE.findall(hyp):
            cand = _plausible_identifier(cand)
            if cand and cand != sink:
                return (cand, sink)

    return (None, None)


# ── query builders (pure; all inputs pre-validated + escaped) ────────


def _escape(value: str) -> str:
    from packages.joern.runner import _escape_scala_string
    return _escape_scala_string(value)


def _valid_sub(value: str) -> bool:
    from packages.joern.runner import _validate_substitution_value
    return _validate_substitution_value(value)


def build_guard_dominance_query(
    function_name: str,
    sink_call: str,
    identifier: str,
) -> str:
    """CPGQL: does a condition on *identifier* dominate each *sink_call*?

    Emits one ``RAPTOR_GD_*`` sentinel line per fact; parsed by
    :func:`_parse_guard_output`.  All three inputs must already have
    passed identifier validation (bare identifiers are regex-safe, so
    the ``\\b<ident>\\b`` interpolation cannot change the regex shape).
    """
    fn = _escape(function_name)
    sink = _escape(sink_call)
    ident = _escape(identifier)
    ident_pat = f"(?s).*\\\\b{ident}\\\\b.*"
    return (
        'import io.shiftleft.semanticcpg.language._\n'
        f'val raptorFn = cpg.method.nameExact("{fn}").l\n'
        'if (raptorFn.isEmpty) {\n'
        f'  println("{_GD_FUNC}missing")\n'
        '} else {\n'
        f'  println("{_GD_FUNC}found")\n'
        '  val raptorSinks = raptorFn.flatMap(\n'
        f'    _.call.nameExact("{sink}")'
        f'.where(_.argument.code("{ident_pat}")).l)\n'
        f'  println("{_GD_SINKS}" + raptorSinks.size)\n'
        '  val raptorConds = raptorFn.flatMap(\n'
        f'    _.controlStructure.condition.code("{ident_pat}").l)\n'
        '  raptorSinks.foreach { s =>\n'
        '    val doms = s.dominatedBy.id.toSet\n'
        '    val guards = raptorConds.filter(c => doms.contains(c.id))\n'
        '    val sCode = s.code.take(200)'
        '.replace("\\n", " ").replace("|", "/")\n'
        '    if (guards.isEmpty) {\n'
        f'      println("{_GD_UNGUARDED}" + '
        's.lineNumber.getOrElse(0) + "|" + sCode)\n'
        '    } else {\n'
        '      val g = guards.head\n'
        '      val gCode = g.code.take(200)'
        '.replace("\\n", " ").replace("|", "/")\n'
        f'      println("{_GD_GUARDED}" + '
        's.lineNumber.getOrElse(0) + "|" + '
        'g.lineNumber.getOrElse(0) + "|" + gCode + "|" + sCode)\n'
        '    }\n'
        '  }\n'
        '}\n'
    )


def build_flow_query(
    function_name: str,
    source_id: str,
    sink_call: str,
    *,
    max_call_depth: int = 2,
) -> str:
    """CPGQL: reachableByFlows from *source_id* to *sink_call* args.

    Scoped to *function_name*.  Sources are the parameter(s) and
    identifier occurrences named *source_id* inside the function;
    sinks are the arguments of calls to *sink_call* inside the same
    function.  Emits ``RAPTOR_FLOW_*`` sentinels plus standard
    ``JOERN_FLOW:`` lines (the server's parser turns those into
    :class:`packages.joern.models.TaintFlow` objects for us).
    """
    fn = _escape(function_name)
    src = _escape(source_id)
    sink = _escape(sink_call)
    meth = f'cpg.method.nameExact("{fn}")'
    flow_print = (
        '  raptorFlows.foreach { flow =>\n'
        '    val steps = flow.elements.map { e =>\n'
        '      val ln = e.lineNumber.getOrElse(0)\n'
        '      val cd = e.code.take(200).replace("\\\\", "\\\\\\\\")'
        '.replace("\\"", "\\\\\\"").replace("\\n", " ")'
        '.replace("\\r", "")\n'
        '      val (fnName, fl) = e match {\n'
        '        case n: CfgNode =>\n'
        '          (Try(n.method.name).getOrElse(""), '
        'Try(n.method.filename).getOrElse(""))\n'
        '        case _ => ("", "")\n'
        '      }\n'
        '      val fnEsc = fnName.replace("\\\\", "\\\\\\\\")'
        '.replace("\\"", "\\\\\\"").replace("\\n", " ")\n'
        '      val flEsc = fl.replace("\\\\", "\\\\\\\\")'
        '.replace("\\"", "\\\\\\"").replace("\\n", " ")\n'
        '      s"""{"line":$ln,"code":"$cd",'
        '"function":"$fnEsc","file":"$flEsc"}"""\n'
        '    }.mkString(",")\n'
        '    println("JOERN_FLOW:[" + steps + "]")\n'
        '  }\n'
    )
    return (
        'import io.joern.dataflowengineoss.queryengine._\n'
        'import io.joern.dataflowengineoss.language._\n'
        'import io.shiftleft.semanticcpg.language._\n'
        'import io.shiftleft.codepropertygraph.generated.nodes.CfgNode\n'
        'import scala.util.Try\n'
        'implicit val raptorCtx: EngineContext = EngineContext('
        f'config = EngineConfig(maxCallDepth = {int(max_call_depth)}))\n'
        f'val raptorFn = {meth}.l\n'
        'if (raptorFn.isEmpty) {\n'
        f'  println("{_FLOW_FUNC}missing")\n'
        '} else {\n'
        f'  println("{_FLOW_FUNC}found")\n'
        f'  val raptorSrcCount = {meth}.parameter.nameExact("{src}").size + '
        f'{meth}.ast.isIdentifier.nameExact("{src}").size\n'
        f'  println("{_FLOW_SRC}" + raptorSrcCount)\n'
        f'  val raptorSnkCount = '
        f'{meth}.call.nameExact("{sink}").argument.size\n'
        f'  println("{_FLOW_SNK}" + raptorSnkCount)\n'
        '  val raptorSources = ('
        f'{meth}.parameter.nameExact("{src}") ++ '
        f'{meth}.ast.isIdentifier.nameExact("{src}")'
        ').collectAll[CfgNode]\n'
        f'  val raptorSinkArgs = '
        f'{meth}.call.nameExact("{sink}").argument\n'
        '  val raptorFlows = '
        'raptorSinkArgs.reachableByFlows(raptorSources).take(20).l\n'
        f'{flow_print}'
        f'  println("{_FLOW_COUNT}" + raptorFlows.size)\n'
        '}\n'
    )


# ── output parsing ───────────────────────────────────────────────────

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _sentinel_lines(raw: str) -> list[str]:
    """De-ANSI and strip REPL echo noise, keeping sentinel payloads."""
    lines = []
    for raw_line in (raw or "").splitlines():
        lines.append(_ANSI_RE.sub("", raw_line).strip())
    return lines


def _parse_guard_output(raw: str) -> dict[str, Any]:
    """Parse RAPTOR_GD_* sentinels into a fact dict."""
    facts: dict[str, Any] = {
        "function_found": None,
        "sink_count": None,
        "unguarded": [],
        "guarded": [],
    }
    for line in _sentinel_lines(raw):
        idx = line.find(_GD_FUNC)
        if idx >= 0:
            val = line[idx + len(_GD_FUNC):].strip()
            if val.startswith("found"):
                facts["function_found"] = True
            elif val.startswith("missing"):
                facts["function_found"] = False
            continue
        idx = line.find(_GD_SINKS)
        if idx >= 0:
            try:
                facts["sink_count"] = int(
                    line[idx + len(_GD_SINKS):].split("|")[0].strip().strip('"')
                )
            except ValueError:
                pass
            continue
        idx = line.find(_GD_UNGUARDED)
        if idx >= 0:
            parts = line[idx + len(_GD_UNGUARDED):].split("|")
            entry = {"line": _to_int(parts[0]),
                     "code": parts[1].strip().strip('"') if len(parts) > 1 else ""}
            if entry not in facts["unguarded"]:
                facts["unguarded"].append(entry)
            continue
        idx = line.find(_GD_GUARDED)
        if idx >= 0:
            parts = line[idx + len(_GD_GUARDED):].split("|")
            entry = {
                "sink_line": _to_int(parts[0]),
                "guard_line": _to_int(parts[1]) if len(parts) > 1 else 0,
                "guard_code": parts[2].strip().strip('"') if len(parts) > 2 else "",
                "sink_code": parts[3].strip().strip('"') if len(parts) > 3 else "",
            }
            if entry not in facts["guarded"]:
                facts["guarded"].append(entry)
    return facts


def _parse_flow_facts(raw: str) -> dict[str, Any]:
    """Parse RAPTOR_FLOW_* sentinels into a fact dict."""
    facts: dict[str, Any] = {
        "function_found": None,
        "source_count": None,
        "sink_count": None,
        "flow_count": None,
    }
    for line in _sentinel_lines(raw):
        idx = line.find(_FLOW_FUNC)
        if idx >= 0:
            val = line[idx + len(_FLOW_FUNC):].strip()
            if val.startswith("found"):
                facts["function_found"] = True
            elif val.startswith("missing"):
                facts["function_found"] = False
            continue
        for marker, key in (
            (_FLOW_SRC, "source_count"),
            (_FLOW_SNK, "sink_count"),
            (_FLOW_COUNT, "flow_count"),
        ):
            idx = line.find(marker)
            if idx >= 0:
                try:
                    facts[key] = int(
                        line[idx + len(marker):].split("|")[0].strip().strip('"')
                    )
                except ValueError:
                    pass
                break
    return facts


def _to_int(value: str) -> int:
    try:
        return int(value.strip().strip('"'))
    except (ValueError, AttributeError):
        return 0


def _word_in(needle: str, haystack: str) -> bool:
    return bool(re.search(rf"\b{re.escape(needle)}\b", haystack or ""))


# ── sweep entry points ───────────────────────────────────────────────


def _error(
    tool_stamp: str, file_path: str, function_name: str, reason: str,
) -> SweepResult:
    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="error",
        errors=[reason],
        rule_id=tool_stamp,
    )


def _inconclusive(
    tool_stamp: str, file_path: str, function_name: str, reason: str,
    details: dict[str, Any] | None = None,
) -> SweepResult:
    d = dict(details or {})
    d.setdefault("reason", reason)
    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="inconclusive",
        rule_id=tool_stamp,
        details=d,
    )


def _validate_common(
    tool_stamp: str,
    target_path: Path,
    file_path: str,
    function_name: str,
    server: Any,
    names: dict[str, str],
) -> SweepResult | None:
    """Shared precondition checks. Returns an error SweepResult or None."""
    escape = _check_path_containment(target_path, file_path, "joern")
    if escape:
        escape.rule_id = tool_stamp
        return escape

    if not is_valid_identifier(function_name):
        return _error(
            tool_stamp, file_path, function_name,
            f"invalid function name: {function_name!r}",
        )
    for label, value in names.items():
        try:
            ok = _valid_sub(value)
        except ImportError:
            return _error(
                tool_stamp, file_path, function_name,
                "joern package not available",
            )
        if not ok:
            return _error(
                tool_stamp, file_path, function_name,
                f"invalid {label}: {value!r}",
            )

    if server is None:
        return _error(
            tool_stamp, file_path, function_name,
            "no live Joern server (joern not installed or server "
            "unavailable)",
        )
    return None


def run_guard_dominance_check(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    identifier: str,
    sink_call: str,
    server: Any = None,
    timeout: int | None = None,
) -> SweepResult:
    """Guard-dominance verdict for a "missing check" hypothesis.

    Outcomes:
      * ``refuted`` — a condition mentioning *identifier* dominates
        every matched sink call site (evidence: the dominator nodes).
      * ``confirmed`` — at least one matched sink call site has no
        dominating check on *identifier* (evidence: the unguarded
        sink sites).  Only reachable when both the sink and the
        identifier from the hypothesis matched in the CPG.
      * ``inconclusive`` — function not in the CPG (vacuity guard) or
        no sink call passing *identifier* exists (identifier-
        consistency control: the hypothesis premise did not bind).
      * ``error`` — Joern unavailable, invalid input, or query error.
    """
    tool_stamp = GUARD_DOMINANCE_STAMP
    sink_bare = sink_call.split(".")[-1]
    pre = _validate_common(
        tool_stamp, target_path, file_path, function_name, server,
        {"identifier": identifier, "sink_call": sink_bare},
    )
    if pre:
        return pre
    if not is_valid_identifier(identifier):
        return _error(
            tool_stamp, file_path, function_name,
            f"invalid identifier: {identifier!r}",
        )

    if timeout is None:
        timeout = default_query_timeout()

    query = build_guard_dominance_query(function_name, sink_bare, identifier)
    try:
        result = server.query(query, timeout=timeout, check_length=False)
    except Exception as exc:  # noqa: BLE001 — degrade to outcome=error, never crash
        return _error(tool_stamp, file_path, function_name, str(exc))

    if result.errors:
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=list(result.errors),
            rule_id=tool_stamp,
            raw_output=(result.raw_output or "")[:2000],
        )

    facts = _parse_guard_output(result.raw_output or "")

    if facts["function_found"] is None:
        return _error(
            tool_stamp, file_path, function_name,
            "guard-dominance query produced no protocol output",
        )
    if facts["function_found"] is False:
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"function {function_name!r} not in CPG (no coverage — "
            "cannot refute or confirm)",
        )
    if not facts["sink_count"]:
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"no call to {sink_bare!r} passing {identifier!r} in "
            f"{function_name!r} — hypothesis identifiers did not bind "
            "(identifier-consistency control)",
            details={"sink": sink_bare, "identifier": identifier},
        )

    if facts["unguarded"]:
        # Negative control: only confirm when the matched sink code
        # actually mentions the hypothesis identifier.
        consistent = [
            u for u in facts["unguarded"]
            if _word_in(identifier, u.get("code", ""))
        ]
        if not consistent:
            return _inconclusive(
                tool_stamp, file_path, function_name,
                "unguarded sink matched but its code does not mention "
                f"{identifier!r} — refusing to confirm",
                details={"unguarded": facts["unguarded"]},
            )
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="confirmed",
            matches=[
                {
                    "line": u["line"],
                    "code": u["code"],
                    "sink": sink_bare,
                    "identifier": identifier,
                    "kind": "unguarded_sink",
                }
                for u in consistent
            ],
            rule_id=tool_stamp,
            raw_output=(result.raw_output or "")[:2000],
            details={"guarded": facts["guarded"]},
        )

    # Every matched sink is dominated by a check on the identifier:
    # the "missing check" hypothesis is mechanically refuted.
    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="refuted",
        rule_id=tool_stamp,
        raw_output=(result.raw_output or "")[:2000],
        details={
            "dominators": facts["guarded"],
            "reason": (
                f"a check on {identifier!r} dominates every "
                f"{sink_bare!r} call site in {function_name!r}"
            ),
        },
    )


def run_flow_reachability_check(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    source_id: str,
    sink_call: str,
    server: Any = None,
    timeout: int | None = None,
    max_call_depth: int = 2,
) -> SweepResult:
    """Flow-reachability verdict for a taint-style hypothesis.

    Outcomes:
      * ``confirmed`` — a dataflow from *source_id* to an argument of
        *sink_call* exists (evidence: the flow path).
      * ``refuted`` — CPG covers the function, both endpoints exist,
        and no flow was found.
      * ``inconclusive`` — function not in the CPG, or either endpoint
        absent (vacuity guard: an empty-source query "finding no flow"
        proves nothing).
      * ``error`` — Joern unavailable, invalid input, or query error.
    """
    tool_stamp = FLOW_STAMP
    sink_bare = sink_call.split(".")[-1]
    pre = _validate_common(
        tool_stamp, target_path, file_path, function_name, server,
        {"source_id": source_id, "sink_call": sink_bare},
    )
    if pre:
        return pre
    if not is_valid_identifier(source_id):
        return _error(
            tool_stamp, file_path, function_name,
            f"invalid source_id: {source_id!r}",
        )

    if timeout is None:
        timeout = default_query_timeout()

    query = build_flow_query(
        function_name, source_id, sink_bare,
        max_call_depth=max_call_depth,
    )
    try:
        result = server.query(query, timeout=timeout, check_length=False)
    except Exception as exc:  # noqa: BLE001 — degrade to outcome=error, never crash
        return _error(tool_stamp, file_path, function_name, str(exc))

    if result.errors:
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=list(result.errors),
            rule_id=tool_stamp,
            raw_output=(result.raw_output or "")[:2000],
        )

    facts = _parse_flow_facts(result.raw_output or "")

    if facts["function_found"] is None:
        return _error(
            tool_stamp, file_path, function_name,
            "flow query produced no protocol output",
        )
    if facts["function_found"] is False:
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"function {function_name!r} not in CPG (vacuity guard: "
            "cannot refute what was never analysed)",
        )

    flows = list(getattr(result, "flows", []) or [])
    if flows:
        # Identifier-consistency: some step of some flow must mention
        # the named source, and the flow must end in the named sink's
        # argument (the query already constrains the sink; check the
        # source binding on the returned path).
        consistent = []
        for flow in flows:
            steps = getattr(flow, "steps", []) or []
            texts = " ".join(
                f"{getattr(s, 'code', '')} {getattr(s, 'variable', '')}"
                for s in steps
            )
            if _word_in(source_id, texts):
                consistent.append(flow)
        if not consistent:
            return _inconclusive(
                tool_stamp, file_path, function_name,
                f"flows returned but none mentions {source_id!r} — "
                "refusing to confirm (identifier-consistency control)",
            )
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="confirmed",
            matches=[f.to_dict() for f in consistent],
            rule_id=tool_stamp,
            raw_output=(result.raw_output or "")[:2000],
            details={"source": source_id, "sink": sink_bare},
        )

    if not facts["source_count"] or not facts["sink_count"]:
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"endpoint missing in CPG (source {source_id!r}: "
            f"{facts['source_count'] or 0}, sink {sink_bare!r}: "
            f"{facts['sink_count'] or 0}) — query was vacuous",
            details={
                "source_count": facts["source_count"] or 0,
                "sink_count": facts["sink_count"] or 0,
            },
        )

    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="refuted",
        rule_id=tool_stamp,
        raw_output=(result.raw_output or "")[:2000],
        details={
            "reason": (
                f"no dataflow from {source_id!r} to {sink_bare!r} in "
                f"{function_name!r} (both endpoints present in CPG)"
            ),
            "source_count": facts["source_count"],
            "sink_count": facts["sink_count"],
        },
    )
