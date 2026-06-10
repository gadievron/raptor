"""Finding-normalisation adapter — Phase 5 of the value-binding arc.

Bridges static-analyser output formats (SARIF / Semgrep /
RAPTOR-native) to the inputs Phase 4's
:func:`core.inventory.sanitizer_cut.evaluate_finding` needs.

The adapter is the single point of contact between the upstream
finders (CodeQL queries, Semgrep rules, RAPTOR's own dataflow
validation) and the value-bound suppression gate. Phase 7 will
call this from the ``smt_barrier`` wire-up; the legacy lexical
check stays as the fallback when this returns
:class:`ResolutionFailure` (the call-site can't determine value
context, so we don't pretend to).

What the adapter does:

1. Detect the input format from the finding dict's shape.
2. Pull file, CWE, language, source line, sink line, optional
   sink-arg hint.
3. AST-parse the source file and find the enclosing function.
4. Build the Phase 1 :class:`PythonCFG`.
5. Resolve ``source_symbols`` and ``sink_arg`` from the CFG's
   :class:`CallSite` records and statement-level defs/uses.
6. Return :class:`ResolvedFinding` (CFG + node refs included so
   the caller can hand directly to ``evaluate_finding`` without
   re-parsing) or :class:`ResolutionFailure` with an audit reason.

Scope:

* **Python intra-procedural** — full end-to-end.
* **C / C++ / Java / other** — return ``ResolutionFailure`` with
  ``reason="language=…  not yet supported"``. Phase 9 adds C/C++
  intra-proc CFG; Phase 11 wires it through here.

The resolver is pure: no IO except reading the source file
mentioned in the finding; no logging side-effects (the audit
trail's :class:`ResolutionFailure.reason` is what Phase 6 writes
to ``suppressions.jsonl``).
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

from core.inventory.cfg_builder import (
    PyCFGNode,
    PythonCFG,
    build_python_cfg,
)


# CWE extraction patterns.
# CodeQL tags look like ``external/cwe/cwe-079``.
_CWE_TAG_RE = re.compile(r"external/cwe/cwe-(\d+)", re.IGNORECASE)
# Semgrep metadata strings look like ``CWE-79: …`` or just ``CWE-79``.
_CWE_SEMGREP_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class ResolvedFinding:
    """All inputs Phase 4's :func:`evaluate_finding` needs.

    Plus the CFG and source/sink node references — so the Phase 7
    smt_barrier wire-up can call ``evaluate_finding(rf.cfg,
    [rf.source_node], rf.sink_node, cwe=rf.cwe, ...)`` directly
    without rebuilding the CFG. Rebuilding would invalidate the
    node-identity invariant Phase 4 relies on
    (:class:`PyCFGNode` instances aren't deduplicated across
    builds).
    """
    file: str
    enclosing_function: str
    source_lineno: int
    source_symbols: FrozenSet[str]
    sink_lineno: int
    sink_arg: str
    cwe: str
    language: str
    cfg: PythonCFG
    source_node: PyCFGNode
    sink_node: PyCFGNode


@dataclass(frozen=True)
class ResolutionFailure:
    """Reason resolution couldn't proceed.

    Phase 6 writes this to ``suppressions.jsonl`` with
    ``verdict="unresolved"`` so operators can see which findings
    skipped the value-bound check and why. The legacy lexical
    check at ``smt_barrier.py:746`` / ``:940`` is the fallback in
    these cases; the finding survives to the LLM untouched.
    """
    reason: str


Resolution = Union[ResolvedFinding, ResolutionFailure]


@dataclass(frozen=True)
class _ParsedFinding:
    """Intermediate between format-specific parsing and AST resolution.

    Format-specific parsers (``_parse_sarif``, ``_parse_semgrep``,
    ``_parse_raptor_native``) all produce this shape; the resolver
    then runs the AST work uniformly.
    """
    file: str
    cwe: str
    language: str
    source_lineno: int
    source_col: Optional[int]
    sink_lineno: int
    sink_col: Optional[int]
    sink_arg_hint: Optional[str] = None


def resolve_finding(finding: Mapping[str, Any]) -> Resolution:
    """Resolve a finding (any supported format) to a
    :class:`ResolvedFinding` ready for ``evaluate_finding``, or
    :class:`ResolutionFailure` with the audit reason.

    Format dispatch is by dict shape (no explicit ``format`` key
    required):

    * SARIF result: ``ruleId`` + ``codeFlows`` present
    * Semgrep finding: ``check_id`` + ``extra``
    * RAPTOR-native: ``cwe`` + ``file_path`` + ``source_line`` +
      ``sink_line``
    """
    parsed = _parse_input_format(finding)
    if isinstance(parsed, ResolutionFailure):
        return parsed
    return _resolve_from_parsed(parsed)


# ---------------------------------------------------------------------------
# Format dispatch
# ---------------------------------------------------------------------------


def _parse_input_format(
    finding: Mapping[str, Any],
) -> Union[_ParsedFinding, ResolutionFailure]:
    if "ruleId" in finding and "codeFlows" in finding:
        return _parse_sarif(finding)
    if "check_id" in finding and "extra" in finding:
        return _parse_semgrep(finding)
    if all(
        k in finding for k in ("cwe", "file_path", "source_line", "sink_line")
    ):
        return _parse_raptor_native(finding)
    return ResolutionFailure(reason="unknown input format")


def _parse_sarif(finding: Mapping[str, Any]) -> Union[_ParsedFinding, ResolutionFailure]:
    rule_tags = finding.get("properties", {}).get("tags", [])
    cwe = ""
    for tag in rule_tags:
        m = _CWE_TAG_RE.search(str(tag))
        if m:
            cwe = f"CWE-{int(m.group(1))}"
            break
    if not cwe:
        return ResolutionFailure(reason="sarif: no CWE tag in properties.tags")

    code_flows = finding.get("codeFlows", [])
    if not code_flows:
        return ResolutionFailure(reason="sarif: no codeFlows")
    thread_flows = code_flows[0].get("threadFlows", [])
    if not thread_flows:
        return ResolutionFailure(reason="sarif: no threadFlows in codeFlows[0]")
    locations = thread_flows[0].get("locations", [])
    if len(locations) < 2:
        return ResolutionFailure(
            reason="sarif: need ≥2 locations in threadFlow (source + sink)",
        )

    src_phys = _sarif_physical_location(locations[0])
    sink_phys = _sarif_physical_location(locations[-1])
    src_region = src_phys.get("region", {})
    sink_region = sink_phys.get("region", {})
    file = (
        src_phys.get("artifactLocation", {}).get("uri", "")
        or sink_phys.get("artifactLocation", {}).get("uri", "")
    )
    if not file:
        return ResolutionFailure(reason="sarif: no artifactLocation.uri")

    src_line = src_region.get("startLine", 0)
    sink_line = sink_region.get("startLine", 0)
    if not src_line or not sink_line:
        return ResolutionFailure(
            reason="sarif: missing startLine on source or sink",
        )

    return _ParsedFinding(
        file=file,
        cwe=cwe,
        language=_detect_language(file),
        source_lineno=src_line,
        source_col=src_region.get("startColumn"),
        sink_lineno=sink_line,
        sink_col=sink_region.get("startColumn"),
    )


def _sarif_physical_location(loc_entry: Mapping[str, Any]) -> Mapping[str, Any]:
    """SARIF threadFlow locations wrap ``physicalLocation`` inside
    either a top-level ``location`` field or directly."""
    inner = loc_entry.get("location", loc_entry)
    return inner.get("physicalLocation", {})


def _parse_semgrep(
    finding: Mapping[str, Any],
) -> Union[_ParsedFinding, ResolutionFailure]:
    extra = finding.get("extra", {})
    cwes = extra.get("metadata", {}).get("cwe", [])
    cwe = ""
    if isinstance(cwes, str):
        cwes = [cwes]
    for entry in cwes:
        m = _CWE_SEMGREP_RE.search(str(entry))
        if m:
            cwe = f"CWE-{int(m.group(1))}"
            break
    if not cwe:
        return ResolutionFailure(
            reason="semgrep: no CWE in extra.metadata.cwe",
        )

    file = finding.get("path", "")
    if not file:
        return ResolutionFailure(reason="semgrep: no path")

    trace = extra.get("dataflow_trace", {})
    src_line = _semgrep_extract_line(trace.get("taint_source"))
    if not src_line:
        src_line = finding.get("start", {}).get("line", 0)
    sink_line = _semgrep_extract_line(trace.get("taint_sink"))
    if not sink_line:
        sink_line = finding.get("end", {}).get("line", 0) or finding.get(
            "start", {},
        ).get("line", 0)

    if not src_line or not sink_line:
        return ResolutionFailure(
            reason="semgrep: missing source or sink line",
        )

    return _ParsedFinding(
        file=file,
        cwe=cwe,
        language=_detect_language(file),
        source_lineno=src_line,
        source_col=None,
        sink_lineno=sink_line,
        sink_col=None,
    )


def _semgrep_extract_line(trace: Any) -> Optional[int]:
    """Semgrep's ``taint_source`` / ``taint_sink`` can be a dict
    with a single location or a list with the chain. Pull the
    first ``location.start.line`` we find."""
    if trace is None:
        return None
    if isinstance(trace, dict):
        loc = trace.get("location", {})
        line = loc.get("start", {}).get("line")
        if line:
            return line
        # Some semgrep shapes have the line at the top of the trace
        start = trace.get("start", {})
        line = start.get("line") if isinstance(start, dict) else None
        if line:
            return line
    if isinstance(trace, list) and trace:
        return _semgrep_extract_line(trace[0])
    return None


def _parse_raptor_native(
    finding: Mapping[str, Any],
) -> Union[_ParsedFinding, ResolutionFailure]:
    file = finding["file_path"]
    return _ParsedFinding(
        file=file,
        cwe=finding["cwe"],
        language=finding.get("language") or _detect_language(file),
        source_lineno=finding["source_line"],
        source_col=finding.get("source_col"),
        sink_lineno=finding["sink_line"],
        sink_col=finding.get("sink_col"),
        sink_arg_hint=finding.get("sink_arg"),
    )


def _detect_language(file_path: str) -> str:
    p = file_path.lower()
    if p.endswith(".py"):
        return "python"
    if p.endswith(".java"):
        return "java"
    if p.endswith(".jsx") or p.endswith(".js"):
        return "javascript"
    if p.endswith(".tsx") or p.endswith(".ts"):
        return "typescript"
    if p.endswith((".c", ".h")):
        return "c"
    if p.endswith((".cpp", ".cc", ".hpp", ".hh", ".cxx")):
        return "cpp"
    return "unknown"


# ---------------------------------------------------------------------------
# AST resolution
# ---------------------------------------------------------------------------


def _resolve_from_parsed(parsed: _ParsedFinding) -> Resolution:
    if parsed.language != "python":
        return ResolutionFailure(
            reason=(
                f"language={parsed.language!r} not yet supported — phase 9 "
                "adds c/c++ intra-procedural CFG, phase 11 wires through here"
            ),
        )

    file_path = Path(parsed.file)
    try:
        source_text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return ResolutionFailure(reason=f"cannot read {parsed.file}: {e}")
    try:
        tree = ast.parse(source_text)
    except SyntaxError as e:
        return ResolutionFailure(
            reason=f"syntax error in {parsed.file}: {e}",
        )

    fn = _find_enclosing_function(
        tree, parsed.source_lineno, parsed.sink_lineno,
    )
    if fn is None:
        return ResolutionFailure(
            reason=(
                f"no enclosing function for source line "
                f"{parsed.source_lineno} / sink line {parsed.sink_lineno} "
                f"in {parsed.file}"
            ),
        )

    cfg = build_python_cfg(source_text, fn.name)
    if cfg is None:
        return ResolutionFailure(
            reason=f"CFG construction failed for {fn.name} in {parsed.file}",
        )

    source_node, source_symbols = _resolve_source(
        cfg, fn, parsed.source_lineno,
    )
    if source_node is None:
        return ResolutionFailure(
            reason=(
                f"no source statement at line {parsed.source_lineno} in "
                f"{fn.name}"
            ),
        )

    sink_node, sink_arg = _resolve_sink(
        cfg, parsed.sink_lineno, parsed.sink_arg_hint,
    )
    if sink_node is None:
        return ResolutionFailure(
            reason=(
                f"no sink call at line {parsed.sink_lineno} in {fn.name}"
            ),
        )
    if not sink_arg:
        return ResolutionFailure(
            reason=(
                f"sink call at line {parsed.sink_lineno} has no bare-name "
                "argument; cannot resolve sink_arg"
            ),
        )

    return ResolvedFinding(
        file=parsed.file,
        enclosing_function=fn.name,
        source_lineno=parsed.source_lineno,
        source_symbols=source_symbols,
        sink_lineno=parsed.sink_lineno,
        sink_arg=sink_arg,
        cwe=parsed.cwe,
        language=parsed.language,
        cfg=cfg,
        source_node=source_node,
        sink_node=sink_node,
    )


def _find_enclosing_function(
    tree: ast.AST, source_line: int, sink_line: int,
) -> Optional[Union[ast.FunctionDef, ast.AsyncFunctionDef]]:
    """Smallest FunctionDef containing both source and sink lines.

    "Smallest" by end-line span so a nested helper wins over its
    enclosing function when both contain the lines.
    """
    candidates: List[
        Tuple[int, Union[ast.FunctionDef, ast.AsyncFunctionDef]]
    ] = []
    lo = min(source_line, sink_line)
    hi = max(source_line, sink_line)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = node.lineno
        end = _function_end_line(node)
        if start <= lo and hi <= end:
            candidates.append((end - start, node))
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    return candidates[0][1]


def _function_end_line(
    fn: Union[ast.FunctionDef, ast.AsyncFunctionDef],
) -> int:
    end = fn.lineno
    for child in ast.walk(fn):
        ln = getattr(child, "end_lineno", None) or getattr(child, "lineno", 0)
        if ln and ln > end:
            end = ln
    return end


def _resolve_source(
    cfg: PythonCFG,
    fn: Union[ast.FunctionDef, ast.AsyncFunctionDef],
    source_line: int,
) -> Tuple[Optional[PyCFGNode], FrozenSet[str]]:
    """Resolve source location to ``(cfg_node, source_symbols)``.

    Cases:

    * ``source_line == fn.lineno`` — the source IS the function
      entry; the taint is the function's params. Return
      ``(cfg.entry, cfg.params)``.
    * ``source_line`` matches an Assign in the CFG — the source
      is a body assignment; return ``(node, node.defs)``.
    * Other body stmt at ``source_line`` — fall back to
      ``node.uses`` (best-effort; the gate's condition 2 will
      still work but with weaker taint propagation).
    """
    if source_line == fn.lineno:
        return cfg.entry_node, frozenset(cfg.params)
    node = _node_at_lineno(cfg, source_line)
    if node is None:
        return None, frozenset()
    symbols = node.defs if node.defs else node.uses
    return node, symbols


def _resolve_sink(
    cfg: PythonCFG,
    sink_line: int,
    sink_arg_hint: Optional[str],
) -> Tuple[Optional[PyCFGNode], str]:
    """Resolve sink location to ``(cfg_node, sink_arg)``.

    Locate the CFG node at ``sink_line``. Inspect its call_sites:

    * If a hint is provided and matches a CallSite's
      ``arg_names``, use the hint.
    * Else the outermost call (last in source order) is the
      assumed sink; its first ``arg_name`` (lexicographic for
      determinism) is ``sink_arg``.

    Returns ``(None, "")`` on failure; the caller surfaces the
    audit reason.
    """
    node = _node_at_lineno(cfg, sink_line)
    if node is None:
        return None, ""
    if not node.call_sites:
        return None, ""
    if sink_arg_hint:
        for cs in node.call_sites:
            if sink_arg_hint in cs.arg_names:
                return node, sink_arg_hint
    outermost = node.call_sites[-1]
    if not outermost.arg_names:
        return None, ""
    return node, sorted(outermost.arg_names)[0]


def _node_at_lineno(cfg: PythonCFG, lineno: int) -> Optional[PyCFGNode]:
    for n in cfg.nodes():
        if not isinstance(n, PyCFGNode):
            continue
        if n.lineno == lineno:
            return n
    return None


__all__ = [
    "ResolvedFinding",
    "ResolutionFailure",
    "Resolution",
    "resolve_finding",
]
