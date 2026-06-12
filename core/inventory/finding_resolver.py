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
from core.inventory.cfg_builder_cpp import (
    CPPCFG,
    CPPCFGNode,
    build_cpp_intraproc_cfg,
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
    node-identity invariant Phase 4 relies on (CFG node instances
    aren't deduplicated across builds).

    ``cfg`` is :class:`PythonCFG` for Python findings and
    :class:`CPPCFG` for C / C++ findings (Phase 11 wired the C/C++
    branch). Both satisfy :class:`core.inventory.dominators.Graph`
    so evaluate_finding consumes either with no language branch.
    Source / sink node types vary in parallel.

    ``inter_proc_bindings`` (Phase 14) are inter-procedural synthetic
    sanitizer bindings computed for Python findings whose enclosing
    function calls an in-module helper that cleanly sanitizes. Pass
    them as ``evaluate_finding(..., extra_bindings=rf.inter_proc_bindings)``
    so a sanitizer inside a callee counts toward the cut. Empty for
    C / C++ (inter-procedural C/C++ is a future arc) and for Python
    functions with no qualifying helper calls.
    """
    file: str
    enclosing_function: str
    source_lineno: int
    source_symbols: FrozenSet[str]
    sink_lineno: int
    sink_arg: str
    cwe: str
    language: str
    cfg: Union[PythonCFG, CPPCFG]
    source_node: Union[PyCFGNode, CPPCFGNode]
    sink_node: Union[PyCFGNode, CPPCFGNode]
    inter_proc_bindings: FrozenSet = frozenset()


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
    if parsed.language == "python":
        return _resolve_from_parsed_python(parsed)
    if parsed.language in ("c", "cpp"):
        return _resolve_from_parsed_cpp(parsed)
    return ResolutionFailure(
        reason=(
            f"language={parsed.language!r} not yet supported — "
            "python is shipped (phases 1-7), c/c++ wired in phase 11; "
            "other languages await future arcs"
        ),
    )


def _resolve_from_parsed_python(parsed: _ParsedFinding) -> Resolution:
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

    inter_proc = _inter_proc_bindings_python(
        source_text, fn, cfg, parsed.cwe,
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
        inter_proc_bindings=inter_proc,
    )


def _inter_proc_bindings_python(
    source_text: str,
    fn: Union[ast.FunctionDef, ast.AsyncFunctionDef],
    cfg: PythonCFG,
    cwe: str,
) -> FrozenSet:
    """Phase 14 — compute inter-procedural synthetic sanitizer
    bindings for a Python finding's enclosing function.

    Builds the module-local call graph + taint summaries from the
    same source text, then asks
    :func:`core.inventory.interproc.synthetic_sanitizer_bindings`
    for bindings at call sites where an in-module helper cleanly
    sanitizes. Returns an empty frozenset on any failure (best-effort
    — the intra-procedural verdict still stands). Imports are local
    so the Phase 12-14 modules aren't loaded for callers that never
    resolve a Python finding."""
    try:
        from core.inventory.callgraph import (
            build_python_module_callgraph,
        )
        from core.inventory.interproc import (
            synthetic_sanitizer_bindings,
        )
        from core.inventory.taint_summaries import (
            build_taint_summaries,
        )
    except ImportError:                                     # pragma: no cover
        return frozenset()
    cg = build_python_module_callgraph(source_text)
    if cg is None:
        return frozenset()
    summaries = build_taint_summaries(cg, source_text)
    return synthetic_sanitizer_bindings(
        cfg, fn, summaries, cwe, "python",
    )


def _resolve_from_parsed_cpp(parsed: _ParsedFinding) -> Resolution:
    """C / C++ branch of the resolver — Phase 11.

    Uses tree-sitter (via ``build_cpp_intraproc_cfg``) to find the
    enclosing function spanning [source_line, sink_line]. The same
    source / sink resolution algorithm as Python is then applied,
    using ``cfg.params`` / ``defs`` / ``call_sites`` — all of which
    :class:`CPPCFG` exposes with the same contract as
    :class:`PythonCFG`.

    Degrades to :class:`ResolutionFailure` when the tree-sitter
    grammar isn't installed, when the source can't be parsed, when
    no function spans the line range, or when the CFG produces no
    node at the requested source / sink line. The legacy lexical
    fallback at ``smt_barrier.py:746`` / ``:940`` is the safety net.
    """
    file_path = Path(parsed.file)
    try:
        source_text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return ResolutionFailure(reason=f"cannot read {parsed.file}: {e}")

    fn_name, fn_start = _find_enclosing_function_cpp(
        source_text, parsed.language, parsed.source_lineno,
        parsed.sink_lineno,
    )
    if fn_name is None:
        return ResolutionFailure(
            reason=(
                f"no enclosing C/C++ function for source line "
                f"{parsed.source_lineno} / sink line {parsed.sink_lineno} "
                f"in {parsed.file} (tree-sitter grammar missing or no "
                "function definition spans the range)"
            ),
        )

    cfg = build_cpp_intraproc_cfg(
        source_text, fn_name, language=parsed.language,
    )
    if cfg is None:
        return ResolutionFailure(
            reason=(
                f"CFG construction failed for {fn_name} in {parsed.file} "
                "(tree-sitter grammar missing or function not found by "
                "the builder)"
            ),
        )

    source_node, source_symbols = _resolve_source_cpp(
        cfg, fn_start, parsed.source_lineno,
    )
    if source_node is None:
        return ResolutionFailure(
            reason=(
                f"no source statement at line {parsed.source_lineno} in "
                f"{fn_name}"
            ),
        )

    sink_node, sink_arg = _resolve_sink_cpp(
        cfg, parsed.sink_lineno, parsed.sink_arg_hint,
    )
    if sink_node is None:
        return ResolutionFailure(
            reason=(
                f"no sink call at line {parsed.sink_lineno} in {fn_name}"
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
        enclosing_function=fn_name,
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


# ---------------------------------------------------------------------------
# C / C++ resolution (Phase 11)
# ---------------------------------------------------------------------------


def _find_enclosing_function_cpp(
    source_text: str, language: str, source_line: int, sink_line: int,
) -> Tuple[Optional[str], int]:
    """Smallest C / C++ function_definition spanning [source, sink].

    Returns ``(function_name, header_line)`` on success, ``(None, 0)``
    on any failure (missing grammar, no spanning definition, function
    has no resolvable name). ``header_line`` is the function's
    start_point line (1-indexed) — the value Phase 11's
    :func:`_resolve_source_cpp` compares against to spot the
    "source == function entry" case.

    Smallest by end-line span so nested helpers / lambdas win over
    their enclosing function when both contain the range.
    """
    # Lazy-import the parser via the cfg_builder_cpp module's helper
    # — keeps the import surface minimal and reuses the same
    # cached parser. Identical to the Phase 9 walker's grammar
    # plumbing.
    from core.inventory.cfg_builder_cpp import (
        _function_name as _cpp_function_name,
        _get_parser as _cpp_get_parser,
    )

    parser = _cpp_get_parser(language)
    if parser is None:
        return None, 0
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    lo = min(source_line, sink_line)
    hi = max(source_line, sink_line)
    best: Optional[Tuple[int, str, int]] = None   # (span, name, header_line)
    stack = [tree.root_node]
    while stack:
        cur = stack.pop()
        if cur.type == "function_definition":
            start = cur.start_point[0] + 1
            end = cur.end_point[0] + 1
            if start <= lo and hi <= end:
                name = _cpp_function_name(cur)
                if name is not None:
                    span = end - start
                    if best is None or span < best[0]:
                        best = (span, name, start)
        for child in cur.children:
            if child.is_named:
                stack.append(child)
    if best is None:
        return None, 0
    return best[1], best[2]


def _resolve_source_cpp(
    cfg: CPPCFG, fn_start_line: int, source_line: int,
) -> Tuple[Optional[CPPCFGNode], FrozenSet[str]]:
    """C / C++ analog of :func:`_resolve_source`.

    * ``source_line == fn_start_line`` → the source is the function
      entry; tainted symbols are the parameters.
    * Otherwise, locate the statement-level CFG node at ``source_line``
      and return its ``defs`` (or fall back to ``uses`` when the line
      is an expression-statement with no LHS).
    """
    if source_line == fn_start_line:
        return cfg.entry_node, frozenset(cfg.params)
    node = _cpp_node_at_lineno(cfg, source_line)
    if node is None:
        return None, frozenset()
    symbols = node.defs if node.defs else node.uses
    return node, symbols


def _resolve_sink_cpp(
    cfg: CPPCFG, sink_line: int, sink_arg_hint: Optional[str],
) -> Tuple[Optional[CPPCFGNode], str]:
    """C / C++ analog of :func:`_resolve_sink`. Same algorithm:
    locate the CFG node at ``sink_line``, consult its ``call_sites``,
    pick the hint match or fall back to the outermost call's first
    bare-name argument (lexicographic for determinism)."""
    node = _cpp_node_at_lineno(cfg, sink_line)
    if node is None or not node.call_sites:
        return None, ""
    if sink_arg_hint:
        for cs in node.call_sites:
            if sink_arg_hint in cs.arg_names:
                return node, sink_arg_hint
    outermost = node.call_sites[-1]
    if not outermost.arg_names:
        return None, ""
    return node, sorted(outermost.arg_names)[0]


def _cpp_node_at_lineno(cfg: CPPCFG, lineno: int) -> Optional[CPPCFGNode]:
    for n in cfg.nodes():
        if not isinstance(n, CPPCFGNode):
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
