"""Finding-normalisation adapter — Phase 5 of the value-binding arc.

Bridges static-analyser output formats (SARIF / Semgrep /
RAPTOR-native) to the inputs Phase 4's
:func:`core.analysis.sanitizer_cut.evaluate_finding` needs.

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
* **C / C++ intra-procedural** — full end-to-end via Phase 9's
  :func:`build_cpp_intraproc_cfg`, wired through here in Phase 11.
* **Java intra-procedural** — tree-sitter CFG with import-resolved
  callable names; methods containing constructs the builder can't
  model faithfully are refused (whole-build ``ResolutionFailure``).
* **Other languages** — return ``ResolutionFailure`` with
  ``reason="language=… not yet supported"``; they await future
  arcs.

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
    TYPE_CHECKING,
    Any,
    Union,
)
from collections.abc import Mapping

from core.analysis.cfg_builder import (
    PyCFGNode,
    PythonCFG,
    build_python_cfg,
)
from core.analysis.cfg_builder_cpp import (
    CPPCFG,
    CPPCFGNode,
    build_cpp_intraproc_cfg,
)

if TYPE_CHECKING:                                       # pragma: no cover
    from core.analysis.cfg_builder_java import JavaCFG


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
    branch). Both satisfy :class:`core.analysis.dominators.Graph`
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
    source_symbols: frozenset[str]
    sink_lineno: int
    sink_arg: str
    cwe: str
    language: str
    cfg: PythonCFG | CPPCFG | JavaCFG
    source_node: Any
    sink_node: Any
    inter_proc_bindings: frozenset = frozenset()


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
    sink_lineno: int
    sink_arg_hint: str | None = None


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
) -> _ParsedFinding | ResolutionFailure:
    if "ruleId" in finding and "codeFlows" in finding:
        return _parse_sarif(finding)
    if "check_id" in finding and "extra" in finding:
        return _parse_semgrep(finding)
    if all(
        k in finding for k in ("cwe", "file_path", "source_line", "sink_line")
    ):
        return _parse_raptor_native(finding)
    return ResolutionFailure(reason="unknown input format")


def _parse_sarif(finding: Mapping[str, Any]) -> _ParsedFinding | ResolutionFailure:
    rule_tags = (finding.get("properties") or {}).get("tags") or []
    cwe = ""
    from core.cve.cwe import format_cwe
    for tag in rule_tags:
        m = _CWE_TAG_RE.search(str(tag))
        if m:
            cwe = format_cwe(m.group(1)) or ""
            if cwe:
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
    src_region = src_phys.get("region") or {}
    sink_region = sink_phys.get("region") or {}
    file = (
        (src_phys.get("artifactLocation") or {}).get("uri", "")
        or (sink_phys.get("artifactLocation") or {}).get("uri", "")
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
        sink_lineno=sink_line,
    )


def _sarif_physical_location(loc_entry: Mapping[str, Any]) -> Mapping[str, Any]:
    """SARIF threadFlow locations wrap ``physicalLocation`` inside
    either a top-level ``location`` field or directly."""
    inner = loc_entry.get("location", loc_entry)
    return inner.get("physicalLocation") or {}


def _parse_semgrep(
    finding: Mapping[str, Any],
) -> _ParsedFinding | ResolutionFailure:
    extra = finding.get("extra") or {}
    cwes = (extra.get("metadata") or {}).get("cwe") or []
    cwe = ""
    if isinstance(cwes, str):
        cwes = [cwes]
    from core.cve.cwe import format_cwe
    for entry in cwes:
        m = _CWE_SEMGREP_RE.search(str(entry))
        if m:
            cwe = format_cwe(m.group(1)) or ""
            if cwe:
                break
    if not cwe:
        return ResolutionFailure(
            reason="semgrep: no CWE in extra.metadata.cwe",
        )

    file = finding.get("path", "")
    if not file:
        return ResolutionFailure(reason="semgrep: no path")

    trace = extra.get("dataflow_trace") or {}
    src_line = _semgrep_extract_line(trace.get("taint_source"))
    if src_line is None:
        src_line = (finding.get("start") or {}).get("line") or None
    sink_line = _semgrep_extract_line(trace.get("taint_sink"))
    if sink_line is None:
        sink_line = (finding.get("end") or {}).get("line") or (
            finding.get("start") or {}
        ).get("line") or None

    if src_line is None or sink_line is None:
        return ResolutionFailure(
            reason="semgrep: missing source or sink line",
        )

    return _ParsedFinding(
        file=file,
        cwe=cwe,
        language=_detect_language(file),
        source_lineno=src_line,
        sink_lineno=sink_line,
    )


def _semgrep_extract_line(trace: Any) -> int | None:
    """Semgrep's ``taint_source`` / ``taint_sink`` can be a dict
    with a single location or a list with the chain. Pull the
    first ``location.start.line`` we find."""
    if trace is None:
        return None
    if isinstance(trace, dict):
        loc = trace.get("location", {})
        line = loc.get("start", {}).get("line")
        if line is not None:
            return line
        # Some semgrep shapes have the line at the top of the trace
        start = trace.get("start", {})
        line = start.get("line") if isinstance(start, dict) else None
        if line is not None:
            return line
    if isinstance(trace, list) and trace:
        return _semgrep_extract_line(trace[0])
    return None


def _parse_raptor_native(
    finding: Mapping[str, Any],
) -> _ParsedFinding | ResolutionFailure:
    file = finding["file_path"]
    return _ParsedFinding(
        file=file,
        cwe=finding["cwe"],
        language=finding.get("language") or _detect_language(file),
        source_lineno=finding["source_line"],
        sink_lineno=finding["sink_line"],
        sink_arg_hint=finding.get("sink_arg"),
    )


def _detect_language(file_path: str) -> str:
    p = file_path.lower()
    if p.endswith(".py"):
        return "python"
    if p.endswith(".java"):
        return "java"
    if p.endswith((".jsx", ".js")):
        return "javascript"
    if p.endswith((".tsx", ".ts")):
        return "typescript"
    if p.endswith((".c", ".h")):
        return "c"
    if p.endswith((".cpp", ".cc", ".hpp", ".hh", ".cxx")):
        return "cpp"
    return "unknown"


# ---------------------------------------------------------------------------
# AST resolution
# ---------------------------------------------------------------------------


def _read_finding_source(file: str) -> str | ResolutionFailure:
    """Containment-checked read of the source file named by a finding.

    The path comes verbatim from externally-produced analyser output
    (SARIF ``artifactLocation.uri``, Semgrep ``path``, native
    ``file_path``), so it is untrusted: a ``..`` segment would let a
    crafted record walk the resolver out of the scanned tree and read
    an arbitrary file (same defense as
    ``core.annotations.storage``). Absolute paths stay allowed —
    RAPTOR-native findings legitimately carry absolute paths into the
    scanned repo.
    """
    try:
        parts = Path(file).parts
    except (TypeError, ValueError):
        return ResolutionFailure(reason=f"malformed file path: {file!r}")
    if any(part == ".." for part in parts):
        return ResolutionFailure(
            reason=f"refusing file path with '..' segment: {file!r}",
        )
    try:
        return Path(file).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return ResolutionFailure(reason=f"cannot read {file}: {e}")


def _resolve_from_parsed(parsed: _ParsedFinding) -> Resolution:
    if parsed.language == "python":
        return _resolve_from_parsed_python(parsed)
    if parsed.language in ("c", "cpp"):
        return _resolve_from_parsed_cpp(parsed)
    if parsed.language == "java":
        return _resolve_from_parsed_java(parsed)
    return ResolutionFailure(
        reason=(
            f"language={parsed.language!r} not yet supported — "
            "python is shipped (phases 1-7), c/c++ wired in phase 11, "
            "java in the b13 leg; other languages await future arcs"
        ),
    )


def _resolve_from_parsed_python(parsed: _ParsedFinding) -> Resolution:
    source_text = _read_finding_source(parsed.file)
    if isinstance(source_text, ResolutionFailure):
        return source_text
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
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    cfg: PythonCFG,
    cwe: str,
) -> frozenset:
    """Phase 14 — compute inter-procedural synthetic sanitizer
    bindings for a Python finding's enclosing function.

    Builds the module-local call graph + taint summaries from the
    same source text, then asks
    :func:`core.analysis.interproc.synthetic_sanitizer_bindings`
    for bindings at call sites where an in-module helper cleanly
    sanitizes. Returns an empty frozenset on any failure (best-effort
    — the intra-procedural verdict still stands). Imports are local
    so the Phase 12-14 modules aren't loaded for callers that never
    resolve a Python finding."""
    try:
        from core.analysis.python_module_callgraph import (
            build_python_module_callgraph,
        )
        from core.analysis.interproc import (
            synthetic_sanitizer_bindings,
        )
        from core.analysis.taint_summaries import (
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
    source_text = _read_finding_source(parsed.file)
    if isinstance(source_text, ResolutionFailure):
        return source_text

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
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Smallest FunctionDef containing both source and sink lines.

    "Smallest" by end-line span so a nested helper wins over its
    enclosing function when both contain the lines.
    """
    candidates: list[
        tuple[int, ast.FunctionDef | ast.AsyncFunctionDef]
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
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> int:
    end = fn.lineno
    for child in ast.walk(fn):
        ln = getattr(child, "end_lineno", None) or getattr(child, "lineno", 0)
        if ln and ln > end:
            end = ln
    return end


def _resolve_source(
    cfg: PythonCFG,
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    source_line: int,
) -> tuple[PyCFGNode | None, frozenset[str]]:
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
    symbols = node.defs or node.uses
    return node, symbols


def _forward_assignment_sink_java(cfg, node):
    """Forward an assignment-located java sink to its consuming call.

    Applies only when the flagged node defines exactly one name and
    carries no call of its own. The first later call taking that name
    as a (deep) argument becomes the sink — but only when the flagged
    assignment is the SOLE reaching definer of the name at that call:
    any intervening or branch-merged redefinition breaks the value
    identity the finding flagged, so the first failing candidate
    refuses outright (a later consumer is strictly worse). Returns
    ``(None, "")`` on any refusal.
    """
    from core.analysis.dataflow import reaching_defs as _rd

    if node is None or node.call_sites or len(node.defs) != 1:
        return None, ""
    name = next(iter(node.defs))
    rd = _rd(cfg)
    candidates = sorted(
        (
            n for n in cfg.nodes()
            if getattr(n, "lineno", 0) > node.lineno
            and any(
                name in cs.arg_names
                or name in getattr(cs, "arg_deep_names", frozenset())
                for cs in getattr(n, "call_sites", ())
            )
        ),
        key=lambda n: n.lineno,
    )
    for cand in candidates:
        if rd.at(cand, name) == frozenset({node}):
            return cand, name
        return None, ""
    return None, ""


def _receiver_hop_sink_java(cfg, node):
    """Hop a zero-argument receiver call to its constructing call.

    ``statement.execute()`` carries the sink data in ``statement``'s
    construction. Requires: the outermost call has no (deep) arguments,
    the node uses exactly one name (the receiver), that name has
    exactly one reaching definer here, and the definer assigns the
    receiver from a call with exactly one bare-name argument (or a
    single deep name when no bare names exist). Anything else returns
    ``(None, "")`` — reassigned receivers, multi-use statements, and
    multi-argument constructors all break the single-value identity.
    """
    from core.analysis.dataflow import reaching_defs as _rd

    outermost = node.call_sites[-1]
    if outermost.arg_names or getattr(outermost, "arg_deep_names",
                                      frozenset()):
        return None, ""
    if len(node.uses) != 1:
        return None, ""
    receiver = next(iter(node.uses))
    definers = _rd(cfg).at(node, receiver)
    if len(definers) != 1:
        return None, ""
    definer = next(iter(definers))
    if definer is getattr(cfg, "entry_node", None):
        return None, ""
    for cs in getattr(definer, "call_sites", ()):
        if receiver not in cs.assigned_names:
            continue
        if len(cs.arg_names) == 1:
            return definer, next(iter(cs.arg_names))
        deep = getattr(cs, "arg_deep_names", frozenset())
        if not cs.arg_names and len(deep) == 1:
            return definer, next(iter(deep))
        return None, ""
    return None, ""


def _resolve_sink(
    cfg: PythonCFG,
    sink_line: int,
    sink_arg_hint: str | None,
) -> tuple[PyCFGNode | None, str]:
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
    if outermost.arg_names:
        return node, sorted(outermost.arg_names)[0]
    # Fallback: no bare-name argument, but the argument subtrees
    # reference exactly ONE variable (``print(bar.toCharArray())``,
    # ``println("x: " + bar)``) — the sink consumes that variable's
    # value, so binding sink_arg to it asks the gate exactly the
    # right exclusivity question. Two or more referenced names stay
    # a refusal: picking one would under-constrain the others.
    # Producers that don't populate arg_deep_names (python/c today)
    # keep the historical refusal.
    if len(outermost.arg_deep_names) == 1:
        return node, next(iter(outermost.arg_deep_names))
    return None, ""


def _node_at_lineno(cfg: PythonCFG, lineno: int) -> PyCFGNode | None:
    for n in cfg.nodes():
        if not isinstance(n, PyCFGNode):
            continue
        if n.lineno == lineno:
            return n
    return None


# ---------------------------------------------------------------------------
# Java resolution (b13 leg)
# ---------------------------------------------------------------------------


_JAVA_STMT_TYPES = frozenset({
    "local_variable_declaration",
    "expression_statement",
    "return_statement",
    "throw_statement",
})


def _java_statement_start_line(
    source_text: str, lineno: int,
) -> int | None:
    r"""Start line of the smallest Java STATEMENT spanning ``lineno``.

    Findings frequently flag a continuation line of a multi-line
    statement (``new java.io.FileWriter(\n    fileTarget, true);``
    flagged on the constructor line) — the CFG's statement node lives
    at the statement's start line, so an exact-line lookup lands on
    nothing. Returns ``None`` when the grammar is missing or no
    statement spans the line; returns the start line otherwise (which
    may equal ``lineno`` — the caller treats that as "no retarget").
    Only leaf statement kinds are considered: retargeting to a
    compound statement (if/try/block) would bind a different
    computation than the finding flagged.
    """
    from core.analysis.cfg_builder_java import _get_parser

    parser = _get_parser()
    if parser is None:
        return None
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    best: tuple[int, int] | None = None      # (span, start_line)
    stack = [tree.root_node]
    while stack:
        cur = stack.pop()
        start = cur.start_point[0] + 1
        end = cur.end_point[0] + 1
        if start > lineno or end < lineno:
            continue
        if cur.type in _JAVA_STMT_TYPES:
            span = end - start
            if best is None or span < best[0]:
                best = (span, start)
        stack.extend(c for c in cur.children if c.is_named)
    return best[1] if best is not None else None


def _pick_value_name(names, cfg) -> str:
    """Deterministic sink-arg pick from a multi-name argument surface.

    Prefers names that carry values in this CFG — parameters or names
    some node defines — over namespace-shaped leftovers the argument
    walkers cannot distinguish syntactically (``java`` from a
    ``java.util.Locale.US`` chain, unimported ``String`` receivers):
    binding those asks the gate a question about a name with no
    definitions, wasting the adjudication. Lexicographic within each
    preference class keeps the pick deterministic. Soundness is
    unchanged by the pick: every non-picked argument name is
    adjudicated by the gate's sibling guards regardless
    (``_sibling_args_tainted`` / ``_siblings_fold_or_refuse``), so the
    pick only selects which name gets the primary value question.
    """
    ranked = sorted(names)
    defined = set(getattr(cfg, "params", ()) or ())
    for n in cfg.nodes():
        defined |= set(getattr(n, "defs", ()) or ())
    carrying = [n for n in ranked if n in defined]
    return (carrying or ranked)[0]


def _resolve_from_parsed_java(parsed: _ParsedFinding) -> Resolution:
    """Java branch of the resolver.

    Uses the tree-sitter Java builder
    (:func:`core.analysis.cfg_builder_java.build_java_intraproc_cfg`)
    with the finding's line range as the overload disambiguator —
    Java methods share names across overloads, so name-only selection
    could build the wrong body. The builder REFUSES methods
    containing constructs it cannot model faithfully (lambdas,
    anonymous classes, switch, labeled jumps); refusal degrades to
    :class:`ResolutionFailure`, never a silently wrong graph.
    """
    from core.analysis.cfg_builder_java import (
        JavaCFGNode,
        build_java_intraproc_cfg,
        find_enclosing_method,
    )

    # Route through the ..-containment guard the Python (_resolve_from_
    # parsed_python) and C++ (_resolve_from_parsed_cpp) branches already
    # use; the Java branch previously read the untrusted finding path
    # directly, skipping the check (00092 residual).
    source_text = _read_finding_source(parsed.file)
    if isinstance(source_text, ResolutionFailure):
        return source_text

    fn_name, fn_start = find_enclosing_method(
        source_text, parsed.source_lineno, parsed.sink_lineno,
    )
    if fn_name is None:
        return ResolutionFailure(
            reason=(
                f"no enclosing Java method for source line "
                f"{parsed.source_lineno} / sink line {parsed.sink_lineno} "
                f"in {parsed.file} (tree-sitter grammar missing or no "
                "method declaration spans the range)"
            ),
        )

    cfg = build_java_intraproc_cfg(
        source_text, fn_name,
        line_hint=(parsed.source_lineno, parsed.sink_lineno),
    )
    if cfg is None:
        return ResolutionFailure(
            reason=(
                f"Java CFG construction refused for {fn_name} in "
                f"{parsed.file} (grammar missing, or the method contains "
                "a construct the builder refuses: lambda, method "
                "reference, anonymous/local class, switch, or labeled "
                "jump)"
            ),
        )

    def node_at(lineno: int) -> JavaCFGNode | None:
        for n in cfg.nodes():
            if isinstance(n, JavaCFGNode) and n.lineno == lineno:
                return n
        return None

    def node_at_or_statement_start(lineno: int) -> JavaCFGNode | None:
        """Exact-line node, retargeted to the enclosing statement's
        start line when the flagged line is a continuation line of a
        multi-line statement (exact node missing, or present but
        empty — the builder emits content-free nodes for some
        continuation lines). The retargeted node carries the whole
        statement's calls/defs, which is the computation the finding
        flagged."""
        node = node_at(lineno)
        if node is not None and (
                node.call_sites or node.defs or node.uses):
            return node
        start = _java_statement_start_line(source_text, lineno)
        if start is None or start == lineno:
            return node
        retargeted = node_at(start)
        if retargeted is not None and (
                retargeted.call_sites or retargeted.defs
                or retargeted.uses):
            return retargeted
        return node

    if parsed.source_lineno == fn_start:
        source_node, source_symbols = cfg.entry_node, frozenset(cfg.params)
    else:
        source_node = node_at_or_statement_start(parsed.source_lineno)
        if source_node is None:
            return ResolutionFailure(
                reason=(
                    f"no source statement at line {parsed.source_lineno} "
                    f"in {fn_name}"
                ),
            )
        source_symbols = source_node.defs or source_node.uses

    sink_node = node_at_or_statement_start(parsed.sink_lineno)
    if sink_node is None or not sink_node.call_sites:
        # Assignment-located finding (``sql = "..." + bar + "...";`` —
        # the concatenated-sql / assignment-shaped rule class): no call
        # exists on the flagged line, but the assigned value flows to a
        # later consuming call. Forward the sink to that call iff the
        # flagged assignment is provably the value the call receives
        # (sole reaching definer) — then the gate asks exactly the
        # exclusivity question the finding raised.
        fwd_node, fwd_arg = _forward_assignment_sink_java(cfg, sink_node)
        if fwd_node is None:
            return ResolutionFailure(
                reason=(
                    f"no sink call at line {parsed.sink_lineno} in {fn_name}"
                ),
            )
        sink_node, sink_arg = fwd_node, fwd_arg
        inter_proc = _inter_proc_bindings_java(
            source_text, cfg,
            (parsed.source_lineno, parsed.sink_lineno), parsed.cwe,
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
            inter_proc_bindings=inter_proc,
        )
    sink_arg = ""
    if parsed.sink_arg_hint:
        for cs in sink_node.call_sites:
            if parsed.sink_arg_hint in cs.arg_names:
                sink_arg = parsed.sink_arg_hint
                break
    if not sink_arg:
        outermost = sink_node.call_sites[-1]
        if outermost.arg_names:
            sink_arg = _pick_value_name(outermost.arg_names, cfg)
        elif outermost.arg_deep_names:
            # No bare-name argument, but the argument subtrees
            # reference variables (``print(bar.toCharArray())``,
            # ``exec(cmd + bar)``) — the sink consumes their values,
            # so binding sink_arg to one asks the gate the primary
            # value question, and EVERY other referenced name is
            # adjudicated by the gate's sibling-argument guards
            # (fold-or-refuse on the constant/whole-array paths,
            # taint-front plus per-path value conditions elsewhere) —
            # the same division of labor multi-bare-name calls have
            # always had. The historical two-or-more refusal predates
            # those guards.
            sink_arg = _pick_value_name(outermost.arg_deep_names, cfg)
    if not sink_arg:
        # Zero-argument sink call on a receiver (``statement.execute()``
        # — the prepared-statement execute shape): the sink data is the
        # receiver's construction. Hop through the single-use receiver
        # to its constructing call's single bare argument, provided the
        # construction is the receiver's sole reaching definer.
        hop_node, hop_arg = _receiver_hop_sink_java(cfg, sink_node)
        if hop_node is not None:
            sink_node, sink_arg = hop_node, hop_arg
    if not sink_arg:
        return ResolutionFailure(
            reason=(
                f"sink call at line {parsed.sink_lineno} has no bare-name "
                "argument; cannot resolve sink_arg"
            ),
        )

    inter_proc = _inter_proc_bindings_java(
        source_text, cfg,
        (parsed.source_lineno, parsed.sink_lineno), parsed.cwe,
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
        inter_proc_bindings=inter_proc,
    )


def _inter_proc_bindings_java(
    source_text: str,
    cfg: JavaCFG,
    line_hint: tuple[int, int],
    cwe: str,
) -> frozenset:
    """Java analog of :func:`_inter_proc_bindings_python` — one-level
    same-class wrapper summaries
    (:mod:`core.analysis.java_wrapper_summaries`) synthesised into
    bindings at qualifying call sites. Empty frozenset on any failure
    (best-effort — the intra-procedural verdict still stands)."""
    try:
        from core.analysis.java_wrapper_summaries import (
            synthetic_wrapper_bindings_java,
        )
        return synthetic_wrapper_bindings_java(
            cfg, source_text, line_hint, cwe, "java",
        )
    except Exception:                                       # noqa: BLE001
        return frozenset()


# ---------------------------------------------------------------------------
# C / C++ resolution (Phase 11)
# ---------------------------------------------------------------------------


def _find_enclosing_function_cpp(
    source_text: str, language: str, source_line: int, sink_line: int,
) -> tuple[str | None, int]:
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
    from core.analysis.cfg_builder_cpp import (
        _function_name as _cpp_function_name,
        _get_parser as _cpp_get_parser,
    )

    parser = _cpp_get_parser(language)
    if parser is None:
        return None, 0
    tree = parser.parse(source_text.encode("utf-8", errors="replace"))
    lo = min(source_line, sink_line)
    hi = max(source_line, sink_line)
    best: tuple[int, str, int] | None = None   # (span, name, header_line)
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
        stack.extend(child for child in cur.children if child.is_named)
    if best is None:
        return None, 0
    return best[1], best[2]


def _resolve_source_cpp(
    cfg: CPPCFG, fn_start_line: int, source_line: int,
) -> tuple[CPPCFGNode | None, frozenset[str]]:
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
    symbols = node.defs or node.uses
    return node, symbols


def _resolve_sink_cpp(
    cfg: CPPCFG, sink_line: int, sink_arg_hint: str | None,
) -> tuple[CPPCFGNode | None, str]:
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
    if outermost.arg_names:
        return node, sorted(outermost.arg_names)[0]
    # Fallback: no bare-name argument, but the argument subtrees
    # reference exactly ONE variable (``print(bar.toCharArray())``,
    # ``println("x: " + bar)``) — the sink consumes that variable's
    # value, so binding sink_arg to it asks the gate exactly the
    # right exclusivity question. Two or more referenced names stay
    # a refusal: picking one would under-constrain the others.
    # Producers that don't populate arg_deep_names (python/c today)
    # keep the historical refusal.
    if len(outermost.arg_deep_names) == 1:
        return node, next(iter(outermost.arg_deep_names))
    return None, ""


def _cpp_node_at_lineno(cfg: CPPCFG, lineno: int) -> CPPCFGNode | None:
    for n in cfg.nodes():
        if not isinstance(n, CPPCFGNode):
            continue
        if n.lineno == lineno:
            return n
    return None


__all__ = [
    "Resolution",
    "ResolutionFailure",
    "ResolvedFinding",
    "resolve_finding",
]
