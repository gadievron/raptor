"""Tree-sitter structural validation of claimed dataflow paths.

When CodeQL is unavailable, this module validates SARIF ``codeFlows``
paths (e.g. from Semgrep Pro) by checking that:

1. Each step location exists and is parseable.
2. Consecutive steps are linked by a call site in the AST.
3. Sanitizer/validator calls between source and sink are identified.
4. Branch guards enclosing each step are extracted as
   ``path_conditions`` for SMT Tier 4.

This is **structural** validation — it confirms the call chain
exists in source, not that tainted data actually flows through it.
Confidence is clearly lower than CodeQL IRIS.  The priority cascade
is hardwired: CodeQL IRIS > structural tree-sitter > LLM-only.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.inventory.call_graph import (
    FileCallGraph,
    extract_call_graph_c,
    extract_call_graph_cpp,
    extract_call_graph_go,
    extract_call_graph_java,
    extract_call_graph_javascript,
    extract_call_graph_python,
    extract_call_graph_ruby,
    extract_call_graph_rust,
)
from core.inventory.languages import detect_language

logger = logging.getLogger(__name__)

_EXTRACTORS = {
    "python": extract_call_graph_python,
    "javascript": extract_call_graph_javascript,
    "typescript": extract_call_graph_javascript,
    "tsx": extract_call_graph_javascript,
    "java": extract_call_graph_java,
    "go": extract_call_graph_go,
    "rust": extract_call_graph_rust,
    "ruby": extract_call_graph_ruby,
    "c": extract_call_graph_c,
    "cpp": extract_call_graph_cpp,
}

_SANITIZER_KEYWORDS = frozenset({
    "sanitiz", "sanitise", "escape", "encode", "validat",
    "filter", "clean", "purify", "strip", "bleach", "quote",
    "parameteriz", "prepared", "bind",
})

_CONDITION_NODE_TYPES = frozenset({
    "if_statement", "elif_clause", "else_clause",
    "switch_statement", "case_clause", "match_statement",
    "ternary_expression", "conditional_expression",
    "while_statement", "for_statement",
    "guard_statement", "if_expression",
})


@dataclass
class StepVerification:
    """Result of verifying one step in a dataflow path."""
    step_index: int
    file: str
    line: int
    function: Optional[str]
    exists: bool
    call_link_to_next: Optional[bool] = None
    has_indirection: bool = False
    sanitizer_calls: List[str] = field(default_factory=list)
    branch_guards: List[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "step_index": self.step_index,
            "file": self.file,
            "line": self.line,
            "exists": self.exists,
        }
        if self.function:
            d["function"] = self.function
        if self.call_link_to_next is not None:
            d["call_link_to_next"] = self.call_link_to_next
        if self.has_indirection:
            d["has_indirection"] = True
        if self.sanitizer_calls:
            d["sanitizer_calls"] = self.sanitizer_calls
        if self.branch_guards:
            d["branch_guards"] = self.branch_guards
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class StructuralResult:
    """Validation result matching the IRIS output shape."""
    verdict: str
    reasoning: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    sanitizers: List[str] = field(default_factory=list)
    path_conditions: List[Dict[str, Any]] = field(default_factory=list)
    confidence: str = "low"
    method: str = "structural-treesitter"

    @property
    def refuted(self) -> bool:
        return self.verdict == "refuted"

    @property
    def iterations(self) -> int:
        return 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "sanitizers": self.sanitizers,
            "path_conditions": self.path_conditions,
            "confidence": self.confidence,
            "method": self.method,
        }


def _resolve_file(step: Dict, repo_path: Path) -> Optional[Path]:
    """Resolve a step's file path against the repo root.

    Rejects paths that escape ``repo_path`` (traversal defense — step
    files originate from SARIF which is untrusted scanner output).
    """
    raw = step.get("file") or ""
    if not raw:
        return None
    if ".." in raw:
        return None
    p = Path(raw)
    if p.is_absolute():
        try:
            resolved = p.resolve()
            if not str(resolved).startswith(str(repo_path.resolve())):
                return None
        except (OSError, ValueError):
            return None
        if resolved.exists():
            return resolved
        return None
    candidate = (repo_path / p).resolve()
    if not str(candidate).startswith(str(repo_path.resolve())):
        return None
    if candidate.exists():
        return candidate
    return None


def _read_file_content(path: Path) -> Optional[str]:
    """Read file content, returning None on failure."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _extract_graph(content: str, language: str) -> Optional[FileCallGraph]:
    """Extract call graph for the given language."""
    extractor = _EXTRACTORS.get(language)
    if extractor is None:
        return None
    try:
        return extractor(content)
    except Exception:
        return None


def _find_enclosing_function(
    line: int,
    graph: FileCallGraph,
    content: str,
    language: str,
) -> Optional[str]:
    """Find the function name enclosing a given line number.

    Uses call sites' caller field as a hint, then falls back to
    function extraction.
    """
    callers_at = [c.caller for c in graph.calls
                  if c.caller and c.line == line]
    if callers_at:
        return callers_at[0]

    try:
        from core.inventory.extractors import extract_functions
        funcs = extract_functions("<structural-validator>", language, content)
        for f in funcs:
            if f.line_start <= line and (f.line_end is None or line <= f.line_end):
                return f.name
    except Exception:
        pass
    return None


def _check_call_link(
    from_func: Optional[str],
    to_func: Optional[str],
    graph: FileCallGraph,
    cross_file: bool = False,
) -> Tuple[Optional[bool], bool]:
    """Check if from_func calls to_func via the call graph.

    Returns (link_found, has_indirection).
    link_found: True=confirmed, False=refuted, None=inconclusive.
    """
    if not to_func:
        return None, False

    to_name = to_func.split(".")[-1]

    if from_func:
        calls_from_func = [
            c for c in graph.calls if c.caller == from_func
        ]
    else:
        calls_from_func = [c for c in graph.calls if c.caller is None]

    for call in calls_from_func:
        if not call.chain:
            continue
        if call.chain[-1] == to_name:
            return True, False
        if to_func in ".".join(call.chain):
            return True, False

    if cross_file:
        for alias, target in graph.imports.items():
            if to_name == alias or to_name in target:
                return True, False

    has_indirection = bool(graph.indirection)
    if has_indirection:
        return None, True

    if cross_file:
        return None, False

    return False, False


def _identify_sanitizer_calls(
    calls: list,
    label: str,
) -> List[str]:
    """Identify sanitizer/validator calls from call sites and labels."""
    found = []
    for call in calls:
        if not call.chain:
            continue
        name = call.chain[-1].lower()
        for kw in _SANITIZER_KEYWORDS:
            if kw in name:
                found.append(".".join(call.chain))
                break

    if label:
        label_lower = label.lower()
        for kw in _SANITIZER_KEYWORDS:
            if kw in label_lower:
                found.append(f"label:{label}")
                break

    return found


def _extract_branch_guards_from_content(
    content: str,
    line: int,
    language: str,
) -> List[str]:
    """Extract branch guard conditions enclosing the given line.

    Uses tree-sitter when available, falls back to regex for
    simple ``if (...)`` patterns.
    """
    guards = []
    lines = content.splitlines()
    if line < 1 or line > len(lines):
        return guards

    _if_re = re.compile(
        r'^\s*(?:if|elif|else\s+if|while|for)\s*[\(]?\s*(.+?)\s*[\)]?\s*[:{]?\s*$'
    )
    scan_start = max(0, line - 30)
    indent_at_line = len(lines[line - 1]) - len(lines[line - 1].lstrip()) if line <= len(lines) else 0

    for i in range(line - 2, scan_start - 1, -1):
        if i < 0:
            break
        src_line = lines[i]
        indent = len(src_line) - len(src_line.lstrip())
        if indent < indent_at_line:
            m = _if_re.match(src_line)
            if m:
                cond = m.group(1).strip()
                if cond and len(cond) < 200:
                    guards.append(cond)
            indent_at_line = indent

    return guards


def _build_all_steps(dataflow_path: Dict) -> List[Dict]:
    """Build the ordered step list from a dataflow_path dict."""
    source = dataflow_path.get("source")
    sink = dataflow_path.get("sink")
    intermediate = dataflow_path.get("steps") or []

    steps = []
    if source:
        steps.append(source)
    steps.extend(intermediate)
    if sink:
        steps.append(sink)
    return steps


def validate_structurally(
    dataflow_path: Dict[str, Any],
    repo_path: Path,
    *,
    language: Optional[str] = None,
) -> StructuralResult:
    """Validate a claimed dataflow path using tree-sitter structural analysis.

    Args:
        dataflow_path: Dict with ``source``, ``sink``, ``steps`` keys,
            each containing ``file``, ``line``, ``label``, ``snippet``.
        repo_path: Repository root for resolving relative paths.
        language: Override language detection (optional).

    Returns:
        StructuralResult with verdict, evidence, and path_conditions.
    """
    steps = _build_all_steps(dataflow_path)
    if len(steps) < 2:
        return StructuralResult(
            verdict="inconclusive",
            reasoning="Dataflow path has fewer than 2 steps",
            confidence="low",
        )

    verifications: List[StepVerification] = []
    all_sanitizers: List[str] = []
    all_conditions: List[Dict[str, Any]] = []
    file_cache: Dict[str, Tuple[Optional[str], Optional[str], Optional[FileCallGraph]]] = {}

    for i, step in enumerate(steps):
        file_path_str = step.get("file", "")
        line = step.get("line", 0) or 0
        label = step.get("label", "") or ""

        resolved = _resolve_file(step, repo_path)
        if resolved is None:
            verifications.append(StepVerification(
                step_index=i, file=file_path_str, line=line,
                function=None, exists=False,
                detail=f"File not found: {file_path_str}",
            ))
            continue

        cache_key = str(resolved)
        if cache_key not in file_cache:
            content = _read_file_content(resolved)
            lang = language or detect_language(str(resolved))
            graph = _extract_graph(content, lang) if content and lang else None
            file_cache[cache_key] = (content, lang, graph)
        content, lang, graph = file_cache[cache_key]

        if content is None:
            verifications.append(StepVerification(
                step_index=i, file=file_path_str, line=line,
                function=None, exists=False,
                detail="Could not read file",
            ))
            continue

        line_count = content.count("\n") + 1
        if line > line_count:
            verifications.append(StepVerification(
                step_index=i, file=file_path_str, line=line,
                function=None, exists=False,
                detail=f"Line {line} exceeds file length {line_count}",
            ))
            continue

        func_name = None
        if graph and lang:
            func_name = _find_enclosing_function(line, graph, content, lang)

        sanitizer_calls = []
        if graph:
            calls_in_range = [
                c for c in graph.calls
                if c.caller == func_name
            ]
            sanitizer_calls = _identify_sanitizer_calls(calls_in_range, label)
            all_sanitizers.extend(sanitizer_calls)

        guards: List[str] = []
        if lang and content:
            guards = _extract_branch_guards_from_content(content, line, lang)
            for g in guards:
                all_conditions.append({
                    "text": g,
                    "step_index": i,
                    "negated": False,
                })

        call_link: Optional[bool] = None
        has_indirection = False
        if i < len(steps) - 1:
            next_step = steps[i + 1]
            next_resolved = _resolve_file(next_step, repo_path)
            cross_file = next_resolved is not None and str(next_resolved) != cache_key

            next_func = None
            if next_resolved and str(next_resolved) in file_cache:
                next_content, next_lang, next_graph = file_cache[str(next_resolved)]
                next_line = next_step.get("line", 0) or 0
                if next_graph and next_lang and next_content:
                    next_func = _find_enclosing_function(
                        next_line, next_graph, next_content, next_lang,
                    )
            elif next_resolved:
                next_content = _read_file_content(next_resolved)
                next_lang = language or detect_language(str(next_resolved))
                next_graph = _extract_graph(next_content, next_lang) if next_content and next_lang else None
                file_cache[str(next_resolved)] = (next_content, next_lang, next_graph)
                next_line = next_step.get("line", 0) or 0
                if next_graph and next_lang and next_content:
                    next_func = _find_enclosing_function(
                        next_line, next_graph, next_content, next_lang,
                    )

            if graph:
                call_link, has_indirection = _check_call_link(
                    func_name, next_func, graph, cross_file=cross_file,
                )

        verifications.append(StepVerification(
            step_index=i, file=file_path_str, line=line,
            function=func_name, exists=True,
            call_link_to_next=call_link,
            has_indirection=has_indirection,
            sanitizer_calls=sanitizer_calls,
            branch_guards=guards,
        ))

    return _compute_verdict(verifications, all_sanitizers, all_conditions)


def _compute_verdict(
    verifications: List[StepVerification],
    sanitizers: List[str],
    path_conditions: List[Dict[str, Any]],
) -> StructuralResult:
    """Derive a verdict from step verifications."""
    if not verifications:
        return StructuralResult(
            verdict="inconclusive",
            reasoning="No steps to verify",
            confidence="low",
        )

    total = len(verifications)
    missing = [v for v in verifications if not v.exists]

    links = [v for v in verifications if v.call_link_to_next is not None]
    confirmed_links = [v for v in links if v.call_link_to_next is True]
    broken_links = [v for v in links if v.call_link_to_next is False]
    indirect_links = [v for v in verifications if v.has_indirection and v.call_link_to_next is None]

    evidence = [v.to_dict() for v in verifications]

    if len(missing) > total // 2:
        return StructuralResult(
            verdict="inconclusive",
            reasoning=f"{len(missing)}/{total} steps not found on disk",
            evidence=evidence,
            sanitizers=sanitizers,
            path_conditions=path_conditions,
            confidence="low",
        )

    if broken_links and not indirect_links:
        broken_descs = [
            f"step {v.step_index} ({v.function or '?'}) → step {v.step_index + 1}"
            for v in broken_links
        ]
        return StructuralResult(
            verdict="refuted",
            reasoning=(
                f"Call chain broken at {len(broken_links)} link(s): "
                + "; ".join(broken_descs)
            ),
            evidence=evidence,
            sanitizers=sanitizers,
            path_conditions=path_conditions,
            confidence="high" if not missing else "medium",
        )

    if confirmed_links and not broken_links and not missing:
        return StructuralResult(
            verdict="confirmed",
            reasoning=(
                f"All {len(confirmed_links)} call link(s) verified in AST"
                + (f"; {len(sanitizers)} sanitizer(s) identified" if sanitizers else "")
            ),
            evidence=evidence,
            sanitizers=sanitizers,
            path_conditions=path_conditions,
            confidence="high" if not indirect_links else "medium",
        )

    if confirmed_links and not broken_links:
        return StructuralResult(
            verdict="confirmed",
            reasoning=(
                f"{len(confirmed_links)}/{len(links)} call link(s) verified"
                + (f"; {len(indirect_links)} indirect" if indirect_links else "")
                + (f"; {len(missing)} step(s) not found" if missing else "")
            ),
            evidence=evidence,
            sanitizers=sanitizers,
            path_conditions=path_conditions,
            confidence="medium",
        )

    parts = []
    if confirmed_links:
        parts.append(f"{len(confirmed_links)} verified")
    if broken_links:
        parts.append(f"{len(broken_links)} broken")
    if indirect_links:
        parts.append(f"{len(indirect_links)} indirect")

    return StructuralResult(
        verdict="inconclusive",
        reasoning=f"Mixed call chain evidence: {', '.join(parts)}",
        evidence=evidence,
        sanitizers=sanitizers,
        path_conditions=path_conditions,
        confidence="low",
    )
