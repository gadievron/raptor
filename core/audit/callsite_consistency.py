"""Detect call-site deviations via Engler-style statistical inference.

If a function's return value is captured at most call sites but discarded
at a few, the discarding sites are likely bugs — missing error checks,
ignored validation results, swallowed status codes.

Intellectual ancestor: Engler et al., "Bugs as Deviant Behavior" (2001).
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Sequence

from .prompt_defence import sanitise_for_prompt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tree-sitter availability
# ---------------------------------------------------------------------------

try:
    from .condition_extraction import _get_parser, language_for_file
    from .ts_extract import (
        _CALL_TYPES,
        _find_enclosing_function,
        _get_func_name,
        _node_line,
        _node_text,
        _walk_descendants,
    )
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

MIN_CALL_SITES = 3
MAJORITY_THRESHOLD = 0.75

_SECURITY_CALLEE_RE = re.compile(
    r"\b(?:valid|verif|check|auth|saniti|pars|escap|encod|decod|"
    r"connect|open|clos|lock|unlock|init|clean|free|dealloc|"
    r"login|permit|sign|hash|crypt|token|certif|handshake|"
    r"resolv|bind|listen|accept|recv|send|write|read|exec|eval|"
    r"compil|load|fetch|query|prepar|marshal|unmarshal|deseriali)",
    re.IGNORECASE,
)

_STRING_OR_BLOCK_COMMENT_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'"
    r"|/\*.*?\*/",
    re.DOTALL,
)


def _strip_block_comments(source: str) -> str:
    def _repl(m: re.Match) -> str:
        if m.group().startswith("/*"):
            return ""
        return m.group()
    return _STRING_OR_BLOCK_COMMENT_RE.sub(_repl, source)


_KEYWORDS = frozenset({
    "if", "else", "elif", "while", "for", "switch", "case", "catch",
    "return", "yield", "raise", "throw", "new", "delete", "sizeof",
    "typeof", "instanceof", "assert", "print", "println",
    "import", "from", "class", "struct", "enum", "interface",
    "try", "except", "finally", "with", "as", "in", "range",
    "func", "function", "def", "fn", "pub", "private", "protected",
    "var", "let", "const", "auto", "static", "extern", "volatile",
    "int", "char", "void", "bool", "float", "double", "long",
    "string", "byte", "uint", "int32", "int64", "uint32", "uint64",
    "package", "type", "go", "defer", "select",
    "not", "and", "or", "is", "None", "True", "False",
    "null", "nil", "undefined", "true", "false",
})


@dataclass
class CallSite:
    """A single call site in the codebase."""

    file: str
    line: int
    callee: str
    enclosing_function: str
    discarded: bool


@dataclass
class CallSiteDeviation:
    """A call site that deviates from the majority pattern."""

    callee: str
    file: str
    line: int
    enclosing_function: str
    total_sites: int
    captured_count: int
    discarded_count: int
    security_relevant: bool = False

    def __post_init__(self) -> None:
        if not self.security_relevant:
            self.security_relevant = bool(_SECURITY_CALLEE_RE.search(self.callee))

    @property
    def confidence(self) -> float:
        majority = max(self.captured_count, self.discarded_count)
        return majority / self.total_sites if self.total_sites else 0.0

    def to_dict(self) -> dict:
        return {
            "callee": self.callee,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "total_sites": self.total_sites,
            "captured_count": self.captured_count,
            "discarded_count": self.discarded_count,
            "confidence": round(self.confidence, 2),
            "security_relevant": self.security_relevant,
        }


# ---------------------------------------------------------------------------
# Tree-sitter extraction
# ---------------------------------------------------------------------------

def _callee_name_ts(call_node, lang: str, src: bytes) -> Optional[str]:
    """Extract the function/method name from a call node."""
    func = call_node.child_by_field_name("function")
    if func is None:
        func = call_node.child_by_field_name("name")
    if func is None:
        if call_node.children:
            func = call_node.children[0]
        else:
            return None

    if func.type in ("identifier", "name"):
        return _node_text(func, src)

    if func.type in ("member_expression", "attribute",
                      "field_expression", "selector_expression"):
        for child in reversed(func.children):
            if child.type in ("identifier", "property_identifier",
                              "field_identifier"):
                return _node_text(child, src)

    if func.type == "scoped_identifier":
        name_node = func.child_by_field_name("name")
        if name_node:
            return _node_text(name_node, src)

    text = _node_text(func, src)
    if "." in text:
        return text.rsplit(".", 1)[-1]
    return text


def _is_discarded_ts(call_node) -> bool:
    """Check if a call's return value is discarded."""
    node = call_node
    while node.parent:
        parent = node.parent
        ptype = parent.type

        if ptype == "expression_statement":
            return True

        if ptype in ("expression_list", "parenthesized_expression"):
            node = parent
            continue

        return False
    return False


def _parse_file(source: str, ext: str):
    """Parse source with tree-sitter, return (tree, lang) or (None, None)."""
    if not _TS_AVAILABLE:
        return None, None
    lang = language_for_file("x" + ext)
    if not lang:
        return None, None
    parser = _get_parser(lang)
    if not parser:
        return None, None
    src_bytes = source.encode("utf-8", errors="replace")
    tree = parser.parse(src_bytes)
    return tree, lang


def _extract_callsites_ts(
    file_path: str, source: str,
) -> Optional[List[CallSite]]:
    """Extract call sites via tree-sitter. Returns None if unavailable."""
    ext = PurePosixPath(file_path).suffix
    tree, lang = _parse_file(source, ext)
    if tree is None or lang is None:
        return None

    call_types = _CALL_TYPES.get(lang, ())
    if not call_types:
        return None

    src = source.encode("utf-8", errors="replace")
    sites: List[CallSite] = []

    for node in _walk_descendants(tree.root_node):
        if node.type not in call_types:
            continue

        callee = _callee_name_ts(node, lang, src)
        if not callee or callee in _KEYWORDS:
            continue
        if len(callee) < 2:
            continue

        enclosing = _find_enclosing_function(node, lang)
        func_name = _get_func_name(enclosing, lang, src) if enclosing else "<module>"

        sites.append(CallSite(
            file=file_path,
            line=_node_line(node),
            callee=callee,
            enclosing_function=func_name,
            discarded=_is_discarded_ts(node),
        ))

    return sites


# ---------------------------------------------------------------------------
# Regex fallback
# ---------------------------------------------------------------------------

_FUNC_HEADER_RE = re.compile(
    r"\s*(?:"
    r"(?:def|func|function|fn)\s+"
    r"(?:\([^)]*\)\s+)?"
    r"(\w+)"
    r"|(?:public|private|protected|static|async|export|default)\s+"
    r".*?(\w+)\s*\("
    r")",
)

_CALL_IN_LINE_RE = re.compile(
    r"(\w+(?:\.\w+)*)\s*\(",
)

_ASSIGN_LINE_RE = re.compile(
    r"^\s*(?:(?:const|let|var|auto|int|char|void|bool|string|float|double|"
    r"long|unsigned|size_t|ssize_t|[\w:*&]+)\s+)?"
    r"\w+\s*(?::=|=[^=])"
)

_RETURN_LINE_RE = re.compile(r"^\s*(?:return|yield)\s+")

_COND_LINE_RE = re.compile(
    r"^\s*(?:if|while|elif|else\s+if|assert)\s*[\s(]"
)

_STMT_ONLY_LINE_RE = re.compile(
    r"^\s*(\w+(?:\.\w+)*)\s*\(",
)


def _extract_callsites_regex(
    file_path: str, source: str,
) -> List[CallSite]:
    """Regex fallback for call site extraction."""
    sites: List[CallSite] = []
    lines = source.splitlines()
    current_func = "<module>"

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1

        fm = _FUNC_HEADER_RE.match(line)
        if fm:
            current_func = fm.group(1) or fm.group(2) or current_func
            continue

        stripped = line.lstrip()
        # Determine if this line captures or discards return values
        is_assign = bool(_ASSIGN_LINE_RE.match(stripped))
        is_return = bool(_RETURN_LINE_RE.match(stripped))
        is_cond = bool(_COND_LINE_RE.match(stripped))
        is_stmt_only = bool(_STMT_ONLY_LINE_RE.match(line))

        for m in _CALL_IN_LINE_RE.finditer(line):
            callee_full = m.group(1)
            callee = callee_full.rsplit(".", 1)[-1] if "." in callee_full else callee_full
            if callee in _KEYWORDS or len(callee) < 2:
                continue

            if is_assign or is_return or is_cond:
                discarded = False
            elif is_stmt_only:
                discarded = True
            else:
                discarded = False

            sites.append(CallSite(
                file=file_path,
                line=lineno,
                callee=callee,
                enclosing_function=current_func,
                discarded=discarded,
            ))

    return sites


# ---------------------------------------------------------------------------
# Statistical analysis
# ---------------------------------------------------------------------------

def _find_deviations(
    sites: List[CallSite],
    min_sites: int = MIN_CALL_SITES,
    threshold: float = MAJORITY_THRESHOLD,
) -> List[CallSiteDeviation]:
    """Find call sites that deviate from the majority pattern."""
    by_callee: Dict[str, List[CallSite]] = defaultdict(list)
    for site in sites:
        by_callee[site.callee].append(site)

    deviations: List[CallSiteDeviation] = []

    for callee, callee_sites in sorted(by_callee.items()):
        if len(callee_sites) < min_sites:
            continue

        captured = [s for s in callee_sites if not s.discarded]
        discarded = [s for s in callee_sites if s.discarded]
        total = len(callee_sites)

        if not discarded or not captured:
            continue

        captured_ratio = len(captured) / total
        discarded_ratio = len(discarded) / total

        if captured_ratio >= threshold:
            for site in discarded:
                deviations.append(CallSiteDeviation(
                    callee=callee,
                    file=site.file,
                    line=site.line,
                    enclosing_function=site.enclosing_function,
                    total_sites=total,
                    captured_count=len(captured),
                    discarded_count=len(discarded),
                ))
        elif discarded_ratio >= threshold:
            for site in captured:
                deviations.append(CallSiteDeviation(
                    callee=callee,
                    file=site.file,
                    line=site.line,
                    enclosing_function=site.enclosing_function,
                    total_sites=total,
                    captured_count=len(captured),
                    discarded_count=len(discarded),
                ))

    return deviations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CPG_CALLEE_CAP = 100
_CPG_BATCH_SIZE = 25


def _extract_callsites_cpg(
    joern_server,
    callee_names: frozenset[str],
) -> List[CallSite]:
    """Query Joern CPG for cross-file callsite data.

    Batches callees into groups to avoid per-callee query overhead that
    can deadlock the JVM under sustained load.  Caps at _CPG_CALLEE_CAP
    callees (prioritised by name length as a proxy for specificity).
    """
    from .cross_function_verify import _safe_name, _run_query

    safe_callees = []
    for callee in callee_names:
        safe = _safe_name(callee)
        if safe is not None:
            safe_callees.append((callee, safe))

    if not safe_callees:
        return []

    safe_callees.sort(key=lambda t: -len(t[0]))
    if len(safe_callees) > _CPG_CALLEE_CAP:
        logger.debug(
            "callsite_consistency: capping CPG callees %d → %d",
            len(safe_callees), _CPG_CALLEE_CAP,
        )
        safe_callees = safe_callees[:_CPG_CALLEE_CAP]

    sites: List[CallSite] = []
    for batch_start in range(0, len(safe_callees), _CPG_BATCH_SIZE):
        batch = safe_callees[batch_start:batch_start + _CPG_BATCH_SIZE]
        names_scala = ", ".join(f'"{s}"' for _, s in batch)
        name_to_orig = {s: orig for orig, s in batch}

        query = (
            f"val targets = List({names_scala})\n"
            f"cpg.call.filter(c => targets.contains(c.name)).map {{ call =>\n"
            f"  val enc = call.method.name\n"
            f"  val fname = call.file.name.headOption.getOrElse(\"\")\n"
            f"  val ln = call.lineNumber.getOrElse(0)\n"
            f"  val disc = !call.inAst.isControlStructure.nonEmpty "
            f"&& !call.inAst.isReturn.nonEmpty"
            f" && !call.inAst.isCall.name(\"<operator>.assignment.*\").nonEmpty\n"
            f"  val callee = call.name\n"
            f"  (callee, enc, fname, ln, disc)\n"
            f"}}.l"
        )

        raw = _run_query(joern_server, query)
        if not raw:
            continue

        for item in raw:
            if not isinstance(item, (list, tuple)) or len(item) < 5:
                continue
            callee_name = str(item[0])
            orig = name_to_orig.get(callee_name, callee_name)
            sites.append(CallSite(
                file=str(item[2]),
                line=int(item[3]),
                callee=orig,
                enclosing_function=str(item[1]),
                discarded=str(item[4]).lower() == "true",
            ))

    return sites


def detect_callsite_deviations(
    source_texts: Dict[str, str],
    *,
    min_sites: int = MIN_CALL_SITES,
    threshold: float = MAJORITY_THRESHOLD,
    extra_security_names: Optional[frozenset] = None,
    joern_server=None,
) -> List[CallSiteDeviation]:
    """Detect call sites that deviate from the majority return-value handling.

    *extra_security_names*: additional callee names considered
    security-relevant (e.g. from IRIS spec store).

    When *joern_server* is provided, CPG queries supplement the
    source_texts-based extraction with cross-file callsites from the
    entire indexed codebase.

    Returns deviations sorted by (security_relevant desc, confidence desc).
    """
    all_sites: List[CallSite] = []

    for file_path, source in source_texts.items():
        ts_sites = _extract_callsites_ts(file_path, source)
        if ts_sites is not None:
            all_sites.extend(ts_sites)
        else:
            cleaned = _strip_block_comments(source) if "/*" in source else source
            all_sites.extend(_extract_callsites_regex(file_path, cleaned))

    if joern_server is not None and all_sites:
        seen_callees = frozenset({s.callee for s in all_sites})
        seen_keys = {(s.file, s.line, s.callee) for s in all_sites}
        try:
            cpg_sites = _extract_callsites_cpg(joern_server, seen_callees)
            for cs in cpg_sites:
                key = (cs.file, cs.line, cs.callee)
                if key not in seen_keys:
                    all_sites.append(cs)
                    seen_keys.add(key)
            if cpg_sites:
                logger.debug(
                    "callsite_consistency: CPG added %d cross-file sites",
                    len(cpg_sites),
                )
        except Exception:
            logger.debug(
                "callsite_consistency: CPG enhancement failed",
                exc_info=True,
            )

    deviations = _find_deviations(all_sites, min_sites, threshold)
    extra = extra_security_names or frozenset()
    for d in deviations:
        if d.callee in extra:
            d.security_relevant = True
    deviations.sort(key=lambda d: (not d.security_relevant, -d.confidence, d.file, d.line))
    return deviations


def format_callsite_deviations_for_prompt(
    deviations: Sequence[CallSiteDeviation],
) -> str:
    """Format deviations for injection into the LLM review prompt."""
    if not deviations:
        return ""

    parts = ["### Return-value handling deviations\n"]
    for d in deviations:
        safe_callee = sanitise_for_prompt(d.callee, content_type="name")
        safe_file = sanitise_for_prompt(d.file, content_type="path")
        safe_enclosing = sanitise_for_prompt(d.enclosing_function, content_type="name")
        majority = "captured" if d.captured_count > d.discarded_count else "discarded"
        minority = "discarded" if majority == "captured" else "captured"
        ratio = d.captured_count if majority == "captured" else d.discarded_count
        parts.append(
            f"- `{safe_callee}()` return value {minority} at "
            f"{safe_file}:{d.line} (in `{safe_enclosing}`), "
            f"but {majority} at {ratio}/{d.total_sites} other sites"
        )
        if minority == "discarded":
            parts.append(
                f"  → CHECK: Is the return value of `{safe_callee}()` "
                f"meaningful here? If callers typically check it, this "
                f"may be a missing error/validation check."
            )
    return "\n".join(parts)
