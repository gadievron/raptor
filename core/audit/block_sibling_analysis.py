"""Block-level sibling analysis within functions.

Applies the same asymmetry logic as cross-function sibling analysis
to branches within a function: switch cases, if/elif chains.  If
most branches validate input but one doesn't, the outlier is
flagged — the classic dispatch-table bug at block granularity.

Integration with block_review: when a function is complex enough
for block-level review, block sibling asymmetries are injected as
mechanical evidence alongside the per-block taint state.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .prompt_defence import sanitise_for_prompt
from .sibling_analysis import (
    SiblingGroup,
    SiblingPath,
    SiblingType,
    find_asymmetries,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tree-sitter availability
# ---------------------------------------------------------------------------

try:
    from .condition_extraction import _get_parser, language_for_file
    from .ts_extract import (
        _CASE_TYPES,
        _SWITCH_TYPES,
        _node_line,
        _node_text,
        _walk_descendants,
        _find_enclosing_function,
        _get_func_name,
    )
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Property extraction regexes
# ---------------------------------------------------------------------------

_VALIDATION_RE = re.compile(
    r"\b(?:validate|verify|check|assert|require|ensure|confirm|must"
    r"|is_valid|is_safe|is_allowed)\s*\(",
    re.IGNORECASE,
)

_SANITIZER_RE = re.compile(
    r"\b(?:sanitize|sanitise|escape|encode|clean|filter|purify"
    r"|strip_tags|scrub|bleach|defang|html_escape|markupsafe"
    r"|shlex\.quote|pipes\.quote|re\.escape)\s*\(",
    re.IGNORECASE,
)

_AUTH_RE = re.compile(
    r"\b(?:is_authenticated|is_authorized|check_auth|require_auth"
    r"|check_permission|has_permission|has_role|require_login"
    r"|login_required|auth_required|verify_token|check_token"
    r"|authenticate|authorize|verify_session|check_session)\b",
    re.IGNORECASE,
)

_ERROR_HANDLING_RE = re.compile(
    r"\b(?:raise|throw|panic|abort|exit"
    r"|return\s+(?:err|error|nil|null|None|false|False|-1))\b",
    re.IGNORECASE,
)

_LOGGING_RE = re.compile(
    r"\b(?:log\.|logger\.|logging\.|audit_log|record_event"
    r"|track_event|syslog|EventLog)\b",
    re.IGNORECASE,
)

MIN_BRANCHES = 3


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class BlockSiblingFinding:
    """A sibling asymmetry detected across branches within a function."""

    file: str
    function: str
    line: int
    branch_label: str
    property_name: str
    majority_count: int
    total_branches: int
    explanation: str
    severity: str = "medium"
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "branch_label": self.branch_label,
            "property_name": self.property_name,
            "majority_count": self.majority_count,
            "total_branches": self.total_branches,
            "explanation": self.explanation,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
        }


# ---------------------------------------------------------------------------
# Property extraction from branch text
# ---------------------------------------------------------------------------

def _extract_branch_properties(body_text: str) -> dict[str, Any]:
    """Extract security-relevant properties from a branch body."""
    return {
        "validates_input": bool(_VALIDATION_RE.search(body_text)),
        "sanitizes_input": bool(_SANITIZER_RE.search(body_text)),
        "checks_auth": bool(_AUTH_RE.search(body_text)),
        "handles_error": bool(_ERROR_HANDLING_RE.search(body_text)),
        "logs_action": bool(_LOGGING_RE.search(body_text)),
    }


def _truncate_label(text: str, max_len: int = 60) -> str:
    text = text.strip().replace("\n", " ")
    if len(text) > max_len:
        return text[:max_len - 3] + "..."
    return text


# ---------------------------------------------------------------------------
# Tree-sitter branch collection
# ---------------------------------------------------------------------------

def _collect_switch_branches(
    switch_node, lang: str, src: bytes,
) -> list[tuple[str, str, int]]:
    """Collect (label, body_text, line) for each case in a switch."""
    case_types = _CASE_TYPES.get(lang, ())
    if not case_types:
        return []

    branches: list[tuple[str, str, int]] = []
    for child in switch_node.children:
        if child.type not in case_types:
            continue

        body_text = _node_text(child, src)
        value = child.child_by_field_name("value")
        pattern = child.child_by_field_name("pattern")
        label_node = value or pattern
        if label_node:
            label = _truncate_label(_node_text(label_node, src))
        else:
            label = f"case@L{_node_line(child)}"
        branches.append((label, body_text, _node_line(child)))

    return branches


def _collect_if_branches(
    if_node, lang: str, src: bytes,
) -> list[tuple[str, str, int]]:
    """Collect (label, body_text, line) from an if/elif/else chain.

    Handles Python (elif_clause chain), C/JS (else_clause wrapping
    if_statement), and Go (alternative is if_statement directly).
    """
    branches: list[tuple[str, str, int]] = []
    _walk_if_chain(if_node, lang, src, branches, depth=0)
    return branches


def _walk_if_chain(node: Node, lang, src, out, depth) -> None:
    if depth > 20:
        return

    ntype = node.type

    if ntype in ("if_statement", "if_expression", "if",
                 "elif_clause", "elsif", "else_if_clause"):
        cond = node.child_by_field_name("condition")
        body = (node.child_by_field_name("consequence")
                or node.child_by_field_name("body"))
        if body:
            label = _truncate_label(_node_text(cond, src)) if cond else "if"
            out.append((label, _node_text(body, src), _node_line(node)))

        alt = node.child_by_field_name("alternative")
        if alt:
            _walk_if_chain(alt, lang, src, out, depth + 1)

        visited_alt_pos = (alt.start_byte, alt.end_byte) if alt else None
        for child in node.children:
            pos = (child.start_byte, child.end_byte)
            if visited_alt_pos and pos == visited_alt_pos:
                continue
            if child.type in ("elif_clause", "elsif", "else_if_clause",
                              "else_clause", "else"):
                _walk_if_chain(child, lang, src, out, depth + 1)
        return

    if ntype in ("else_clause", "else"):
        for child in node.children:
            if child.type in ("if_statement", "if_expression", "if"):
                _walk_if_chain(child, lang, src, out, depth + 1)
                return

        body = node.child_by_field_name("body")
        if body is None:
            for child in node.children:
                if child.type in ("block", "compound_statement",
                                  "statement_block"):
                    body = child
                    break
        if body:
            out.append(("else", _node_text(body, src), _node_line(node)))
        return

    if ntype in ("block", "compound_statement", "statement_block"):
        out.append(("else", _node_text(node, src), _node_line(node)))


def _collect_branches_ts(
    file_path: str, source: str,
) -> list[tuple[str, str, list[tuple[str, str, int]]]]:
    """Find all switch/if-chain branch groups in a file via tree-sitter.

    Returns list of (function_name, group_label, branches).
    """
    if not _TS_AVAILABLE:
        return []

    ext = PurePosixPath(file_path).suffix
    lang = language_for_file(ext)
    if not lang:
        return []
    parser = _get_parser(lang)
    if not parser:
        return []

    src = source.encode("utf-8", errors="replace")
    tree = parser.parse(src)

    switch_types = _SWITCH_TYPES.get(lang, ())
    if_types = ("if_statement", "if_expression", "if")

    groups: list[tuple[str, str, list[tuple[str, str, int]]]] = []
    visited_starts: set = set()

    for node in _walk_descendants(tree.root_node):
        if node.start_byte in visited_starts:
            continue

        if node.type in switch_types:
            branches = _collect_switch_branches(node, lang, src)
            if len(branches) >= MIN_BRANCHES:
                enclosing = _find_enclosing_function(node, lang)
                func = _get_func_name(enclosing, lang, src) if enclosing else "<module>"
                groups.append((
                    func,
                    f"switch@L{_node_line(node)}",
                    branches,
                ))
                visited_starts.add(node.start_byte)

        elif node.type in if_types:
            parent = node.parent
            if parent and parent.type in ("else_clause", "elif_clause",
                                          "elsif", "else_if_clause"):
                continue
            if parent and parent.type in if_types:
                continue

            branches = _collect_if_branches(node, lang, src)
            if len(branches) >= MIN_BRANCHES:
                enclosing = _find_enclosing_function(node, lang)
                func = _get_func_name(enclosing, lang, src) if enclosing else "<module>"
                groups.append((
                    func,
                    f"if-chain@L{_node_line(node)}",
                    branches,
                ))
                visited_starts.add(node.start_byte)

    return groups


# ---------------------------------------------------------------------------
# Regex fallback
# ---------------------------------------------------------------------------

_CASE_HEADER_RE = re.compile(
    r"^(\s*)(?:case\s+(.+?):|when\s+(.+?)\s|default\s*:)",
    re.MULTILINE,
)

_IF_ELIF_RE = re.compile(
    r"^(\s*)(if|elif|else\s+if|else)\s*[\s(:]",
    re.MULTILINE,
)

_FUNC_RE = re.compile(
    r"(?:def|func|function|fn)\s+(?:\([^)]*\)\s+)?(\w+)\s*\(",
)


def _collect_branches_regex(
    file_path: str, source: str,
) -> list[tuple[str, str, list[tuple[str, str, int]]]]:
    """Regex fallback for branch collection."""
    lines = source.splitlines()
    groups: list[tuple[str, str, list[tuple[str, str, int]]]] = []

    # Try switch/case first
    case_matches = list(_CASE_HEADER_RE.finditer(source))
    if case_matches:
        _collect_case_groups(case_matches, lines, source, file_path, groups)

    # Try if/elif chains
    _collect_if_groups_regex(lines, source, file_path, groups)

    return groups


def _collect_case_groups(case_matches, lines, source, _file_path, groups) -> None:
    """Group consecutive case statements at the same indent level."""
    indent_groups: dict[int, list] = {}
    for m in case_matches:
        indent = len(m.group(1))
        indent_groups.setdefault(indent, []).append(m)

    for indent, matches in indent_groups.items():
        if len(matches) < MIN_BRANCHES:
            continue

        branches: list[tuple[str, str, int]] = []
        for i, m in enumerate(matches):
            label = (m.group(2) or m.group(3) or "default").strip()
            start_line = source[:m.start()].count("\n")
            if i + 1 < len(matches):
                end_pos = matches[i + 1].start()
            else:
                end_pos = min(m.end() + 500, len(source))
            body = source[m.end():end_pos]
            branches.append((label, body, start_line + 1))

        func = _find_enclosing_func_regex(lines, branches[0][2])
        groups.append((func, f"switch@L{branches[0][2]}", branches))


def _collect_if_groups_regex(lines, source, _file_path, groups) -> None:
    """Find if/elif chains with ≥ MIN_BRANCHES at the same indent."""
    matches = list(_IF_ELIF_RE.finditer(source))
    if not matches:
        return

    chains: list[list] = []
    current_chain: list = []
    current_indent = -1

    for m in matches:
        indent = len(m.group(1))
        keyword = m.group(2).strip()

        if keyword == "if":
            if len(current_chain) >= MIN_BRANCHES:
                chains.append(current_chain)
            current_chain = [m]
            current_indent = indent
        elif indent == current_indent and keyword in ("elif", "else if", "else"):
            current_chain.append(m)
        else:
            if len(current_chain) >= MIN_BRANCHES:
                chains.append(current_chain)
            current_chain = [m]
            current_indent = indent

    if len(current_chain) >= MIN_BRANCHES:
        chains.append(current_chain)

    for chain in chains:
        branches: list[tuple[str, str, int]] = []
        for i, m in enumerate(chain):
            label = m.group(2).strip()
            start_line = source[:m.start()].count("\n") + 1
            if i + 1 < len(chain):
                body = source[m.end():chain[i + 1].start()]
            else:
                body = source[m.end():m.end() + 500]
            branches.append((label, body, start_line))

        func = _find_enclosing_func_regex(lines, branches[0][2])
        groups.append((func, f"if-chain@L{branches[0][2]}", branches))


def _find_enclosing_func_regex(lines: list[str], target_line: int) -> str:
    """Find the function name enclosing a line number (1-based)."""
    for i in range(min(target_line - 1, len(lines) - 1), -1, -1):
        m = _FUNC_RE.search(lines[i])
        if m:
            return m.group(1)
    return "<module>"


# ---------------------------------------------------------------------------
# Asymmetry detection
# ---------------------------------------------------------------------------

_SEVERITY_BOOST_PROPS = frozenset({
    "validates_input", "sanitizes_input", "checks_auth",
})


def _detect_asymmetries_in_groups(
    file_path: str,
    branch_groups: list[tuple[str, str, list[tuple[str, str, int]]]],
) -> list[BlockSiblingFinding]:
    """Run sibling asymmetry detection on collected branch groups."""
    findings: list[BlockSiblingFinding] = []

    for func_name, group_label, branches in branch_groups:
        siblings: list[SiblingPath] = []
        for label, body_text, line in branches:
            props = _extract_branch_properties(body_text)
            siblings.append(SiblingPath(
                label=label,
                file=file_path,
                function=func_name,
                line=line,
                properties=props,
            ))

        group = SiblingGroup(
            group_id=f"block:{file_path}:{func_name}:{group_label}",
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description=f"Block siblings in {func_name} ({group_label})",
            siblings=siblings,
        )

        asymmetries = find_asymmetries(group)
        for asym in asymmetries:
            severity = asym.severity
            if (asym.property_name in _SEVERITY_BOOST_PROPS
                    and severity == "medium"
                    and asym.confidence >= 0.75):
                severity = "high"

            for minority_label in asym.minority_siblings:
                sib = next(
                    (s for s in siblings if s.label == minority_label),
                    None,
                )
                line = sib.line if sib else branches[0][2]
                findings.append(BlockSiblingFinding(
                    file=file_path,
                    function=func_name,
                    line=line,
                    branch_label=minority_label,
                    property_name=asym.property_name,
                    majority_count=asym.majority_count,
                    total_branches=len(siblings),
                    explanation=asym.explanation,
                    severity=severity,
                    confidence=asym.confidence,
                ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_block_sibling_asymmetries(
    source_texts: dict[str, str],
) -> list[BlockSiblingFinding]:
    """Detect sibling asymmetries across branches within functions.

    Scans for switch/case, if/elif chains with ≥3 branches, extracts
    security-relevant properties from each branch body, and flags
    outliers where the majority of branches share a property but one
    or more don't.
    """
    all_findings: list[BlockSiblingFinding] = []

    for file_path, source in source_texts.items():
        branch_groups = _collect_branches_ts(file_path, source)
        if not branch_groups:
            branch_groups = _collect_branches_regex(file_path, source)

        if branch_groups:
            all_findings.extend(
                _detect_asymmetries_in_groups(file_path, branch_groups)
            )

    all_findings.sort(
        key=lambda f: (f.severity != "high", -f.confidence, f.file, f.line)
    )
    return all_findings


def format_block_sibling_findings_for_prompt(
    findings: list[BlockSiblingFinding],
) -> str:
    """Format block sibling findings for LLM review prompt injection."""
    if not findings:
        return ""

    parts = ["### Block-level sibling asymmetries\n"]
    for f in findings:
        safe_func = sanitise_for_prompt(f.function, content_type="name")
        safe_prop = sanitise_for_prompt(f.property_name, content_type="name")
        safe_explanation = sanitise_for_prompt(f.explanation, content_type="string")
        safe_branch = sanitise_for_prompt(f.branch_label, content_type="name")
        parts.append(
            f"- [{f.severity.upper()}] `{safe_func}` {safe_prop}: "
            f"{safe_explanation}"
        )
        if f.property_name in _SEVERITY_BOOST_PROPS:
            parts.append(
                f"  → CHECK: Is the missing {safe_prop} in the "
                f"'{safe_branch}' branch intentional or an oversight?"
            )
    return "\n".join(parts)
