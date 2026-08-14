"""Mechanical condition extraction for sink guard analysis.

Given source code and a set of sink call lines, extracts the guard
conditions (if/switch/match) that must hold for each sink to be reached.
Works across all languages RAPTOR supports via tree-sitter CST traversal.

The output tells downstream consumers (prefilter, /validate, /understand)
not just WHETHER a sink exists but UNDER WHAT CONDITIONS it fires.

Design layers:
  Layer 0 (this module): Tree-sitter intraprocedural guard extraction.
  Layer 1 (condition_classifier): Categorize extracted guards.
  Layer 2 (condition_extraction_python): Deep Python AST version.
  Layer 3 (CodeQL queries): Interprocedural, C/C++ — separate module.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class GuardCondition:
    """One condition that gates a sink call."""

    text: str
    category: str  # auth|bounds|null|config|error|type|resource|unknown
    polarity: str  # "required" (sink in true-branch) | "excluded" (sink in else-branch)
    line: int
    resolvable: bool = False
    concrete_values: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "text": self.text,
            "category": self.category,
            "polarity": self.polarity,
            "line": self.line,
        }
        if self.resolvable:
            d["resolvable"] = True
            d["concrete_values"] = self.concrete_values
        return d


@dataclass
class SinkGuard:
    """Guard conditions for one sink call site."""

    sink_file: str
    sink_line: int
    sink_function: str
    sink_api: str
    guards: List[GuardCondition] = field(default_factory=list)
    unconditional: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "sink_function": self.sink_function,
            "sink_api": self.sink_api,
            "guards": [g.to_dict() for g in self.guards],
            "unconditional": self.unconditional,
        }

    @property
    def guard_count(self) -> int:
        return len(self.guards)

    @property
    def has_auth_guard(self) -> bool:
        return any(g.category == "auth" for g in self.guards)

    @property
    def has_bounds_guard(self) -> bool:
        return any(g.category == "bounds" for g in self.guards)

    @property
    def priority_score(self) -> float:
        """Lower score = higher priority (fewer/weaker guards).

        Unconditional sinks get 1.0 (highest priority).
        Each guard reduces priority: auth guards reduce most.
        """
        if self.unconditional:
            return 1.0
        score = 0.8
        for g in self.guards:
            if g.category == "auth":
                score -= 0.25
            elif g.category == "bounds":
                score -= 0.15
            elif g.category == "config":
                score -= 0.20
            elif g.category == "null":
                score -= 0.05
            elif g.category == "error":
                score -= 0.10
            else:
                score -= 0.05
        return max(0.0, score)


# ---------------------------------------------------------------------------
# Tree-sitter availability
# ---------------------------------------------------------------------------

try:
    from tree_sitter import Parser as TSParser
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False


def _get_parser(lang: str) -> Optional[Any]:
    """Get a cached tree-sitter parser for a language.

    Reuses the parser cache from core.inventory.extractors when available.
    """
    try:
        from core.inventory.extractors import _ts_parser_for
        return _ts_parser_for(lang)
    except ImportError:
        pass
    if not _TS_AVAILABLE:
        return None
    try:
        from core.inventory.extractors import _ts_language
        ts_lang = _ts_language(lang)
        if ts_lang is None:
            return None
        parser = TSParser(ts_lang)
        return parser
    except (ImportError, Exception):
        return None


# ---------------------------------------------------------------------------
# Language → file extension mapping
# ---------------------------------------------------------------------------

_EXT_TO_LANG: Dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".py": "python", ".pyw": "python",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".rb": "ruby",
    ".php": "php",
    ".lua": "lua",
    ".cs": "csharp",
}


def language_for_file(filepath: str) -> Optional[str]:
    """Determine tree-sitter language from file extension."""
    for ext, lang in _EXT_TO_LANG.items():
        if filepath.endswith(ext):
            return lang
    return None


# ---------------------------------------------------------------------------
# Node type mappings per language — what constitutes a conditional
# ---------------------------------------------------------------------------

# Node types that represent conditional branching
_CONDITIONAL_TYPES: Dict[str, Tuple[str, ...]] = {
    "c": ("if_statement", "switch_statement", "conditional_expression"),
    "cpp": ("if_statement", "switch_statement", "conditional_expression"),
    "python": ("if_statement", "match_statement"),
    "go": ("if_statement", "expression_switch_statement", "type_switch_statement"),
    "rust": ("if_expression", "match_expression", "if_let_expression"),
    "java": ("if_statement", "switch_expression", "switch_statement"),
    "javascript": ("if_statement", "switch_statement", "ternary_expression"),
    "typescript": ("if_statement", "switch_statement", "ternary_expression"),
    "tsx": ("if_statement", "switch_statement", "ternary_expression"),
    "ruby": ("if", "unless", "case"),
    "php": ("if_statement", "switch_statement", "match_expression"),
    "lua": ("if_statement",),
    "csharp": ("if_statement", "switch_statement", "switch_expression"),
}

# Node types that represent function definitions (for enclosing function lookup)
_FUNCTION_TYPES: Dict[str, Tuple[str, ...]] = {
    "c": ("function_definition",),
    "cpp": ("function_definition",),
    "python": ("function_definition",),
    "go": ("function_declaration", "method_declaration", "func_literal"),
    "rust": ("function_item",),
    "java": ("method_declaration", "constructor_declaration"),
    "javascript": ("function_declaration", "method_definition", "arrow_function", "function_expression"),
    "typescript": ("function_declaration", "method_definition", "arrow_function", "function_expression"),
    "tsx": ("function_declaration", "method_definition", "arrow_function", "function_expression"),
    "ruby": ("method", "singleton_method"),
    "php": ("method_declaration", "function_definition"),
    "lua": ("function_declaration", "function_definition"),
    "csharp": ("method_declaration", "constructor_declaration"),
}

# Node types representing early exit (return/goto/break/throw)
_EXIT_TYPES: Dict[str, Tuple[str, ...]] = {
    "c": ("return_statement", "goto_statement", "break_statement"),
    "cpp": ("return_statement", "goto_statement", "break_statement", "throw_statement"),
    "python": ("return_statement", "raise_statement"),
    "go": ("return_statement",),
    "rust": ("return_expression",),
    "java": ("return_statement", "throw_statement", "break_statement"),
    "javascript": ("return_statement", "throw_statement", "break_statement"),
    "typescript": ("return_statement", "throw_statement", "break_statement"),
    "tsx": ("return_statement", "throw_statement", "break_statement"),
    "ruby": ("return", "raise"),
    "php": ("return_statement", "throw_expression"),
    "lua": ("return_statement",),
    "csharp": ("return_statement", "throw_statement", "break_statement"),
}


# ---------------------------------------------------------------------------
# Core extraction logic
# ---------------------------------------------------------------------------


def _node_text(node, source_bytes: bytes) -> str:
    """Extract the text of a tree-sitter node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _node_line(node) -> int:
    """Get 1-indexed line number for a node."""
    return node.start_point[0] + 1


def _find_enclosing_function_node(node, lang: str):
    """Walk up to find the enclosing function definition node."""
    func_types = _FUNCTION_TYPES.get(lang, ())
    cur = node.parent
    while cur is not None:
        if cur.type in func_types:
            return cur
        cur = cur.parent
    return None


def _get_function_name(func_node, lang: str, source_bytes: bytes) -> str:
    """Extract function name from a function definition node."""
    if func_node is None:
        return "<module>"

    # Most languages have a 'name' or 'declarator' child
    for child in func_node.children:
        if child.type == "identifier":
            return _node_text(child, source_bytes)
        if child.type == "name":
            return _node_text(child, source_bytes)
        if child.type in ("function_declarator", "declarator"):
            # C/C++: dig into declarator for the identifier
            for sub in child.children:
                if sub.type == "identifier":
                    return _node_text(sub, source_bytes)
                if sub.type == "field_identifier":
                    return _node_text(sub, source_bytes)
                # Pointer declarators: int *func()
                if sub.type == "pointer_declarator":
                    for psub in sub.children:
                        if psub.type in ("identifier", "field_identifier"):
                            return _node_text(psub, source_bytes)
            return _node_text(child, source_bytes)
        if child.type == "field_identifier":
            return _node_text(child, source_bytes)

    return "<unknown>"


def _extract_condition_text(cond_node, lang: str, source_bytes: bytes) -> str:
    """Extract the condition expression text from a conditional node.

    For if_statement: extracts the condition/parenthesized expression.
    For switch_statement: extracts the switched value.
    For match: extracts the subject.
    """
    if cond_node.type in ("if_statement", "if_expression", "if_let_expression",
                          "if", "unless"):
        # Look for 'condition', 'parenthesized_expression', or first expression child
        for child in cond_node.children:
            if child.type == "condition_clause":
                return _node_text(child, source_bytes).strip()
            if child.type == "parenthesized_expression":
                inner = _node_text(child, source_bytes)
                # Strip outer parens for readability
                if inner.startswith("(") and inner.endswith(")"):
                    inner = inner[1:-1].strip()
                return inner
            if child.type == "condition":
                return _node_text(child, source_bytes).strip()
            # Python: if_statement has children [if, comparison/expression, :, block...]
            if lang == "python" and child.type not in (
                "if", "elif", ":", "block", "comment", "else_clause",
                "elif_clause",
            ):
                return _node_text(child, source_bytes).strip()
            # Ruby unless
            if lang == "ruby" and child.type not in (
                "unless", "if", "then", "do", "end",
            ):
                text = _node_text(child, source_bytes).strip()
                if text:
                    return text
        # Fallback: first meaningful child after keyword
        for child in cond_node.children:
            if child.type not in ("if", "elif", "switch", "match", "(", ")", "{", "}"):
                text = _node_text(child, source_bytes).strip()
                if text and len(text) < 200:
                    return text

    elif cond_node.type in ("switch_statement", "expression_switch_statement",
                            "type_switch_statement", "switch_expression",
                            "match_statement", "match_expression", "case"):
        # Extract switched value
        for child in cond_node.children:
            if child.type == "parenthesized_expression":
                inner = _node_text(child, source_bytes)
                if inner.startswith("(") and inner.endswith(")"):
                    inner = inner[1:-1].strip()
                return f"switch({inner})"
            if child.type == "value":
                return f"match({_node_text(child, source_bytes).strip()})"
            # Go: expression_switch_statement first expression
            if lang == "go" and child.type not in (
                "switch", "{", "}", "expression_case",
            ):
                text = _node_text(child, source_bytes).strip()
                if text and len(text) < 200:
                    return f"switch({text})"
        # Python match_statement
        if lang == "python":
            for child in cond_node.children:
                if child.type not in ("match", ":", "block", "case_clause"):
                    text = _node_text(child, source_bytes).strip()
                    if text:
                        return f"match({text})"

    elif cond_node.type in ("conditional_expression", "ternary_expression"):
        # condition ? true : false — extract the condition part
        for child in cond_node.children:
            if child.type not in ("?", ":", "consequence", "alternative"):
                return _node_text(child, source_bytes).strip()

    # Last resort: return full text truncated
    full = _node_text(cond_node, source_bytes)
    # Take first line only
    first_line = full.split("\n")[0].strip()
    if len(first_line) > 200:
        first_line = first_line[:197] + "..."
    return first_line


def _determine_polarity(
    cond_node,
    sink_line: int,
    lang: str,
    source_bytes: bytes,
) -> str:
    """Determine if the sink is in the true-branch or else-branch.

    Returns "required" if sink is in the consequence (true/then block),
    "excluded" if sink is in the alternative (else block).
    Also detects the early-return-guard pattern:
      if (error) return;  // sink is AFTER — guard by negation
    """
    # Find consequence and alternative blocks
    consequence = None
    alternative = None

    children = list(cond_node.children)
    for i, child in enumerate(children):
        if child.type in ("block", "compound_statement", "consequence",
                          "statement_block", "then", "body"):
            if consequence is None:
                consequence = child
            elif alternative is None:
                alternative = child
            continue
        if child.type in ("else_clause", "alternative", "else_statement"):
            alternative = child
            continue
        if child.type == "else":
            # Bare "else" keyword — skip punctuation/comments to find body
            for j in range(i + 1, len(children)):
                sib = children[j]
                if sib.type not in ("comment", "{", "}"):
                    alternative = sib
                    break
            continue
        # C/Go/Java: the first statement after condition is consequence
        if (consequence is None and
            child.type not in ("if", "elif", "else", "switch", "match",
                               "unless", "(", ")", "parenthesized_expression",
                               "condition_clause", "condition", ":",
                               "comment", "{", "}")):
            # Check if this is a statement-type node that could be consequence
            if hasattr(child, 'start_point') and hasattr(child, 'end_point'):
                if child.start_point[0] > cond_node.start_point[0]:
                    consequence = child

    # Ruby "unless" inverts the condition — swap polarity at the end
    is_unless = cond_node.type == "unless"

    sink_row = sink_line - 1  # 0-indexed

    # Check if sink is in consequence
    if consequence is not None:
        if consequence.start_point[0] <= sink_row <= consequence.end_point[0]:
            return "excluded" if is_unless else "required"

    # Check if sink is in alternative
    if alternative is not None:
        if alternative.start_point[0] <= sink_row <= alternative.end_point[0]:
            return "required" if is_unless else "excluded"

    # Early-return-guard pattern: if the consequence contains only an exit
    # statement and the sink is AFTER the entire if-block, the guard is
    # effectively negated (sink requires condition to be FALSE).
    if consequence is not None:
        exit_types = _EXIT_TYPES.get(lang, ())
        # Check if consequence is just an exit or contains only exits
        is_exit_only = False
        if consequence.type in exit_types:
            is_exit_only = True
        elif consequence.type in ("block", "compound_statement", "statement_block"):
            blk_children = [c for c in consequence.children
                            if c.type not in ("{", "}", "comment")]
            if blk_children and blk_children[-1].type in exit_types:
                is_exit_only = True

        if is_exit_only and sink_row > cond_node.end_point[0]:
            return "required" if is_unless else "excluded"

    # Sink is after the if-block but not in an early-return pattern,
    # or we can't determine — assume required (conservative)
    if sink_row > cond_node.end_point[0]:
        return "excluded" if is_unless else "required"

    return "excluded" if is_unless else "required"


def _find_enclosing_conditionals(
    root_node,
    sink_line: int,
    lang: str,
    source_bytes: bytes,
    max_depth: int = 5,
) -> List[Tuple[Any, str, str]]:
    """Walk up from the sink line to find all enclosing conditionals.

    Also detects preceding guard clauses (early-return pattern):
      if (!condition) return;  // guard clause
      sink_call();             // guarded by negation of condition

    Returns list of (cond_node, condition_text, polarity) from
    innermost to outermost, capped at max_depth.
    """
    sink_row = sink_line - 1  # tree-sitter is 0-indexed

    target_node = _find_node_at_line(root_node, sink_row)
    if target_node is None:
        return []

    cond_types = _CONDITIONAL_TYPES.get(lang, ())
    results: List[Tuple[Any, str, str]] = []

    # Walk up from target node, collecting enclosing conditionals
    cur = target_node.parent
    while cur is not None and len(results) < max_depth:
        if cur.type in cond_types:
            cond_text = _extract_condition_text(cur, lang, source_bytes)
            polarity = _determine_polarity(cur, sink_line, lang, source_bytes)
            results.append((cur, cond_text, polarity))
        # Stop at function boundary
        func_types = _FUNCTION_TYPES.get(lang, ())
        if cur.type in func_types:
            break
        cur = cur.parent

    # Preceding guard clause detection: scan the enclosing block for
    # if-statements before the sink that contain only exit statements.
    preceding = _find_preceding_guard_clauses(
        target_node, sink_row, lang, source_bytes, max_depth - len(results),
    )
    results.extend(preceding)

    return results


def _find_preceding_guard_clauses(
    target_node,
    sink_row: int,
    lang: str,
    source_bytes: bytes,
    max_count: int,
) -> List[Tuple[Any, str, str]]:
    """Find if-statements before the sink that are guard clauses.

    A guard clause is an if-statement whose body contains only exit
    statements (return/raise/break/goto) and has no else branch.
    These act as negative guards on all subsequent code.
    """
    if max_count <= 0:
        return []

    cond_types = _CONDITIONAL_TYPES.get(lang, ())
    exit_types = _EXIT_TYPES.get(lang, ())
    block_types = ("block", "compound_statement", "statement_block",
                   "statement_list", "function_body", "source_file")

    # Find the enclosing block that contains the sink as a direct child
    enclosing_block = target_node.parent
    while enclosing_block is not None:
        if enclosing_block.type in block_types:
            break
        # Function body nodes vary by language
        func_types = _FUNCTION_TYPES.get(lang, ())
        if enclosing_block.type in func_types:
            # Use the function's body child
            for child in enclosing_block.children:
                if child.type in block_types:
                    enclosing_block = child
                    break
            break
        enclosing_block = enclosing_block.parent

    if enclosing_block is None:
        return []

    results: List[Tuple[Any, str, str]] = []

    for child in enclosing_block.children:
        if len(results) >= max_count:
            break
        # Only look at statements BEFORE the sink
        if child.end_point[0] >= sink_row:
            break
        # Must be a conditional
        if child.type not in cond_types:
            continue
        # Must be an if_statement type (not switch/match)
        if "if" not in child.type and "unless" not in child.type:
            continue
        # Check if its body is exit-only (guard clause pattern)
        if _is_exit_only_body(child, lang, exit_types):
            cond_text = _extract_condition_text(child, lang, source_bytes)
            if cond_text:
                # unless guard: body fires when condition is FALSE,
                # so sink after it requires condition TRUE = "required"
                polarity = "required" if child.type == "unless" else "excluded"
                results.append((child, cond_text, polarity))

    return results


def _is_exit_only_body(if_node, lang: str, exit_types: tuple) -> bool:
    """Check if an if-node's consequence body contains only exit statements.

    Handles multiple tree-sitter patterns:
      - Python: if_statement → [if, expr, :, block{return}]
      - C/Go: if_statement → [if, (cond), compound_statement{return}]
      - C: if_statement → [if, (cond), return_statement] (no braces)
    """
    block_types = ("block", "compound_statement", "statement_block")

    # Strategy: find the first block-type child (the body).
    # If none, look for a bare exit statement as a direct child.
    # Skip: else clause means this isn't a simple guard pattern.
    has_else = any(
        c.type in ("else_clause", "else", "elif_clause", "elif")
        for c in if_node.children
    )
    if has_else:
        return False

    for child in if_node.children:
        if child.type in block_types:
            # This is the body — the last statement must be an exit
            # (preceding log/print calls don't change guard semantics)
            statements = _block_statements(child, exit_types)
            return len(statements) > 0 and statements[-1].type in exit_types

        # C/Go: single-statement body without braces
        if child.type in exit_types:
            return True

    return False


def _block_statements(block_node, exit_types: tuple) -> list:
    """Extract meaningful statement children from a block node.

    Handles Go's block → { statement_list { stmts } } nesting.
    """
    noise = ("{", "}", "comment", ":", "\n")
    children = [c for c in block_node.children if c.type not in noise]
    # Go/some languages wrap statements in a statement_list node
    if len(children) == 1 and children[0].type == "statement_list":
        return [c for c in children[0].children if c.type not in noise]
    return children


def _find_node_at_line(root, target_row: int):
    """Find the deepest node that starts at or contains the target line."""
    best = None

    def _walk(node):
        nonlocal best
        if node.start_point[0] <= target_row <= node.end_point[0]:
            best = node
            for child in node.children:
                if child.start_point[0] <= target_row <= child.end_point[0]:
                    _walk(child)
                    return

    _walk(root)
    return best


# ---------------------------------------------------------------------------
# Call-site detection — find sink calls in source
# ---------------------------------------------------------------------------

# Common call node types across languages
_CALL_TYPES: Dict[str, Tuple[str, ...]] = {
    "c": ("call_expression",),
    "cpp": ("call_expression",),
    "python": ("call",),
    "go": ("call_expression",),
    "rust": ("call_expression", "macro_invocation"),
    "java": ("method_invocation",),
    "javascript": ("call_expression",),
    "typescript": ("call_expression",),
    "tsx": ("call_expression",),
    "ruby": ("call", "method_call"),
    "php": ("function_call_expression", "member_call_expression",
            "scoped_call_expression"),
    "lua": ("function_call",),
    "csharp": ("invocation_expression",),
}


def _extract_call_name(call_node, source_bytes: bytes) -> str:
    """Extract the called function/method name from a call node."""
    for child in call_node.children:
        if child.type == "identifier":
            return _node_text(child, source_bytes)
        if child.type == "field_expression":
            # C: obj->method or obj.method — get the field
            for sub in child.children:
                if sub.type == "field_identifier":
                    return _node_text(sub, source_bytes)
        if child.type in ("member_expression", "attribute"):
            # JS/Python: obj.method — extract the full dotted name
            return _node_text(child, source_bytes)
        if child.type == "selector_expression":
            # Go: pkg.Function
            return _node_text(child, source_bytes)
        if child.type == "scoped_identifier":
            # Rust: module::function
            return _node_text(child, source_bytes)
    # Fallback: first child text
    if call_node.children:
        text = _node_text(call_node.children[0], source_bytes)
        # Truncate long expressions
        if len(text) > 80:
            text = text[:77] + "..."
        return text
    return ""


def find_sink_calls(
    root_node,
    source_bytes: bytes,
    lang: str,
    sink_names: FrozenSet[str],
) -> List[Tuple[int, str]]:
    """Find all call sites in the tree that match a sink name.

    Returns (line_1indexed, matched_sink_name) pairs.
    """
    call_types = _CALL_TYPES.get(lang, ())
    results: List[Tuple[int, str]] = []

    def _walk(node):
        if node.type in call_types:
            name = _extract_call_name(node, source_bytes)
            # Match against sink names: exact match or suffix match
            # (for dotted names like os.system matching "system")
            matched = _match_sink(name, sink_names)
            if matched:
                results.append((_node_line(node), matched))
        for child in node.children:
            _walk(child)

    _walk(root_node)
    return results


def _match_sink(call_name: str, sink_names: FrozenSet[str]) -> Optional[str]:
    """Check if a call name matches any sink. Returns matched name or None."""
    if not call_name:
        return None
    # Direct match
    if call_name in sink_names:
        return call_name
    # Suffix match: "os.system" matches sink "system"
    # Also: "self.system" should not match "system" in most cases,
    # but "subprocess.call" should match "subprocess.call"
    parts = re.split(r"[.:\->]+", call_name)
    if parts:
        last = parts[-1]
        if last in sink_names:
            return last
        # Try last two parts joined with dot
        if len(parts) >= 2:
            dotted = f"{parts[-2]}.{parts[-1]}"
            if dotted in sink_names:
                return dotted
    return None


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------


def extract_sink_guards(
    source: str,
    filepath: str,
    sink_names: Optional[FrozenSet[str]] = None,
    sink_lines: Optional[List[int]] = None,
    max_guard_depth: int = 5,
) -> List[SinkGuard]:
    """Extract guard conditions for sink calls in a source file.

    Two modes:
      1. Provide sink_names: automatically finds sink call sites.
      2. Provide sink_lines: extracts guards for specific lines.

    Args:
        source: Source code text.
        filepath: File path (used for language detection and output).
        sink_names: Set of sink function names to look for.
        sink_lines: Specific line numbers known to contain sinks.
        max_guard_depth: Maximum enclosing conditionals to extract.

    Returns:
        List of SinkGuard instances, one per discovered sink call.
    """
    lang = language_for_file(filepath)
    if lang is None:
        return []

    parser = _get_parser(lang)
    if parser is None:
        return []

    source_bytes = source.encode("utf-8")
    tree = parser.parse(source_bytes)
    root = tree.root_node

    # Determine sink call sites
    call_sites: List[Tuple[int, str]] = []

    if sink_lines is not None:
        # Use provided lines — extract call name at each line
        for line in sink_lines:
            target = _find_node_at_line(root, line - 1)
            if target is not None:
                # Find nearest call node at or around this line
                call_node = _find_call_at_line(root, line - 1, lang)
                if call_node is not None:
                    name = _extract_call_name(call_node, source_bytes)
                    call_sites.append((line, name or "<unknown>"))
                else:
                    call_sites.append((line, "<unknown>"))

    elif sink_names is not None:
        call_sites = find_sink_calls(root, source_bytes, lang, sink_names)

    else:
        return []

    # Extract guards for each call site
    results: List[SinkGuard] = []

    from .condition_classifier import classify_condition

    for sink_line, sink_api in call_sites:
        # Find enclosing function
        target = _find_node_at_line(root, sink_line - 1)
        func_node = _find_enclosing_function_node(
            target, lang) if target else None
        func_name = _get_function_name(func_node, lang, source_bytes)

        # Find enclosing conditionals
        conditionals = _find_enclosing_conditionals(
            root, sink_line, lang, source_bytes,
            max_depth=max_guard_depth,
        )

        guards: List[GuardCondition] = []
        for _cond_node, cond_text, polarity in conditionals:
            if not cond_text:
                continue
            category = classify_condition(cond_text, lang)
            guards.append(GuardCondition(
                text=cond_text,
                category=category,
                polarity=polarity,
                line=_node_line(_cond_node),
            ))

        sg = SinkGuard(
            sink_file=filepath,
            sink_line=sink_line,
            sink_function=func_name,
            sink_api=sink_api,
            guards=guards,
            unconditional=(len(guards) == 0),
        )
        results.append(sg)

    return results


def _find_call_at_line(root, target_row: int, lang: str):
    """Find a call expression node at the given line."""
    call_types = _CALL_TYPES.get(lang, ())
    result = None

    def _walk(node):
        nonlocal result
        if result is not None:
            return
        if node.start_point[0] == target_row and node.type in call_types:
            result = node
            return
        for child in node.children:
            if child.start_point[0] <= target_row <= child.end_point[0]:
                _walk(child)

    _walk(root)
    return result


# ---------------------------------------------------------------------------
# Batch API — process multiple files
# ---------------------------------------------------------------------------


def extract_guards_for_files(
    source_texts: Dict[str, str],
    sink_names: FrozenSet[str],
    max_guard_depth: int = 5,
) -> Dict[str, List[SinkGuard]]:
    """Extract sink guards across multiple files.

    Args:
        source_texts: Mapping of filepath → source code.
        sink_names: Set of dangerous function/method names.
        max_guard_depth: Maximum enclosing conditionals to extract.

    Returns:
        Mapping of filepath → list of SinkGuard instances.
    """
    results: Dict[str, List[SinkGuard]] = {}

    for filepath, source in sorted(source_texts.items()):
        guards = extract_sink_guards(
            source, filepath,
            sink_names=sink_names,
            max_guard_depth=max_guard_depth,
        )
        if guards:
            results[filepath] = guards

    return results
