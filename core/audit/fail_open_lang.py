"""Leg-2 handler-outcome analyzers for the fail-open channel.

One module, per-language dispatch inside (the ``lang_resolve``
pattern). Every analyzer reduces to the same shapes:

* :class:`HandlerOutcome` — one error handler / suppression block with
  its idiom, caught types, and demonstrated outcome (permissive /
  fail-closed / undecided).
* :class:`CallSiteOutcome` — one call site of a role-bound callee for
  the C ignored-return / tri-state legs (``guarded`` / ``unguarded`` /
  ``undecided`` per site, mirroring ``api_boundary.CallSiteCheck``).

Phase 1 languages: Python (handler-outcome leg — a port, not an
import, of the CI census ``classify_handler`` / ``exc_types`` from
``.github/scripts/check_miswiring.py``, which must stay self-contained)
and C/C++ (ignored-return + tri-state comparison shapes on ts_extract
/ tree-sitter primitives, degrading to line-regex with the parser
recorded on every result).

Phase 2 adds Java (catch-clause outcomes: empty catch,
catch-and-continue, swallowed checked exceptions, log-and-proceed —
tree-sitter ``catch_clause`` bodies with caught-type resolution from
the catch parameter). The Java leg has no regex fallback: a missing
parser reports ``None`` and the channel returns
``inconclusive("language-unsupported")`` rather than guessing at
brace-delimited handler bodies.

Phase 2 also adds Go (discarded error returns — blank-identifier
assignment, err bound-then-never-checked, bare call statements — and
``recover()``-to-continue deferred handlers). Same no-regex-fallback
rule as Java: whether an ``if err != nil`` check dominates the
continuation is not honestly decidable from line shapes.

Suffix→language mapping is strictly
``core.inventory.languages.LANGUAGE_MAP`` — no new extension list
(dedup wave-3 rule). Unsupported languages are the caller's problem:
the channel returns ``inconclusive("language-unsupported")``.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Languages with an analyzer. Grows per phase (JS/TS/Rust in
# phase 3).
SUPPORTED_LANGUAGES = frozenset({"python", "c", "cpp", "java", "go"})

# Handler outcome kinds (permissive unless noted).
OUTCOME_PASS = "pass"
OUTCOME_CONTINUE = "continue"
OUTCOME_RETURN_PERMISSIVE = "return_permissive"
OUTCOME_ASSIGN_DEFAULT = "assign_default"
OUTCOME_QUIET_LOG_ONLY = "quiet_log_only"
OUTCOME_IGNORED_RETURN = "ignored_return"
OUTCOME_TRISTATE_ACCEPTS_ERROR = "tristate_accepts_error"
OUTCOME_RECOVER_CONTINUE = "recover_continue"
OUTCOME_FAIL_CLOSED = "fail_closed"        # refuting shape
OUTCOME_FALLBACK_ACTION = "fallback_action"  # undecided shape

PERMISSIVE_OUTCOMES = frozenset({
    OUTCOME_PASS, OUTCOME_CONTINUE, OUTCOME_RETURN_PERMISSIVE,
    OUTCOME_ASSIGN_DEFAULT, OUTCOME_QUIET_LOG_ONLY,
    OUTCOME_RECOVER_CONTINUE,
})


def language_for_path(file_path: str) -> str | None:
    """Language id for a path via the canonical LANGUAGE_MAP."""
    from core.inventory.languages import LANGUAGE_MAP
    return LANGUAGE_MAP.get(Path(file_path).suffix.lower())


@dataclass
class HandlerOutcome:
    """One error handler / suppression block, classified."""

    idiom: str                 # "except_pass" | "except_continue" | ...
    file: str
    line: int
    caught: list[str] = field(default_factory=list)
    broad: bool = False
    outcome_kind: str = OUTCOME_FALLBACK_ACTION
    permissive_value: str = ""
    evidence_snippet: str = ""
    parser: str = "ast"
    enclosing_function: str = ""
    try_calls: list[str] = field(default_factory=list)
    try_span: tuple[int, int] | None = None

    @property
    def is_permissive(self) -> bool:
        return self.outcome_kind in PERMISSIVE_OUTCOMES

    @property
    def is_fail_closed(self) -> bool:
        return self.outcome_kind == OUTCOME_FAIL_CLOSED

    def to_dict(self) -> dict[str, Any]:
        return {
            "idiom": self.idiom,
            "line": self.line,
            "caught": list(self.caught),
            "broad": self.broad,
            "outcome_kind": self.outcome_kind,
            "permissive_value": self.permissive_value,
            "code": self.evidence_snippet,
            "parser": self.parser,
        }


@dataclass
class CallSiteOutcome:
    """One call site of a role-bound callee (C legs)."""

    file: str
    line: int
    code: str
    verdict: str               # guarded | unguarded | undecided
    evidence: str = ""
    shape: str = ""            # e.g. "bare-statement" | "== 1" | "truth-test"
    parser: str = "tree-sitter"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "code": self.code,
            "verdict": self.verdict,
            "evidence": self.evidence,
            "shape": self.shape,
            "parser": self.parser,
        }


# ── Python handler-outcome analyzer (census port) ───────────────────
# Ported (not imported) from .github/scripts/check_miswiring.py
# classify_handler/exc_types — the CI script must stay self-contained
# and the channel must not depend on .github/. Security-role scoping
# is added by the channel (fail_open_verify), not here.

_LOUD_LOG_RE = re.compile(r"\.(error|exception|critical|warning)\(")
_QUIET_LOG_RE = re.compile(r"\.(debug|trace|info)\(")


def _dec_name(node: ast.AST | None) -> str:
    """Dotted name of an expression node ('' when not a name shape)."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(cur, ast.Call):
        return _dec_name(cur.func)
    return ""


def _exc_types(handler: ast.ExceptHandler) -> tuple[list[str], bool]:
    """(caught type names, broad?) — census ``exc_types`` port."""
    if handler.type is None:
        return ["<bare>"], True
    t = handler.type
    elts = t.elts if isinstance(t, ast.Tuple) else [t]
    names: list[str] = []
    broad = False
    for e in elts:
        nm = _dec_name(e)
        names.append(nm or "<expr>")
        if nm in ("Exception", "BaseException"):
            broad = True
    return names, broad


def _return_value_class(node: ast.Return) -> tuple[str, str]:
    """(outcome_kind, value_repr) for a ``return`` in a handler.

    Restrictive literals (False/None/0/empty) are fail-closed for a
    boolean-ish security contract; truthy literals are permissive;
    anything computed is undecided (fallback_action).
    """
    if node.value is None:
        return OUTCOME_FAIL_CLOSED, "None"
    try:
        text = ast.unparse(node.value)
    except Exception:
        logger.debug("ast.unparse failed on return value", exc_info=True)
        text = "<expr>"
    if isinstance(node.value, ast.Constant):
        if node.value.value is True:
            return OUTCOME_RETURN_PERMISSIVE, text
        return OUTCOME_FAIL_CLOSED, text
    if isinstance(node.value, (ast.List, ast.Dict, ast.Tuple)):
        if not getattr(node.value, "elts", None) and not getattr(
                node.value, "keys", None):
            return OUTCOME_FAIL_CLOSED, text
        return OUTCOME_RETURN_PERMISSIVE, text
    return OUTCOME_FALLBACK_ACTION, text


def _classify_python_handler(
    handler: ast.ExceptHandler, lines: list[str],
) -> tuple[str, str]:
    """(outcome_kind, permissive_value) — census ``classify_handler``
    port with fail-closed shapes made explicit (the census returns
    None for them; the channel needs them as refutation receipts)."""
    body = handler.body
    src_seg = "\n".join(
        lines[handler.lineno - 1:(handler.end_lineno or handler.lineno)],
    )

    if any(isinstance(n, ast.Raise) for n in ast.walk(handler)):
        return OUTCOME_FAIL_CLOSED, "re-raises"
    if "sys.exit" in src_seg or re.search(r"\bos\._exit\(|\babort\(",
                                          src_seg):
        return OUTCOME_FAIL_CLOSED, "aborts"

    returns = [s for s in body if isinstance(s, ast.Return)]
    if returns and all(
        isinstance(s, (ast.Return, ast.Pass)) for s in body
    ):
        kind, value = _return_value_class(returns[0])
        if kind == OUTCOME_FAIL_CLOSED:
            return OUTCOME_FAIL_CLOSED, f"returns {value}"
        if kind == OUTCOME_RETURN_PERMISSIVE:
            return OUTCOME_RETURN_PERMISSIVE, value
        return OUTCOME_FALLBACK_ACTION, value

    if _LOUD_LOG_RE.search(src_seg):
        # Logged loudly → visible, but control still proceeds; the
        # census drops these as "not silent" — the channel gates them
        # to undecided rather than calling them fail-closed.
        return OUTCOME_FALLBACK_ACTION, "loud-log-and-continue"
    if re.search(r"print\(", src_seg) or "sys.stderr" in src_seg:
        return OUTCOME_FALLBACK_ACTION, "prints-and-continues"

    if all(isinstance(s, ast.Pass) for s in body):
        return OUTCOME_PASS, ""
    if all(isinstance(s, (ast.Continue, ast.Break, ast.Pass))
           for s in body):
        return OUTCOME_CONTINUE, ""
    if _QUIET_LOG_RE.search(src_seg):
        return OUTCOME_QUIET_LOG_ONLY, ""
    if all(isinstance(s, (ast.Assign, ast.AugAssign, ast.AnnAssign,
                          ast.Pass, ast.Expr, ast.Continue, ast.Return,
                          ast.Break)) for s in body):
        calls = [s for s in body if isinstance(s, ast.Expr)
                 and isinstance(s.value, ast.Call)]
        if calls:
            return OUTCOME_FALLBACK_ACTION, "handler calls fallback code"
        assigns = [s for s in body if isinstance(
            s, (ast.Assign, ast.AugAssign, ast.AnnAssign))]
        value = ""
        if assigns:
            try:
                value = ast.unparse(assigns[0].value)  # type: ignore[arg-type]
            except Exception:
                logger.debug("ast.unparse failed on assignment",
                             exc_info=True)
                value = "<expr>"
        return OUTCOME_ASSIGN_DEFAULT, value
    return OUTCOME_FALLBACK_ACTION, "substantial handler body"


def _collect_calls(nodes: list[ast.stmt]) -> list[str]:
    calls: list[str] = []
    for b in nodes:
        for n in ast.walk(b):
            if isinstance(n, ast.Call):
                name = _dec_name(n.func)
                if name:
                    calls.append(name)
    return calls


def _enclosing_function_names(tree: ast.Module) -> dict[int, str]:
    """Map statement-line → enclosing function name (dotted for
    methods), for attributing handlers to reviewed functions."""
    spans: list[tuple[int, int, str]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
                spans.append(
                    (child.lineno, child.end_lineno or child.lineno, name),
                )
                visit(child, name)
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}.{child.name}" if prefix
                      else child.name)
            else:
                visit(child, prefix)

    visit(tree, "")
    # Innermost span wins: sort by size, smallest last.
    spans.sort(key=lambda s: s[1] - s[0], reverse=True)
    result: dict[int, str] = {}
    for start, end, name in spans:
        for ln in range(start, end + 1):
            result[ln] = name
    return result


def python_handlers(source: str, file_path: str) -> list[HandlerOutcome]:
    """All classified exception handlers / suppress blocks in a Python
    source file. Empty list on syntax errors (never a guess)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        logger.debug("fail_open_lang: syntax error in %s", file_path)
        return []
    lines = source.splitlines()
    enclosing = _enclosing_function_names(tree)
    out: list[HandlerOutcome] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                ce = item.context_expr
                if not (isinstance(ce, ast.Call)
                        and _dec_name(ce.func).endswith("suppress")):
                    continue
                types = [_dec_name(a) or "<expr>" for a in ce.args]
                broad = any(t in ("Exception", "BaseException")
                            for t in types)
                span = (
                    node.body[0].lineno,
                    node.body[-1].end_lineno or node.body[0].lineno,
                ) if node.body else (node.lineno, node.lineno)
                out.append(HandlerOutcome(
                    idiom="contextlib_suppress",
                    file=file_path,
                    line=node.lineno,
                    caught=types,
                    broad=broad,
                    outcome_kind=OUTCOME_PASS,
                    evidence_snippet=lines[node.lineno - 1].strip()
                    if node.lineno <= len(lines) else "",
                    parser="ast",
                    enclosing_function=enclosing.get(node.lineno, ""),
                    try_calls=_collect_calls(node.body),
                    try_span=span,
                ))
            continue
        if not isinstance(node, ast.Try):
            continue
        try_span = (
            node.body[0].lineno,
            node.body[-1].end_lineno or node.body[0].lineno,
        ) if node.body else (node.lineno, node.lineno)
        try_calls = _collect_calls(node.body)
        for handler in node.handlers:
            outcome_kind, value = _classify_python_handler(handler, lines)
            types, broad = _exc_types(handler)
            snippet_end = min(
                handler.end_lineno or handler.lineno, handler.lineno + 2,
            )
            out.append(HandlerOutcome(
                idiom=f"except_{outcome_kind}",
                file=file_path,
                line=handler.lineno,
                caught=types,
                broad=broad,
                outcome_kind=outcome_kind,
                permissive_value=value,
                evidence_snippet=" ".join(
                    ln.strip()
                    for ln in lines[handler.lineno - 1:snippet_end]
                ),
                parser="ast",
                enclosing_function=enclosing.get(handler.lineno, ""),
                try_calls=try_calls,
                try_span=try_span,
            ))
    return out


def python_function_raises(
    source: str, function_name: str,
) -> list[str]:
    """Exception type names a same-file function ``raise``s.

    Fallibility evidence for leg 2b: a callee inside the try body that
    this returns non-empty for is demonstrably raise-capable."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    tail = function_name.rsplit(".", 1)[-1]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == tail:
            raised: list[str] = []
            for n in ast.walk(node):
                if isinstance(n, ast.Raise) and n.exc is not None:
                    name = _dec_name(n.exc)
                    raised.append(name or "<expr>")
                elif isinstance(n, ast.Raise):
                    raised.append("<re-raise>")
            return raised
    return []


# ── C legs: tree-sitter primary, line-regex fallback ────────────────


def _ts_parser(language: str):
    try:
        from core.audit.condition_extraction import _get_parser
        return _get_parser(language)
    except Exception:
        logger.debug("tree-sitter parser unavailable for %s", language,
                     exc_info=True)
        return None


def _ts_node_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode(
        "utf-8", errors="replace",
    )


def _call_name(node, src: bytes) -> str:
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    return _ts_node_text(fn, src)


def _line_of(node) -> int:
    return node.start_point[0] + 1


def _function_span_ts(tree, src: bytes, function_name: str,
                      language: str) -> tuple[int, int] | None:
    """(start_line, end_line) of a named function definition."""
    try:
        from core.audit.condition_extraction import _FUNCTION_TYPES
        func_types = _FUNCTION_TYPES.get(language, ())
    except ImportError:
        func_types = ("function_definition",)

    def find_name(node) -> str:
        for child in node.children:
            if child.type in ("function_declarator", "declarator",
                              "pointer_declarator"):
                inner = find_name(child)
                if inner:
                    return inner
            if child.type in ("identifier", "field_identifier"):
                return _ts_node_text(child, src)
        return ""

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in func_types and find_name(node) == function_name:
            return (node.start_point[0] + 1, node.end_point[0] + 1)
        stack.extend(node.children)
    return None


def _iter_calls_ts(tree, src: bytes, callee: str,
                   span: tuple[int, int] | None):
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "call_expression":
            name = _call_name(node, src)
            tail = name.rsplit(".", 1)[-1].rsplit("->", 1)[-1]
            if tail == callee:
                line = _line_of(node)
                if span is None or span[0] <= line <= span[1]:
                    yield node
        stack.extend(node.children)


def _classify_ignored_return_site(
    node, src: bytes, lines: list[str],
) -> CallSiteOutcome:
    """One call node → guarded/unguarded/undecided for the
    ignored-return leg."""
    line = _line_of(node)
    code = lines[line - 1].strip() if line <= len(lines) else ""
    site = CallSiteOutcome(
        file="", line=line, code=code, verdict="undecided",
        parser="tree-sitter",
    )
    cur = node.parent
    through_void_cast = False
    while cur is not None:
        t = cur.type
        if t == "cast_expression":
            cast_text = _ts_node_text(cur, src)
            if re.match(r"\(\s*void\s*\)", cast_text):
                through_void_cast = True
            cur = cur.parent
            continue
        if t == "expression_statement":
            site.verdict = "unguarded"
            site.shape = ("(void)-cast statement" if through_void_cast
                          else "bare-statement")
            site.evidence = (
                "result explicitly discarded with (void) — author saw "
                "the return but control proceeds regardless"
                if through_void_cast else
                "call result neither assigned nor compared"
            )
            return site
        if t in ("if_statement", "while_statement", "do_statement",
                 "for_statement", "conditional_expression",
                 "binary_expression", "unary_expression",
                 "condition_clause", "parenthesized_expression",
                 "switch_statement"):
            site.verdict = "guarded"
            site.shape = "tested"
            site.evidence = "call result consumed by a control condition"
            return site
        if t in ("init_declarator", "assignment_expression"):
            site.verdict = "guarded"
            site.shape = "captured"
            site.evidence = "call result assigned to a binding"
            return site
        if t == "return_statement":
            site.verdict = "guarded"
            site.shape = "propagated"
            site.evidence = "call result propagated to the caller"
            return site
        if t in ("argument_list",):
            site.verdict = "guarded"
            site.shape = "consumed-as-argument"
            site.evidence = "call result consumed by an enclosing call"
            return site
        cur = cur.parent
    site.evidence = "could not classify the call's consumption context"
    return site


# Regex fallback for the ignored-return leg: a bare call statement.
def _ignored_return_regex(
    source: str, callee: str, span: tuple[int, int] | None,
) -> list[CallSiteOutcome]:
    sites: list[CallSiteOutcome] = []
    call_re = re.compile(
        rf"^\s*(?:\(\s*void\s*\)\s*)?{re.escape(callee)}\s*\(",
    )
    used_re = re.compile(
        rf"(?:=|\breturn\b|\bif\b|\bwhile\b|[!=<>]=|&&|\|\|)"
        rf"[^;]*\b{re.escape(callee)}\s*\(",
    )
    for idx, line in enumerate(source.splitlines(), 1):
        if span and not (span[0] <= idx <= span[1]):
            continue
        if callee not in line:
            continue
        if call_re.match(line) and line.rstrip().endswith(";"):
            sites.append(CallSiteOutcome(
                file="", line=idx, code=line.strip(),
                verdict="unguarded", shape="bare-statement",
                evidence="call result neither assigned nor compared "
                         "(line-regex fallback)",
                parser="regex",
            ))
        elif used_re.search(line):
            sites.append(CallSiteOutcome(
                file="", line=idx, code=line.strip(),
                verdict="guarded", shape="consumed",
                evidence="call result assigned/tested (line-regex "
                         "fallback)",
                parser="regex",
            ))
        elif re.search(rf"\b{re.escape(callee)}\s*\(", line):
            sites.append(CallSiteOutcome(
                file="", line=idx, code=line.strip(),
                verdict="undecided", shape="unclassified",
                evidence="line-regex fallback could not classify "
                         "the consumption context",
                parser="regex",
            ))
    return sites


def c_ignored_return_sites(
    source: str,
    file_path: str,
    callee: str,
    *,
    language: str = "c",
    function_span: tuple[int, int] | None = None,
) -> list[CallSiteOutcome]:
    """Call sites of ``callee`` classified for the ignored-return leg.

    Confined to ``function_span`` when given (the hypothesis's
    function). tree-sitter primary; line-regex fallback with
    ``parser="regex"`` recorded on every site.
    """
    parser = _ts_parser(language)
    if parser is not None:
        try:
            src = source.encode("utf-8", errors="replace")
            tree = parser.parse(src)
            lines = source.splitlines()
            sites = []
            for node in _iter_calls_ts(tree, src, callee, function_span):
                site = _classify_ignored_return_site(node, src, lines)
                site.file = file_path
                sites.append(site)
            return sites
        except Exception:
            logger.debug("fail_open_lang: ts ignored-return failed for %s",
                         file_path, exc_info=True)
    sites = _ignored_return_regex(source, callee, function_span)
    for s in sites:
        s.file = file_path
    return sites


# ── C tri-state comparison shapes ───────────────────────────────────
# Contract 1=ok, 0=fail, -1=error (the EVP_VerifyFinal CVE-2008-5077
# class). A comparison shape is fail-closed iff its acceptance set is
# exactly {1}; shapes accepting -1 (or 0) are permissive; error-only
# tests (< 0) are undecided — a second check may follow.

_TRISTATE_GUARDED = {
    ("==", "1"), (">", "0"), (">=", "1"), ("!=", "1"),
    ("<", "1"), ("<=", "0"),
}
_TRISTATE_PERMISSIVE = {
    ("!=", "0"), ("==", "0"), (">=", "0"), (">", "-1"),
}
_TRISTATE_UNDECIDED = {
    ("<", "0"), ("==", "-1"), ("<=", "-1"),
}


def _classify_tristate_comparison(op: str, literal: str) -> tuple[str, str]:
    """(verdict, evidence) for a comparison of a tri-state result."""
    key = (op, literal)
    if key in _TRISTATE_GUARDED:
        return "guarded", (
            f"comparison `{op} {literal}` accepts only the success "
            "value 1 (rejects 0=fail and -1=error)"
        )
    if key in _TRISTATE_PERMISSIVE:
        return "unguarded", (
            f"comparison `{op} {literal}` accepts the error value -1 "
            "(or the failure value 0) as success"
        )
    if key in _TRISTATE_UNDECIDED:
        return "undecided", (
            f"comparison `{op} {literal}` tests only the error value; "
            "a second failure check may follow"
        )
    return "undecided", f"unrecognised comparison shape `{op} {literal}`"


def _classify_tristate_site(
    node, src: bytes, lines: list[str],
) -> CallSiteOutcome:
    line = _line_of(node)
    code = lines[line - 1].strip() if line <= len(lines) else ""
    site = CallSiteOutcome(
        file="", line=line, code=code, verdict="undecided",
        parser="tree-sitter",
    )
    cur = node.parent
    negated = False
    while cur is not None:
        t = cur.type
        if t == "parenthesized_expression":
            cur = cur.parent
            continue
        if t == "unary_expression" and _ts_node_text(
                cur, src).lstrip().startswith("!"):
            negated = not negated
            cur = cur.parent
            continue
        if t == "binary_expression":
            op_node = cur.child_by_field_name("operator")
            op = (op_node.type if op_node is not None
                  else _ts_node_text(cur, src))
            left = cur.child_by_field_name("left")
            right = cur.child_by_field_name("right")
            literal_node = None
            if left is not None and left.type == "number_literal":
                literal_node = left
                # Normalise `1 == f()` to `f() == 1` (flip relationals).
                flip = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}
                op = flip.get(op, op)
            elif right is not None and right.type in (
                    "number_literal", "unary_expression"):
                literal_node = right
            if literal_node is None:
                site.evidence = (
                    "tri-state result compared against a non-literal"
                )
                return site
            literal = _ts_node_text(literal_node, src).replace(" ", "")
            verdict, evidence = _classify_tristate_comparison(op, literal)
            site.verdict, site.evidence = verdict, evidence
            site.shape = f"{op} {literal}"
            return site
        if t in ("condition_clause", "if_statement", "while_statement",
                 "conditional_expression"):
            # Bare truth test: -1 (error) is truthy → accepted.
            site.verdict = "unguarded"
            site.shape = "!truth-test" if negated else "truth-test"
            site.evidence = (
                "boolean truth test on a tri-state result — the error "
                "value -1 is truthy and passes as success"
            )
            return site
        if t in ("init_declarator", "assignment_expression"):
            site.evidence = (
                "result captured in a binding; comparison shape not "
                "at the call site"
            )
            return site
        cur = cur.parent
    site.evidence = "could not classify the comparison context"
    return site


_TRISTATE_LINE_RE_TEMPLATE = (
    r"if\s*\(\s*(!?)\s*{callee}\s*\("
)


def _tristate_regex(
    source: str, callee: str, span: tuple[int, int] | None,
) -> list[CallSiteOutcome]:
    sites: list[CallSiteOutcome] = []
    cmp_re = re.compile(
        rf"{re.escape(callee)}\s*\([^;]*?\)\s*(==|!=|<=|>=|<|>)\s*(-?\d+)",
    )
    truth_re = re.compile(
        _TRISTATE_LINE_RE_TEMPLATE.format(callee=re.escape(callee)),
    )
    for idx, line in enumerate(source.splitlines(), 1):
        if span and not (span[0] <= idx <= span[1]):
            continue
        if callee not in line:
            continue
        m = cmp_re.search(line)
        if m:
            verdict, evidence = _classify_tristate_comparison(
                m.group(1), m.group(2),
            )
            sites.append(CallSiteOutcome(
                file="", line=idx, code=line.strip(), verdict=verdict,
                evidence=evidence + " (line-regex fallback)",
                shape=f"{m.group(1)} {m.group(2)}", parser="regex",
            ))
            continue
        if truth_re.search(line):
            sites.append(CallSiteOutcome(
                file="", line=idx, code=line.strip(), verdict="unguarded",
                evidence="boolean truth test on a tri-state result — "
                         "the error value -1 is truthy and passes as "
                         "success (line-regex fallback)",
                shape="truth-test", parser="regex",
            ))
    return sites


def c_tristate_sites(
    source: str,
    file_path: str,
    callee: str,
    *,
    language: str = "c",
    function_span: tuple[int, int] | None = None,
) -> list[CallSiteOutcome]:
    """Comparison-shape classification of every ``callee`` call for
    the tri-state contract leg (1=ok, 0=fail, -1=error)."""
    parser = _ts_parser(language)
    if parser is not None:
        try:
            src = source.encode("utf-8", errors="replace")
            tree = parser.parse(src)
            lines = source.splitlines()
            sites = []
            for node in _iter_calls_ts(tree, src, callee, function_span):
                site = _classify_tristate_site(node, src, lines)
                site.file = file_path
                sites.append(site)
            return sites
        except Exception:
            logger.debug("fail_open_lang: ts tristate failed for %s",
                         file_path, exc_info=True)
    sites = _tristate_regex(source, callee, function_span)
    for s in sites:
        s.file = file_path
    return sites


def c_function_span(
    source: str, function_name: str, *, language: str = "c",
) -> tuple[int, int] | None:
    """(start_line, end_line) of a C function definition, or None.

    tree-sitter primary; brace-counting regex fallback.
    """
    parser = _ts_parser(language)
    if parser is not None:
        try:
            src = source.encode("utf-8", errors="replace")
            tree = parser.parse(src)
            span = _function_span_ts(tree, src, function_name, language)
            if span:
                return span
        except Exception:
            logger.debug("fail_open_lang: ts span failed", exc_info=True)
    # Fallback: definition line + brace counting.
    lines = source.splitlines()
    def_re = re.compile(
        rf"^[\w\s\*]*\b{re.escape(function_name)}\s*\([^;]*$"
        rf"|^[\w\s\*]*\b{re.escape(function_name)}\s*\([^;]*\)\s*\{{?\s*$",
    )
    for idx, line in enumerate(lines, 1):
        if function_name not in line or not def_re.match(line):
            continue
        depth = 0
        opened = False
        for j in range(idx - 1, len(lines)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                opened = True
            if opened and depth <= 0:
                return (idx, j + 1)
        return (idx, len(lines))
    return None


# ── Java handler-outcome analyzer (tree-sitter) ─────────────────────
# Catch-clause classification mirrors the Python census port: the
# same outcome vocabulary, computed from the java grammar's
# catch_clause bodies. "Swallowed checked exception" is the channel's
# Java-specific fallibility story (fail_open_verify._java_fallibility):
# the type system forced the author to handle a declared-throws type
# and the handler is reflexively empty.

_JAVA_BROAD_TYPES = frozenset({"Exception", "Throwable", "RuntimeException"})
_JAVA_LOUD_LOG_RE = re.compile(r"\.(?:error|severe|fatal|warn(?:ing)?)\s*\(")
_JAVA_QUIET_LOG_RE = re.compile(
    r"\.(?:debug|trace|info|config|fine|finer|finest|log)\s*\(",
)
_JAVA_ABORT_RE = re.compile(
    r"\bSystem\.exit\s*\(|\.halt\s*\(",
)
_JAVA_PRINT_RE = re.compile(
    r"\bprintStackTrace\s*\(|\bSystem\.(?:err|out)\b",
)
_JAVA_RESTRICTIVE_RETURNS = frozenset({"false", "null", "0", "-1", '""'})

_JAVA_TRY_TYPES = ("try_statement", "try_with_resources_statement")
_JAVA_FUNC_TYPES = ("method_declaration", "constructor_declaration")
_JAVA_COMMENT_TYPES = ("line_comment", "block_comment", "{", "}")


def _java_stmts(block) -> list:
    """Named statement children of a block, comments excluded."""
    if block is None:
        return []
    return [
        c for c in block.children
        if c.is_named and c.type not in _JAVA_COMMENT_TYPES
    ]


def _java_catch_types(clause, src: bytes) -> tuple[list[str], bool]:
    """(caught type names, broad?) from the catch formal parameter
    (union types ``A | B`` yield both names)."""
    names: list[str] = []
    for param in clause.children:
        if param.type != "catch_formal_parameter":
            continue
        for child in param.children:
            if child.type != "catch_type":
                continue
            for t in child.children:
                if t.is_named:
                    name = _ts_node_text(t, src)
                    names.append(name.rsplit(".", 1)[-1])
    broad = any(n in _JAVA_BROAD_TYPES for n in names)
    return (names or ["<expr>"]), broad


def _java_calls_in(node, src: bytes) -> list[str]:
    """Dotted method-invocation names inside a node."""
    calls: list[str] = []
    stack = list(node.children) if node is not None else []
    while stack:
        cur = stack.pop()
        if cur.type in ("method_invocation", "object_creation_expression"):
            if cur.type == "method_invocation":
                name_node = cur.child_by_field_name("name")
                obj = cur.child_by_field_name("object")
                name = _ts_node_text(name_node, src) if name_node else ""
                if obj is not None and obj.type in (
                        "identifier", "field_access"):
                    name = f"{_ts_node_text(obj, src)}.{name}"
            else:
                type_node = cur.child_by_field_name("type")
                name = (_ts_node_text(type_node, src)
                        if type_node is not None else "")
            if name:
                calls.append(name)
        stack.extend(cur.children)
    return calls


def _classify_java_catch(clause, src: bytes) -> tuple[str, str]:
    """(outcome_kind, permissive_value) for one catch clause —
    the census classification vocabulary on the Java grammar."""
    block = clause.child_by_field_name("body")
    text = _ts_node_text(clause, src)

    def _has_descendant(node, node_type: str) -> bool:
        stack = list(node.children) if node is not None else []
        while stack:
            cur = stack.pop()
            if cur.type == node_type:
                return True
            # A nested try's throw still aborts this handler's
            # continuation — do not descend past lambda bodies though.
            if cur.type != "lambda_expression":
                stack.extend(cur.children)
        return False

    if _has_descendant(block, "throw_statement"):
        return OUTCOME_FAIL_CLOSED, "re-throws"
    if _JAVA_ABORT_RE.search(text):
        return OUTCOME_FAIL_CLOSED, "aborts"

    stmts = _java_stmts(block)
    if not stmts:
        return OUTCOME_PASS, ""

    returns = [s for s in stmts if s.type == "return_statement"]
    if returns and all(s.type == "return_statement" for s in stmts):
        ret = returns[0]
        exprs = [c for c in ret.children if c.is_named]
        value = _ts_node_text(exprs[0], src).strip() if exprs else ""
        if value == "" or value in _JAVA_RESTRICTIVE_RETURNS:
            return OUTCOME_FAIL_CLOSED, f"returns {value or '<void>'}"
        if value == "true":
            return OUTCOME_RETURN_PERMISSIVE, value
        if ret and exprs and exprs[0].type in (
                "decimal_integer_literal", "string_literal",
                "character_literal",
        ):
            return OUTCOME_RETURN_PERMISSIVE, value
        return OUTCOME_FALLBACK_ACTION, value

    if _JAVA_LOUD_LOG_RE.search(text):
        return OUTCOME_FALLBACK_ACTION, "loud-log-and-continue"
    if _JAVA_PRINT_RE.search(text):
        return OUTCOME_FALLBACK_ACTION, "prints-and-continues"

    if all(s.type in ("continue_statement", "break_statement")
           for s in stmts):
        return OUTCOME_CONTINUE, ""
    if _JAVA_QUIET_LOG_RE.search(text) and all(
        s.type in ("expression_statement", "return_statement")
        for s in stmts
    ):
        # Quiet log only (permissive returns alongside keep the
        # quiet-log classification; restrictive ones were caught by
        # the all-returns branch above only when the log is absent).
        non_return = [s for s in stmts if s.type == "expression_statement"]
        if all(
            _JAVA_QUIET_LOG_RE.search(_ts_node_text(s, src))
            for s in non_return
        ):
            return OUTCOME_QUIET_LOG_ONLY, ""

    assigns = [
        s for s in stmts
        if s.type == "local_variable_declaration"
        or (s.type == "expression_statement" and s.children
            and s.children[0].type == "assignment_expression")
    ]
    if assigns and all(
        s.type in ("expression_statement", "local_variable_declaration")
        for s in stmts
    ):
        calls = [
            s for s in stmts
            if s.type == "expression_statement" and s.children
            and s.children[0].type == "method_invocation"
        ]
        if calls:
            return OUTCOME_FALLBACK_ACTION, "handler calls fallback code"
        first = assigns[0]
        value = ""
        if first.type == "expression_statement" and first.children:
            rhs = first.children[0].child_by_field_name("right")
            value = _ts_node_text(rhs, src) if rhs is not None else ""
        else:
            decl = next(
                (c for c in first.children
                 if c.type == "variable_declarator"), None,
            )
            rhs = (decl.child_by_field_name("value")
                   if decl is not None else None)
            value = _ts_node_text(rhs, src) if rhs is not None else ""
        return OUTCOME_ASSIGN_DEFAULT, value
    return OUTCOME_FALLBACK_ACTION, "substantial handler body"


def _java_enclosing_function(node, src: bytes) -> str:
    cur = node.parent
    while cur is not None:
        if cur.type in _JAVA_FUNC_TYPES:
            name_node = cur.child_by_field_name("name")
            return _ts_node_text(name_node, src) if name_node else ""
        cur = cur.parent
    return ""


def java_handlers(
    source: str, file_path: str,
) -> list[HandlerOutcome] | None:
    """All classified catch clauses in a Java source file.

    ``None`` when no tree-sitter java parser is available (the channel
    reports ``language-unsupported`` — there is no honest regex
    fallback for brace-delimited handler bodies); empty list when the
    file has no handlers.
    """
    parser = _ts_parser("java")
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        logger.debug("fail_open_lang: java parse failed for %s",
                     file_path, exc_info=True)
        return None
    lines = source.splitlines()
    out: list[HandlerOutcome] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _JAVA_TRY_TYPES:
            continue
        body = node.child_by_field_name("body")
        try_calls = _java_calls_in(body, src)
        try_span = (
            (body.start_point[0] + 1, body.end_point[0] + 1)
            if body is not None else (_line_of(node), _line_of(node))
        )
        enclosing = _java_enclosing_function(node, src)
        for clause in node.children:
            if clause.type != "catch_clause":
                continue
            outcome_kind, value = _classify_java_catch(clause, src)
            caught, broad = _java_catch_types(clause, src)
            line = _line_of(clause)
            snippet_end = min(clause.end_point[0] + 1, line + 2)
            out.append(HandlerOutcome(
                idiom=f"catch_{outcome_kind}",
                file=file_path,
                line=line,
                caught=caught,
                broad=broad,
                outcome_kind=outcome_kind,
                permissive_value=value,
                evidence_snippet=" ".join(
                    ln.strip() for ln in lines[line - 1:snippet_end]
                ),
                parser="tree-sitter",
                enclosing_function=enclosing,
                try_calls=try_calls,
                try_span=try_span,
            ))
    return out


def java_function_throws(source: str, function_name: str) -> list[str]:
    """Exception types a same-file Java method declares (``throws``
    clause) or raises (``throw new X``) — leg-2b fallibility evidence.

    The declared-throws leg is the checked-exception story: the type
    system forced every caller to handle these.
    """
    parser = _ts_parser("java")
    if parser is None:
        return []
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return []
    tail = function_name.rsplit(".", 1)[-1]
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _JAVA_FUNC_TYPES:
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None or _ts_node_text(name_node, src) != tail:
            continue
        thrown: list[str] = []
        for child in node.children:
            if child.type != "throws":
                continue
            for t in child.children:
                if t.is_named:
                    thrown.append(
                        _ts_node_text(t, src).rsplit(".", 1)[-1],
                    )
        inner = [node]
        while inner:
            cur = inner.pop()
            inner.extend(cur.children)
            if cur.type == "throw_statement":
                for c in cur.children:
                    if c.type == "object_creation_expression":
                        type_node = c.child_by_field_name("type")
                        if type_node is not None:
                            thrown.append(_ts_node_text(
                                type_node, src).rsplit(".", 1)[-1])
        return list(dict.fromkeys(thrown))
    return []


def java_method_segment(source: str, function_name: str) -> str:
    """Source of a Java method (annotations included — the node span
    covers its modifiers) plus the enclosing class declaration header,
    for Tier-B hook-mechanics matching (``implements Filter``,
    ``@WebFilter``, ``@PreAuthorize`` live on the class or method)."""
    parser = _ts_parser("java")
    if parser is None:
        return ""
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return ""
    tail = function_name.rsplit(".", 1)[-1]
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _JAVA_FUNC_TYPES:
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None or _ts_node_text(name_node, src) != tail:
            continue
        segment = _ts_node_text(node, src)
        cur = node.parent
        while cur is not None and cur.type not in (
                "class_declaration", "interface_declaration"):
            cur = cur.parent
        if cur is not None:
            body = cur.child_by_field_name("body")
            header_end = (body.start_byte if body is not None
                          else cur.end_byte)
            header = src[cur.start_byte:header_end].decode(
                "utf-8", errors="replace",
            )
            segment = header.strip() + "\n" + segment
        return segment
    return ""


def java_class_extends(source: str, type_name: str) -> str | None:
    """Superclass name of a same-file Java class declaration, or
    ``None`` when the type is not declared (or not subclassed) in this
    file.

    Used to decide whether a *specifically* caught exception type is
    checked: ``catch (X e)`` around a try body compiles only when the
    body can throw ``X`` — but only for checked ``X`` (javac rejects a
    catch of a checked type nothing in the body throws). A same-file
    ``class X extends Exception`` (not RuntimeException/Error) makes
    the catch clause itself the fallibility witness.
    """
    parser = _ts_parser("java")
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return None
    tail = type_name.rsplit(".", 1)[-1]
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "class_declaration":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None or _ts_node_text(name_node, src) != tail:
            continue
        for child in node.children:
            if child.type == "superclass":
                for t in child.children:
                    if t.is_named:
                        return _ts_node_text(t, src).rsplit(".", 1)[-1]
        return None
    return None


# ── Go legs: discarded errors + recover()-to-continue ───────────────
# Go has no exceptions: the handler-outcome question splits into (a)
# what happens to the `error` second return (blank-discarded /
# assigned-never-checked / bare call statement) and (b) whether a
# deferred recover() swallows panics and lets the request/loop
# continue. CWE-252 premise split: these sites are adjudicated here
# only for role-bound, hypothesis-driven checks; the contract/majority
# census sweep over ALL callees is the consistency programme's
# (callsite_consistency), which classifies the same Go shapes with its
# usage enum and hands acknowledged discards of security-role callees
# back to this channel as fail-open hypotheses.

_GO_FUNC_TYPES = ("function_declaration", "method_declaration")
_GO_ABORT_RE = re.compile(
    r"\bos\.Exit\s*\(|\blog\.Fatal\w*\s*\(|\bpanic\s*\(",
)


def _go_enclosing_function(node, src: bytes):
    cur = node.parent
    while cur is not None:
        if cur.type in _GO_FUNC_TYPES:
            return cur
        cur = cur.parent
    return None


def _go_function_name(func_node, src: bytes) -> str:
    if func_node is None:
        return ""
    name_node = func_node.child_by_field_name("name")
    return _ts_node_text(name_node, src) if name_node is not None else ""


def _go_calls_in(node, src: bytes, *, skip=None) -> list[str]:
    """Call names inside a node (selector calls dotted), optionally
    skipping one subtree (the recover defer literal itself)."""
    calls: list[str] = []
    stack = list(node.children) if node is not None else []
    while stack:
        cur = stack.pop()
        if skip is not None and cur == skip:
            continue
        if cur.type == "call_expression":
            name = _call_name(cur, src)
            # Identifier-shaped names only: a func-literal invocation's
            # "name" is the literal's whole source text.
            if name and name != "recover" \
                    and re.fullmatch(r"[A-Za-z_][\w.]*", name):
                calls.append(name)
        stack.extend(cur.children)
    return calls


def go_recover_handlers(
    source: str, file_path: str,
) -> list[HandlerOutcome] | None:
    """Deferred ``recover()`` blocks, classified.

    A ``defer func(){ ... recover() ... }()`` whose body neither
    re-panics nor aborts swallows every panic in the enclosing
    function — ``recover_continue``, a permissive outcome. Re-panic /
    ``os.Exit`` / ``log.Fatal`` bodies are fail-closed. ``None`` when
    no tree-sitter go parser is available.
    """
    parser = _ts_parser("go")
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        logger.debug("fail_open_lang: go parse failed for %s",
                     file_path, exc_info=True)
        return None
    lines = source.splitlines()
    out: list[HandlerOutcome] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "defer_statement":
            continue
        call = next(
            (c for c in node.children if c.type == "call_expression"),
            None,
        )
        if call is None:
            continue
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "func_literal":
            continue
        literal_text = _ts_node_text(fn, src)
        if not re.search(r"\brecover\s*\(\s*\)", literal_text):
            continue
        body_after_recover = literal_text.split("recover", 1)[1]
        if _GO_ABORT_RE.search(body_after_recover):
            outcome_kind = OUTCOME_FAIL_CLOSED
            value = ("re-panics" if "panic" in body_after_recover
                     else "aborts")
        else:
            outcome_kind = OUTCOME_RECOVER_CONTINUE
            value = ("recovered-and-logged"
                     if re.search(r"\blog\.", body_after_recover)
                     else "recovered-and-discarded")
        func_node = _go_enclosing_function(node, src)
        func_name = _go_function_name(func_node, src)
        # The guarded region is the whole enclosing function: a
        # deferred recover swallows a panic raised anywhere in it.
        region = (func_node.child_by_field_name("body")
                  if func_node is not None else None)
        try_calls = _go_calls_in(region, src, skip=fn)
        try_span = (
            (region.start_point[0] + 1, region.end_point[0] + 1)
            if region is not None
            else (_line_of(node), _line_of(node))
        )
        line = _line_of(node)
        out.append(HandlerOutcome(
            idiom="recover_continue",
            file=file_path,
            line=line,
            caught=["<panic>"],
            broad=True,
            outcome_kind=outcome_kind,
            permissive_value=value,
            evidence_snippet=" ".join(
                ln.strip()
                for ln in lines[line - 1:min(len(lines), line + 2)]
            ),
            parser="tree-sitter",
            enclosing_function=func_name,
            try_calls=try_calls,
            try_span=try_span,
        ))
    return out


def _go_err_binding_name(assign, src: bytes) -> tuple[str, list[str]]:
    """(last-LHS identifier, all LHS identifiers) of a Go assignment /
    short var declaration — the error binding is conventionally last."""
    left = assign.child_by_field_name("left")
    if left is None or left.type != "expression_list":
        return "", []
    names = [
        _ts_node_text(c, src)
        for c in left.children
        if c.type == "identifier"
    ]
    return (names[-1] if names else ""), names


def _go_next_use(func_node, src: bytes, var: str, after_byte: int):
    """First identifier node spelling ``var`` after ``after_byte`` in
    the function, or None."""
    if func_node is None:
        return None
    best = None
    stack = [func_node]
    while stack:
        cur = stack.pop()
        if cur.type == "identifier" and cur.start_byte > after_byte \
                and _ts_node_text(cur, src) == var:
            if best is None or cur.start_byte < best.start_byte:
                best = cur
        stack.extend(cur.children)
    return best


def _go_use_is_reassignment(use, src: bytes) -> bool:
    """Is this identifier occurrence an LHS position of `=`/`:=`?"""
    cur = use
    while cur.parent is not None:
        parent = cur.parent
        if parent.type == "expression_list":
            grand = parent.parent
            if grand is not None and grand.type in (
                    "assignment_statement", "short_var_declaration"):
                return grand.child_by_field_name("left") == parent
        cur = parent
        if cur.type in ("block",) + _GO_FUNC_TYPES:
            break
    return False


def _classify_go_call_site(
    node, src: bytes, lines: list[str],
) -> CallSiteOutcome:
    """One Go call node → guarded/unguarded/undecided for the
    discarded-error leg."""
    line = _line_of(node)
    code = lines[line - 1].strip() if line <= len(lines) else ""
    site = CallSiteOutcome(
        file="", line=line, code=code, verdict="undecided",
        parser="tree-sitter",
    )
    cur = node.parent
    while cur is not None:
        t = cur.type
        if t == "expression_statement":
            site.verdict = "unguarded"
            site.shape = "bare-statement"
            site.evidence = (
                "call result neither assigned nor compared"
            )
            return site
        if t in ("assignment_statement", "short_var_declaration"):
            err_var, names = _go_err_binding_name(cur, src)
            if not err_var:
                site.evidence = "unrecognised assignment shape"
                return site
            if err_var == "_":
                site.verdict = "unguarded"
                site.shape = "blank-discard"
                site.evidence = (
                    "error result explicitly discarded with the "
                    "blank identifier"
                )
                return site
            func_node = _go_enclosing_function(cur, src)
            use = _go_next_use(func_node, src, err_var, cur.end_byte)
            if use is None:
                site.verdict = "unguarded"
                site.shape = "err-never-checked"
                site.evidence = (
                    f"`{err_var}` bound at line {line} is never "
                    "read afterwards in this function"
                )
                return site
            if _go_use_is_reassignment(use, src):
                site.verdict = "unguarded"
                site.shape = "err-overwritten-before-check"
                site.evidence = (
                    f"`{err_var}` bound at line {line} is "
                    f"reassigned at line {_line_of(use)} before any "
                    "check"
                )
                return site
            site.verdict = "guarded"
            site.shape = "tested"
            site.evidence = (
                f"`{err_var}` consumed at line {_line_of(use)}"
            )
            return site
        if t in ("if_statement", "binary_expression", "for_statement",
                 "expression_switch_statement", "unary_expression",
                 "parenthesized_expression"):
            site.verdict = "guarded"
            site.shape = "tested"
            site.evidence = "call result consumed by a control condition"
            return site
        if t == "return_statement":
            site.verdict = "guarded"
            site.shape = "propagated"
            site.evidence = "call result propagated to the caller"
            return site
        if t == "argument_list":
            site.verdict = "guarded"
            site.shape = "consumed-as-argument"
            site.evidence = "call result consumed by an enclosing call"
            return site
        cur = cur.parent
    site.evidence = "could not classify the call's consumption context"
    return site


def go_discard_sites(
    source: str,
    file_path: str,
    callee: str,
    *,
    function_span: tuple[int, int] | None = None,
) -> list[CallSiteOutcome] | None:
    """Call sites of ``callee`` classified for the Go discarded-error
    leg. ``None`` when no tree-sitter go parser is available (dominance
    of an `if err != nil` check is not honestly decidable from line
    shapes)."""
    parser = _ts_parser("go")
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
        lines = source.splitlines()
    except Exception:
        logger.debug("fail_open_lang: go discard scan failed for %s",
                     file_path, exc_info=True)
        return None
    sites = []
    for node in _iter_calls_ts(tree, src, callee, function_span):
        site = _classify_go_call_site(node, src, lines)
        site.file = file_path
        sites.append(site)
    return sites


def go_function_returns_error(source: str, function_name: str) -> bool:
    """True when a same-file Go function's result type includes
    ``error`` — the leg-2b fallibility witness for the discard leg."""
    parser = _ts_parser("go")
    tail = function_name.rsplit(".", 1)[-1]
    if parser is not None:
        try:
            src = source.encode("utf-8", errors="replace")
            tree = parser.parse(src)
            stack = [tree.root_node]
            while stack:
                node = stack.pop()
                stack.extend(node.children)
                if node.type not in _GO_FUNC_TYPES:
                    continue
                if _go_function_name(node, src) != tail:
                    continue
                result = node.child_by_field_name("result")
                if result is None:
                    return False
                return bool(re.search(
                    r"\berror\b", _ts_node_text(result, src),
                ))
            return False
        except Exception:
            logger.debug("fail_open_lang: go signature scan failed",
                         exc_info=True)
    # Line-regex fallback: `func [recv] name(...) (..., error) {` or
    # `func name(...) error {`.
    return bool(re.search(
        rf"func\s+(?:\([^)]*\)\s*)?{re.escape(tail)}\s*\([^)]*\)\s*"
        rf"(?:\([^()]*\berror\b[^()]*\)|error)\s*\{{",
        source,
    ))


def go_function_span(
    source: str, function_name: str,
) -> tuple[int, int] | None:
    """(start_line, end_line) of a Go function/method, or None."""
    parser = _ts_parser("go")
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return None
    tail = function_name.rsplit(".", 1)[-1]
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type in _GO_FUNC_TYPES \
                and _go_function_name(node, src) == tail:
            return (node.start_point[0] + 1, node.end_point[0] + 1)
    return None


def function_parameters(
    source: str, function_name: str, language: str,
) -> list[str]:
    """Parameter names of a same-file function — the leg-3 escalator's
    source-identifier candidates.

    Python uses stdlib ast (exact); tree-sitter languages extract the
    identifier nodes of the function's parameter list (coarse for C
    declarators, but the flow check's own identifier-consistency
    control rejects a mis-bound source downstream). Empty list when
    unresolvable — the escalator then simply does not run.
    """
    tail = function_name.rsplit(".", 1)[-1] if function_name else ""
    if not tail:
        return []
    if language == "python":
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and node.name == tail:
                args = node.args
                names = [
                    a.arg
                    for a in (args.posonlyargs + args.args
                              + args.kwonlyargs)
                ]
                if args.vararg:
                    names.append(args.vararg.arg)
                if args.kwarg:
                    names.append(args.kwarg.arg)
                return [n for n in names if n not in ("self", "cls")]
        return []

    parser = _ts_parser(language)
    if parser is None:
        return []
    try:
        from core.audit.condition_extraction import _FUNCTION_TYPES
        func_types = _FUNCTION_TYPES.get(language, ())
    except ImportError:
        func_types = ()
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return []

    def _name_of(node) -> str:
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            return _ts_node_text(name_node, src)
        # C: the identifier lives inside the declarator chain.
        return _function_name_c(node, src)

    def _function_name_c(node, src_bytes: bytes) -> str:
        for child in node.children:
            if child.type in ("function_declarator", "declarator",
                              "pointer_declarator"):
                inner = _function_name_c(child, src_bytes)
                if inner:
                    return inner
            if child.type in ("identifier", "field_identifier"):
                return _ts_node_text(child, src_bytes)
        return ""

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in func_types or _name_of(node) != tail:
            continue
        params: list[str] = []
        # The grammar's parameters field when present (Go methods:
        # skips the receiver list); else the first parameters node not
        # inside the body (C nests it in the declarator chain).
        param_node = node.child_by_field_name("parameters")
        search = [] if param_node is not None else [
            c for c in node.children
            if c.type not in ("block", "compound_statement", "body")
        ]
        while search and param_node is None:
            cur = search.pop(0)
            if cur.type in ("parameters", "parameter_list",
                            "formal_parameters"):
                param_node = cur
                break
            search.extend(cur.children)
        param_stack = [param_node] if param_node is not None else []
        while param_stack:
            cur = param_stack.pop()
            if cur.type == "identifier":
                params.append(_ts_node_text(cur, src))
                continue
            param_stack.extend(cur.children)
        return params
    return []
