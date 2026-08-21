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

Phase 3 adds JS/TS (catch-clause outcomes on the shared census
vocabulary, promise ``.catch(() => {})`` swallows, and floating-
promise call sites for the unawaited leg) and Rust (ignored ``Result``
shapes — ``let _ =`` discards, ``.ok()`` drops, ``unwrap_or_default``
error-erasure — where ``unwrap``/``expect``/``?`` are *fail-closed*
consumptions: Rust's idiom for "ignored error" is not Go's). Both
follow the Java/Go no-regex-fallback rule: a missing grammar reports
``None`` and the channel returns ``inconclusive("language-
unsupported")`` rather than guessing.

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

# Languages with an analyzer. Phase 3 added JS/TS and Rust.
SUPPORTED_LANGUAGES = frozenset({
    "python", "c", "cpp", "java", "go",
    "javascript", "typescript", "tsx", "rust",
})

# The JS analyzer family shares one grammar-node vocabulary; the
# language id is passed through to the parser so .ts/.tsx files use
# their own grammars.
JS_LANGUAGES = frozenset({"javascript", "typescript", "tsx"})

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

    # Explicit-stack walk — recursion depth would track the AST
    # nesting depth and overflow on deeply nested (possibly
    # adversarial) inputs the parser itself still accepts.
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        node, prefix = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
                spans.append(
                    (child.lineno, child.end_lineno or child.lineno, name),
                )
                stack.append((child, name))
            elif isinstance(child, ast.ClassDef):
                stack.append((child, f"{prefix}.{child.name}" if prefix
                              else child.name))
            else:
                stack.append((child, prefix))
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


# ── JS/TS legs: catch-clause outcomes + promise swallows ────────────
# The handler-outcome vocabulary on the javascript/typescript
# grammars. Two handler families: syntactic ``catch`` clauses (always
# broad — JS catch carries no type filter) and promise ``.catch(fn)``
# callbacks with an inline function/arrow handler. The unawaited leg
# (RULE_UNAWAITED) classifies call sites of a hypothesis-named callee
# for the floating-promise shape. No regex fallback for any of them
# (the Java rule: brace-delimited handler bodies are not honestly
# classifiable from line shapes).

_JS_FUNC_TYPES = (
    "function_declaration", "function_expression", "method_definition",
    "arrow_function", "generator_function_declaration",
)
_JS_LOUD_LOG_RE = re.compile(r"\.(?:error|warn)\s*\(")
_JS_QUIET_LOG_RE = re.compile(r"\.(?:debug|trace|info|log)\s*\(")
_JS_ABORT_RE = re.compile(r"\bprocess\.(?:exit|abort)\s*\(")
_JS_RESTRICTIVE_RETURNS = frozenset({
    "false", "null", "undefined", "0", "-1", '""', "''", "``",
})
_JS_COMMENT_TYPES = ("comment", "{", "}")
# Promise combinator properties: ``catch`` receives the rejection;
# ``then``'s second argument would too but the inline-``.catch`` shape
# is the swallow idiom the channel adjudicates.
_JS_HANDLER_FN_TYPES = ("arrow_function", "function_expression")


def _js_stmts(block) -> list:
    if block is None:
        return []
    return [
        c for c in block.children
        if c.is_named and c.type not in _JS_COMMENT_TYPES
    ]


def _js_calls_in(node, src: bytes) -> list[str]:
    """Dotted call names inside a node (chained-call receivers whose
    text is not name-shaped are skipped; their inner calls are still
    visited)."""
    calls: list[str] = []
    stack = list(node.children) if node is not None else []
    while stack:
        cur = stack.pop()
        if cur.type in ("call_expression", "new_expression"):
            fn = cur.child_by_field_name(
                "function") or cur.child_by_field_name("constructor")
            if fn is not None:
                name = _ts_node_text(fn, src)
                if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*",
                                name):
                    calls.append(name)
        stack.extend(cur.children)
    return calls


def _js_has_descendant(node, node_type: str) -> bool:
    """Descendant search that does not cross nested function bodies
    (a throw inside a callback does not abort this handler)."""
    stack = list(node.children) if node is not None else []
    while stack:
        cur = stack.pop()
        if cur.type == node_type:
            return True
        if cur.type not in _JS_FUNC_TYPES:
            stack.extend(cur.children)
    return False


def _js_return_value_class(value_text: str, value_node) -> tuple[str, str]:
    """(outcome_kind, value_repr) for a returned/expression value."""
    text = value_text.strip()
    if text == "" or text in _JS_RESTRICTIVE_RETURNS:
        return OUTCOME_FAIL_CLOSED, f"returns {text or '<void>'}"
    if text == "true":
        return OUTCOME_RETURN_PERMISSIVE, text
    if value_node is not None and value_node.type in (
            "number", "string", "template_string", "object", "array"):
        return OUTCOME_RETURN_PERMISSIVE, text
    return OUTCOME_FALLBACK_ACTION, text


def _classify_js_handler_body(body, src: bytes) -> tuple[str, str]:
    """(outcome_kind, permissive_value) for a catch-clause body or a
    ``.catch`` callback body — the census classification vocabulary on
    the JS grammar. ``body`` may be a statement_block or an arrow
    function's bare expression body."""
    if body is None:
        return OUTCOME_PASS, ""
    text = _ts_node_text(body, src)

    if body.type != "statement_block":
        # Arrow expression body: () => null / () => defaultValue.
        if _js_has_descendant(body, "call_expression") \
                or body.type == "call_expression":
            return OUTCOME_FALLBACK_ACTION, "handler calls fallback code"
        return _js_return_value_class(text, body)

    if _js_has_descendant(body, "throw_statement"):
        return OUTCOME_FAIL_CLOSED, "re-throws"
    if _JS_ABORT_RE.search(text):
        return OUTCOME_FAIL_CLOSED, "aborts"

    stmts = _js_stmts(body)
    if not stmts:
        return OUTCOME_PASS, ""

    returns = [s for s in stmts if s.type == "return_statement"]
    if returns and all(s.type == "return_statement" for s in stmts):
        exprs = [c for c in returns[0].children if c.is_named]
        value_node = exprs[0] if exprs else None
        value = _ts_node_text(value_node, src) if value_node else ""
        return _js_return_value_class(value, value_node)

    if _JS_LOUD_LOG_RE.search(text):
        return OUTCOME_FALLBACK_ACTION, "loud-log-and-continue"

    if all(s.type in ("continue_statement", "break_statement")
           for s in stmts):
        return OUTCOME_CONTINUE, ""
    if _JS_QUIET_LOG_RE.search(text) and all(
        s.type in ("expression_statement", "return_statement")
        for s in stmts
    ):
        non_return = [s for s in stmts if s.type == "expression_statement"]
        if all(
            _JS_QUIET_LOG_RE.search(_ts_node_text(s, src))
            for s in non_return
        ):
            return OUTCOME_QUIET_LOG_ONLY, ""

    assigns = [
        s for s in stmts
        if s.type in ("lexical_declaration", "variable_declaration")
        or (s.type == "expression_statement" and s.children
            and s.children[0].type in ("assignment_expression",
                                       "augmented_assignment_expression"))
    ]
    if assigns and all(
        s.type in ("expression_statement", "lexical_declaration",
                   "variable_declaration") for s in stmts
    ):
        calls = [
            s for s in stmts
            if s.type == "expression_statement" and s.children
            and s.children[0].type == "call_expression"
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


def _js_enclosing_function(node, src: bytes) -> str:
    """Nearest named enclosing function: declaration/method name, or
    the variable/property an anonymous function is bound to."""
    cur = node.parent
    while cur is not None:
        if cur.type in _JS_FUNC_TYPES:
            name_node = cur.child_by_field_name("name")
            if name_node is not None:
                return _ts_node_text(name_node, src)
            parent = cur.parent
            if parent is not None and parent.type == "variable_declarator":
                bound = parent.child_by_field_name("name")
                if bound is not None:
                    return _ts_node_text(bound, src)
            if parent is not None and parent.type == "pair":
                key = parent.child_by_field_name("key")
                if key is not None:
                    return _ts_node_text(key, src)
            if parent is not None and parent.type in (
                    "assignment_expression",):
                lhs = parent.child_by_field_name("left")
                if lhs is not None:
                    return _ts_node_text(lhs, src)
        cur = cur.parent
    return ""


def _js_promise_catch_handler(node, src: bytes):
    """(receiver, callback_body) when *node* is a promise
    ``.catch(fn)`` call with an inline handler, else None."""
    if node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "member_expression":
        return None
    prop = fn.child_by_field_name("property")
    if prop is None or _ts_node_text(prop, src) != "catch":
        return None
    args = node.child_by_field_name("arguments")
    handler = next(
        (a for a in (args.children if args is not None else [])
         if a.type in _JS_HANDLER_FN_TYPES),
        None,
    )
    if handler is None:
        return None
    receiver = fn.child_by_field_name("object")
    return receiver, handler.child_by_field_name("body")


def js_handlers(
    source: str, file_path: str, *, language: str = "javascript",
) -> list[HandlerOutcome] | None:
    """All classified error handlers in a JS/TS source file: syntactic
    catch clauses and inline promise ``.catch`` callbacks.

    ``None`` when no tree-sitter grammar for *language* is available
    (the channel reports ``language-unsupported`` — no regex fallback
    for brace-delimited handler bodies); empty list when the file has
    no handlers.
    """
    parser = _ts_parser(language)
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        logger.debug("fail_open_lang: %s parse failed for %s",
                     language, file_path, exc_info=True)
        return None
    lines = source.splitlines()
    out: list[HandlerOutcome] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)

        if node.type == "try_statement":
            body = node.child_by_field_name("body")
            try_calls = _js_calls_in(body, src)
            try_span = (
                (body.start_point[0] + 1, body.end_point[0] + 1)
                if body is not None else (_line_of(node), _line_of(node))
            )
            handler = node.child_by_field_name("handler")
            if handler is None:
                continue
            outcome_kind, value = _classify_js_handler_body(
                handler.child_by_field_name("body"), src,
            )
            line = _line_of(handler)
            snippet_end = min(handler.end_point[0] + 1, line + 2)
            out.append(HandlerOutcome(
                idiom=f"catch_{outcome_kind}",
                file=file_path,
                line=line,
                caught=["<any>"],   # JS catch has no type filter
                broad=True,
                outcome_kind=outcome_kind,
                permissive_value=value,
                evidence_snippet=" ".join(
                    ln.strip() for ln in lines[line - 1:snippet_end]
                ),
                parser="tree-sitter",
                enclosing_function=_js_enclosing_function(node, src),
                try_calls=try_calls,
                try_span=try_span,
            ))
            continue

        promise = _js_promise_catch_handler(node, src)
        if promise is None:
            continue
        receiver, callback_body = promise
        outcome_kind, value = _classify_js_handler_body(
            callback_body, src,
        )
        receiver_calls = _js_calls_in(receiver, src) if receiver else []
        if receiver is not None and receiver.type == "call_expression":
            fn = receiver.child_by_field_name("function")
            if fn is not None:
                name = _ts_node_text(fn, src)
                if re.fullmatch(
                        r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", name):
                    receiver_calls.insert(0, name)
        line = _line_of(node)
        span = (
            (receiver.start_point[0] + 1, receiver.end_point[0] + 1)
            if receiver is not None else (line, line)
        )
        out.append(HandlerOutcome(
            idiom=f"promise_catch_{outcome_kind}",
            file=file_path,
            line=line,
            caught=["<rejection>"],
            broad=True,
            outcome_kind=outcome_kind,
            permissive_value=value,
            evidence_snippet=" ".join(
                ln.strip()
                for ln in lines[line - 1:min(len(lines), line + 2)]
            ),
            parser="tree-sitter",
            enclosing_function=_js_enclosing_function(node, src),
            try_calls=receiver_calls,
            try_span=span,
        ))
    return out


def _js_named_function_node(tree, src: bytes, function_name: str):
    """The named function's node: declaration/method name match, or an
    anonymous function bound to a matching variable/property."""
    tail = function_name.rsplit(".", 1)[-1]
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _JS_FUNC_TYPES:
            continue
        name_node = node.child_by_field_name("name")
        if name_node is not None and _ts_node_text(name_node, src) == tail:
            return node
        parent = node.parent
        if parent is not None and parent.type == "variable_declarator":
            bound = parent.child_by_field_name("name")
            if bound is not None and _ts_node_text(bound, src) == tail:
                return node
        if parent is not None and parent.type == "pair":
            key = parent.child_by_field_name("key")
            if key is not None and _ts_node_text(key, src) == tail:
                return node
    return None


def js_function_span(
    source: str, function_name: str, *, language: str = "javascript",
) -> tuple[int, int] | None:
    """(start_line, end_line) of a JS/TS function, or None."""
    parser = _ts_parser(language)
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return None
    node = _js_named_function_node(tree, src, function_name)
    if node is None:
        return None
    return (node.start_point[0] + 1, node.end_point[0] + 1)


def js_function_throws(
    source: str, function_name: str, *, language: str = "javascript",
) -> list[str]:
    """Exception/type names a same-file JS/TS function ``throw``s —
    leg-2b fallibility evidence for the handler-outcome leg."""
    parser = _ts_parser(language)
    if parser is None:
        return []
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return []
    node = _js_named_function_node(tree, src, function_name)
    if node is None:
        return []
    thrown: list[str] = []
    stack = list(node.children)
    while stack:
        cur = stack.pop()
        stack.extend(cur.children)
        if cur.type != "throw_statement":
            continue
        new_expr = next(
            (c for c in cur.children if c.type == "new_expression"), None,
        )
        if new_expr is not None:
            ctor = new_expr.child_by_field_name("constructor")
            thrown.append(
                _ts_node_text(ctor, src).rsplit(".", 1)[-1]
                if ctor is not None else "<expr>",
            )
        else:
            thrown.append("<expr>")
    return list(dict.fromkeys(thrown))


def js_function_returns_promise(
    source: str, function_name: str, *, language: str = "javascript",
) -> bool:
    """True when a same-file JS/TS function demonstrably returns a
    promise: declared ``async``, or its body constructs
    ``new Promise`` — the unawaited leg's fallibility witness."""
    parser = _ts_parser(language)
    if parser is None:
        return False
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return False
    node = _js_named_function_node(tree, src, function_name)
    if node is None:
        return False
    if any(c.type == "async" or (not c.is_named
                                 and _ts_node_text(c, src) == "async")
           for c in node.children):
        return True
    return bool(re.search(r"\bnew\s+Promise\s*\(",
                          _ts_node_text(node, src)))


def _js_call_tail(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _iter_js_calls(tree, src: bytes, callee: str,
                   span: tuple[int, int] | None):
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None:
            continue
        name = _ts_node_text(fn, src)
        if "(" in name:            # chained receiver, not a name
            continue
        if _js_call_tail(name) != callee:
            continue
        line = _line_of(node)
        if span is None or span[0] <= line <= span[1]:
            yield node


def _classify_js_unawaited_site(
    node, src: bytes, lines: list[str],
) -> CallSiteOutcome:
    """One JS call node → guarded/unguarded/undecided for the
    floating-promise (unawaited) leg."""
    line = _line_of(node)
    code = lines[line - 1].strip() if line <= len(lines) else ""
    site = CallSiteOutcome(
        file="", line=line, code=code, verdict="undecided",
        parser="tree-sitter",
    )
    cur = node.parent
    prev = node
    while cur is not None:
        t = cur.type
        if t == "await_expression":
            site.verdict = "guarded"
            site.shape = "awaited"
            site.evidence = "call is awaited — a rejection propagates"
            return site
        if t == "member_expression" \
                and cur.child_by_field_name("object") == prev:
            prop = cur.child_by_field_name("property")
            prop_name = _ts_node_text(prop, src) if prop else ""
            if prop_name in ("then", "catch"):
                site.verdict = "guarded"
                site.shape = f".{prop_name}-chained"
                site.evidence = (
                    f"a .{prop_name} handler is attached to the "
                    "returned promise"
                )
                return site
            # .finally / other chaining does not receive the
            # rejection — keep walking from the outer call.
            prev, cur = cur, cur.parent
            continue
        if t == "unary_expression" and _ts_node_text(
                cur, src).lstrip().startswith("void"):
            site.verdict = "unguarded"
            site.shape = "void-discard"
            site.evidence = (
                "promise explicitly discarded with `void` — the "
                "author saw the result but any rejection is swallowed"
            )
            return site
        if t == "expression_statement":
            site.verdict = "unguarded"
            site.shape = "floating-promise"
            site.evidence = (
                "promise neither awaited nor given a handler — a "
                "rejection is silently unobserved"
            )
            return site
        if t in ("variable_declarator", "assignment_expression"):
            site.evidence = (
                "promise captured in a binding; its consumption is "
                "not traced"
            )
            return site
        if t == "return_statement" or (
                t in _JS_FUNC_TYPES
                and cur.child_by_field_name("body") == prev):
            site.verdict = "guarded"
            site.shape = "propagated"
            site.evidence = "promise propagated to the caller"
            return site
        if t == "arguments":
            site.verdict = "guarded"
            site.shape = "consumed-as-argument"
            site.evidence = "promise consumed by an enclosing call"
            return site
        prev, cur = cur, cur.parent
    site.evidence = "could not classify the call's consumption context"
    return site


def js_unawaited_sites(
    source: str,
    file_path: str,
    callee: str,
    *,
    language: str = "javascript",
    function_span: tuple[int, int] | None = None,
) -> list[CallSiteOutcome] | None:
    """Call sites of ``callee`` classified for the unawaited /
    floating-promise leg. ``None`` when no tree-sitter grammar for
    *language* is available."""
    parser = _ts_parser(language)
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
        lines = source.splitlines()
    except Exception:
        logger.debug("fail_open_lang: js unawaited scan failed for %s",
                     file_path, exc_info=True)
        return None
    sites = []
    for node in _iter_js_calls(tree, src, callee, function_span):
        site = _classify_js_unawaited_site(node, src, lines)
        site.file = file_path
        sites.append(site)
    return sites


# ── Rust leg: ignored Result shapes ─────────────────────────────────
# Rust's idiom for "ignored error" differs from Go's: `unwrap()` /
# `expect()` / `?` all CONSUME the Result fail-closed (panic or
# propagate), while `let _ =`, a bare statement, `.ok()` dropped on
# the floor, and `unwrap_or_default()` erase the error branch — the
# failure becomes indistinguishable from success. The census sweep
# over ALL callees stays with the consistency programme (CWE-252
# premise split); this leg adjudicates role-bound hypotheses only.

_RUST_FUNC_TYPES = ("function_item",)
# Result-consuming method vocabulary (each set stays under the seed
# cap; these are stdlib method names — properties of the platform).
_RUST_PANIC_METHODS = frozenset({"unwrap", "expect"})
_RUST_DEFAULT_METHODS = frozenset({
    "unwrap_or", "unwrap_or_default", "unwrap_or_else",
})
_RUST_TEST_METHODS = frozenset({"is_ok", "is_err"})
_RUST_PASSTHROUGH_METHODS = frozenset({
    "ok", "err", "map", "map_err", "inspect_err", "and_then",
})


def _rust_call_tail(name: str) -> str:
    return name.rsplit("::", 1)[-1].rsplit(".", 1)[-1]


def _iter_rust_calls(tree, src: bytes, callee: str,
                     span: tuple[int, int] | None):
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None:
            continue
        name = _ts_node_text(fn, src)
        if "(" in name:            # method on a chained receiver
            continue
        if _rust_call_tail(name) != callee:
            continue
        line = _line_of(node)
        if span is None or span[0] <= line <= span[1]:
            yield node


def _rust_enclosing_function(node):
    cur = node.parent
    while cur is not None:
        if cur.type in _RUST_FUNC_TYPES:
            return cur
        cur = cur.parent
    return None


def _rust_next_use(func_node, src: bytes, var: str, after_byte: int):
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


def _classify_rust_let(cur, node, src: bytes, site, line: int,
                       through: list[str]):
    """Classify a ``let`` binding of the call result."""
    pattern = cur.child_by_field_name("pattern")
    if pattern is None:
        pattern = next(
            (c for c in cur.children if c.is_named
             or c.type == "_"), None,
        )
    ptype = pattern.type if pattern is not None else ""
    if ptype == "_":
        site.verdict = "unguarded"
        site.shape = "let-underscore-discard"
        site.evidence = (
            "Result explicitly discarded with `let _ =` — the author "
            "saw the return but the error branch cannot alter control"
        )
        return site
    if ptype == "identifier":
        var = _ts_node_text(pattern, src)
        if var.startswith("_"):
            site.verdict = "unguarded"
            site.shape = "let-underscore-discard"
            site.evidence = (
                f"Result bound to the deliberately-unused `{var}` — "
                "the error branch cannot alter control"
            )
            return site
        func_node = _rust_enclosing_function(cur)
        use = _rust_next_use(func_node, src, var, cur.end_byte)
        if use is None:
            site.verdict = "unguarded"
            site.shape = "result-never-checked"
            site.evidence = (
                f"`{var}` bound at line {line} is never read "
                "afterwards in this function"
            )
            return site
        site.verdict = "guarded"
        site.shape = "captured"
        site.evidence = f"`{var}` consumed at line {_line_of(use)}"
        return site
    # Destructuring patterns (let-else, tuple structs) consume the
    # variants explicitly.
    site.verdict = "guarded"
    site.shape = "destructured"
    site.evidence = "Result destructured by a pattern"
    return site


def _classify_rust_call_site(
    node, src: bytes, lines: list[str],
) -> CallSiteOutcome:
    """One Rust call node → guarded/unguarded/undecided for the
    ignored-Result leg."""
    line = _line_of(node)
    code = lines[line - 1].strip() if line <= len(lines) else ""
    site = CallSiteOutcome(
        file="", line=line, code=code, verdict="undecided",
        parser="tree-sitter",
    )
    cur = node.parent
    prev = node
    through: list[str] = []
    while cur is not None:
        t = cur.type
        if t == "field_expression" \
                and cur.child_by_field_name("value") == prev:
            field = cur.child_by_field_name("field")
            method = _ts_node_text(field, src) if field else ""
            outer = cur.parent
            if outer is None or outer.type != "call_expression":
                # Plain field access on the result — not a Result
                # consumption we can classify.
                site.evidence = (
                    f"field `{method}` accessed on the result; "
                    "consumption shape unrecognised"
                )
                return site
            if method in _RUST_PANIC_METHODS:
                site.verdict = "guarded"
                site.shape = f".{method}()-panics-on-error"
                site.evidence = (
                    f".{method}() aborts on the error branch — "
                    "fail-closed at this site"
                )
                return site
            if method in _RUST_TEST_METHODS:
                site.verdict = "guarded"
                site.shape = "tested"
                site.evidence = (
                    f".{method}() result consumed as a condition"
                )
                return site
            if method in _RUST_DEFAULT_METHODS:
                site.verdict = "unguarded"
                site.shape = f".{method}()-erases-error"
                site.evidence = (
                    f".{method}() replaces the error branch with a "
                    "default — failure is indistinguishable from "
                    "success"
                )
                return site
            if method in _RUST_PASSTHROUGH_METHODS:
                through.append(method)
                prev, cur = outer, outer.parent
                continue
            site.evidence = (
                f"method `.{method}()` applied to the result; its "
                "contract is not traced"
            )
            return site
        if t == "try_expression":
            site.verdict = "guarded"
            site.shape = "propagated"
            site.evidence = "`?` propagates the error to the caller"
            return site
        if t == "await_expression":
            prev, cur = cur, cur.parent
            continue
        if t == "let_declaration":
            return _classify_rust_let(cur, node, src, site, line, through)
        if t == "let_condition" or t in (
                "if_expression", "while_expression", "match_expression",
                "binary_expression", "unary_expression",
                "parenthesized_expression"):
            site.verdict = "guarded"
            site.shape = "tested"
            site.evidence = "call result consumed by a control condition"
            return site
        if t == "return_expression":
            site.verdict = "guarded"
            site.shape = "propagated"
            site.evidence = "call result propagated to the caller"
            return site
        if t == "arguments":
            site.verdict = "guarded"
            site.shape = "consumed-as-argument"
            site.evidence = "call result consumed by an enclosing call"
            return site
        if t == "expression_statement":
            site.verdict = "unguarded"
            if "ok" in through:
                site.shape = "ok-discarded"
                site.evidence = (
                    ".ok() converts the Result and the Option is "
                    "dropped on the floor — the error branch cannot "
                    "alter control"
                )
            else:
                site.shape = "bare-statement"
                site.evidence = (
                    "call result neither bound nor tested"
                )
            return site
        if t == "block":
            site.verdict = "guarded"
            site.shape = "propagated"
            site.evidence = (
                "trailing expression — the result is the block's value"
            )
            return site
        prev, cur = cur, cur.parent
    site.evidence = "could not classify the call's consumption context"
    return site


def rust_discard_sites(
    source: str,
    file_path: str,
    callee: str,
    *,
    function_span: tuple[int, int] | None = None,
) -> list[CallSiteOutcome] | None:
    """Call sites of ``callee`` classified for the Rust ignored-Result
    leg. ``None`` when no tree-sitter rust parser is available
    (binding consumption and `?`/match shapes are not honestly
    decidable from line shapes)."""
    parser = _ts_parser("rust")
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
        lines = source.splitlines()
    except Exception:
        logger.debug("fail_open_lang: rust discard scan failed for %s",
                     file_path, exc_info=True)
        return None
    sites = []
    for node in _iter_rust_calls(tree, src, callee, function_span):
        site = _classify_rust_call_site(node, src, lines)
        site.file = file_path
        sites.append(site)
    return sites


def _rust_function_node(tree, src: bytes, function_name: str):
    tail = function_name.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _RUST_FUNC_TYPES:
            continue
        name_node = node.child_by_field_name("name")
        if name_node is not None and _ts_node_text(name_node, src) == tail:
            return node
    return None


def rust_function_returns_result(
    source: str, function_name: str,
) -> bool:
    """True when a same-file Rust function's return type is a
    ``Result`` — the leg-2b fallibility witness for the discard leg."""
    parser = _ts_parser("rust")
    tail = function_name.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
    if parser is not None:
        try:
            src = source.encode("utf-8", errors="replace")
            tree = parser.parse(src)
            node = _rust_function_node(tree, src, tail)
            if node is None:
                return False
            ret = node.child_by_field_name("return_type")
            if ret is None:
                return False
            return bool(re.search(r"\bResult\b", _ts_node_text(ret, src)))
        except Exception:
            logger.debug("fail_open_lang: rust signature scan failed",
                         exc_info=True)
    # Line-regex fallback: signature shapes only (never handler
    # bodies): `fn name(...) -> Result<...>`.
    return bool(re.search(
        rf"fn\s+{re.escape(tail)}\s*(?:<[^>]*>)?\s*\([^)]*\)\s*->\s*"
        rf"[\w:]*Result\b",
        source,
    ))


def rust_function_span(
    source: str, function_name: str,
) -> tuple[int, int] | None:
    """(start_line, end_line) of a Rust function, or None."""
    parser = _ts_parser("rust")
    if parser is None:
        return None
    try:
        src = source.encode("utf-8", errors="replace")
        tree = parser.parse(src)
    except Exception:
        return None
    node = _rust_function_node(tree, src, function_name)
    if node is None:
        return None
    return (node.start_point[0] + 1, node.end_point[0] + 1)


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
