r"""Closure gate: splitlines() never feeds line-number arithmetic.

``str.splitlines()`` breaks on ``\v \f \x1c \x1d \x1e \x85 \u2028
\u2029`` beyond ``\n``, while every external line-number producer
RAPTOR consumes (semgrep, CodeQL SARIF, tree-sitter rows,
``ast.lineno``, DWARF, gcc diagnostics, git hunks, editors) counts
``\n`` only.  Pairing a splitlines() view with such a line number
desyncs on one attacker-plantable byte (``\f`` is legal code
whitespace in C and Python and legal in string literals and comments
everywhere): guards get harvested from planted lines, analysts are
shown substitute code, suppression comments are forged.  The fix is
``core.source.lines.split_lines`` — the \n-only chokepoint.

This census derives, from the runtime-source universe (the shared
``runtime_file_universe()`` derivation), every ``.splitlines()``
call whose result COUPLES to line-number arithmetic in the same
scope:

* arm A — the call (or a name bound to it) is enumerated 1-based:
  ``enumerate(x.splitlines(), 1)`` / ``enumerate(lines, start=1)``;
* arm B — a name (or ``self.attr``, tracked across a class's methods
  in textual order) bound to the result — including via ``:=`` and
  annotated assignment — is subscripted with an index or slice bound
  that is 1-corrected: ``lines[line - 1]``, or ``lines[start:end]``
  where ``start``/``end`` was assigned from an expression containing
  ``... - 1`` (the ``max(0, line - 1)`` idiom); a chained
  ``x.splitlines()[line - 1]`` counts the same way;
* arm C — 0-based enumerate whose index is 1-corrected inside the
  loop: ``for i, ln in enumerate(lines): ... i + 1``.

Named blind spots (deliberate: each needs whole-program dataflow):
line numbers flowing through helper calls or returned across
functions, while-loop cursor arithmetic (``i += 1 … i + 1``), tuple
unpacking, conditional-expression bindings
(``x.splitlines() if c else y``), and a binding in a textually LATER
method than its use.  A separate read-layer trap sits ABOVE any
splitter: a universal-newline read translates a plantable bare
``\r`` into ``\n`` before splitting — scanner-paired readers must
pass ``newline=""`` (see ``read_text_capped``); this census cannot
see read modes.
A site only these shapes would catch still desyncs — reviewers, not
this gate, are the backstop there.  Conversely the arms are
intent-blind: a self-consistent ``lines[i - 1]`` previous-line idiom
over the same list is flagged and needs a ``# line-model:`` marker —
that cost is accepted; the marker documents the model either way.

Every coupled site must either use ``split_lines`` (and so vanish
from the census) or carry an inline adjudication marker on the
call's first line::

    lines = text.splitlines()  # line-model: <why splitlines is right here>

There is deliberately NO allowlist file: the marker at the call site
IS the adjudication record, so the justification lives next to the
pairing it excuses and moves with it.

The boundary, named: splitlines() calls that never meet a 1-indexed
external line number — tool/subprocess stdout iteration (nm,
readelf, git, docker, joern), LLM response parsing, display
wrapping, RAPTOR-owned artifact munging — are single-model and
correct as written; they are exactly the sites this census does NOT
flag, and they need no marker.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

_MARKER = "line-model:"
# The marker must carry an actual justification — a bare
# "# line-model:" is a rubber stamp, not an adjudication record.
_MARKER_RE = re.compile(r"#[ \t]*" + re.escape(_MARKER) + r"[ \t]*\S")

_GUIDANCE = (
    "splitlines() result feeds 1-indexed line-number arithmetic — "
    "external line numbers count \\n only, so this desyncs on one "
    "plantable byte. Use core.source.lines.split_lines, or justify "
    f"inline with '# {_MARKER} <why>' on the call's first line:\n"
)


def _is_splitlines_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "splitlines"
    )


def _is_one(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value == 1


def _enumerate_start_is_one(call: ast.Call) -> bool:
    if not (isinstance(call.func, ast.Name) and call.func.id == "enumerate"):
        return False
    if len(call.args) >= 2 and _is_one(call.args[1]):
        return True
    return any(kw.arg == "start" and _is_one(kw.value) for kw in call.keywords)


def _target_key(target: ast.AST) -> str | None:
    """A stable key for Name / self-attribute assignment targets."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return f".{target.attr}"
    return None


def _expr_key(node: ast.AST) -> str | None:
    return _target_key(node)


def _contains_minus_one(node: ast.AST) -> bool:
    return any(
        isinstance(sub, ast.BinOp)
        and isinstance(sub.op, ast.Sub)
        and _is_one(sub.right)
        for sub in ast.walk(node)
    )


def _zero_based_enumerate_plus_one(
    node: ast.For, scope: "_Scope",
) -> tuple[int, str] | None:
    """Arm C: ``for i, ln in enumerate(<splitlines>): … i + 1``."""
    it = node.iter
    if not (
        isinstance(it, ast.Call)
        and isinstance(it.func, ast.Name)
        and it.func.id == "enumerate"
        and it.args
    ):
        return None
    start_args = it.args[1:2] or [
        kw.value for kw in it.keywords if kw.arg == "start"
    ]
    if start_args and not (
        isinstance(start_args[0], ast.Constant)
        and start_args[0].value == 0
    ):
        return None  # 1-based handled by arm A; symbolic starts skipped
    first = it.args[0]
    if _is_splitlines_call(first):
        lineno = first.lineno
    else:
        key = _expr_key(first)
        if key not in scope.splitlines_bindings:
            return None
        lineno = scope.splitlines_bindings[key]
    if not isinstance(node.target, ast.Tuple) or not node.target.elts:
        return None
    tgt = node.target.elts[0]
    if not isinstance(tgt, ast.Name):
        return None
    idx = tgt.id
    for sub in ast.walk(node):
        if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Add):
            operands = (sub.left, sub.right)
            if any(
                isinstance(a, ast.Name) and a.id == idx for a in operands
            ) and any(_is_one(b) for b in operands):
                return (
                    lineno,
                    "0-based enumerate of a splitlines list with a "
                    "1-corrected index",
                )
    return None


class _Scope:
    """One function (or module) body's splitlines/pairing facts."""

    def __init__(self) -> None:
        # key -> lineno of the splitlines() call bound to it
        self.splitlines_bindings: dict[str, int] = {}
        # keys assigned from an expression containing `... - 1`
        self.minus_one_names: set[str] = set()
        # (lineno, why) couplings found so far
        self.coupled: list[tuple[int, str]] = []


def _scan_scope(body: list[ast.stmt], scope: _Scope) -> None:
    """Walk one scope's statements (recursing into nested scopes with
    fresh Scope objects) and record splitlines/line-number couplings."""

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = _Scope()
            # self.attr bindings propagate across a class's methods in
            # textual order (the F5 _source_lines shape: bind in one
            # method, subscript in another).
            inner.splitlines_bindings = {
                k: v for k, v in scope.splitlines_bindings.items()
                if k.startswith(".")
            }
            _scan_scope(node.body, inner)
            scope.coupled.extend(inner.coupled)
            scope.splitlines_bindings.update({
                k: v for k, v in inner.splitlines_bindings.items()
                if k.startswith(".")
            })
            return
        bind_pairs: list[tuple[ast.AST, ast.AST]] = []
        if isinstance(node, ast.Assign):
            bind_pairs = [(t, node.value) for t in node.targets]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bind_pairs = [(node.target, node.value)]
        elif isinstance(node, ast.NamedExpr):
            bind_pairs = [(node.target, node.value)]
        elif isinstance(node, ast.AugAssign):
            if (
                isinstance(node.op, ast.Sub)
                and _is_one(node.value)
            ):
                key = _target_key(node.target)
                if key is not None:
                    scope.minus_one_names.add(key)
        for target, value in bind_pairs:
            key = _target_key(target)
            if key is None:
                continue
            if _is_splitlines_call(value):
                scope.splitlines_bindings[key] = value.lineno
            elif key in scope.splitlines_bindings:
                # rebound to something else — drop the binding
                del scope.splitlines_bindings[key]
            if _contains_minus_one(value):
                scope.minus_one_names.add(key)
        if isinstance(node, ast.Call):
            if _enumerate_start_is_one(node) and node.args:
                first = node.args[0]
                if _is_splitlines_call(first):
                    scope.coupled.append(
                        (first.lineno, "enumerate(x.splitlines(), 1)"),
                    )
                else:
                    key = _expr_key(first)
                    if key in scope.splitlines_bindings:
                        scope.coupled.append((
                            scope.splitlines_bindings[key],
                            "splitlines list enumerated 1-based",
                        ))
        if isinstance(node, ast.For):
            hit = _zero_based_enumerate_plus_one(node, scope)
            if hit is not None:
                scope.coupled.append(hit)
        if isinstance(node, ast.Subscript):
            direct = _is_splitlines_call(node.value) or (
                isinstance(node.value, ast.NamedExpr)
                and _is_splitlines_call(node.value.value)
            )
            key = _expr_key(node.value)
            if direct or key in scope.splitlines_bindings:
                idx = node.slice
                parts: list[ast.AST] = (
                    [p for p in (idx.lower, idx.upper, idx.step) if p]
                    if isinstance(idx, ast.Slice) else [idx]
                )
                for part in parts:
                    if _contains_minus_one(part) or any(
                        isinstance(sub, ast.Name)
                        and sub.id in scope.minus_one_names
                        for sub in ast.walk(part)
                    ):
                        lineno = (
                            node.value.lineno if direct
                            else scope.splitlines_bindings[key]
                        )
                        scope.coupled.append((
                            lineno,
                            "splitlines list indexed with a "
                            "1-corrected line number",
                        ))
                        break
        for child in ast.iter_child_nodes(node):
            visit(child)

    for stmt in body:
        visit(stmt)


def census_offenders(rel: str, source: str) -> list[str]:
    """Coupled splitlines() sites in *source* lacking the marker."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.split("\n")
    scope = _Scope()
    _scan_scope(tree.body, scope)
    offenders = []
    for lineno, why in sorted(set(scope.coupled)):
        if not _MARKER_RE.search(lines[lineno - 1]):
            offenders.append(f"{rel}:{lineno}: {why}")
    return offenders


def test_no_unadjudicated_splitlines_line_pairings() -> None:
    repo = repo_root()
    offenders: list[str] = []
    for path in runtime_file_universe(repo, include_dev_scripts=True):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "splitlines" not in source:
            continue
        rel = path.relative_to(repo).as_posix()
        offenders.extend(census_offenders(rel, source))
    assert not offenders, _GUIDANCE + "\n".join(offenders)


class TestCensusMechanics:
    """The census's own failure directions, on planted sources."""

    def test_direct_enumerate_flagged(self):
        src = "for i, ln in enumerate(text.splitlines(), 1):\n    pass\n"
        assert census_offenders("x.py", src)

    def test_enumerate_start_kw_flagged(self):
        src = ("for i, ln in enumerate(text.splitlines(), start=1):\n"
               "    pass\n")
        assert census_offenders("x.py", src)

    def test_bound_name_enumerated_flagged(self):
        src = ("lines = text.splitlines()\n"
               "for i, ln in enumerate(lines, 1):\n    pass\n")
        assert census_offenders("x.py", src)

    def test_minus_one_subscript_flagged(self):
        src = "lines = text.splitlines()\ncode = lines[line - 1]\n"
        assert census_offenders("x.py", src)

    def test_minus_one_derived_slice_flagged(self):
        src = ("def f(text, start_line, end_line):\n"
               "    lines = text.splitlines(keepends=True)\n"
               "    start_idx = max(0, start_line - 1)\n"
               "    return lines[start_idx:end_line]\n")
        assert census_offenders("x.py", src)

    def test_self_attribute_binding_flagged(self):
        src = ("class C:\n"
               "    def load(self, content):\n"
               "        self._source_lines = content.splitlines(True)\n"
               "        return self._source_lines[row - 1]\n")
        assert census_offenders("x.py", src)

    def test_marker_with_justification_passes(self):
        src = ("lines = text.splitlines()  # line-model: numbers "
               "re-derived from this same list, single model\n"
               "code = lines[line - 1]\n")
        assert census_offenders("x.py", src) == []

    def test_bare_marker_is_a_rubber_stamp(self):
        src = ("lines = text.splitlines()  # line-model:\n"
               "code = lines[line - 1]\n")
        assert census_offenders("x.py", src)

    def test_split_lines_adoption_passes(self):
        src = ("from core.source.lines import split_lines\n"
               "lines = split_lines(text)\n"
               "code = lines[line - 1]\n"
               "for i, ln in enumerate(split_lines(text), 1):\n    pass\n")
        assert census_offenders("x.py", src) == []

    def test_uncoupled_splitlines_not_flagged(self):
        # The named boundary: tool output iteration with no
        # 1-indexed pairing is single-model and needs no marker.
        src = ("for ln in proc.stdout.splitlines():\n"
               "    handle(ln)\n"
               "lines = text.splitlines()\n"
               "first = lines[0]\n")
        assert census_offenders("x.py", src) == []

    def test_enumerate_from_zero_not_flagged(self):
        src = ("for i, ln in enumerate(text.splitlines()):\n"
               "    pass\n")
        assert census_offenders("x.py", src) == []

    def test_rebound_name_not_flagged(self):
        src = ("lines = text.splitlines()\n"
               "lines = other_list\n"
               "code = lines[line - 1]\n")
        assert census_offenders("x.py", src) == []

    def test_unparseable_source_skipped(self):
        assert census_offenders("x.py", "def broken(:\n") == []

    def test_chained_subscript_flagged(self):
        src = "code = text.splitlines()[line - 1]\n"
        assert census_offenders("x.py", src)

    def test_walrus_expression_subscript_flagged(self):
        src = "code = (lines := text.splitlines())[line - 1]\n"
        assert census_offenders("x.py", src)

    def test_walrus_binding_flagged(self):
        src = ("if (lines := text.splitlines()):\n"
               "    code = lines[line - 1]\n")
        assert census_offenders("x.py", src)

    def test_annotated_binding_flagged(self):
        src = ("lines: list[str] = text.splitlines()\n"
               "code = lines[line - 1]\n")
        assert census_offenders("x.py", src)

    def test_cross_method_self_attr_flagged(self):
        # the F5 _source_lines shape: bind in one method, subscript
        # in a textually later one
        src = ("class C:\n"
               "    def load(self, content):\n"
               "        self._source_lines = content.splitlines(True)\n"
               "    def find(self, row):\n"
               "        return self._source_lines[row - 1]\n")
        assert census_offenders("x.py", src)

    def test_zero_based_enumerate_plus_one_flagged(self):
        src = ("for i, ln in enumerate(text.splitlines()):\n"
               "    emit(i + 1, ln)\n")
        assert census_offenders("x.py", src)

    def test_zero_based_bound_name_plus_one_flagged(self):
        src = ("lines = text.splitlines()\n"
               "for idx, ln in enumerate(lines):\n"
               "    out.append(idx + 1)\n")
        assert census_offenders("x.py", src)

    def test_zero_based_enumerate_without_correction_passes(self):
        src = ("for i, ln in enumerate(text.splitlines()):\n"
               "    handle(ln)\n")
        assert census_offenders("x.py", src) == []
