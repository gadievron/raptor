"""Enumerate the ``review_result`` keys pipeline code reads and writes.

Shared by the field-forgery closure test (test_model_body_markers.py).
``review_result`` is the model's parsed review JSON, carried on every
ReviewOutcome, into which pipeline stages also write their own flags.
A key the pipeline READS or WRITES must be classified: model-authored
(the model may set it) or pipeline-owned (only pipeline code may set
it; the review_fn and edge-review parse boundaries drop it from model
output, batch glance rejects off-schema elements, and the chain
detector and refuter copy explicit fields only).

Aliases tracked per function: any expression ``<x>.review_result``,
``(<x>.review_result or {})``, ``getattr(<x>, "review_result", ...)``,
names bound from an alias (``rr = outcome.review_result or {}``,
``x = rr``, ``x = rr | {...}``, ``(x := rr)``, ``x, n = rr, 0``, and
every target of a chained assignment one of whose targets is reached),
names passed as a ``review_result=`` keyword, parameters and locals
named ``review_result`` / ``rr`` / ``_rr`` / ``primary`` (the multi-pass
panel item) inside :data:`NAME_ALIAS_SCOPE`, and — inside
llm_review.make_review_fn — the model dict ``result`` itself.

Reads: ``a.get("k")``, ``a["k"]`` (load), ``"k" in a``, ``a.pop("k")``.

Writes are the modelled expressions that reach a review_result:

* a ``review_result=`` keyword (or ``**{"review_result": v}``) in any
  call, anywhere;
* an assignment, annotated assignment, augmented assignment, walrus,
  ``for`` / ``with`` / unpacking / ``match`` capture target that is an
  alias or an ``<x>.review_result`` attribute (and ``setattr(x,
  "review_result", v)`` / ``__setattr__``);
* a ``|`` with an alias operand;
* ``a["k"] = ...``, ``a.setdefault("k", ...)``, ``a.__setitem__("k",
  ...)``, ``a.update(k=...)`` / ``a.update({...})`` on an alias.

The written value resolves to keys through dict literals, ``dict(...)``
keywords and literal positionals, conditional arms, ``or`` / ``|``
operands and walrus values; an alias (or ``None``) contributes no new
key. Any other value at a modelled write is an UNRESOLVED :class:`Site`:
a computed key, ``**`` of a non-alias, a comprehension, a non-literal
value or arm, a ``for`` / ``with`` / unpacking / ``match`` binding.
Writes outside the modelled shapes are not reported at all — see the
residual in :func:`scan_full`. A site is bound to its content by
:func:`expr_digest`, so a pin survives line moves and fails on any
edit of the pinned expression.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import NamedTuple


class Site(NamedTuple):
    """An unresolved review_result write."""

    file: str
    line: int
    qualname: str
    shape: str
    digest: str

    @property
    def pin(self) -> tuple:
        """Content key (no line number): file, function, shape, digest."""
        return (self.file, self.qualname, self.shape, self.digest)


def _canon(node) -> str:
    # A version-stable rendering: ``ast.dump`` drops empty fields on
    # newer interpreters, and ``ctx`` (load / store) is not content.
    if isinstance(node, ast.AST):
        return type(node).__name__ + "(" + ",".join(
            f"{f}={_canon(getattr(node, f, None))}"
            for f in node._fields if f != "ctx") + ")"
    if isinstance(node, list):
        return "[" + ",".join(_canon(x) for x in node) + "]"
    return repr(node)


def expr_digest(node) -> str:
    """sha256 (first 16 hex digits) of an expression's AST content."""
    return hashlib.sha256(_canon(node).encode()).hexdigest()[:16]


def _is_rr_expr(node) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "review_result":
        return True
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return any(_is_rr_expr(v) for v in node.values)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "getattr" and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "review_result"):
        return True
    return False


def _const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


#: Names that denote a review_result dict wherever they are bound —
#: function parameters and locals alike: the conventional local names,
#: and the multi-pass / multi-model panel item (``primary``), which IS
#: a review_result (``_outcome_to_panel_result`` merges it in).
ALIAS_NAMES = frozenset({"review_result", "rr", "_rr", "primary"})
#: Where the name convention holds: the audit pipeline, which owns
#: ReviewOutcome.review_result, and the multi-model panel merge, whose
#: merged ``primary`` item becomes an audit review_result
#: (the audit orchestrator's multi-pass review passes
#: ``review_result=primary`` from the panel's items).
#: Elsewhere — /agentic, SCA, startup — the same local names denote
#: unrelated dicts.
NAME_ALIAS_SCOPE = ("core/audit/", "core/llm/multi_model/")


def _value_names(node):
    """Names a ``review_result=`` value passes through unchanged."""
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, ast.IfExp):
        yield from _value_names(node.body)
        yield from _value_names(node.orelse)
    elif isinstance(node, ast.BoolOp):
        for v in node.values:
            yield from _value_names(v)
    elif isinstance(node, ast.NamedExpr):
        yield node.target.id
        yield from _value_names(node.value)


def _keyword_values(call):
    """Values a call passes as ``review_result``: ``review_result=v``
    and ``**{"review_result": v}``."""
    for kw in call.keywords:
        if kw.arg == "review_result":
            yield kw.value
        elif kw.arg is None and isinstance(kw.value, ast.Dict):
            for k, v in zip(kw.value.keys, kw.value.values):
                if k is not None and _const_str(k) == "review_result":
                    yield v


def _setattr_value(call):
    """The value of ``setattr(x, "review_result", v)``,
    ``object.__setattr__(x, "review_result", v)`` or
    ``x.__setattr__("review_result", v)``; None otherwise."""
    f = call.func
    if not ((isinstance(f, ast.Name) and f.id == "setattr")
            or (isinstance(f, ast.Attribute) and f.attr == "__setattr__")):
        return None
    if len(call.args) >= 2 and _const_str(call.args[-2]) == "review_result":
        return call.args[-1]
    return None


def _capture_name(node):
    """The name a ``match`` pattern binds, if any."""
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return node.name
    if isinstance(node, ast.MatchMapping):
        return node.rest
    return None


def _qualnames(tree) -> dict:
    """id(node) -> qualname of the innermost enclosing def / class."""
    out: dict = {}

    def visit(node, owner, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)):
                q = prefix + child.name
                inner = q + ("." if isinstance(child, ast.ClassDef)
                             else ".<locals>.")
                out[id(child)] = q
                visit(child, q, inner)
            else:
                out[id(child)] = owner
                visit(child, owner, prefix)

    visit(tree, "<module>", "")
    return out


def _scan_function(fn, rel, reads, writes, model_dict_names=(),
                   unresolved=None, qualnames=None):
    if unresolved is None:
        unresolved = set()
    if qualnames is None:
        qualnames = _qualnames(fn)
        qualnames.setdefault(id(fn), fn.name)
    nodes = list(ast.walk(fn))
    aliases = set(model_dict_names)
    if rel.startswith(NAME_ALIAS_SCOPE):
        params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        aliases.update(a.arg for a in params if a.arg in ALIAS_NAMES)
        aliases.update(
            n.id for n in nodes
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
            and n.id in ALIAS_NAMES)
        aliases.update(
            name for name in map(_capture_name, nodes)
            if name in ALIAS_NAMES)
    for n in nodes:
        if isinstance(n, ast.Call):
            for v in _keyword_values(n):
                aliases.update(_value_names(v))

    def atomic_alias(node):
        return _is_rr_expr(node) or (
            isinstance(node, ast.Name) and node.id in aliases)

    def aliasish(node):
        if atomic_alias(node):
            return True
        if isinstance(node, ast.BoolOp):
            return any(aliasish(v) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return aliasish(node.left) or aliasish(node.right)
        if isinstance(node, ast.NamedExpr):
            return aliasish(node.value)
        return False

    def reached(t):
        return ((isinstance(t, ast.Name) and t.id in aliases)
                or (isinstance(t, ast.Attribute)
                    and t.attr == "review_result"))

    def reached_in(t):
        if isinstance(t, (ast.Tuple, ast.List)):
            return any(reached_in(e) for e in t.elts)
        if isinstance(t, ast.Starred):
            return reached_in(t.value)
        return reached(t)

    def pairable(t, value):
        return (isinstance(t, (ast.Tuple, ast.List))
                and isinstance(value, (ast.Tuple, ast.List))
                and len(t.elts) == len(value.elts)
                and not any(isinstance(e, ast.Starred)
                            for e in (*t.elts, *value.elts)))

    # Alias propagation (function scope, flow-insensitive).
    def bind(t, value, chained):
        if isinstance(t, ast.Name):
            if t.id not in aliases and (aliasish(value) or chained):
                aliases.add(t.id)
                return True
            return False
        if pairable(t, value):
            return any([bind(te, ve, False)
                        for te, ve in zip(t.elts, value.elts)])
        return False

    changed = True
    while changed:
        changed = False
        for n in nodes:
            if isinstance(n, ast.Assign):
                chained = len(n.targets) > 1 and any(
                    reached(t) for t in n.targets)
                for t in n.targets:
                    changed |= bind(t, n.value, chained)
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                changed |= bind(n.target, n.value, False)
            elif isinstance(n, ast.NamedExpr):
                changed |= bind(n.target, n.value, False)

    def site(top, line, shape):
        unresolved.add(Site(rel, line, qualnames.get(id(top), fn.name),
                            shape, expr_digest(top)))

    def value(node, top, line, fallback="value-expression"):
        if isinstance(node, ast.IfExp):
            value(node.body, top, line, fallback)
            value(node.orelse, top, line, fallback)
            return
        if isinstance(node, ast.BoolOp):
            for v in node.values:
                value(v, top, line, fallback)
            return
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            value(node.left, top, line, fallback)
            value(node.right, top, line, fallback)
            return
        if isinstance(node, ast.NamedExpr):
            value(node.value, top, line, fallback)
            return
        if atomic_alias(node):
            return
        if isinstance(node, ast.Constant) and node.value is None:
            return
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if k is None:
                    value(v, top, line, "dict-unpack")
                    continue
                key = _const_str(k)
                if key is None:
                    site(top, line, "computed-key")
                else:
                    writes.add((key, rel, line))
            return
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "dict"):
            for kw in node.keywords:
                if kw.arg is None:
                    value(kw.value, top, line, "dict-unpack")
                else:
                    writes.add((kw.arg, rel, line))
            for a in node.args:
                value(a, top, line, "dict-from-expression")
            return
        if isinstance(node, ast.DictComp):
            site(top, line, "comprehension")
            return
        site(top, line, fallback)

    def target(t, val, line):
        if reached(t):
            value(val, val, line)
        elif reached_in(t):
            if pairable(t, val):
                for te, ve in zip(t.elts, val.elts):
                    target(te, ve, line)
            else:
                site(val, line, "unpack-target")

    for n in nodes:
        if isinstance(n, ast.Assign):
            for t in n.targets:
                target(t, n.value, n.lineno)
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            target(n.target, n.value, n.lineno)
        elif isinstance(n, ast.AugAssign) and reached(n.target):
            if isinstance(n.op, ast.BitOr):
                value(n.value, n.value, n.lineno)
            else:
                site(n.value, n.lineno, "augmented-assign")
        elif isinstance(n, ast.NamedExpr):
            target(n.target, n.value, n.lineno)
        elif isinstance(n, (ast.For, ast.AsyncFor)) and reached_in(n.target):
            site(n.iter, n.lineno, "for-target")
        elif isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp,
                            ast.DictComp)):
            for gen in n.generators:
                if reached_in(gen.target):
                    site(gen.iter, n.lineno, "for-target")
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if (item.optional_vars is not None
                        and reached_in(item.optional_vars)):
                    site(item.context_expr, n.lineno, "with-target")
        elif isinstance(n, ast.Match):
            if any(_capture_name(p) in aliases
                   for case in n.cases for p in ast.walk(case.pattern)):
                site(n.subject, n.lineno, "match-capture")
        if (isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr)
                and (atomic_alias(n.left) or atomic_alias(n.right))):
            value(n, n, n.lineno)
        if isinstance(n, ast.Call):
            for v in _keyword_values(n):
                value(v, v, n.lineno)
            v = _setattr_value(n)
            if v is not None:
                value(v, v, n.lineno)
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and aliasish(n.func.value)):
            meth = n.func.attr
            if n.args and meth in ("get", "pop", "setdefault", "__setitem__"):
                k = _const_str(n.args[0])
                if meth in ("get", "pop"):
                    if k is not None:
                        reads.add((k, rel, n.lineno))
                elif k is not None:
                    writes.add((k, rel, n.lineno))
                else:
                    site(n, n.lineno, "computed-key")
            if meth == "update":
                for kw in n.keywords:
                    if kw.arg:
                        writes.add((kw.arg, rel, n.lineno))
                    else:
                        value(kw.value, kw.value, n.lineno, "dict-unpack")
                for a in n.args:
                    value(a, a, n.lineno, "update-from-expression")
        if isinstance(n, ast.Subscript) and aliasish(n.value):
            k = _const_str(n.slice)
            if k is not None:
                if isinstance(n.ctx, ast.Store):
                    writes.add((k, rel, n.lineno))
                else:
                    reads.add((k, rel, n.lineno))
            elif isinstance(n.ctx, ast.Store):
                site(n, n.lineno, "computed-key")
        if (isinstance(n, ast.Compare) and len(n.ops) == 1
                and isinstance(n.ops[0], (ast.In, ast.NotIn))
                and aliasish(n.comparators[0])):
            k = _const_str(n.left)
            if k is not None:
                reads.add((k, rel, n.lineno))


def scan(root: Path):
    """(reads, writes): sets of (key, file, line)."""
    reads, writes, _ = scan_full(root)
    return reads, writes


def scan_full(root: Path):
    """(reads, writes, unresolved). ``unresolved`` is a set of
    :class:`Site` for reached writes whose keys cannot be resolved
    statically. They are NOT counted as covered; the closure test fails
    on every one that is not pinned by content.

    Residual — writes that are neither counted nor reported
    (documented, not resolved):

    * aliasing is per function and flow-insensitive (a name that is an
      alias anywhere in the function is an alias everywhere in it; a
      rebinding to an unrelated dict is not distinguished);
    * module-level and class-body code is not scanned (``class C:
      review_result = {...}``, a dataclass ``field(default_factory=
      lambda: {...})``);
    * the default of an alias-named parameter or lambda parameter
      (``def f(o, review_result={...})``, ``lambda primary={...}: ...``)
      is not read: an alias adds no key;
    * a ``**kw`` mapping, even one built in the same function
      (``kw = {"review_result": {...}}; Thing(**kw)``);
    * ``vars(o)[...]`` / ``o.__dict__[...]`` / ``globals()[...]``
      subscripts (and ``o.__dict__.update({...})``);
    * a review dict passed positionally to ``ReviewOutcome`` (only the
      ``review_result=`` keyword is read);
    * ``setattr`` with a non-constant attribute name;
    * code in ``exec`` / ``eval`` strings;
    * a dict built elsewhere and passed in unchanged (a parameter, a
      callee's return value, ``self.<attr>``) is resolved where it is
      built only if that site is itself reached;
    * dicts passed to a callee under another parameter name are
      tracked only if the parameter is named by the convention
      (``ALIAS_NAMES``).
    """
    reads: set = set()
    writes: set = set()
    unresolved: set = set()
    for sub in ("core", "packages", "libexec"):
        for f in (root / sub).rglob("*.py"):
            if "tests" in f.parts or f.name.startswith("test_"):
                continue
            try:
                tree = ast.parse(f.read_text())
            except (SyntaxError, UnicodeDecodeError):
                continue
            rel = str(f.relative_to(root))
            qualnames = _qualnames(tree)
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    model = ("result",) if (
                        rel == "core/audit/llm_review.py"
                        and fn.name == "review_fn") else ()
                    _scan_function(fn, rel, reads, writes, model,
                                   unresolved, qualnames)
    return reads, writes, unresolved


def unclassified(records, *classes) -> list:
    """Sorted (key, file, line) records whose key is in none of
    ``classes``."""
    return sorted(r for r in records
                  if not any(r[0] in c for c in classes))


def pin_violations(unresolved, pins) -> tuple:
    """(unpinned sites, stale pins): sites whose content key is not in
    ``pins``, and pins that match no site."""
    have = {s.pin for s in unresolved}
    unpinned = sorted(s for s in unresolved if s.pin not in pins)
    stale = sorted(p for p in pins if p not in have)
    return unpinned, stale
