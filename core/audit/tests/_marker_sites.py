"""Enumerate every check site that tests a bracketed machine marker.

Shared by the closure tests (test_model_body_markers.py). A *marker* is a
string starting with ``[`` + a letter. A *site* is code that tests text
against a marker:

* ``m in x`` / ``m not in x`` and ``x == m`` / ``x != m`` (e.g.
  ``body.partition("]")[0] == "[gate"``);
* ``x.startswith/endswith/find/rfind/index/count(m)``;
* ``re.search/match/fullmatch/compile/findall/sub(pattern, ...)`` whose
  pattern, after ``^`` / ``\\A`` / inline-flag groups, starts with ``\\[``;

with ``m`` resolved through: string literals, concatenations of literals
(``"[" + "x:"``), module/function constants assigned with ``=`` or an
annotation (``X: tuple[str, ...] = (...)``), tuple/list/set/frozenset
literals, ``dict`` literal ``.values()`` / ``.keys()`` / the dict itself,
and comprehension / ``any(...)`` / ``for`` loop variables bound over any of
those. A site whose tested text is case-normalised (``x.lower()``,
``.casefold()``, ``.upper()``) is reported separately: the defang matches
markers case-sensitively, so such a consumer could be steered by
``[GATE VIOLATION:`` and must not exist.

Files: every ``*.py`` under core/, packages/, libexec/ (tests excluded) and
every extensionless libexec entry point whose first line is a python
shebang.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

MARK = re.compile(r"^\[[A-Za-z]")
_RX_LEAD = re.compile(r"^(?:\^|\\A|\(\?[a-zA-Z]+\))*\\\[")
_NORMALISERS = {"lower", "casefold", "upper"}


def repo_sources(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for sub in ("core", "packages", "libexec"):
        base = root / sub
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            if not f.is_file() or "tests" in f.parts:
                continue
            if f.suffix == ".py":
                pass
            elif sub == "libexec" and f.suffix == "":
                try:
                    with f.open("rb") as fh:
                        first = fh.readline(200)
                except OSError:
                    continue
                if not (first.startswith(b"#!") and b"python" in first):
                    continue
            else:
                continue
            try:
                out[str(f.relative_to(root))] = f.read_text()
            except (UnicodeDecodeError, OSError):
                continue
    return out


def _lit(node) -> tuple[str, ...]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)):
        left, right = _lit(node.left), _lit(node.right)
        if len(left) == 1 and len(right) == 1:
            return (left[0] + right[0],)
    return ()


def _collection(node, env) -> tuple[str, ...]:
    """Strings a constant expression can denote (for `in`/loops)."""
    s = _lit(node)
    if s:
        return s
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        out: tuple[str, ...] = ()
        for e in node.elts:
            out += _collection(e, env)
        return out
    if isinstance(node, ast.Dict):
        out = ()
        for k, v in zip(node.keys, node.values):
            if k is not None:
                out += _collection(k, env)
            out += _collection(v, env)
        return out
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in ("frozenset", "set", "tuple", "list")
            and node.args):
        return _collection(node.args[0], env)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("values", "keys", "items")):
        return _collection(node.func.value, env)
    if isinstance(node, ast.Name) and node.id in env:
        return env[node.id]
    if isinstance(node, ast.Attribute) and node.attr in env:
        return env[node.attr]
    return ()


def _consts(tree) -> dict[str, tuple[str, ...]]:
    env: dict[str, tuple[str, ...]] = {}
    for _ in range(2):  # second pass resolves constants built from constants
        for n in ast.walk(tree):
            target = value = None
            if (isinstance(n, ast.Assign) and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Name)):
                target, value = n.targets[0].id, n.value
            elif (isinstance(n, ast.AnnAssign) and n.value is not None
                  and isinstance(n.target, ast.Name)):
                target, value = n.target.id, n.value
            if target is None:
                continue
            got = _collection(value, env)
            if got:
                env[target] = got
    return env


def _loop_env(tree, env) -> dict[str, tuple[str, ...]]:
    """Loop / comprehension variables bound over constant collections."""
    loops = dict(env)
    for n in ast.walk(tree):
        gens = []
        if isinstance(n, (ast.For, ast.AsyncFor)):
            gens = [(n.target, n.iter)]
        elif isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp,
                            ast.DictComp)):
            gens = [(g.target, g.iter) for g in n.generators]
        for target, it in gens:
            if isinstance(target, ast.Name):
                got = _collection(it, loops)
                if got:
                    loops[target.id] = got
    return loops


def _normalised(node) -> bool:
    """Is this receiver/haystack a case-normalised string?"""
    while True:
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            if node.func.attr in _NORMALISERS:
                return True
            node = node.func.value
            continue
        if isinstance(node, ast.Subscript):
            node = node.value
            continue
        return False


def scan(sources: dict[str, str]) -> tuple[list[tuple], list[tuple]]:
    """(sites, normalised_sites); each item (file, line, kind, marker)."""
    trees = {}
    genv: dict[str, tuple[str, ...]] = {}
    for rel, text in sources.items():
        try:
            t = ast.parse(text)
        except SyntaxError:
            continue
        trees[rel] = t
        for k, v in _consts(t).items():
            genv.setdefault(k, v)
    sites, normed = set(), set()
    for rel, t in trees.items():
        env = dict(genv)
        env.update(_consts(t))
        env = _loop_env(t, env)
        for n in ast.walk(t):
            hits: list[tuple[str, str, bool]] = []
            if isinstance(n, ast.Compare) and len(n.ops) == 1:
                op, right = n.ops[0], n.comparators[0]
                if isinstance(op, (ast.In, ast.NotIn)):
                    hits = [(s, "in", _normalised(right))
                            for s in _collection(n.left, env)]
                elif isinstance(op, (ast.Eq, ast.NotEq)):
                    for a, b in ((n.left, right), (right, n.left)):
                        hits += [(s, "==", _normalised(b))
                                 for s in _collection(a, env)]
            elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.args):
                attr = n.func.attr
                if attr in ("startswith", "endswith", "find", "rfind",
                            "index", "count"):
                    hits = [(s, attr, _normalised(n.func.value))
                            for s in _collection(n.args[0], env)]
                elif attr in ("search", "match", "fullmatch", "compile",
                              "findall", "sub", "finditer"):
                    hay = n.args[1] if len(n.args) > 1 else None
                    for s in _collection(n.args[0], env):
                        m = _RX_LEAD.match(s)
                        if m:
                            rest = s[m.end():]
                            marker = "[" + re.split(r"[\\(\[\]|*+?{]", rest, maxsplit=1)[0]
                            hits.append((marker, "re." + attr,
                                         hay is not None and _normalised(hay)))
            for s, kind, low in hits:
                if MARK.match(s):
                    item = (rel, n.lineno, kind, s)
                    sites.add(item)
                    if low:
                        normed.add(item)
    return sorted(sites), sorted(normed)
