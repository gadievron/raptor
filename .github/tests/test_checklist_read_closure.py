"""Closure gate: no direct checklist.json JSON-load outside core.inventory.

The checklist accessors (``core.inventory.read_checklist`` /
``read_checklist_meta`` / ``iter_checklist_items`` /
``checklist_exists``) own three properties a bespoke load silently
drops: the writers' flock (torn-read safety against a concurrent
``update_checklist``), project-symlink resolution (read and write
sides pointed at the same inode), and the sharded ``checklist/``
layout with its integrity contract — a hand-rolled ``load_json(dir /
"checklist.json")`` reads NOTHING once a big target's inventory goes
sharded.

This census derives every call site from the runtime-source universe
(shared ``runtime_file_universe()`` derivation) and flags any JSON
loader call whose arguments carry the literal ``"checklist.json"`` —
or a local name assigned from an expression carrying it — outside
``core/inventory/``. An adjudicated exception carries an inline
justification marker on the call's first line::

    data = load_json(cl, ...)  # checklist-direct-read: <why>

There is deliberately NO allowlist file: the marker at the call site
is the adjudication record (same doctrine as
``test_load_json_budget_closure.py``).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

_MARKER = "checklist-direct-read:"
# The marker must carry an actual justification — a bare marker is a
# rubber stamp, not an adjudication record.
_MARKER_RE = re.compile(re.escape(_MARKER) + r"[ \t]*\S")

_LITERAL = "checklist.json"

#: JSON loader spellings (name or attribute form). ``load`` covers
#: ``json.load``; the budgeted/unbounded variants cover core.json.
_LOADER_NAMES = frozenset({
    "load_json",
    "load_json_with_comments",
    "load_json_unbounded",
    "load_json_bounded",
    "load",
    "loads",
})

#: The accessor home — the ONLY place direct checklist.json parsing
#: lives (plus its own builder, which writes the artifact).
_EXEMPT_PREFIX = "core/inventory/"


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _contains_literal(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Constant) and n.value == _LITERAL
        for n in ast.walk(node)
    )


def census_offenders(rel: str, source: str) -> list[str]:
    """Direct checklist.json loader spellings lacking the marker."""
    if rel.startswith(_EXEMPT_PREFIX):
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    offenders: list[str] = []

    def _line_has_marker(lineno: int) -> bool:
        return _MARKER_RE.search(lines[lineno - 1]) is not None

    def _visit(node: ast.AST, tainted: frozenset[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Fresh function scope: collect simple names assigned
            # from expressions carrying the literal (the
            # ``cl = d / "checklist.json"; load_json(cl)`` spelling).
            names: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign) and _contains_literal(
                        sub.value):
                    for tgt in sub.targets:
                        if isinstance(tgt, ast.Name):
                            names.add(tgt.id)
            tainted = frozenset(names)
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in _LOADER_NAMES:
                args = list(node.args) + [
                    kw.value for kw in node.keywords
                ]
                direct = any(_contains_literal(a) for a in args)
                via_name = any(
                    isinstance(a, ast.Name) and a.id in tainted
                    for a in args
                )
                if (direct or via_name) and not _line_has_marker(
                        node.lineno):
                    offenders.append(
                        f"{rel}:{node.lineno}: {name}(...) reads "
                        "checklist.json directly"
                    )
        for child in ast.iter_child_nodes(node):
            _visit(child, tainted)

    _visit(tree, frozenset())
    return offenders


def test_no_direct_checklist_json_loads_outside_core_inventory() -> None:
    repo = repo_root()
    offenders: list[str] = []
    for path in runtime_file_universe(repo, include_dev_scripts=True):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _LITERAL not in source:
            continue
        rel = path.relative_to(repo).as_posix()
        offenders.extend(census_offenders(rel, source))
    assert not offenders, (
        "direct checklist.json JSON-load outside core.inventory — "
        "route it through core.inventory.read_checklist / "
        "read_checklist_meta / iter_checklist_items (flock, symlink "
        "resolution, sharded layout), or adjudicate with an inline "
        f"'# {_MARKER} <why>' on the call's first line:\n"
        + "\n".join(offenders)
    )


class TestCensusMechanics:
    """The census's own failure directions, on planted sources."""

    def test_direct_literal_flagged(self):
        src = 'data = load_json(run / "checklist.json")\n'
        assert census_offenders("core/audit/x.py", src)

    def test_attribute_loader_flagged(self):
        src = 'data = json.load(open(d / "checklist.json"))\n'
        assert census_offenders("packages/x.py", src)

    def test_assigned_name_flagged(self):
        src = (
            "def f(d):\n"
            '    cl = d / "checklist.json"\n'
            "    return load_json(cl)\n"
        )
        assert census_offenders("core/audit/x.py", src)

    def test_marker_with_justification_passes(self):
        src = (
            'data = load_json(d / "checklist.json")  '
            "# checklist-direct-read: run-local promote read, "
            "symlink-excluded\n"
        )
        assert census_offenders("core/run/x.py", src) == []

    def test_bare_marker_flagged(self):
        src = (
            'data = load_json(d / "checklist.json")  '
            "# checklist-direct-read:\n"
        )
        assert census_offenders("core/run/x.py", src)

    def test_core_inventory_exempt(self):
        src = 'data = load_json(d / "checklist.json")\n'
        assert census_offenders("core/inventory/builder.py", src) == []

    def test_other_literals_not_flagged(self):
        src = (
            'a = load_json(d / "binary-checklist.json")\n'
            'b = load_json(d / "findings.json")\n'
            'c = save_json(d / "checklist.json", data)\n'
        )
        assert census_offenders("core/audit/x.py", src) == []

    def test_accessor_reads_not_flagged(self):
        src = (
            "from core.inventory import read_checklist\n"
            "data = read_checklist(out_dir)\n"
        )
        assert census_offenders("core/audit/x.py", src) == []

    def test_unparseable_source_skipped(self):
        assert census_offenders("core/x.py", "def broken(:\n") == []
