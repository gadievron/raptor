"""Closure gate: no runtime reader waives the JSON read budget silently.

``core.json.load_json`` is capped by default; the unbounded read is
the exception a caller must spell out AND justify. This census
derives every call site from the runtime-source universe (the shared
``runtime_file_universe()`` derivation) and requires each unbounded
spelling to carry an inline justification marker on the call's first
line::

    data = load_json_unbounded(path)  # json-unbounded: <why>

Three spellings count as unbounded (all AST-derived, never grep):

* a ``load_json_unbounded(...)`` call (name or attribute form);
* ``load_json(...)`` / ``load_json_with_comments(...)`` with a
  literal ``max_bytes=None``;
* ``load_json(..., max_bytes=<param>)`` where ``<param>`` is a
  parameter of the enclosing function whose default is ``None`` —
  the wrapper hole: a pass-through shim whose own default silently
  re-opens the unbounded path for every caller that forgets.

There is deliberately NO allowlist file: the marker at the call site
IS the adjudication record, so the justification lives next to the
read it excuses and moves with it.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

_MARKER = "json-unbounded:"
# The marker must carry an actual justification — a bare
# "# json-unbounded:" is a rubber stamp, not an adjudication record.
_MARKER_RE = re.compile(re.escape(_MARKER) + r"[ \t]*\S")

_LOADER_NAMES = frozenset({"load_json", "load_json_with_comments"})
_UNBOUNDED_NAME = "load_json_unbounded"


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _none_default_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    out: set[str] = set()
    args = fn.args
    positional = args.posonlyargs + args.args
    for arg, default in zip(
        positional[len(positional) - len(args.defaults):], args.defaults,
    ):
        if isinstance(default, ast.Constant) and default.value is None:
            out.add(arg.arg)
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if (
            default is not None
            and isinstance(default, ast.Constant)
            and default.value is None
        ):
            out.add(arg.arg)
    return out


def census_offenders(rel: str, source: str) -> list[str]:
    """Unbounded loader spellings in *source* lacking the marker."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    offenders: list[str] = []

    def _line_has_marker(lineno: int) -> bool:
        return _MARKER_RE.search(lines[lineno - 1]) is not None

    def _flag(node: ast.Call, why: str) -> None:
        if not _line_has_marker(node.lineno):
            offenders.append(f"{rel}:{node.lineno}: {why}")

    def _visit(node: ast.AST, none_params: frozenset[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            none_params = frozenset(_none_default_params(node))
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name == _UNBOUNDED_NAME:
                _flag(node, "load_json_unbounded call")
            elif name in _LOADER_NAMES:
                for kw in node.keywords:
                    if kw.arg != "max_bytes":
                        continue
                    if (
                        isinstance(kw.value, ast.Constant)
                        and kw.value.value is None
                    ):
                        _flag(node, f"{name}(max_bytes=None)")
                    elif (
                        isinstance(kw.value, ast.Name)
                        and kw.value.id in none_params
                    ):
                        _flag(
                            node,
                            f"{name}(max_bytes=<param defaulting to "
                            "None>) — wrapper re-opens the unbounded "
                            "path by default",
                        )
        for child in ast.iter_child_nodes(node):
            _visit(child, none_params)

    _visit(tree, frozenset())
    return offenders


def test_no_unjustified_unbounded_reads_in_runtime_source() -> None:
    repo = repo_root()
    offenders: list[str] = []
    for path in runtime_file_universe(repo, include_dev_scripts=True):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "load_json" not in source:
            continue
        rel = path.relative_to(repo).as_posix()
        offenders.extend(census_offenders(rel, source))
    assert not offenders, (
        "unbounded JSON read without an inline justification — add "
        f"'# {_MARKER} <why>' on the call's first line, or better, "
        "pass an explicit max_bytes bound:\n" + "\n".join(offenders)
    )


class TestCensusMechanics:
    """The census's own failure directions, on planted sources."""

    def test_unbounded_call_without_marker_flagged(self):
        src = "from core.json import load_json_unbounded\n" \
              "data = load_json_unbounded(p)\n"
        assert census_offenders("x.py", src)

    def test_unbounded_call_with_marker_passes(self):
        src = (
            "from core.json import load_json_unbounded\n"
            "data = load_json_unbounded(p)  # json-unbounded: trusted"
            " multi-GiB corpus artifact, bounded by the corpus builder\n"
        )
        assert census_offenders("x.py", src) == []

    def test_empty_justification_flagged(self):
        src = "data = load_json_unbounded(p)  # json-unbounded:\n"
        assert census_offenders("x.py", src)

    def test_literal_none_flagged_both_loaders(self):
        for fn in ("load_json", "load_json_with_comments"):
            src = f"data = {fn}(p, max_bytes=None)\n"
            assert census_offenders("x.py", src), fn

    def test_attribute_spelling_counted(self):
        src = "data = core_json.load_json_unbounded(p)\n"
        assert census_offenders("x.py", src)

    def test_wrapper_none_default_flagged(self):
        src = (
            "def read(p, max_bytes=None):\n"
            "    return load_json(p, max_bytes=max_bytes)\n"
        )
        assert census_offenders("x.py", src)

    def test_wrapper_with_real_default_passes(self):
        src = (
            "def read(p, max_bytes=1024):\n"
            "    return load_json(p, max_bytes=max_bytes)\n"
        )
        assert census_offenders("x.py", src) == []

    def test_capped_and_default_calls_pass(self):
        src = (
            "a = load_json(p)\n"
            "b = load_json(p, max_bytes=64 * 1024)\n"
            "c = load_json_with_comments(p, max_bytes=CAP)\n"
        )
        assert census_offenders("x.py", src) == []

    def test_unparseable_source_skipped(self):
        assert census_offenders("x.py", "def broken(:\n") == []
