"""Mechanical closure: every ``tree_sitter.Parser`` construction in
the runtime tree routes through the bounded-parse chokepoint.

The bounded-parse guarantee is only as strong as its coverage, and a
hand-maintained site list drifts — a new module (or a surface outside
the original sweep, like a ``libexec`` script) can construct a raw
parser and reopen the unbudgeted-parse hang on untrusted content.
This census derives the construction-site universe mechanically from
the sources on disk (AST-resolved imports, so aliases like
``from tree_sitter import Parser as TSParser`` are seen) and asserts
each construction is wrapped in ``bounded(...)`` /
``BoundedParser(...)`` at the construction expression itself. The
only exemption is the canonical wrap site inside ``_ts_cache``.
"""

from __future__ import annotations

import ast
import functools
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

# Runtime roots. Tests are excluded (fixtures legitimately build raw
# parsers to probe the wrapper itself); .github is CI tooling.
_ROOTS = ("core", "packages", "plugins", "libexec", "bin")

# The chokepoint's own construction — the one raw Parser() allowed.
_CANONICAL = REPO / "core" / "inventory" / "_ts_cache.py"

_WRAPPER_NAMES = frozenset({"bounded", "BoundedParser"})


def _runtime_sources() -> list[Path]:
    files: list[Path] = []
    for root in _ROOTS:
        base = REPO / root
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if "tests" in p.parts or any(
                part.startswith(".") for part in p.relative_to(REPO).parts
            ):
                continue
            files.append(p)
    # Extensionless python launchers (libexec/, bin/).
    for root in ("libexec", "bin"):
        base = REPO / root
        if not base.is_dir():
            continue
        for p in sorted(base.iterdir()):
            if not p.is_file() or p.suffix:
                continue
            try:
                head = p.open("rb").readline()
            except OSError:
                continue
            if b"python" in head:
                files.append(p)
    files.extend(sorted(REPO.glob("*.py")))
    return files


def _parser_constructions(tree: ast.AST) -> list[ast.Call]:
    """Call nodes that construct a ``tree_sitter.Parser``."""
    parser_names: set[str] = set()
    ts_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "tree_sitter":
                    ts_aliases.add(alias.asname or "tree_sitter")
        elif isinstance(node, ast.ImportFrom) and node.module == "tree_sitter":
            for alias in node.names:
                if alias.name == "Parser":
                    parser_names.add(alias.asname or "Parser")
    if not parser_names and not ts_aliases:
        return []
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in parser_names:
            calls.append(node)
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "Parser"
            and isinstance(func.value, ast.Name)
            and func.value.id in ts_aliases
        ):
            calls.append(node)
    return calls


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _is_wrapped(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(call)
    if not isinstance(parent, ast.Call) or call not in parent.args:
        return False
    func = parent.func
    name = func.id if isinstance(func, ast.Name) else (
        func.attr if isinstance(func, ast.Attribute) else None
    )
    return name in _WRAPPER_NAMES


@functools.lru_cache(maxsize=1)
def _census() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (all_sites, unwrapped_sites) as ``path:line`` strings."""
    sites: list[str] = []
    unwrapped: list[str] = []
    for path in _runtime_sources():
        text = path.read_text(encoding="utf-8", errors="replace")
        # Token pre-filter before the (expensive) ast.parse: any
        # construction this census can flag needs an import that
        # spells the literal module name — `import tree_sitter` or
        # `from tree_sitter import ...` (aliasing renames the BOUND
        # name, never the imported one) — so a source without the
        # token has no reachable site by construction. Cuts the parse
        # set from the whole runtime tree (~1.5k files) to the few
        # dozen that mention it; parsing the full tree blew the CI
        # per-test budget under a loaded worker.
        if "tree_sitter" not in text:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        constructions = _parser_constructions(tree)
        if not constructions:
            continue
        parents = _parent_map(tree)
        for call in constructions:
            where = f"{path.relative_to(REPO)}:{call.lineno}"
            sites.append(where)
            if path == _CANONICAL:
                continue
            if not _is_wrapped(call, parents):
                unwrapped.append(where)
    return tuple(sites), tuple(unwrapped)


def test_every_parser_construction_is_bounded():
    sites, unwrapped = _census()
    assert not unwrapped, (
        "raw tree_sitter.Parser construction(s) outside the bounded "
        f"chokepoint: {unwrapped} — wrap with "
        "core.inventory._ts_cache.bounded(...) so crafted input "
        "cannot hang the parse unbudgeted"
    )


def test_census_sees_the_known_universe():
    """Breadth floor: a broken walker that finds nothing must fail
    here, never green the closure vacuously."""
    sites, _ = _census()
    assert len(sites) >= 6, sites
    assert any(
        site.startswith("core/inventory/_ts_cache.py") for site in sites
    ), sites
    assert any(site.startswith("libexec/") for site in sites), sites


def test_census_flags_a_planted_raw_construction(tmp_path):
    """Non-vacuity: the detection logic must flag an unwrapped
    construction when one exists."""
    planted = ast.parse(
        "import tree_sitter\n"
        "def f(lang):\n"
        "    return tree_sitter.Parser(lang)\n"
    )
    calls = _parser_constructions(planted)
    assert len(calls) == 1
    assert not _is_wrapped(calls[0], _parent_map(planted))
    wrapped = ast.parse(
        "from tree_sitter import Parser as TSParser\n"
        "from core.inventory._ts_cache import bounded\n"
        "def f(lang):\n"
        "    return bounded(TSParser(lang), label='x')\n"
    )
    calls = _parser_constructions(wrapped)
    assert len(calls) == 1
    assert _is_wrapped(calls[0], _parent_map(wrapped))
