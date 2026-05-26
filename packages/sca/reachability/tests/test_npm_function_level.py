"""Tests for the npm function-level reachability tier.

Mirrors ``test_python_function_level`` but exercises npm deps
against JS / TS source via the tree-sitter call-graph extractor.
The end-to-end tests require the JS extractor to be available;
those are skipped when ``tree_sitter_javascript`` isn't installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from packages.sca.models import Confidence, Dependency, PinStyle, Reachability
from packages.sca.reachability.npm_function_level import (
    _qualified_name,
    build_npm_symbol_map,
    refine_npm_verdicts,
)


@dataclass
class _Adv:
    ecosystem_specific: Optional[Dict[str, Any]] = None
    database_specific: Optional[Dict[str, Any]] = None


@dataclass
class _OsvResult:
    dep_key: str
    advisories: List[_Adv] = field(default_factory=list)


def _dep(name: str, version: str = "1.0.0", ecosystem: str = "npm") -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _imported(reason: str = "tier-1 imported") -> Reachability:
    return Reachability(
        verdict="imported",
        confidence=Confidence("high", reason=reason),
        evidence=["src/main.js:1"],
    )


# ---------------------------------------------------------------------------
# build_npm_symbol_map — every shape OSV ever ships
# ---------------------------------------------------------------------------


def test_extract_imports_symbols_ecosystem_specific():
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "lodash", "symbols": ["get", "set"]}],
    })
    out = build_npm_symbol_map([
        _OsvResult(dep_key="npm:lodash@4.17.21", advisories=[adv]),
    ])
    assert out == {"npm:lodash@4.17.21": ["get", "set"]}


def test_extract_imports_symbols_database_specific():
    adv = _Adv(database_specific={
        "imports": [{"symbols": ["dangerous"]}],
    })
    out = build_npm_symbol_map([
        _OsvResult(dep_key="npm:foo@1.0", advisories=[adv]),
    ])
    assert out == {"npm:foo@1.0": ["dangerous"]}


def test_extract_affected_symbols_flat():
    adv = _Adv(database_specific={"affected_symbols": ["fn1", "fn2"]})
    out = build_npm_symbol_map([
        _OsvResult(dep_key="npm:foo@1.0", advisories=[adv]),
    ])
    assert out == {"npm:foo@1.0": ["fn1", "fn2"]}


def test_extract_affected_functions_flat():
    adv = _Adv(database_specific={"affected_functions": ["sink"]})
    out = build_npm_symbol_map([
        _OsvResult(dep_key="npm:foo@1.0", advisories=[adv]),
    ])
    assert out == {"npm:foo@1.0": ["sink"]}


def test_dedup_across_advisories():
    adv1 = _Adv(database_specific={"affected_functions": ["a", "b"]})
    adv2 = _Adv(database_specific={"affected_functions": ["b", "c"]})
    out = build_npm_symbol_map([
        _OsvResult(dep_key="npm:foo@1.0", advisories=[adv1, adv2]),
    ])
    assert out == {"npm:foo@1.0": ["a", "b", "c"]}


def test_skips_non_npm_dep_keys():
    """A PyPI advisory shouldn't show up in the npm map."""
    adv = _Adv(database_specific={"affected_functions": ["x"]})
    out = build_npm_symbol_map([
        _OsvResult(dep_key="PyPI:requests@2.31.0", advisories=[adv]),
    ])
    assert out == {}


def test_empty_or_missing_returns_empty():
    assert build_npm_symbol_map(None) == {}
    assert build_npm_symbol_map([]) == {}
    assert build_npm_symbol_map([
        _OsvResult(dep_key="npm:x@1.0", advisories=[]),
    ]) == {}


# ---------------------------------------------------------------------------
# _qualified_name
# ---------------------------------------------------------------------------


def test_qualified_name_simple():
    assert _qualified_name("lodash", "get") == "lodash.get"


def test_qualified_name_scoped_package():
    assert _qualified_name("@scope/pkg", "useState") == "@scope/pkg.useState"


def test_qualified_name_rejects_dotted_func():
    """Dotted function names are out of scope (chain semantics)."""
    assert _qualified_name("lodash", "fp.get") is None


def test_qualified_name_rejects_empty():
    assert _qualified_name("", "get") is None
    assert _qualified_name("lodash", "") is None


# ---------------------------------------------------------------------------
# refine_npm_verdicts — verdict transitions
# ---------------------------------------------------------------------------


pytest.importorskip("tree_sitter_javascript")


def _project(tmp_path: Path, source: str, filename: str = "main.js") -> Path:
    (tmp_path / filename).write_text(source)
    return tmp_path


def test_called_function_upgrades_to_likely_called(tmp_path):
    """Project imports lodash AND calls .get; the advisory says
    .get is affected → upgrade to likely_called."""
    target = _project(
        tmp_path,
        "import lodash from 'lodash';\nlodash.get(obj, 'k');\n",
    )
    deps = [_dep("lodash")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_npm_verdicts(
        deps, out,
        target=target,
        npm_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"
    # Evidence carries the actual call site.
    assert out[deps[0].key()].evidence == ["main.js:2"]


def test_uncalled_function_downgrades(tmp_path):
    """Project imports lodash but only calls .set; advisory says
    .get is affected → downgrade to not_function_reachable."""
    target = _project(
        tmp_path,
        "import lodash from 'lodash';\nlodash.set(obj, 'k', 1);\n",
    )
    deps = [_dep("lodash")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_npm_verdicts(
        deps, out,
        target=target,
        npm_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_uncertain_leaves_at_imported(tmp_path):
    """Project uses bracket dispatch with a literal matching the
    affected function name → resolver returns UNCERTAIN; verdict
    stays imported."""
    target = _project(
        tmp_path,
        "import lodash from 'lodash';\n"
        "function f() {\n"
        "    lodash['get'](obj);\n"
        "}\n",
    )
    deps = [_dep("lodash")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_npm_verdicts(
        deps, out,
        target=target,
        npm_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_partial_called_promotes_to_likely_called(tmp_path):
    """Two affected functions; one called → upgrade to
    likely_called (defensive: any vulnerable call site matters)."""
    target = _project(
        tmp_path,
        "import lodash from 'lodash';\nlodash.get(obj, 'k');\n",
    )
    deps = [_dep("lodash")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_npm_verdicts(
        deps, out,
        target=target,
        npm_symbol_map={deps[0].key(): ["get", "set"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_skips_non_npm_deps(tmp_path):
    target = _project(tmp_path, "x = 1\n", filename="main.py")
    deps = [_dep("requests", ecosystem="PyPI")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_npm_verdicts(
        deps, out,
        target=target,
        npm_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_skips_non_imported_verdicts(tmp_path):
    """Tier only fires on imported. not_reachable / not_evaluated /
    likely_called are out of scope."""
    target = _project(
        tmp_path,
        "import lodash from 'lodash';\nlodash.get(obj, 'k');\n",
    )
    deps = [_dep("lodash")]
    out = {
        deps[0].key(): Reachability(
            verdict="not_reachable",
            confidence=Confidence("medium", reason="t"),
        ),
    }
    refine_npm_verdicts(
        deps, out,
        target=target,
        npm_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "not_reachable"


def test_no_symbols_no_op(tmp_path):
    """Empty npm_symbol_map → don't even build the inventory."""
    target = _project(tmp_path, "x = 1\n", filename="main.js")
    deps = [_dep("lodash")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_npm_verdicts(
        deps, out,
        target=target,
        npm_symbol_map={},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_destructured_require_resolves(tmp_path):
    """``const { get } = require('lodash')`` then ``get(obj)`` —
    the resolver should match against ``lodash.get``."""
    target = _project(
        tmp_path,
        "const { get } = require('lodash');\nget(obj, 'k');\n",
    )
    deps = [_dep("lodash")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_npm_verdicts(
        deps, out,
        target=target,
        npm_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"
