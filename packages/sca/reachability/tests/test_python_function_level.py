"""Tests for the PyPI function-level reachability tier.

Driven against synthetic targets and synthetic OSV-result objects
— the existing module-level Python tests cover the build_inventory
+ AST extraction shape; these tests pin the tier's verdict-update
contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


from packages.sca.models import Confidence, Dependency, PinStyle, Reachability
from packages.sca.reachability.python_function_level import (
    build_pypi_symbol_map,
    refine_pypi_verdicts,
)


# ---------------------------------------------------------------------------
# Synthetic OSV / advisory shapes
# ---------------------------------------------------------------------------


@dataclass
class _Adv:
    ecosystem_specific: Optional[Dict[str, Any]] = None
    database_specific: Optional[Dict[str, Any]] = None


@dataclass
class _OsvResult:
    dep_key: str
    advisories: List[_Adv] = field(default_factory=list)


def _dep(name: str, version: str = "1.0", ecosystem: str = "PyPI") -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("requirements.txt"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:pypi/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _imported(reason: str = "tier-1 imported") -> Reachability:
    return Reachability(
        verdict="imported",
        confidence=Confidence("high", reason=reason),
        evidence=["src/main.py:1"],
    )


# ---------------------------------------------------------------------------
# build_pypi_symbol_map — every shape OSV ever ships
# ---------------------------------------------------------------------------


def test_extract_imports_symbols_ecosystem_specific():
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "requests", "symbols": ["get", "post"]}],
    })
    out = build_pypi_symbol_map([
        _OsvResult(dep_key="PyPI:requests@2.31.0", advisories=[adv]),
    ])
    assert out == {"PyPI:requests@2.31.0": ["get", "post"]}


def test_extract_imports_symbols_database_specific():
    adv = _Adv(database_specific={
        "imports": [{"symbols": ["dangerous"]}],
    })
    out = build_pypi_symbol_map([
        _OsvResult(dep_key="PyPI:foo@1.0", advisories=[adv]),
    ])
    assert out == {"PyPI:foo@1.0": ["dangerous"]}


def test_extract_affected_symbols_flat():
    adv = _Adv(database_specific={"affected_symbols": ["fn1", "fn2"]})
    out = build_pypi_symbol_map([
        _OsvResult(dep_key="PyPI:foo@1.0", advisories=[adv]),
    ])
    assert out == {"PyPI:foo@1.0": ["fn1", "fn2"]}


def test_extract_affected_functions_flat():
    adv = _Adv(database_specific={"affected_functions": ["sink"]})
    out = build_pypi_symbol_map([
        _OsvResult(dep_key="PyPI:foo@1.0", advisories=[adv]),
    ])
    assert out == {"PyPI:foo@1.0": ["sink"]}


def test_dedup_across_advisories():
    """Two advisories listing overlapping function sets dedupe per-dep."""
    adv1 = _Adv(database_specific={"affected_functions": ["a", "b"]})
    adv2 = _Adv(database_specific={"affected_functions": ["b", "c"]})
    out = build_pypi_symbol_map([
        _OsvResult(dep_key="PyPI:foo@1.0", advisories=[adv1, adv2]),
    ])
    assert out == {"PyPI:foo@1.0": ["a", "b", "c"]}


def test_skips_non_pypi_dep_keys():
    adv = _Adv(database_specific={"affected_functions": ["x"]})
    out = build_pypi_symbol_map([
        _OsvResult(dep_key="npm:lodash@4.17.0", advisories=[adv]),
    ])
    assert out == {}


def test_empty_or_missing_returns_empty():
    assert build_pypi_symbol_map(None) == {}
    assert build_pypi_symbol_map([]) == {}
    assert build_pypi_symbol_map([
        _OsvResult(dep_key="PyPI:x@1.0", advisories=[]),
    ]) == {}


def test_ignores_results_without_advisories():
    """An OsvResult-shaped object that lacks .advisories should
    not crash the extractor."""
    @dataclass
    class _Bare:
        dep_key: str
    out = build_pypi_symbol_map([_Bare(dep_key="PyPI:foo@1.0")])
    assert out == {}


# ---------------------------------------------------------------------------
# refine_pypi_verdicts — verdict transitions
# ---------------------------------------------------------------------------


def _project(tmp_path: Path, source: str, filename: str = "main.py") -> Path:
    """Drop a source file in tmp_path, return tmp_path."""
    (tmp_path / filename).write_text(source)
    return tmp_path


def test_called_function_upgrades_to_likely_called(tmp_path):
    """The advisory says ``requests.get`` is the affected function;
    the project does call it; verdict upgrades."""
    target = _project(
        tmp_path,
        "import requests\nrequests.get('/')\n",
    )
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"
    # Evidence carries the actual call site.
    assert out[deps[0].key()].evidence == ["main.py:2"]


def test_uncalled_function_downgrades_to_not_function_reachable(tmp_path):
    """Project imports requests but only calls .post; the advisory
    says .get is affected. Downgrade."""
    target = _project(
        tmp_path,
        "import requests\nrequests.post('/')\n",
    )
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_uncertain_leaves_at_imported(tmp_path):
    """Project uses getattr with a literal matching the affected
    function name; resolver returns UNCERTAIN; verdict stays
    imported."""
    target = _project(
        tmp_path,
        "import requests\n"
        "def f():\n"
        "    g = getattr(requests, 'get')\n"
        "    g()\n",
    )
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_partial_called_promotes_to_likely_called(tmp_path):
    """Two affected functions: one is called, one isn't. Calling
    EITHER upgrades to likely_called — defensive position is
    that the dep is exercising vulnerable code."""
    target = _project(
        tmp_path,
        "import requests\nrequests.get('/')\n",
    )
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["get", "post"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_skips_non_pypi_deps(tmp_path):
    target = _project(tmp_path, "x = 1\n")
    deps = [_dep("lodash", ecosystem="npm")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["foo"]},
    )
    # Untouched.
    assert out[deps[0].key()].verdict == "imported"


def test_skips_non_imported_verdicts(tmp_path):
    """Tier only fires on imported. not_reachable / not_evaluated /
    likely_called are out of scope (already-decided verdicts)."""
    target = _project(
        tmp_path,
        "import requests\nrequests.get('/')\n",
    )
    deps = [_dep("requests")]
    out = {
        deps[0].key(): Reachability(
            verdict="not_reachable",
            confidence=Confidence("medium", reason="t"),
        ),
    }
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["get"]},
    )
    assert out[deps[0].key()].verdict == "not_reachable"


def test_no_symbols_no_op(tmp_path):
    """Empty pypi_symbol_map → don't even build the inventory."""
    target = _project(tmp_path, "x = 1\n")
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_preserves_evidence_only_for_called_paths(tmp_path):
    """Evidence list on the upgraded Reachability should only carry
    actual call-site refs, not the module-level evidence."""
    target = _project(
        tmp_path,
        "import requests\n"
        "import json\n"
        "requests.get('/')\n",
    )
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["get"]},
    )
    new = out[deps[0].key()]
    assert new.verdict == "likely_called"
    # Module-level "src/main.py:1" evidence shouldn't be preserved
    # — the function-level call site replaces it.
    assert new.evidence == ["main.py:3"]
