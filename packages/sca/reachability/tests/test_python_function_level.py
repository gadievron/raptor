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


def test_dist_module_mismatch_called_not_downgraded(tmp_path):
    """Imports bind the MODULE name, not the distribution name:
    installing ``pyyaml`` gives ``import yaml``. A real call of the
    affected function through the module name must upgrade, not read
    as all-NOT_CALLED and get downgraded."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.full_load(payload)\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["full_load"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_dist_module_mismatch_uncalled_still_downgraded(tmp_path):
    """Same dist≠module package but the affected function genuinely
    isn't called — the downgrade must still fire."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.safe_load(payload)\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["full_load"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_empty_function_name_ignored(tmp_path):
    """An empty symbol from a malformed advisory can't form a valid
    qualified name — it is skipped, leaving the verdict untouched."""
    target = _project(tmp_path, "import requests\n")
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): [""]},
    )
    assert out[deps[0].key()].verdict == "imported"


# ---------------------------------------------------------------------------
# Dotted advisory entries — the qualification join
# ---------------------------------------------------------------------------
# Advisory flat lists ship three entry shapes and each must produce a
# resolver-bindable query (the closure oracle for the qualification
# policy is this shape-parametrised block — bare, module-head-
# qualified, partially-qualified; anything else is out of the claimed
# scope):
#   * bare        ("get")                        → "<mod>.get"
#   * module-head ("yaml.full_load")             → verbatim (the
#     dominant GHSA/PYSEC spelling; "<mod>.yaml.full_load" is a
#     garbage query that pairs as NOT_CALLED and manufactured a
#     false high-confidence not_function_reachable)
#   * partial     ("utils.extract_zipped_paths") → "<mod>.utils...."


def test_module_head_qualified_entry_called_is_not_suppressed(tmp_path):
    """The reviewer shape: dist pyyaml → module yaml; the advisory
    entry is module-head-qualified ("yaml.full_load") and the project
    CALLS it — the tier must see CALLED, never mint a false
    high-confidence downgrade from the garbage doubled spelling."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.full_load('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["yaml.full_load"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_module_head_qualified_entry_uncalled_still_downgrades(tmp_path):
    """Two-direction guard: the verbatim spelling still earns the
    legitimate downgrade when the function truly is not called."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.safe_load('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["yaml.full_load"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_deep_module_head_qualified_entry_called(tmp_path):
    """django-style deep qualification under the dist's own module."""
    target = _project(
        tmp_path,
        "import requests\nrequests.utils.extract_zipped_paths('/')\n",
    )
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={
            deps[0].key(): ["requests.utils.extract_zipped_paths"],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_partially_qualified_entry_still_composes(tmp_path):
    """A partial entry whose head is NOT a candidate module keeps the
    compose spelling — and must NOT be tried verbatim (a top-level
    local module named ``utils`` would otherwise fake a CALLED)."""
    target = _project(
        tmp_path,
        "import requests\nrequests.utils.extract_zipped_paths('/')\n",
    )
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={
            deps[0].key(): ["utils.extract_zipped_paths"],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_partial_entry_never_binds_unrelated_local_module(tmp_path):
    """The verbatim spelling is reserved for module-head entries: a
    project-local ``utils`` module calling an unrelated function of
    the same name must not upgrade the dep."""
    target = _project(
        tmp_path,
        "import requests\n"
        "import utils\n"
        "utils.extract_zipped_paths('/')\n",
    )
    (tmp_path / "utils.py").write_text(
        "def extract_zipped_paths(p):\n    return p\n",
    )
    deps = [_dep("requests")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={
            deps[0].key(): ["utils.extract_zipped_paths"],
        },
    )
    # requests.utils.extract_zipped_paths is never called: downgrade
    # (the local utils call must not read as the dep's function).
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_dotted_curated_module_head_entry_called(tmp_path):
    """Dotted candidate modules (curated map: protobuf →
    google.protobuf) have MULTI-SEGMENT heads — the module-head
    spelling must still bind verbatim (a first-segment head check
    misclassified these as partial and composed garbage like
    "google.protobuf.google.protobuf.text_format.Parse")."""
    target = _project(
        tmp_path,
        "import google.protobuf.text_format\n"
        "google.protobuf.text_format.Parse('x')\n",
    )
    deps = [_dep("protobuf")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={
            deps[0].key(): ["google.protobuf.text_format.Parse"],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_dotted_curated_module_head_entry_uncalled_downgrades(tmp_path):
    """Two-direction guard for the dotted-module verbatim path."""
    target = _project(
        tmp_path,
        "import google.protobuf.json_format\n"
        "google.protobuf.json_format.Parse('x')\n",
    )
    deps = [_dep("protobuf")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={
            deps[0].key(): ["google.protobuf.text_format.Parse"],
        },
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_dotted_selfnamed_module_head_entry_called(tmp_path):
    """A dist whose name IS its dotted module (ruamel.yaml)."""
    target = _project(
        tmp_path,
        "import ruamel.yaml\nruamel.yaml.main.load('x')\n",
    )
    deps = [_dep("ruamel.yaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["ruamel.yaml.main.load"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_dotted_heuristic_module_head_entry_called(tmp_path):
    """The norm_dot heuristic (hyphenated unmapped dist foo-bar →
    candidate module foo.bar) also yields multi-segment heads."""
    target = _project(
        tmp_path,
        "import foo.bar\nfoo.bar.danger('x')\n",
    )
    deps = [_dep("foo-bar")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["foo.bar.danger"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_entry_equal_to_module_name_abstains(tmp_path):
    """fn == candidate module exactly: the entry names the module
    itself, not a function. For a DOTTED candidate module
    (ruamel.yaml) the verbatim query is well-formed (module
    ``ruamel``, function ``yaml``) and used to pair NOT_CALLED —
    minting a high-confidence not_function_reachable on a dep whose
    vulnerable code IS exercised — while the dot-less twin (yaml)
    abstained via the resolver's ValueError. Same semantic shape,
    one honest outcome: skip the entry, abstain at ``imported``."""
    target = _project(
        tmp_path,
        "import ruamel.yaml\nruamel.yaml.main.load('x')\n",
    )
    deps = [_dep("ruamel.yaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["ruamel.yaml"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_module_named_entry_in_mixed_list_blocks_downgrade(tmp_path):
    """The mixed-list variant: a module-named entry rides alongside a
    bindable uncalled one. The skipped entry must block the
    downgrade — the advisory names something this tier can't
    evaluate at function level."""
    target = _project(
        tmp_path,
        "import ruamel.yaml\nruamel.yaml.main.load('x')\n",
    )
    deps = [_dep("ruamel.yaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["ruamel.yaml", "absent_fn"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_bare_module_named_entry_same_outcome(tmp_path):
    """The dot-less twin (dist pyyaml, module yaml, entry \"yaml\")
    pins the parity direction: both spellings of \"entry names the
    module\" abstain identically."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.load('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["yaml"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_dist_name_head_entry_rebinds_to_module(tmp_path):
    """dist pyyaml, module yaml, entry ``pyyaml.load`` — the head
    spells the DISTRIBUTION, the spelling a human writes from the
    advisory's package field when dist and module names differ. It
    used to be composed into ``yaml.pyyaml.load``, a well-formed
    garbage query pairing NOT_CALLED — a single-entry list minted the
    high-confidence suppression on a dep whose vulnerable function IS
    called. The remainder must rebind onto each candidate module and
    hit the real call."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.load('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["pyyaml.load"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_dist_named_entry_abstains(tmp_path):
    """An entry EQUAL to the distribution name (``pyyaml``) names the
    package itself, not a function — the same semantic shape as the
    module-named entry: skip it, stay unpaired, abstain at
    ``imported`` (the unpaired entry blocks the downgrade via the
    coverage gate; it can never enable one)."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.load('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["pyyaml"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_dist_name_head_uncalled_still_downgrades(tmp_path):
    """Counter-direction: the dist-head rebind must not vacuously
    disable the suppression arm — a rebound entry the project never
    calls still downgrades."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.load('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["pyyaml.absent_fn"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_class_tail_entry_binds_via_project_imports(tmp_path):
    """An entry naming a class/submodule by its TAIL alone
    (``Composer.compose`` for ``yaml.composer.Composer.compose``)
    composes only the garbage root reading ``yaml.Composer.compose``
    — pairing NOT_CALLED and minting the suppression on a dep whose
    vulnerable method IS called. A project can only call the method
    after IMPORTING the class, so twins derived from the project's
    own imports under the candidate modules
    (``yaml.composer.Composer`` has tail ``Composer``) must bind."""
    target = _project(
        tmp_path,
        "from yaml.composer import Composer\nComposer.compose('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["Composer.compose"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_candidate_head_skipped_submodule_entry_binds(tmp_path):
    """The verbatim-arm variant of the same shape: a candidate-head
    entry that OMITS intermediate submodules
    (``yaml.Composer.compose`` for ``yaml.composer.Composer.compose``)
    is a well-formed verbatim query pairing NOT_CALLED. The
    import-derived twin must bind it the same way."""
    target = _project(
        tmp_path,
        "from yaml.composer import Composer\nComposer.compose('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["yaml.Composer.compose"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_class_tail_entry_uncalled_still_downgrades(tmp_path):
    """Counter-direction: the import-derived twin itself pairs
    NOT_CALLED for a genuinely-uncalled method — the twins never
    vacuously disable the suppression arm."""
    target = _project(
        tmp_path,
        "from yaml.composer import Composer\nComposer.compose('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["Composer.absent"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_attr_chain_call_tail_entry_binds(tmp_path):
    """``import yaml`` + attribute-chain call
    ``yaml.composer.Composer.compose(...)`` (idiomatic os.path
    style): Python does not require importing the defining
    submodule, so the import map alone ({"yaml": "yaml"}) cannot
    place a ``Composer.compose`` entry. The call chain itself
    carries the provenance — its trailing segments match the entry
    and its resolved prefix (``yaml.composer``) sits under a
    candidate module — so the call-derived twin must bind."""
    target = _project(
        tmp_path,
        "import yaml\nyaml.composer.Composer.compose('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["Composer.compose"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"

    # Mixed with an uncalled bindable entry alongside.
    out = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["Composer.compose", "absent_fn"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_star_import_tail_entry_abstains(tmp_path):
    """``from yaml.composer import *`` + ``Composer.compose(...)``:
    the inventory records NO provenance for a star import (empty
    import map), so the matching call chain cannot be placed under —
    or positively excluded from — the candidate modules. The entry
    must abstain (stay unpaired, blocking the downgrade), never ride
    the garbage compose into a suppression on a function the project
    may genuinely be calling."""
    target = _project(
        tmp_path,
        "from yaml.composer import *\nComposer.compose('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["Composer.compose"]},
    )
    assert out[deps[0].key()].verdict == "imported"


def test_star_import_uncalled_entry_still_downgrades(tmp_path):
    """Counter-direction: in the same star-import file, an entry no
    call chain matches derives no twin and raises no ambiguity — the
    composed query pairs NOT_CALLED and the downgrade proceeds."""
    target = _project(
        tmp_path,
        "from yaml.composer import *\nComposer.compose('x')\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["Composer.absent"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_hostile_chain_borrow_does_not_bind(tmp_path):
    """A crafted entry must not bind via an unrelated module's call
    chain: the chain's head resolves through the import map to a
    path OUTSIDE the candidate modules, so no twin derives and no
    ambiguity is raised — the honest downgrade proceeds."""
    target = _project(
        tmp_path,
        "from somelib import Widget\nWidget.run()\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["Widget.run"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_local_class_chain_does_not_bind(tmp_path):
    """A chain whose head is a locally-defined class is positively
    explained by the file itself — not a candidate-module access, no
    twin, no ambiguity: the downgrade proceeds."""
    target = _project(
        tmp_path,
        "class Widget:\n"
        "    @staticmethod\n"
        "    def run():\n"
        "        pass\n"
        "\n"
        "Widget.run()\n",
    )
    deps = [_dep("pyyaml")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_pypi_verdicts(
        deps, out,
        target=target,
        pypi_symbol_map={deps[0].key(): ["Widget.run"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"
