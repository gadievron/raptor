"""Tests for the four new function-level reachability tiers
(Cargo / RubyGems / NuGet / Packagist).

Each tier follows the Java/Go pattern: build_<eco>_symbol_map
extracts qualified names from OSV results filtered by dep_key
prefix, then refine_<eco>_verdicts runs the function-level
resolver and updates verdicts in place. Tests cover:
  - dep_key prefix filtering
  - empty / missing OSV inputs
  - the symbol_map rebuilds resolver-compatible qualified names
  - verdict transitions on a tiny inventory fixture
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from packages.sca.models import Confidence, Dependency, PinStyle, Reachability


@dataclass
class _Adv:
    ecosystem_specific: Optional[Dict[str, Any]] = None
    database_specific: Optional[Dict[str, Any]] = None


@dataclass
class _OsvResult:
    dep_key: str
    advisories: List[_Adv] = field(default_factory=list)


def _dep(name: str, version: str, ecosystem: str) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("manifest"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _imported() -> Reachability:
    return Reachability(
        verdict="imported",
        confidence=Confidence("high", reason="prior tier"),
        evidence=[],
    )


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_rust")


def test_cargo_symbol_map_filters_by_prefix():
    from packages.sca.reachability.cargo_function_level import (
        build_cargo_symbol_map,
    )
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "serde", "symbols": ["from_str"]}],
    })
    out = build_cargo_symbol_map([
        _OsvResult(dep_key="Cargo:serde@1.0.0", advisories=[adv]),
        _OsvResult(dep_key="Go:foo@1.0", advisories=[adv]),
    ])
    assert "Cargo:serde@1.0.0" in out
    assert "Go:foo@1.0" not in out
    assert out["Cargo:serde@1.0.0"] == ["serde.from_str"]


_RUSTSEC_ADV = _Adv(ecosystem_specific={
    # Real RustSec OSV export shape (RUSTSEC-2021-0003): per-function
    # data lives under ``affects.functions`` as fully-qualified
    # ``crate::Type::method`` strings; the flat key is present but
    # null.
    "affected_functions": None,
    "affects": {
        "functions": ["smallvec::SmallVec::insert_many"],
        "arch": [], "os": [],
    },
})


def test_cargo_rustsec_affects_called_not_downgraded(tmp_path: Path):
    """A RustSec-convention advisory whose affected function the
    project genuinely calls must land on ``likely_called`` through
    the REAL producer (build → refine). Pre-fix the tier read only
    ``imports[]`` / flat lists, so the dominant Rust producer's
    shape extracted nothing and the tier silently no-oped."""
    from packages.sca.reachability.cargo_function_level import (
        build_cargo_symbol_map,
        refine_cargo_verdicts,
    )
    smap = build_cargo_symbol_map([
        _OsvResult(dep_key="Cargo:smallvec@1.6.0",
                   advisories=[_RUSTSEC_ADV]),
    ])
    assert smap == {
        "Cargo:smallvec@1.6.0": ["smallvec.SmallVec.insert_many"],
    }
    (tmp_path / "main.rs").write_text(
        "use smallvec::SmallVec;\n"
        "fn main() { SmallVec::insert_many(v); }\n"
    )
    deps = [_dep("smallvec", "1.6.0", "Cargo")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_cargo_verdicts(
        deps, out, target=tmp_path, cargo_symbol_map=smap,
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_cargo_rustsec_affects_uncalled_downgrades(tmp_path: Path):
    """Counter-direction: the RustSec shape must feed the suppression
    arm too — an uncalled affected function still downgrades."""
    from packages.sca.reachability.cargo_function_level import (
        build_cargo_symbol_map,
        refine_cargo_verdicts,
    )
    smap = build_cargo_symbol_map([
        _OsvResult(dep_key="Cargo:smallvec@1.6.0",
                   advisories=[_RUSTSEC_ADV]),
    ])
    (tmp_path / "main.rs").write_text(
        "use smallvec::SmallVec;\n"
        "fn main() { SmallVec::with_capacity(4); }\n"
    )
    deps = [_dep("smallvec", "1.6.0", "Cargo")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_cargo_verdicts(
        deps, out, target=tmp_path, cargo_symbol_map=smap,
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_cargo_refine_likely_called(tmp_path: Path):
    from packages.sca.reachability.cargo_function_level import (
        refine_cargo_verdicts,
    )
    (tmp_path / "main.rs").write_text(
        "use serde::from_str;\nfn main() { from_str(s); }\n"
    )
    deps = [_dep("serde", "1.0.0", "Cargo")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_cargo_verdicts(
        deps, out,
        target=tmp_path,
        cargo_symbol_map={deps[0].key(): ["serde.from_str"]},
    )
    # serde.from_str -> chain ["from_str"] resolves via import map.
    assert out[deps[0].key()].verdict == "likely_called"


def test_cargo_refine_not_function_reachable(tmp_path: Path):
    from packages.sca.reachability.cargo_function_level import (
        refine_cargo_verdicts,
    )
    (tmp_path / "main.rs").write_text(
        "use serde::other;\nfn main() { other(); }\n"
    )
    deps = [_dep("serde", "1.0.0", "Cargo")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_cargo_verdicts(
        deps, out,
        target=tmp_path,
        cargo_symbol_map={deps[0].key(): ["serde.from_str"]},
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


def test_cargo_skips_non_imported_verdict(tmp_path: Path):
    from packages.sca.reachability.cargo_function_level import (
        refine_cargo_verdicts,
    )
    deps = [_dep("serde", "1.0.0", "Cargo")]
    out = {
        deps[0].key(): Reachability(
            verdict="not_reachable",
            confidence=Confidence("high", reason="prior"),
        ),
    }
    refine_cargo_verdicts(
        deps, out,
        target=tmp_path,
        cargo_symbol_map={deps[0].key(): ["serde.from_str"]},
    )
    assert out[deps[0].key()].verdict == "not_reachable"


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_ruby")


def test_rubygems_symbol_map_filters_by_prefix():
    from packages.sca.reachability.rubygems_function_level import (
        build_rubygems_symbol_map,
    )
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "json", "symbols": ["parse"]}],
    })
    out = build_rubygems_symbol_map([
        _OsvResult(dep_key="RubyGems:json@2.0.0", advisories=[adv]),
        _OsvResult(dep_key="PyPI:json@1.0", advisories=[adv]),
    ])
    assert "RubyGems:json@2.0.0" in out
    assert "PyPI:json@1.0" not in out


def test_rubygems_refine_likely_called(tmp_path: Path):
    from packages.sca.reachability.rubygems_function_level import (
        refine_rubygems_verdicts,
    )
    (tmp_path / "x.rb").write_text(
        'require "json"\nclass C\n  def m\n    json.parse(s)\n  end\nend\n'
    )
    deps = [_dep("json", "2.0.0", "RubyGems")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_rubygems_verdicts(
        deps, out,
        target=tmp_path,
        rubygems_symbol_map={deps[0].key(): ["json.parse"]},
    )
    assert out[deps[0].key()].verdict == "likely_called"


_ACTIONPACK_ADV = _Adv(ecosystem_specific={
    "imports": [{"path": "ActionDispatch::Routing",
                 "symbols": ["Mapper#draw"]}],
})


def test_rubygems_ruby_style_symbol_called_not_downgraded(tmp_path: Path):
    """Ruby advisories qualify symbols with '::' and '#'. The
    resolver splits on '.' only, so without normalisation a real
    call of the affected method would read NOT_CALLED and the dep
    would be wrongly downgraded at high confidence."""
    from packages.sca.reachability.rubygems_function_level import (
        build_rubygems_symbol_map,
        refine_rubygems_verdicts,
    )
    smap = build_rubygems_symbol_map([
        _OsvResult(dep_key="RubyGems:actionpack@7.0.0",
                   advisories=[_ACTIONPACK_ADV]),
    ])
    assert smap == {
        "RubyGems:actionpack@7.0.0": ["ActionDispatch.Routing.Mapper.draw"],
    }
    (tmp_path / "routes.rb").write_text(
        "class C\n  def m\n"
        "    ActionDispatch::Routing::Mapper.draw(x)\n"
        "  end\nend\n"
    )
    deps = [_dep("actionpack", "7.0.0", "RubyGems")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_rubygems_verdicts(
        deps, out, target=tmp_path, rubygems_symbol_map=smap,
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_rubygems_ruby_style_symbol_uncalled_still_downgraded(tmp_path: Path):
    """Same '::'/'#' symbol but the project never calls it — the
    downgrade must still fire."""
    from packages.sca.reachability.rubygems_function_level import (
        build_rubygems_symbol_map,
        refine_rubygems_verdicts,
    )
    smap = build_rubygems_symbol_map([
        _OsvResult(dep_key="RubyGems:actionpack@7.0.0",
                   advisories=[_ACTIONPACK_ADV]),
    ])
    (tmp_path / "routes.rb").write_text(
        "class C\n  def m\n"
        "    ActionDispatch::Routing::Mapper.match(x)\n"
        "  end\nend\n"
    )
    deps = [_dep("actionpack", "7.0.0", "RubyGems")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_rubygems_verdicts(
        deps, out, target=tmp_path, rubygems_symbol_map=smap,
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_c_sharp")


def test_nuget_symbol_map_filters_by_prefix():
    from packages.sca.reachability.nuget_function_level import (
        build_nuget_symbol_map,
    )
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "Newtonsoft.Json",
                     "symbols": ["JsonConvert.DeserializeObject"]}],
    })
    out = build_nuget_symbol_map([
        _OsvResult(dep_key="NuGet:Newtonsoft.Json@13.0.1",
                   advisories=[adv]),
        _OsvResult(dep_key="npm:json@1.0", advisories=[adv]),
    ])
    assert "NuGet:Newtonsoft.Json@13.0.1" in out
    assert "npm:json@1.0" not in out


def test_nuget_refine_likely_called_explicit_class_alias(tmp_path: Path):
    """C# ``using Namespace`` only brings the namespace into scope —
    classes inside it aren't bound directly. Function-level
    matching works cleanly when the source uses an explicit alias
    like ``using JsonConvert = Newtonsoft.Json.JsonConvert;`` or
    when the OSV qualified name matches the chain shape directly.

    For the bare ``using Namespace`` shape, function-level
    reachability is best-effort — verdict stays ``imported``
    (preserved) when the chain head doesn't match the import map.
    Documenting this limitation rather than over-claiming a match.
    """
    from packages.sca.reachability.nuget_function_level import (
        refine_nuget_verdicts,
    )
    (tmp_path / "X.cs").write_text(
        "using JsonConvert = Newtonsoft.Json.JsonConvert;\n"
        "class C { void M() { JsonConvert.DeserializeObject(s); } }\n"
    )
    deps = [_dep("Newtonsoft.Json", "13.0.1", "NuGet")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_nuget_verdicts(
        deps, out,
        target=tmp_path,
        nuget_symbol_map={
            deps[0].key():
                ["Newtonsoft.Json.JsonConvert.DeserializeObject"],
        },
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_nuget_bare_namespace_using_preserves_imported(tmp_path: Path):
    """Bare ``using Namespace`` shape — the DOMINANT C# import
    shape: ``using Newtonsoft.Json;`` binds only ``Json``, so the
    chain head ``JsonConvert`` is unbound and the resolver cannot
    see the call. The fixture plainly CALLS the affected function,
    so the tier must preserve ``imported`` — a NOT_CALLED-driven
    downgrade here is a false high-confidence suppression."""
    from packages.sca.reachability.nuget_function_level import (
        refine_nuget_verdicts,
    )
    (tmp_path / "X.cs").write_text(
        "using Newtonsoft.Json;\n"
        "class C { void M() { JsonConvert.DeserializeObject(s); } }\n"
    )
    deps = [_dep("Newtonsoft.Json", "13.0.1", "NuGet")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_nuget_verdicts(
        deps, out,
        target=tmp_path,
        nuget_symbol_map={
            deps[0].key():
                ["Newtonsoft.Json.JsonConvert.DeserializeObject"],
        },
    )
    assert out[deps[0].key()].verdict == "imported"


def test_nuget_bare_namespace_without_class_call_still_downgrades(
    tmp_path: Path,
):
    """Counter-direction: the namespace is ``using``-bound but the
    affected class/method is never mentioned — NOT_CALLED is
    well-supported and the downgrade must still fire (the
    bare-using mask may not disable the tier's suppression arm)."""
    from packages.sca.reachability.nuget_function_level import (
        refine_nuget_verdicts,
    )
    (tmp_path / "X.cs").write_text(
        "using Newtonsoft.Json;\n"
        "class C { void M() { Other.DoThing(s); } }\n"
    )
    deps = [_dep("Newtonsoft.Json", "13.0.1", "NuGet")]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_nuget_verdicts(
        deps, out,
        target=tmp_path,
        nuget_symbol_map={
            deps[0].key():
                ["Newtonsoft.Json.JsonConvert.DeserializeObject"],
        },
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"


# ---------------------------------------------------------------------------
# Packagist (PHP)
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_php")


def test_packagist_symbol_map_filters_by_prefix():
    from packages.sca.reachability.packagist_function_level import (
        build_packagist_symbol_map,
    )
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "Symfony\\Component\\HttpFoundation",
                     "symbols": ["Request.create"]}],
    })
    out = build_packagist_symbol_map([
        _OsvResult(
            dep_key="Packagist:symfony/http-foundation@5.4.0",
            advisories=[adv],
        ),
        _OsvResult(dep_key="npm:foo@1.0", advisories=[adv]),
    ])
    assert "Packagist:symfony/http-foundation@5.4.0" in out
    assert "npm:foo@1.0" not in out


def test_packagist_refine_likely_called(tmp_path: Path):
    """A genuinely-called OSV symbol MUST land on ``likely_called``.

    The symbol map is built through the real producer from the OSV
    backslash shape (``Request::create`` under a ``Foo\\Bar`` path)
    — hand-set dotted maps masked the missing ``\\`` normalisation,
    and the previous three-way ``in (...)`` assert accepted every
    possible verdict including the false high-confidence
    ``not_function_reachable`` downgrade."""
    from packages.sca.reachability.packagist_function_level import (
        build_packagist_symbol_map,
        refine_packagist_verdicts,
    )
    (tmp_path / "X.php").write_text(
        '<?php\nuse Symfony\\Component\\HttpFoundation\\Request;\n'
        'class C { function m() { Request::create("/"); } }\n'
    )
    deps = [_dep("symfony/http-foundation", "5.4.0", "Packagist")]
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "Symfony\\Component\\HttpFoundation",
                     "symbols": ["Request::create"]}],
    })
    symbol_map = build_packagist_symbol_map([
        _OsvResult(dep_key=deps[0].key(), advisories=[adv]),
    ])
    assert symbol_map[deps[0].key()] == [
        "Symfony.Component.HttpFoundation.Request.create",
    ]
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_packagist_verdicts(
        deps, out,
        target=tmp_path,
        packagist_symbol_map=symbol_map,
    )
    assert out[deps[0].key()].verdict == "likely_called"


def test_packagist_refine_not_called_still_downgrades(tmp_path: Path):
    """Counter-direction: the namespace is imported but the affected
    symbol is never called — the downgrade to
    ``not_function_reachable`` must still fire (the separator fix
    may not silently disable the tier's suppression arm)."""
    from packages.sca.reachability.packagist_function_level import (
        build_packagist_symbol_map,
        refine_packagist_verdicts,
    )
    (tmp_path / "X.php").write_text(
        '<?php\nuse Symfony\\Component\\HttpFoundation\\Request;\n'
        'class C { function m() { Request::createFromGlobals(); } }\n'
    )
    deps = [_dep("symfony/http-foundation", "5.4.0", "Packagist")]
    adv = _Adv(ecosystem_specific={
        "imports": [{"path": "Symfony\\Component\\HttpFoundation",
                     "symbols": ["Request::create"]}],
    })
    symbol_map = build_packagist_symbol_map([
        _OsvResult(dep_key=deps[0].key(), advisories=[adv]),
    ])
    out: Dict[str, Reachability] = {deps[0].key(): _imported()}
    refine_packagist_verdicts(
        deps, out,
        target=tmp_path,
        packagist_symbol_map=symbol_map,
    )
    assert out[deps[0].key()].verdict == "not_function_reachable"
