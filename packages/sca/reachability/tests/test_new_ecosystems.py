"""Reachability tests for the 5 ecosystems added in this PR:
Cargo, Go, RubyGems, NuGet, Composer.

Each ecosystem gets the same shape:
  - import found in non-test source → ``imported``
  - import found only in tests → ``not_reachable``
  - no import → ``not_reachable``
  - ecosystem-specific quirk (kebab→snake, vendor prefix, etc.)
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.reachability import (
    cargo as rcargo,
    composer as rcomposer,
    gemfile as rgem,
    gomod as rgo,
    nuget as rnuget,
)


# ---------------------------------------------------------------------------
# Cargo (Rust)
# ---------------------------------------------------------------------------

def test_cargo_imported_in_main_src(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text(
        "use serde::Serialize;\nfn main() {}\n", encoding="utf-8")
    scan = rcargo.scan_imports(tmp_path)
    r = rcargo.resolve_dep("serde", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_cargo_kebab_to_snake_normalisation(tmp_path: Path) -> None:
    """Cargo crate ``tokio-util`` is imported via ``use tokio_util``."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text(
        "use tokio_util::codec;\n", encoding="utf-8")
    scan = rcargo.scan_imports(tmp_path)
    r = rcargo.resolve_dep("tokio-util", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_cargo_extern_crate_form(tmp_path: Path) -> None:
    """Legacy ``extern crate foo;`` is also recognised."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text(
        "extern crate libc;\n", encoding="utf-8")
    scan = rcargo.scan_imports(tmp_path)
    r = rcargo.resolve_dep("libc", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_cargo_only_in_tests(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "integration.rs").write_text(
        "use proptest::prelude::*;\n", encoding="utf-8")
    scan = rcargo.scan_imports(tmp_path)
    r = rcargo.resolve_dep("proptest", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


def test_cargo_crate_root_examples_still_test(tmp_path: Path) -> None:
    # A crate-root examples/ dir IS a Cargo example target (not in the lib),
    # so a dep used only there stays not_reachable.
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "demo.rs").write_text(
        "use rand::random;\nfn main() {}\n", encoding="utf-8")
    scan = rcargo.scan_imports(tmp_path)
    r = rcargo.resolve_dep("rand", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


def test_cargo_nested_examples_module_is_production(tmp_path: Path) -> None:
    # A module named examples NESTED in the library (src/foo/examples/…) is
    # compiled into the crate = production code. It must NOT be treated as a
    # Cargo example target, or a dependency it uses is wrongly downgraded
    # (the silent false-negative this fix addresses).
    nested = tmp_path / "src" / "foo" / "examples"
    nested.mkdir(parents=True)
    (nested / "bar.rs").write_text(
        "use rand::random;\npub fn use_it() { let _ = random::<u8>(); }\n",
        encoding="utf-8")
    scan = rcargo.scan_imports(tmp_path)
    r = rcargo.resolve_dep("rand", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_cargo_no_match(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text(
        "fn main() {}\n", encoding="utf-8")
    scan = rcargo.scan_imports(tmp_path)
    r = rcargo.resolve_dep("anyhow", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

def test_go_single_line_import(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(
        'package main\nimport "github.com/foo/bar"\n', encoding="utf-8")
    scan = rgo.scan_imports(tmp_path)
    r = rgo.resolve_dep("github.com/foo/bar", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_go_block_import(tmp_path: Path) -> None:
    body = '''\
package main

import (
    "fmt"
    foo "github.com/foo/bar"
    "github.com/baz/qux/sub"
)
'''
    (tmp_path / "main.go").write_text(body, encoding="utf-8")
    scan = rgo.scan_imports(tmp_path)
    # Sub-package import should resolve dep at the parent module path.
    r = rgo.resolve_dep("github.com/baz/qux", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_go_only_in_test_file(tmp_path: Path) -> None:
    (tmp_path / "main_test.go").write_text(
        'package main\nimport "github.com/stretchr/testify"\n',
        encoding="utf-8")
    scan = rgo.scan_imports(tmp_path)
    r = rgo.resolve_dep("github.com/stretchr/testify", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


def test_go_vendor_dir_skipped(tmp_path: Path) -> None:
    (tmp_path / "vendor" / "github.com" / "foo" / "bar").mkdir(parents=True)
    (tmp_path / "vendor" / "github.com" / "foo" / "bar" / "lib.go").write_text(
        'package bar\nimport "github.com/foo/bar"\n', encoding="utf-8")
    (tmp_path / "main.go").write_text(
        "package main\n", encoding="utf-8")
    scan = rgo.scan_imports(tmp_path)
    r = rgo.resolve_dep("github.com/foo/bar", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------

def test_ruby_require_in_lib(tmp_path: Path) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "app.rb").write_text(
        "require 'rails'\n", encoding="utf-8")
    scan = rgem.scan_imports(tmp_path)
    r = rgem.resolve_dep("rails", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_ruby_kebab_to_underscore_alias(tmp_path: Path) -> None:
    """Gem ``rest-client`` is required as ``rest_client``."""
    (tmp_path / "app.rb").write_text(
        "require 'rest_client'\n", encoding="utf-8")
    scan = rgem.scan_imports(tmp_path)
    r = rgem.resolve_dep("rest-client", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_ruby_subpath_require(tmp_path: Path) -> None:
    """``require 'rails/all'`` should match the ``rails`` gem."""
    (tmp_path / "app.rb").write_text(
        "require 'rails/all'\n", encoding="utf-8")
    scan = rgem.scan_imports(tmp_path)
    r = rgem.resolve_dep("rails", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_ruby_only_in_spec(tmp_path: Path) -> None:
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "app_spec.rb").write_text(
        "require 'rspec'\n", encoding="utf-8")
    scan = rgem.scan_imports(tmp_path)
    r = rgem.resolve_dep("rspec", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


# ---------------------------------------------------------------------------
# NuGet (.NET)
# ---------------------------------------------------------------------------

def test_nuget_csharp_using(tmp_path: Path) -> None:
    (tmp_path / "App.cs").write_text(
        "using Newtonsoft.Json;\nclass App {}\n", encoding="utf-8")
    scan = rnuget.scan_imports(tmp_path)
    r = rnuget.resolve_dep("Newtonsoft.Json", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_nuget_namespace_subprefix_match(tmp_path: Path) -> None:
    """``using Newtonsoft.Json.Linq;`` matches dep ``Newtonsoft.Json``."""
    (tmp_path / "App.cs").write_text(
        "using Newtonsoft.Json.Linq;\n", encoding="utf-8")
    scan = rnuget.scan_imports(tmp_path)
    r = rnuget.resolve_dep("Newtonsoft.Json", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_nuget_using_alias_form(tmp_path: Path) -> None:
    """``using J = Newtonsoft.Json;`` (alias) — extract the RHS namespace."""
    (tmp_path / "App.cs").write_text(
        "using J = Newtonsoft.Json;\n", encoding="utf-8")
    scan = rnuget.scan_imports(tmp_path)
    r = rnuget.resolve_dep("Newtonsoft.Json", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_nuget_fsharp_open(tmp_path: Path) -> None:
    (tmp_path / "App.fs").write_text(
        "open Newtonsoft.Json\n", encoding="utf-8")
    scan = rnuget.scan_imports(tmp_path)
    r = rnuget.resolve_dep("Newtonsoft.Json", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_nuget_vb_imports(tmp_path: Path) -> None:
    (tmp_path / "App.vb").write_text(
        "Imports Newtonsoft.Json\n", encoding="utf-8")
    scan = rnuget.scan_imports(tmp_path)
    r = rnuget.resolve_dep("Newtonsoft.Json", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_nuget_only_in_tests_dir(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "App.cs").write_text(
        "using xunit;\n", encoding="utf-8")
    scan = rnuget.scan_imports(tmp_path)
    r = rnuget.resolve_dep("xunit", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


# ---------------------------------------------------------------------------
# Composer (PHP)
# ---------------------------------------------------------------------------

def test_composer_pkg_namespace_match(tmp_path: Path) -> None:
    """`use Symfony\\Console\\...` matches dep `symfony/console`."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.php").write_text(
        "<?php\nuse Symfony\\Console\\Input\\InputInterface;\n",
        encoding="utf-8")
    scan = rcomposer.scan_imports(tmp_path)
    r = rcomposer.resolve_dep("symfony/console", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_composer_kebab_pkg_name_pascalised(tmp_path: Path) -> None:
    """Pkg ``my-thing`` → namespace segment ``MyThing``."""
    (tmp_path / "App.php").write_text(
        "<?php\nuse Acme\\MyThing\\Foo;\n", encoding="utf-8")
    scan = rcomposer.scan_imports(tmp_path)
    r = rcomposer.resolve_dep("acme/my-thing", scan, target=tmp_path)
    assert r.verdict == "imported"


def test_composer_vendor_only_lower_confidence(tmp_path: Path) -> None:
    """`use Symfony\\Other` — vendor matches but pkg-segment doesn't.
    Still ``imported`` but with lower confidence."""
    (tmp_path / "App.php").write_text(
        "<?php\nuse Symfony\\Component\\Other\\Stuff;\n", encoding="utf-8")
    scan = rcomposer.scan_imports(tmp_path)
    r = rcomposer.resolve_dep("symfony/console", scan, target=tmp_path)
    assert r.verdict == "imported"
    assert r.confidence.level == "low"


def test_composer_no_match(tmp_path: Path) -> None:
    (tmp_path / "App.php").write_text(
        "<?php\nuse OtherVendor\\Lib\\X;\n", encoding="utf-8")
    scan = rcomposer.scan_imports(tmp_path)
    r = rcomposer.resolve_dep("symfony/console", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


def test_composer_only_in_tests(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "AppTest.php").write_text(
        "<?php\nuse Symfony\\Console\\X;\n", encoding="utf-8")
    scan = rcomposer.scan_imports(tmp_path)
    r = rcomposer.resolve_dep("symfony/console", scan, target=tmp_path)
    assert r.verdict == "not_reachable"


def test_composer_invalid_dep_name(tmp_path: Path) -> None:
    """Non-``vendor/pkg`` shape → not_evaluated."""
    scan = rcomposer.scan_imports(tmp_path)
    r = rcomposer.resolve_dep("invalid-name", scan, target=tmp_path)
    assert r.verdict == "not_evaluated"


# ---------------------------------------------------------------------------
# Orchestrator dispatch — every new ecosystem flows through scan()
# ---------------------------------------------------------------------------

def test_orchestrator_dispatches_to_each(tmp_path: Path) -> None:
    """Smoke: ``reachability.scan(deps)`` returns Reachability for one
    dep per ecosystem without crashing."""
    from packages.sca.reachability import scan
    from packages.sca.models import Confidence, Dependency, PinStyle
    deps = [
        Dependency(ecosystem=eco, name=name, version="1.0",
                    declared_in=Path("/x/manifest"),
                    scope="main", is_lockfile=False,
                    pin_style=PinStyle.EXACT, direct=True,
                    purl=f"pkg:foo/{name}@1.0",
                    parser_confidence=Confidence("high", reason="t"))
        for eco, name in (
            ("Cargo", "serde"),
            ("Go", "github.com/foo/bar"),
            ("RubyGems", "rails"),
            ("NuGet", "Newtonsoft.Json"),
            ("Packagist", "symfony/console"),
        )
    ]
    out = scan(tmp_path, deps)
    assert len(out) == 5
    # All should be not_reachable on an empty target.
    for r in out.values():
        assert r.verdict in ("not_reachable", "not_evaluated")
