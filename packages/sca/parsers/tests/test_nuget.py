"""Tests for the NuGet parser (.csproj + packages.config + packages.lock.json)."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.models import PinStyle
from packages.sca.parsers.nuget import (
    parse_lockfile,
    parse_msbuild_project,
    parse_packages_config,
)


def _write(tmp_path: Path, body: str, name: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# .csproj — modern SDK-style
# ---------------------------------------------------------------------------

def test_csproj_attribute_form(tmp_path: Path) -> None:
    body = """\
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="3.1.0" />
  </ItemGroup>
</Project>
"""
    p = _write(tmp_path, body, "App.csproj")
    by_name = {d.name: d for d in parse_msbuild_project(p)}
    assert "Newtonsoft.Json" in by_name
    assert by_name["Newtonsoft.Json"].version == "13.0.1"


def test_csproj_child_element_version(tmp_path: Path) -> None:
    """Some projects use ``<Version>X</Version>`` as a child."""
    body = """\
<Project>
  <ItemGroup>
    <PackageReference Include="Foo">
      <Version>1.2.3</Version>
    </PackageReference>
  </ItemGroup>
</Project>
"""
    p = _write(tmp_path, body, "App.csproj")
    deps = parse_msbuild_project(p)
    assert len(deps) == 1
    assert deps[0].version == "1.2.3"


def test_csproj_namespaced(tmp_path: Path) -> None:
    """Legacy projects with the MSBuild XML namespace."""
    body = """\
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <PackageReference Include="OldPkg" Version="1.0.0" />
  </ItemGroup>
</Project>
"""
    p = _write(tmp_path, body, "App.csproj")
    deps = parse_msbuild_project(p)
    assert len(deps) == 1
    assert deps[0].name == "OldPkg"


def test_csproj_private_assets_marks_build(tmp_path: Path) -> None:
    body = """\
<Project>
  <ItemGroup>
    <PackageReference Include="Analyzer.Pkg" Version="1.0.0"
                      PrivateAssets="all" />
  </ItemGroup>
</Project>
"""
    p = _write(tmp_path, body, "App.csproj")
    deps = parse_msbuild_project(p)
    assert deps[0].scope == "build"


def test_csproj_exact_pin_brackets(tmp_path: Path) -> None:
    body = """\
<Project>
  <ItemGroup>
    <PackageReference Include="Foo" Version="[1.2.3]" />
  </ItemGroup>
</Project>
"""
    p = _write(tmp_path, body, "App.csproj")
    deps = parse_msbuild_project(p)
    assert deps[0].pin_style is PinStyle.EXACT
    assert deps[0].version == "1.2.3"


def test_csproj_range_brackets(tmp_path: Path) -> None:
    body = """\
<Project>
  <ItemGroup>
    <PackageReference Include="Foo" Version="[1.0,2.0)" />
  </ItemGroup>
</Project>
"""
    p = _write(tmp_path, body, "App.csproj")
    deps = parse_msbuild_project(p)
    assert deps[0].pin_style is PinStyle.RANGE


def test_csproj_minimum_form(tmp_path: Path) -> None:
    """``Version="1.2.3"`` (no brackets) is NuGet's "≥1.2.3" — RANGE."""
    body = """\
<Project>
  <ItemGroup>
    <PackageReference Include="Foo" Version="1.2.3" />
  </ItemGroup>
</Project>
"""
    p = _write(tmp_path, body, "App.csproj")
    deps = parse_msbuild_project(p)
    assert deps[0].pin_style is PinStyle.RANGE
    assert deps[0].version == "1.2.3"


def test_csproj_invalid_xml_returns_empty(tmp_path: Path) -> None:
    p = _write(tmp_path, "<Project><ItemGroup></Project>", "App.csproj")
    assert parse_msbuild_project(p) == []


@pytest.mark.parametrize("spec", [
    "(1.2.3)",   # exclusive on both sides + single value = empty interval
    "[1.2.3)",   # inclusive lower, exclusive upper, single value = empty
    "(1.2.3]",   # exclusive lower, inclusive upper, single value = empty
])
def test_csproj_pathological_brackets_classified_unknown(
    tmp_path: Path, spec: str,
) -> None:
    """Regression for the 2026-05-21 lint-sweep find: only ``[V]``
    (both inclusive, single value) is a valid EXACT pin per the
    NuGet version-range spec. The pathological one-value forms
    ``(V)`` / ``[V)`` / ``(V]`` describe empty intervals and
    must NOT be classified as EXACT — otherwise the harden
    planner would treat a malformed manifest entry as a
    concrete pinned version and propagate the bad version
    downstream. Pre-fix: ``_classify_version_spec`` extracted
    both bracket tokens but ignored them, returning EXACT
    whenever the regex matched a single value. Post-fix:
    bracket tokens are checked; non-``[..]`` single-value forms
    return ``PinStyle.UNKNOWN``."""
    from packages.sca.parsers.nuget import _classify_version_spec

    style, version = _classify_version_spec(spec)
    assert style is PinStyle.UNKNOWN, (
        f"pathological spec {spec!r} classified as {style!r} "
        f"(should be UNKNOWN); version={version!r}"
    )
    # No concrete version pinned — the planner gets nothing to
    # mistake for a real version.
    assert version is None, (
        f"pathological spec {spec!r} returned version={version!r} "
        f"(should be None to prevent downstream propagation)"
    )


def test_csproj_canonical_single_value_still_exact(
    tmp_path: Path,
) -> None:
    """Companion to the pathological-bracket test: ``[1.2.3]``
    (the ONLY valid single-value form per spec) must still be
    classified as EXACT. Pins the regression-fix didn't
    over-correct into rejecting valid input."""
    from packages.sca.parsers.nuget import _classify_version_spec

    style, version = _classify_version_spec("[1.2.3]")
    assert style is PinStyle.EXACT
    assert version == "1.2.3"


# ---------------------------------------------------------------------------
# packages.config — legacy
# ---------------------------------------------------------------------------

def test_packages_config_basic(tmp_path: Path) -> None:
    body = """\
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" />
  <package id="Serilog" version="3.1.0" />
</packages>
"""
    p = _write(tmp_path, body, "packages.config")
    deps = parse_packages_config(p)
    assert {d.name for d in deps} == {"Newtonsoft.Json", "Serilog"}


# ---------------------------------------------------------------------------
# packages.lock.json — lockfile
# ---------------------------------------------------------------------------

def test_lockfile_direct_vs_transitive(tmp_path: Path) -> None:
    body = """\
{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.1, )",
        "resolved": "13.0.1"
      },
      "Microsoft.Foo": {
        "type": "Transitive",
        "resolved": "5.0.0"
      }
    }
  }
}
"""
    p = _write(tmp_path, body, "packages.lock.json")
    deps = parse_lockfile(p)
    by_name = {d.name: d for d in deps}
    assert by_name["Newtonsoft.Json"].direct is True
    assert by_name["Microsoft.Foo"].direct is False
    assert by_name["Newtonsoft.Json"].pin_style is PinStyle.EXACT


def test_lockfile_dedup_across_targets(tmp_path: Path) -> None:
    """Same dep present in multiple target frameworks — emit once."""
    body = """\
{
  "dependencies": {
    "net8.0": {"Foo": {"type": "Direct", "resolved": "1.0.0"}},
    "net6.0": {"Foo": {"type": "Direct", "resolved": "1.0.0"}}
  }
}
"""
    p = _write(tmp_path, body, "packages.lock.json")
    deps = parse_lockfile(p)
    assert len(deps) == 1


# ---------------------------------------------------------------------------
# Discovery → parser dispatch
# ---------------------------------------------------------------------------

def test_dispatch_csproj_via_suffix(tmp_path: Path) -> None:
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest as dispatch
    repo = tmp_path / "dotnet-proj"
    repo.mkdir()
    (repo / "App.csproj").write_text(
        '<Project><ItemGroup>'
        '<PackageReference Include="Foo" Version="1.0.0" />'
        '</ItemGroup></Project>',
        encoding="utf-8",
    )
    manifests = find_manifests(repo)
    csproj = next(m for m in manifests if m.path.suffix == ".csproj")
    assert csproj.ecosystem == "NuGet"
    deps = dispatch(csproj)
    assert deps and deps[0].name == "Foo"


def test_dispatch_lockfile_via_filename(tmp_path: Path) -> None:
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest as dispatch
    repo = tmp_path / "dotnet-proj"
    repo.mkdir()
    (repo / "packages.lock.json").write_text(
        '{"dependencies":{"net8":{"Foo":{"type":"Direct","resolved":"1.0"}}}}',
        encoding="utf-8",
    )
    manifests = find_manifests(repo)
    lock = next(m for m in manifests if m.path.name == "packages.lock.json")
    assert lock.ecosystem == "NuGet"
    deps = dispatch(lock)
    assert deps and deps[0].name == "Foo"


# ---------------------------------------------------------------------------
# Central Package Management (CPM) — Directory.Packages.props resolution
# ---------------------------------------------------------------------------

def _cpm_setup(
    tmp_path: Path, csproj_body: str, cpm_body: str,
    *, sub_dir: str = "",
    inner_cpm_body: str = "",
    use_git: bool = True,
) -> Path:
    """Build a CPM-shaped test repo. ``cpm_body`` is the root
    Directory.Packages.props; ``inner_cpm_body`` (when set) goes
    in ``sub_dir`` for hierarchical-resolution tests.

    A ``.git`` directory is created at the repo root to bound the
    ``find_cpm_chain`` walk — without it, the chain walks all
    the way to the filesystem root and may accidentally pick up
    /tmp/Directory.Packages.props from a parallel test run.
    """
    if use_git:
        (tmp_path / ".git").mkdir(exist_ok=True)
    (tmp_path / "Directory.Packages.props").write_text(
        cpm_body, encoding="utf-8",
    )
    csproj_dir = tmp_path / sub_dir if sub_dir else tmp_path
    csproj_dir.mkdir(parents=True, exist_ok=True)
    if inner_cpm_body:
        (csproj_dir / "Directory.Packages.props").write_text(
            inner_cpm_body, encoding="utf-8",
        )
    csproj = csproj_dir / "App.csproj"
    csproj.write_text(csproj_body, encoding="utf-8")
    return csproj


def test_cpm_resolves_versionless_package_reference(tmp_path: Path):
    """Modern .NET pattern: csproj has no Version attribute, the
    version comes from Directory.Packages.props. Pre-fix SCA
    silently dropped these; post-fix the CPM lookup resolves them."""
    # Reset the CPM parse cache so this test's writes are seen
    # fresh — without this, a sibling test could pre-populate
    # the cache.
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    _reset_cache_for_tests()

    csproj = _cpm_setup(
        tmp_path,
        csproj_body="""\
<Project>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" />
  </ItemGroup>
</Project>
""",
        cpm_body="""\
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
""",
    )
    deps = parse_msbuild_project(csproj)
    assert len(deps) == 1
    assert deps[0].name == "Newtonsoft.Json"
    assert deps[0].version == "13.0.3"
    assert deps[0].source_extra.get("origin") == "cpm_central"


def test_csproj_inline_version_overrides_cpm(tmp_path: Path):
    """Precedence: csproj inline Version dominates over CPM
    entry, matching MSBuild's resolution. Pre-CPM-era projects
    that adopted CPM partial typically rely on this."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    _reset_cache_for_tests()
    csproj = _cpm_setup(
        tmp_path,
        csproj_body="""\
<Project>
  <ItemGroup>
    <PackageReference Include="X" Version="2.0.0" />
  </ItemGroup>
</Project>
""",
        cpm_body="""\
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""",
    )
    deps = parse_msbuild_project(csproj)
    assert deps[0].version == "2.0.0"
    assert deps[0].source_extra.get("origin") == "inline_version"


def test_version_override_takes_precedence_over_cpm(tmp_path: Path):
    """``<PackageReference Include="X" VersionOverride="9.9.9" />``
    is the documented escape hatch for per-csproj overrides of
    a CPM-managed version. Resolver must honour."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    _reset_cache_for_tests()
    csproj = _cpm_setup(
        tmp_path,
        csproj_body="""\
<Project>
  <ItemGroup>
    <PackageReference Include="X" VersionOverride="9.9.9" />
  </ItemGroup>
</Project>
""",
        cpm_body="""\
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""",
    )
    deps = parse_msbuild_project(csproj)
    assert deps[0].version == "9.9.9"
    assert deps[0].source_extra.get("origin") == "version_override"


def test_inner_cpm_overrides_outer(tmp_path: Path):
    """Hierarchical: a Directory.Packages.props at ``src/MyLib/``
    overrides a Directory.Packages.props at the repo root for the
    same package name."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    _reset_cache_for_tests()
    csproj = _cpm_setup(
        tmp_path,
        csproj_body="""\
<Project>
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""",
        cpm_body="""\
<Project>
  <ItemGroup><PackageVersion Include="X" Version="1.0.0" /></ItemGroup>
</Project>
""",
        sub_dir="src/MyLib",
        inner_cpm_body="""\
<Project>
  <ItemGroup><PackageVersion Include="X" Version="2.0.0" /></ItemGroup>
</Project>
""",
    )
    deps = parse_msbuild_project(csproj)
    assert deps[0].version == "2.0.0"


def test_global_package_reference_auto_emitted(tmp_path: Path):
    """``<GlobalPackageReference>`` is forcibly included in
    every csproj in the solution. The resolver emits these as
    Dependency rows even when the csproj never explicitly
    references the package."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    _reset_cache_for_tests()
    csproj = _cpm_setup(
        tmp_path,
        csproj_body="""\
<Project>
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""",
        cpm_body="""\
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
    <GlobalPackageReference Include="Microsoft.SourceLink.GitHub" Version="1.1.1" />
  </ItemGroup>
</Project>
""",
    )
    deps = parse_msbuild_project(csproj)
    by_name = {d.name: d for d in deps}
    assert "X" in by_name
    assert "Microsoft.SourceLink.GitHub" in by_name
    assert by_name["Microsoft.SourceLink.GitHub"].version == "1.1.1"
    assert by_name["Microsoft.SourceLink.GitHub"].source_extra.get("origin") == "cpm_global"


def test_directory_build_props_provides_version_for_csproj(
    tmp_path: Path,
):
    """Pre-CPM convention: a versionless ``<PackageReference>`` in
    csproj can pull its version from an inherited
    ``Directory.Build.props`` with a versioned PackageReference
    of the same name. SCA must read that path so projects that
    haven't migrated to CPM yet still get full coverage."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    _reset_cache_for_tests()

    (tmp_path / ".git").mkdir()
    (tmp_path / "Directory.Build.props").write_text(
        """\
<Project>
  <ItemGroup>
    <PackageReference Include="Microsoft.SourceLink.GitHub" Version="1.0.0" />
  </ItemGroup>
</Project>
""", encoding="utf-8",
    )
    csproj = tmp_path / "App.csproj"
    csproj.write_text(
        """\
<Project>
  <ItemGroup>
    <PackageReference Include="Microsoft.SourceLink.GitHub" />
  </ItemGroup>
</Project>
""", encoding="utf-8",
    )
    deps = parse_msbuild_project(csproj)
    assert len(deps) == 1
    assert deps[0].name == "Microsoft.SourceLink.GitHub"
    assert deps[0].version == "1.0.0"
    # Origin labels it ``cpm_central`` because the resolver treats
    # Directory.Build.props PackageReference entries as
    # central-declaration-equivalent (it's the same mechanism
    # MSBuild uses for auto-import). The bumper rewriter will
    # disambiguate the actual file at write time.
    assert deps[0].source_extra.get("origin") == "cpm_central"


def test_cpm_overrides_directory_build_props_for_same_dir(tmp_path: Path):
    """Within the same directory, Directory.Packages.props (CPM)
    is applied AFTER Directory.Build.props — so CPM's
    PackageVersion overrides the inherited PackageReference's
    Version when both declare the same package name. Matches
    MSBuild import order."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    _reset_cache_for_tests()

    (tmp_path / ".git").mkdir()
    (tmp_path / "Directory.Build.props").write_text(
        """\
<Project>
  <ItemGroup>
    <PackageReference Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""", encoding="utf-8",
    )
    (tmp_path / "Directory.Packages.props").write_text(
        """\
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="2.0.0" />
  </ItemGroup>
</Project>
""", encoding="utf-8",
    )
    csproj = tmp_path / "App.csproj"
    csproj.write_text(
        """\
<Project>
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""", encoding="utf-8",
    )
    deps = parse_msbuild_project(csproj)
    assert deps[0].version == "2.0.0"


def test_cpm_disabled_returns_to_inline_only(tmp_path: Path):
    """``<ManagePackageVersionsCentrally>false</>`` disables CPM
    even when the file is present. The csproj's versionless
    PackageReference becomes unresolvable; we skip it and the
    test verifies no Dependency is emitted."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
    )
    _reset_cache_for_tests()
    csproj = _cpm_setup(
        tmp_path,
        csproj_body="""\
<Project>
  <ItemGroup>
    <PackageReference Include="X" />
    <PackageReference Include="Y" Version="2.0.0" />
  </ItemGroup>
</Project>
""",
        cpm_body="""\
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""",
    )
    deps = parse_msbuild_project(csproj)
    names = {d.name for d in deps}
    assert names == {"Y"}    # X dropped — CPM disabled, no inline

