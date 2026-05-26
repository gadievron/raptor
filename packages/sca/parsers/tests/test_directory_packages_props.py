"""Tests for ``packages.sca.parsers.directory_packages_props``.

NuGet Central Package Management (CPM) reader. Pins:

  * The two element shapes we care about
    (``<PackageVersion>`` + ``<GlobalPackageReference>``).
  * ``<ManagePackageVersionsCentrally>`` toggle behaviour
    (default-true; explicit ``false`` disables; case-folded).
  * MSBuild property expressions like ``$(MyVersion)`` get
    skipped (can't resolve statically without a full
    PropertyGroup evaluator).
  * Hierarchical resolution via ``find_cpm_chain`` — walks up
    to the nearest ``.git`` boundary or filesystem root,
    innermost-first ordering for caller-side merge semantics.
  * Per-process cache + the test-reset seam.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.parsers.directory_packages_props import (
    CentralPackage,
    _reset_cache_for_tests,
    find_cpm_chain,
    parse_directory_packages_props,
)


@pytest.fixture(autouse=True)
def _reset_cache():
    """Each test gets a clean cache. The cache is correct
    behaviour (one parse per file per process), but tests
    that mutate file contents between calls need a reset to
    see the new bytes."""
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


def _write(tmp_path: Path, body: str, name: str = "Directory.Packages.props") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Basic shapes
# ---------------------------------------------------------------------------

def test_single_package_version(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert cpm is not None
    assert cpm.cpm_enabled is True
    assert len(cpm.packages) == 1
    assert cpm.packages[0].name == "Newtonsoft.Json"
    assert cpm.packages[0].version == "13.0.1"
    assert cpm.packages[0].is_global is False


def test_multiple_package_versions(tmp_path: Path):
    """Realistic CPM file shape — multiple ItemGroup blocks,
    mix of PackageVersion entries. Order in ``packages`` follows
    document order (matters for diff-friendly rewriter later)."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="A" Version="1.0.0" />
    <PackageVersion Include="B" Version="2.0.0" />
  </ItemGroup>
  <ItemGroup>
    <PackageVersion Include="C" Version="3.0.0" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert [pkg.name for pkg in cpm.packages] == ["A", "B", "C"]
    assert cpm.version_map() == {"a": "1.0.0", "b": "2.0.0", "c": "3.0.0"}


def test_global_package_reference_flagged(tmp_path: Path):
    """``<GlobalPackageReference>`` is auto-applied to every csproj
    in the solution — bumper consumers need to distinguish it
    from regular PackageVersion entries for the blast-radius
    warning."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
    <GlobalPackageReference Include="Microsoft.SourceLink.GitHub" Version="1.1.1" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    names_by_global = {p.name: p.is_global for p in cpm.packages}
    assert names_by_global == {
        "X": False,
        "Microsoft.SourceLink.GitHub": True,
    }
    globals_only = cpm.global_packages()
    assert len(globals_only) == 1
    assert globals_only[0].name == "Microsoft.SourceLink.GitHub"


def test_version_in_child_element(tmp_path: Path):
    """Some CPM files use the child-element shape rather than
    attribute. Same fallback path ``parsers/nuget.py`` already
    handles for PackageReference."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="X">
      <Version>2.5.0</Version>
    </PackageVersion>
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert cpm.packages == [
        CentralPackage(name="X", version="2.5.0",
                       is_global=False, declared_in=p.resolve()),
    ]


# ---------------------------------------------------------------------------
# ManagePackageVersionsCentrally toggle
# ---------------------------------------------------------------------------

def test_cpm_enabled_defaults_true(tmp_path: Path):
    """No ``<ManagePackageVersionsCentrally>`` property → defaults
    to enabled (MSBuild's documented default when
    Directory.Packages.props exists)."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert cpm.cpm_enabled is True


def test_cpm_explicit_false_disables(tmp_path: Path):
    """An operator mid-migration may have the file but disable
    CPM via the property. The csproj resolver must honour this
    — otherwise we'd return versions that runtime would ignore."""
    p = _write(tmp_path, """\
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert cpm.cpm_enabled is False
    # Packages are still parsed — disabled-mode operators may
    # want to inspect what CPM would have provided. The csproj
    # resolver gates on ``cpm_enabled``, not us.
    assert len(cpm.packages) == 1


def test_cpm_case_insensitive_true(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>True</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    assert parse_directory_packages_props(p).cpm_enabled is True


def test_cpm_last_propertygroup_wins(tmp_path: Path):
    """MSBuild lets multiple ``<PropertyGroup>`` blocks declare
    the same property; last-wins. CPM resolver must follow."""
    p = _write(tmp_path, """\
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    assert parse_directory_packages_props(p).cpm_enabled is False


# ---------------------------------------------------------------------------
# Skip cases
# ---------------------------------------------------------------------------

def test_msbuild_property_version_skipped(tmp_path: Path):
    """``Version="$(MyVersion)"`` requires evaluating the project's
    PropertyGroup graph. SCA can't do that statically — better to
    skip than emit a wrong version."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="Resolvable" Version="1.2.3" />
    <PackageVersion Include="Unresolvable" Version="$(MyVersion)" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert [p.name for p in cpm.packages] == ["Resolvable"]


def test_missing_version_skipped(tmp_path: Path):
    """An entry without a Version attribute (and no child) is an
    operator error. Skip with a debug log; don't emit a versionless
    Dependency."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="X" />
    <PackageVersion Include="Y" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert [p.name for p in cpm.packages] == ["Y"]


def test_missing_include_skipped(tmp_path: Path):
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Version="1.0.0" />
    <PackageVersion Include="Z" Version="3.0.0" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert [p.name for p in cpm.packages] == ["Z"]


def test_duplicate_last_wins(tmp_path: Path):
    """NuGet is case-insensitive on package names. Duplicate
    declarations (case-folded equal) — last wins, matching
    MSBuild evaluation order."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="MyLib" Version="1.0.0" />
    <PackageVersion Include="mylib" Version="2.0.0" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert len(cpm.packages) == 1
    # Last declaration wins on both name and version.
    assert cpm.packages[0].name == "mylib"
    assert cpm.packages[0].version == "2.0.0"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_malformed_xml_returns_none(tmp_path: Path):
    p = _write(tmp_path, "<Project><ItemGroup>unclosed")
    assert parse_directory_packages_props(p) is None


def test_wrong_root_tag_returns_none(tmp_path: Path):
    """Some operators have similarly-named files (legacy build
    config, custom MSBuild imports) that aren't valid CPM files.
    Skip silently rather than emit garbage."""
    p = _write(tmp_path, "<NotAProject><X /></NotAProject>")
    assert parse_directory_packages_props(p) is None


def test_namespaced_xml_supported(tmp_path: Path):
    """Older MSBuild format wraps the file in
    ``xmlns="http://schemas.microsoft.com/developer/msbuild/2003"``.
    Strip namespaces before tag matching."""
    p = _write(tmp_path, """\
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    cpm = parse_directory_packages_props(p)
    assert cpm is not None
    assert [p.name for p in cpm.packages] == ["X"]


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

def test_parse_is_cached(tmp_path: Path):
    """A solution can have 100+ csproj all walking to the same
    CPM file. The cache ensures one parse per resolved path per
    process."""
    p = _write(tmp_path, """\
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""")
    cpm1 = parse_directory_packages_props(p)
    cpm2 = parse_directory_packages_props(p)
    assert cpm1 is cpm2     # same object → cache hit


# ---------------------------------------------------------------------------
# find_cpm_chain
# ---------------------------------------------------------------------------

def test_chain_walks_up_to_repo_root(tmp_path: Path):
    """Hierarchical case: outer CPM at the repo root, inner CPM
    in a subdir. Resolver returns innermost-first so the
    csproj-resolution layer merges with innermost-wins
    precedence."""
    (tmp_path / ".git").mkdir()
    outer = _write(tmp_path, """\
<Project><ItemGroup><PackageVersion Include="A" Version="1.0.0" /></ItemGroup></Project>
""")
    sub = tmp_path / "src" / "MyLib"
    sub.mkdir(parents=True)
    inner = _write(sub, """\
<Project><ItemGroup><PackageVersion Include="A" Version="2.0.0" /></ItemGroup></Project>
""")
    chain = find_cpm_chain(sub)
    assert chain == [inner, outer]


def test_chain_stops_at_git_boundary(tmp_path: Path):
    """A scanned project nested under an unrelated parent repo
    must not pick up the parent's Directory.Packages.props.
    Walk stops at the inner .git directory."""
    parent_repo = tmp_path / "parent"
    parent_repo.mkdir()
    (parent_repo / ".git").mkdir()
    # Outer CPM in the parent — should NOT be picked up.
    _write(parent_repo, """\
<Project><ItemGroup><PackageVersion Include="Outer" Version="9.0.0" /></ItemGroup></Project>
""")
    # Inner repo with its own .git and its own CPM.
    inner_repo = parent_repo / "child"
    inner_repo.mkdir()
    (inner_repo / ".git").mkdir()
    inner = _write(inner_repo, """\
<Project><ItemGroup><PackageVersion Include="Inner" Version="1.0.0" /></ItemGroup></Project>
""")

    chain = find_cpm_chain(inner_repo)
    assert chain == [inner]


def test_chain_no_cpm_returns_empty(tmp_path: Path):
    """No CPM file in the chain → empty list, NOT an error."""
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "src"
    sub.mkdir()
    assert find_cpm_chain(sub) == []


# ---------------------------------------------------------------------------
# Directory.Build.props inheritance — pre-CPM PackageReference path
# ---------------------------------------------------------------------------

def test_directory_build_props_carries_package_reference(tmp_path: Path):
    """Pre-CPM convention: ``<PackageReference>`` in
    Directory.Build.props is auto-applied to every csproj that
    inherits the file. The parser surfaces them in the same
    CPMFile shape so the csproj resolver can treat both file
    types uniformly."""
    from packages.sca.parsers.directory_packages_props import (
        parse_directory_build_props,
    )

    p = tmp_path / "Directory.Build.props"
    p.write_text("""\
<Project>
  <ItemGroup>
    <PackageReference Include="Microsoft.SourceLink.GitHub" Version="1.0.0" />
    <PackageReference Include="Microsoft.CodeAnalysis.Analyzers" Version="3.3.4" />
  </ItemGroup>
</Project>
""", encoding="utf-8")
    f = parse_directory_build_props(p)
    assert f is not None
    assert [pkg.name for pkg in f.packages] == [
        "Microsoft.SourceLink.GitHub",
        "Microsoft.CodeAnalysis.Analyzers",
    ]
    # is_global must be False — Directory.Build.props doesn't have
    # the global-include shape (that's CPM's GlobalPackageReference).
    assert all(not pkg.is_global for pkg in f.packages)


def test_directory_build_props_skips_versionless_packageref(tmp_path: Path):
    """A versionless ``<PackageReference>`` in Directory.Build.props
    is unresolvable at this layer (the csproj walker is what knits
    versionless refs with CPM); the parser drops it silently."""
    from packages.sca.parsers.directory_packages_props import (
        parse_directory_build_props,
    )

    p = tmp_path / "Directory.Build.props"
    p.write_text("""\
<Project>
  <ItemGroup>
    <PackageReference Include="HasVersion" Version="1.0.0" />
    <PackageReference Include="NoVersion" />
  </ItemGroup>
</Project>
""", encoding="utf-8")
    f = parse_directory_build_props(p)
    assert [pkg.name for pkg in f.packages] == ["HasVersion"]


def test_find_build_props_chain_walks_to_git_boundary(tmp_path: Path):
    """Same walk semantics as find_cpm_chain — innermost first,
    stop at .git or filesystem root."""
    from packages.sca.parsers.directory_packages_props import (
        find_build_props_chain,
    )

    (tmp_path / ".git").mkdir()
    (tmp_path / "Directory.Build.props").write_text(
        "<Project />", encoding="utf-8",
    )
    sub = tmp_path / "src" / "App"
    sub.mkdir(parents=True)
    (sub / "Directory.Build.props").write_text(
        "<Project />", encoding="utf-8",
    )
    chain = find_build_props_chain(sub)
    assert chain == [
        sub / "Directory.Build.props",
        tmp_path / "Directory.Build.props",
    ]
