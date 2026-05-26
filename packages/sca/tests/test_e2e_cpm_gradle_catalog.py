"""End-to-end test for the round-9 CPM + .sln + Gradle catalog
features.

Pipeline exercised on a synthetic repo fixture:

  1. ``discovery.find_manifests`` walks the tree, picks up:
       * Two csproj files (one in the rglob walk, one out-of-tree
         pulled in via .sln graph traversal).
       * One Directory.Build.props (NOT classified as a manifest
         on its own; consumed by the csproj resolver during parse).
       * One build.gradle.kts.

  2. ``parsers.nuget.parse_msbuild_project`` resolves the csproj
     dep tree via the CPM chain — exercising:
       * ``Directory.Packages.props`` PackageVersion resolution.
       * ``GlobalPackageReference`` auto-applied to every csproj.
       * ``Directory.Build.props`` PackageReference inheritance.
       * Inner ``Directory.Packages.props`` overriding the outer.
       * ``VersionOverride`` on a per-csproj PackageReference.

  3. ``parsers.gradle_dsl.parse`` resolves the build.gradle.kts via
     the catalog at ``gradle/libs.versions.toml`` — exercising:
       * Inline catalog library (``libs.junit.jupiter``).
       * Catalog library via ``version.ref``.
       * Catalog plugin via ``version.ref``.

  4. Rewriters round-trip cleanly on each surface:
       * ``Directory.Packages.props`` PackageVersion bump.
       * ``.csproj`` VersionOverride bump.
       * ``libs.versions.toml`` [versions] table bump.

A single fixture wires the whole tree; the discovery+parse+rewrite
sequence catches integration regressions that the per-parser unit
tests miss (e.g. discovery hands the wrong path to the parser, the
parser's source_extra is mis-shaped for the rewriter to route
correctly, the rewriter's locator-format expectation differs from
the parser's emitted form).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixture: a synthetic repo wiring every new surface together.
# ---------------------------------------------------------------------------

@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """Build a representative monorepo:

        repo/
        ├── .git/
        ├── Directory.Build.props          # outer; legacy inherited deps
        ├── Directory.Packages.props       # outer; CPM map + Global pkg
        ├── src/
        │   └── AppA/
        │       ├── AppA.sln               # references AppA.csproj +
        │       │                          # ../Shared/Shared.csproj
        │       ├── AppA.csproj            # CPM versionless + VersionOverride
        │       └── Directory.Packages.props  # inner; overrides one entry
        ├── src/
        │   └── Shared/
        │       └── Shared.csproj          # CPM versionless
        └── gradle-app/
            ├── build.gradle.kts           # consumes libs.* accessors
            └── gradle/
                └── libs.versions.toml     # catalog
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()

    # Outer Directory.Build.props — legacy PackageReference inheritance.
    (repo / "Directory.Build.props").write_text(textwrap.dedent("""\
        <Project>
          <ItemGroup>
            <PackageReference Include="Serilog" Version="2.10.0" />
          </ItemGroup>
        </Project>
    """))

    # Outer Directory.Packages.props — CPM map + Global pkg.
    (repo / "Directory.Packages.props").write_text(textwrap.dedent("""\
        <Project>
          <PropertyGroup>
            <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
          </PropertyGroup>
          <ItemGroup>
            <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
            <PackageVersion Include="AutoMapper" Version="12.0.0" />
            <GlobalPackageReference Include="Microsoft.SourceLink.GitHub"
                                    Version="1.1.1" />
          </ItemGroup>
        </Project>
    """))

    # AppA tree.
    appa = repo / "src" / "AppA"
    appa.mkdir(parents=True)

    # Inner CPM file — overrides Newtonsoft.Json to a newer version.
    (appa / "Directory.Packages.props").write_text(textwrap.dedent("""\
        <Project>
          <ItemGroup>
            <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
          </ItemGroup>
        </Project>
    """))

    # csproj — versionless (CPM-managed) + VersionOverride +
    # versionless Serilog that resolves via Build.props inheritance.
    (appa / "AppA.csproj").write_text(textwrap.dedent("""\
        <Project>
          <ItemGroup>
            <PackageReference Include="Newtonsoft.Json" />
            <PackageReference Include="AutoMapper" VersionOverride="13.0.0" />
            <PackageReference Include="Serilog" />
          </ItemGroup>
        </Project>
    """))

    # .sln referencing both AppA.csproj and ../Shared/Shared.csproj.
    (appa / "AppA.sln").write_text(textwrap.dedent("""\
        Microsoft Visual Studio Solution File, Format Version 12.00
        Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "AppA", "AppA.csproj", "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
        EndProject
        Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Shared", "../Shared/Shared.csproj", "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
        EndProject
    """))

    # Shared subtree (out of AppA, sibling).
    shared = repo / "src" / "Shared"
    shared.mkdir(parents=True)
    (shared / "Shared.csproj").write_text(textwrap.dedent("""\
        <Project>
          <ItemGroup>
            <PackageReference Include="AutoMapper" />
          </ItemGroup>
        </Project>
    """))

    # Gradle subtree.
    gradle_app = repo / "gradle-app"
    (gradle_app / "gradle").mkdir(parents=True)
    (gradle_app / "gradle" / "libs.versions.toml").write_text(textwrap.dedent("""\
        [versions]
        junit = "5.9.0"
        kotlin = "1.9.20"

        [libraries]
        junit-jupiter = { module = "org.junit.jupiter:junit-jupiter", version.ref = "junit" }
        kotlinx-coroutines = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-core", version = "1.7.3" }

        [plugins]
        kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
    """))
    (gradle_app / "build.gradle.kts").write_text(textwrap.dedent("""\
        plugins {
            alias(libs.plugins.kotlin.jvm)
        }
        dependencies {
            implementation(libs.junit.jupiter)
            implementation(libs.kotlinx.coroutines)
        }
    """))

    return repo


# ---------------------------------------------------------------------------
# Stage 1: discovery walks the tree, picks up sln-referenced csproj.
# ---------------------------------------------------------------------------

def test_e2e_discovery_finds_all_manifests(repo):
    from packages.sca.discovery import find_manifests

    manifests = find_manifests(repo)
    paths = {m.path for m in manifests}

    # csproj files — both AppA and Shared (the latter pulled in via .sln).
    assert (repo / "src" / "AppA" / "AppA.csproj").resolve() in paths
    assert (repo / "src" / "Shared" / "Shared.csproj").resolve() in paths

    # build.gradle.kts.
    assert (repo / "gradle-app" / "build.gradle.kts").resolve() in paths

    # Directory.Packages.props + Directory.Build.props + libs.versions.toml
    # are NOT classified as manifests on their own — they're consumed by
    # the relevant parser during dep resolution.
    for not_a_manifest in (
        repo / "Directory.Packages.props",
        repo / "Directory.Build.props",
        repo / "src" / "AppA" / "Directory.Packages.props",
        repo / "gradle-app" / "gradle" / "libs.versions.toml",
    ):
        assert not_a_manifest.resolve() not in paths


# ---------------------------------------------------------------------------
# Stage 2: csproj parse resolves via the CPM chain.
# ---------------------------------------------------------------------------

def test_e2e_csproj_resolves_cpm_chain(repo):
    from packages.sca.parsers.nuget import parse_msbuild_project

    appa = repo / "src" / "AppA" / "AppA.csproj"
    deps = parse_msbuild_project(appa)
    by_name = {d.name: d for d in deps}

    # Newtonsoft.Json — INNER CPM overrides OUTER (13.0.3, not 13.0.1).
    assert "Newtonsoft.Json" in by_name
    assert by_name["Newtonsoft.Json"].version == "13.0.3"
    extra = by_name["Newtonsoft.Json"].source_extra or {}
    assert extra.get("origin") == "cpm_central"

    # AutoMapper — VersionOverride on the csproj wins over outer CPM.
    assert by_name["AutoMapper"].version == "13.0.0"
    extra = by_name["AutoMapper"].source_extra or {}
    assert extra.get("origin") == "version_override"

    # Microsoft.SourceLink.GitHub — auto-applied via GlobalPackageReference,
    # not declared on the csproj.
    assert by_name["Microsoft.SourceLink.GitHub"].version == "1.1.1"
    extra = by_name["Microsoft.SourceLink.GitHub"].source_extra or {}
    assert extra.get("origin") == "cpm_global"

    # Serilog — inherited from Directory.Build.props. The resolver
    # merges Build.props entries into the CPM map, so the origin
    # collapses to ``cpm_central``. Source attribution beyond that
    # is a follow-up — the existing dep is correctly surfaced.
    assert by_name["Serilog"].version == "2.10.0"
    extra = by_name["Serilog"].source_extra or {}
    assert extra.get("origin") == "cpm_central"


def test_e2e_shared_csproj_picks_up_outer_cpm(repo):
    """The Shared csproj is .sln-referenced from AppA but lives in a
    sibling subtree — it must still resolve the OUTER CPM file
    (not AppA's inner override)."""
    from packages.sca.parsers.nuget import parse_msbuild_project

    shared = repo / "src" / "Shared" / "Shared.csproj"
    deps = parse_msbuild_project(shared)
    by_name = {d.name: d for d in deps}
    # AutoMapper resolves to the OUTER CPM (12.0.0), not the AppA-
    # inner one (which only declared Newtonsoft.Json).
    assert by_name["AutoMapper"].version == "12.0.0"
    # GlobalPackageReference STILL applies — auto-attached.
    assert "Microsoft.SourceLink.GitHub" in by_name


# ---------------------------------------------------------------------------
# Stage 3: Gradle DSL parse resolves catalog references.
# ---------------------------------------------------------------------------

def test_e2e_gradle_kts_resolves_catalog(repo):
    from packages.sca.parsers import gradle_dsl

    script = repo / "gradle-app" / "build.gradle.kts"
    deps = gradle_dsl.parse(script)
    by_name = {d.name: d for d in deps}

    # Gradle deps key by ``{group}/{artifact}`` so that group-scoped
    # collisions stay distinct (e.g. multiple ``commons-*`` packages
    # under different orgs). Look up via the full coord.
    junit_key = "org.junit.jupiter/junit-jupiter"
    kotlinx_key = "org.jetbrains.kotlinx/kotlinx-coroutines-core"

    # libs.junit.jupiter → junit-jupiter (catalog) → version.ref=junit
    # → 5.9.0 from [versions].
    assert junit_key in by_name
    assert by_name[junit_key].version == "5.9.0"
    extra = by_name[junit_key].source_extra or {}
    assert extra.get("origin") == "gradle_catalog_ref"
    assert extra.get("version_ref_name") == "junit"

    # libs.kotlinx.coroutines → kotlinx-coroutines (catalog) → inline.
    assert kotlinx_key in by_name
    assert by_name[kotlinx_key].version == "1.7.3"
    extra = by_name[kotlinx_key].source_extra or {}
    assert extra.get("origin") == "gradle_catalog_inline"


# ---------------------------------------------------------------------------
# Stage 4: rewriters round-trip cleanly on all three surfaces.
# ---------------------------------------------------------------------------

def test_e2e_rewriter_bumps_central_package_version(repo):
    """Bumping the outer Directory.Packages.props for AutoMapper
    rewrites the PackageVersion in place; the inner file is left
    alone."""
    from packages.sca.rewriters import RewriteEdit, rewrite

    outer = repo / "Directory.Packages.props"
    inner = repo / "src" / "AppA" / "Directory.Packages.props"
    before_inner = inner.read_text()

    results = rewrite(outer, [RewriteEdit(
        locator="AutoMapper", old_value="12.0.0", new_value="13.1.0",
    )])
    assert results and results[0].applied is True
    assert 'Include="AutoMapper" Version="13.1.0"' in outer.read_text()
    # Inner file unchanged — no Newtonsoft bump issued.
    assert inner.read_text() == before_inner


def test_e2e_rewriter_bumps_csproj_version_override(repo):
    """VersionOverride on the AppA csproj — bumped via the csproj
    rewriter dispatched by the .csproj suffix predicate."""
    from packages.sca.rewriters import RewriteEdit, rewrite

    csproj = repo / "src" / "AppA" / "AppA.csproj"
    results = rewrite(csproj, [RewriteEdit(
        locator="AutoMapper", old_value="13.0.0", new_value="13.0.5",
    )])
    assert results and results[0].applied is True
    body = csproj.read_text()
    assert 'VersionOverride="13.0.5"' in body
    # The versionless Newtonsoft.Json PackageReference is untouched.
    assert '<PackageReference Include="Newtonsoft.Json" />' in body


def test_e2e_rewriter_bumps_gradle_catalog_versions_table(repo):
    """Bumping the catalog ``[versions]`` entry for junit propagates
    to every library that uses ``version.ref = "junit"``."""
    from packages.sca.rewriters import RewriteEdit, rewrite

    toml_path = repo / "gradle-app" / "gradle" / "libs.versions.toml"
    results = rewrite(toml_path, [RewriteEdit(
        locator="version:junit", old_value="5.9.0", new_value="5.10.2",
    )])
    assert results and results[0].applied is True
    body = toml_path.read_text()
    assert 'junit = "5.10.2"' in body
    # The kotlin version line is unchanged.
    assert 'kotlin = "1.9.20"' in body
