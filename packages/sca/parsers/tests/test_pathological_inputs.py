"""Robustness tests for pathological parser inputs.

Same shape as ``test_adversarial.py`` — each hardening applied to a
parser gets a regression test here so a future refactor cannot
silently re-open the gap. Two families:

  1. Path handling: symlinked manifests refused (the read must see
     the DISCOVERED path, not its resolve() target), ``-r``/``-c``
     include containment in requirements*.txt, and ``.gitmodules``
     submodule-name / ``ref:`` traversal never resolving outside
     ``.git/modules``.
  2. Regex complexity: version-spec grammars in composer / nuget /
     gemfile that previously backtracked super-linearly on crafted
     input now finish in bounded time. The timing assertions use a
     generous 5s CI-safety bound; the pre-fix behaviour was minutes
     to hours on the same inputs.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from packages.sca.models import PinStyle

# ---------------------------------------------------------------------------
# Symlinked-manifest refusal: the read must not resolve first.
# ---------------------------------------------------------------------------


def test_cpm_symlink_to_valid_props_is_refused(tmp_path: Path) -> None:
    """A symlink pointing at a perfectly VALID props file must still be
    refused — this is the non-vacuous check that the symlink defence
    actually fires (resolving before the read handed ``read_bounded``
    a plain regular file, so the refusal could never trigger)."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
        parse_directory_packages_props,
    )

    _reset_cache_for_tests()
    real = tmp_path / "real.props"
    real.write_text(
        '<Project><ItemGroup>'
        '<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />'
        '</ItemGroup></Project>',
        encoding="utf-8",
    )
    link = tmp_path / "Directory.Packages.props"
    os.symlink(real, link)
    assert parse_directory_packages_props(link) is None
    # The real file, read directly, still parses.
    direct = parse_directory_packages_props(real)
    assert direct is not None
    assert direct.version_map() == {"newtonsoft.json": "13.0.3"}


def test_build_props_symlink_to_valid_file_is_refused(tmp_path: Path) -> None:
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
        parse_directory_build_props,
    )

    _reset_cache_for_tests()
    real = tmp_path / "real.props"
    real.write_text(
        '<Project><ItemGroup>'
        '<PackageReference Include="Foo" Version="1.0.0" />'
        '</ItemGroup></Project>',
        encoding="utf-8",
    )
    link = tmp_path / "Directory.Build.props"
    os.symlink(real, link)
    assert parse_directory_build_props(link) is None
    direct = parse_directory_build_props(real)
    assert direct is not None
    assert direct.version_map() == {"foo": "1.0.0"}


def test_cpm_cache_not_poisoned_via_symlink_alias(tmp_path: Path) -> None:
    """Parsing the real file first must not let a symlink alias ride
    the realpath-keyed cache past the symlink refusal."""
    from packages.sca.parsers.directory_packages_props import (
        _reset_cache_for_tests,
        parse_directory_packages_props,
    )

    _reset_cache_for_tests()
    real = tmp_path / "real" / "Directory.Packages.props"
    real.parent.mkdir()
    real.write_text("<Project/>", encoding="utf-8")
    assert parse_directory_packages_props(real) is not None
    link = tmp_path / "Directory.Packages.props"
    os.symlink(real, link)
    assert parse_directory_packages_props(link) is None


def test_gradle_catalog_symlink_to_valid_toml_is_refused(
    tmp_path: Path,
) -> None:
    from packages.sca.parsers.gradle_version_catalog import (
        _PARSE_CACHE,
        parse_libs_versions_toml,
    )

    _PARSE_CACHE.clear()
    real = tmp_path / "real.toml"
    real.write_text('[versions]\nokio = "3.9.0"\n', encoding="utf-8")
    link = tmp_path / "libs.versions.toml"
    os.symlink(real, link)
    assert parse_libs_versions_toml(link) is None
    direct = parse_libs_versions_toml(real)
    assert direct is not None
    assert direct.versions == {"okio": "3.9.0"}


def test_composer_lock_symlink_is_refused(tmp_path: Path) -> None:
    from packages.sca.parsers.composer import parse_lockfile

    real = tmp_path / "real.lock"
    real.write_text(
        '{"packages": [{"name": "vendor/pkg", "version": "1.2.3"}]}',
        encoding="utf-8",
    )
    link = tmp_path / "composer.lock"
    os.symlink(real, link)
    assert parse_lockfile(link) == []
    # Direct read of the regular file still works.
    [dep] = parse_lockfile(real)
    assert dep.name == "vendor/pkg"


def test_csproj_symlink_is_refused(tmp_path: Path) -> None:
    from packages.sca.parsers.nuget import parse_msbuild_project

    real = tmp_path / "real.csproj"
    real.write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Include="Foo" Version="1.0.0" />'
        '</ItemGroup></Project>',
        encoding="utf-8",
    )
    link = tmp_path / "App.csproj"
    os.symlink(real, link)
    assert parse_msbuild_project(link) == []
    [dep] = parse_msbuild_project(real)
    assert dep.name == "Foo"


# ---------------------------------------------------------------------------
# requirements*.txt include containment.
# ---------------------------------------------------------------------------


def _caplog_warnings(caplog) -> str:
    return "\n".join(
        r.getMessage() for r in caplog.records
        if r.levelno >= logging.WARNING
    )


def test_requirements_refuses_traversal_include(tmp_path, caplog) -> None:
    """``-r ../../..(…)/etc/passwd`` must be refused with a warning,
    not followed out of the scan target."""
    from packages.sca.parsers.requirements import parse

    proj = tmp_path / "proj"
    proj.mkdir()
    p = proj / "requirements.txt"
    p.write_text(
        "-r " + "../" * 20 + "etc/passwd\nrequests==2.31.0\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING, logger="packages.sca.parsers"):
        deps = parse(p, scan_root=proj)
    assert [d.name for d in deps] == ["requests"]
    assert "refusing include" in _caplog_warnings(caplog)


def test_requirements_refuses_absolute_include(tmp_path, caplog) -> None:
    from packages.sca.parsers.requirements import parse

    outside = tmp_path / "outside.txt"
    outside.write_text("evil==6.6.6\n", encoding="utf-8")
    p = tmp_path / "requirements.txt"
    p.write_text(f"-r {outside}\nflask==2.3.0\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="packages.sca.parsers"):
        deps = parse(p, scan_root=tmp_path)
    assert [d.name for d in deps] == ["flask"]
    assert "refusing absolute include" in _caplog_warnings(caplog)


def test_requirements_refuses_escape_via_scan_root(tmp_path, caplog) -> None:
    """A relative include that resolves outside the supplied
    ``scan_root`` is refused even when the target file exists."""
    from packages.sca.parsers.requirements import parse

    proj = tmp_path / "proj"
    proj.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("evil==6.6.6\n", encoding="utf-8")
    p = proj / "requirements.txt"
    p.write_text("-r ../outside.txt\nclick==8.1.7\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="packages.sca.parsers"):
        deps = parse(p, scan_root=proj)
    assert [d.name for d in deps] == ["click"]
    assert "outside the scan root" in _caplog_warnings(caplog)


def test_requirements_nested_include_inherits_bound(tmp_path, caplog) -> None:
    """The containment bound threads through nested includes — an
    inner file cannot escape via its own ``-r`` line."""
    from packages.sca.parsers.requirements import parse

    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    (proj / "requirements.txt").write_text(
        "-r sub/inner.txt\n", encoding="utf-8",
    )
    (proj / "sub" / "inner.txt").write_text(
        "-r " + "../" * 20 + "etc/passwd\nurllib3==2.1.0\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING, logger="packages.sca.parsers"):
        deps = parse(proj / "requirements.txt", scan_root=proj)
    assert [d.name for d in deps] == ["urllib3"]
    assert "refusing include" in _caplog_warnings(caplog)


def test_requirements_one_level_up_include_still_works(tmp_path) -> None:
    """The common ``requirements/dev.txt → -r ../base.txt`` layout must
    keep working under the no-scan_root fallback bound (the manifest's
    grandparent directory, mirroring the ``sln.py`` legacy bound)."""
    from packages.sca.parsers.requirements import parse

    proj = tmp_path / "proj"
    (proj / "requirements").mkdir(parents=True)
    (proj / "base.txt").write_text("django==4.2.7\n", encoding="utf-8")
    dev = proj / "requirements" / "dev.txt"
    dev.write_text("-r ../base.txt\npytest==8.0.0\n", encoding="utf-8")
    deps = parse(dev)
    assert sorted(d.name for d in deps) == ["django", "pytest"]


# ---------------------------------------------------------------------------
# .gitmodules submodule-name / ref traversal containment.
# ---------------------------------------------------------------------------


def _write_gitmodules(repo: Path, section_name: str) -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    (repo / ".git").mkdir(exist_ok=True)
    p = repo / ".gitmodules"
    p.write_text(
        f'[submodule "{section_name}"]\n'
        "\tpath = vendor/x\n"
        "\turl = https://github.com/o/x.git\n",
        encoding="utf-8",
    )
    return p


def test_gitmodules_dotdot_name_never_resolves_outside(tmp_path) -> None:
    """``[submodule "../../evil"]`` must not read a HEAD planted
    outside ``.git/modules`` — the dep is emitted with version=None."""
    from packages.sca.parsers.gitmodules import parse

    repo = tmp_path / "repo"
    sha = "b" * 40
    # Plant a HEAD where the unsanitised join would land:
    # repo/.git/modules/../../evil/HEAD == tmp_path/evil/HEAD.
    # ``modules`` must exist for the ``..`` traversal to stat through.
    (repo / ".git" / "modules").mkdir(parents=True)
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "HEAD").write_text(sha + "\n", encoding="utf-8")
    p = _write_gitmodules(repo, "../../evil")
    [d] = parse(p)
    assert d.version is None
    assert d.pin_style == PinStyle.WILDCARD


def test_gitmodules_absolute_name_refused(tmp_path) -> None:
    from packages.sca.parsers.gitmodules import parse

    sha = "c" * 40
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "HEAD").write_text(sha + "\n", encoding="utf-8")
    p = _write_gitmodules(tmp_path / "repo", str(secret))
    [d] = parse(p)
    assert d.version is None


def test_gitmodules_ref_indirection_cannot_escape(tmp_path) -> None:
    """A hostile ``ref:`` line (absolute path, or ``..`` traversal)
    inside a legitimate submodule's HEAD must not steer the follow-up
    read outside ``.git/modules``."""
    from packages.sca.parsers.gitmodules import parse

    sha = "d" * 40
    repo = tmp_path / "repo"
    outside = tmp_path / "loot"
    outside.write_text(sha + "\n", encoding="utf-8")

    for hostile_ref in (str(outside), "../" * 6 + "loot"):
        mod_dir = repo / ".git" / "modules" / "vendor" / "x"
        mod_dir.mkdir(parents=True, exist_ok=True)
        (mod_dir / "HEAD").write_text(
            f"ref: {hostile_ref}\n", encoding="utf-8",
        )
        p = _write_gitmodules(repo, "vendor/x")
        [d] = parse(p)
        assert d.version is None, hostile_ref


def test_gitmodules_symlinked_module_dir_refused(tmp_path) -> None:
    """A name that passes the fragment checks but whose modules entry
    is a symlink out of the repo is caught by the resolve-containment
    backstop."""
    from packages.sca.parsers.gitmodules import parse

    sha = "e" * 40
    repo = tmp_path / "repo"
    outside = tmp_path / "outside-mod"
    outside.mkdir()
    (outside / "HEAD").write_text(sha + "\n", encoding="utf-8")
    modules = repo / ".git" / "modules"
    modules.mkdir(parents=True)
    os.symlink(outside, modules / "vendor")
    p = _write_gitmodules(repo, "vendor")
    [d] = parse(p)
    assert d.version is None


def test_gitmodules_legitimate_nested_name_still_resolves(tmp_path) -> None:
    from packages.sca.parsers.gitmodules import parse

    sha = "a" * 40
    repo = tmp_path / "repo"
    mod_dir = repo / ".git" / "modules" / "vendor" / "zlib"
    mod_dir.mkdir(parents=True)
    (mod_dir / "HEAD").write_text(sha + "\n", encoding="utf-8")
    p = _write_gitmodules(repo, "vendor/zlib")
    [d] = parse(p)
    assert d.version == sha


def test_gitmodules_legitimate_ref_still_resolves(tmp_path) -> None:
    from packages.sca.parsers.gitmodules import parse

    sha = "f" * 40
    repo = tmp_path / "repo"
    mod_dir = repo / ".git" / "modules" / "vendor" / "x"
    (mod_dir / "refs" / "heads").mkdir(parents=True)
    (mod_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (mod_dir / "refs" / "heads" / "main").write_text(
        sha + "\n", encoding="utf-8",
    )
    p = _write_gitmodules(repo, "vendor/x")
    [d] = parse(p)
    assert d.version == sha


# ---------------------------------------------------------------------------
# Regex complexity — composer / nuget / gemfile version grammars.
# ---------------------------------------------------------------------------

# CI-safety bound. Pre-fix, each pathological input below ran
# super-linearly (minutes+ at these sizes); post-fix they finish in
# milliseconds.
_TIME_BUDGET_S = 5.0


def test_composer_release_tag_pathological_input_is_fast() -> None:
    from packages.sca.parsers.composer import _looks_like_release_tag

    hostile = "1" + ".1" * 50_000 + "!"     # ~100k chars, never matches
    start = time.monotonic()
    assert _looks_like_release_tag(hostile) is False
    assert time.monotonic() - start < _TIME_BUDGET_S


def test_composer_release_tag_length_bound() -> None:
    from packages.sca.parsers.composer import _looks_like_release_tag

    assert _looks_like_release_tag("1." * 100 + "1") is False   # > 128 chars
    assert _looks_like_release_tag("1.2.3") is True


def test_composer_release_tag_classification_unchanged() -> None:
    from packages.sca.parsers.composer import _looks_like_release_tag

    for release in (
        "1.2.3", "v1.2.3", "1.0", "10.4.22", "v6.4.0",
        "1.2.3-beta1", "2.0.0-RC1", "1.0.0+build.5",
    ):
        assert _looks_like_release_tag(release) is True, release
    for non_release in ("dev-master", "dev-feature-x", "1.0-dev", "1.2.x-dev"):
        assert _looks_like_release_tag(non_release) is False, non_release


def test_nuget_bracket_spec_pathological_input_is_fast() -> None:
    from packages.sca.parsers.nuget import _classify_version_spec

    hostile = "[" + " " * 100_000            # unclosed bracket + space run
    start = time.monotonic()
    pin, bare = _classify_version_spec(hostile)
    assert time.monotonic() - start < _TIME_BUDGET_S
    assert pin is PinStyle.UNKNOWN
    assert bare is None


def test_nuget_oversized_spec_is_unknown() -> None:
    from packages.sca.parsers.nuget import _classify_version_spec

    pin, bare = _classify_version_spec("[1.0," + "9" * 300 + ")")
    assert pin is PinStyle.UNKNOWN
    assert bare is None


def test_nuget_bracket_parsing_unchanged() -> None:
    from packages.sca.parsers.nuget import _classify_version_spec

    cases = {
        "[1.2.3]": (PinStyle.EXACT, "1.2.3"),
        "[ 1.2.3 ]": (PinStyle.EXACT, "1.2.3"),
        "[1.0,2.0)": (PinStyle.RANGE, "1.0"),
        "[1.0, 2.0)": (PinStyle.RANGE, "1.0"),
        "(,1.0]": (PinStyle.RANGE, "1.0"),
        "(,1.0)": (PinStyle.RANGE, None),
        "[1.0,)": (PinStyle.RANGE, "1.0"),
        "(1.0)": (PinStyle.UNKNOWN, None),
        "1.2.3": (PinStyle.RANGE, "1.2.3"),
        "garbage": (PinStyle.UNKNOWN, None),
    }
    for spec, expected in cases.items():
        assert _classify_version_spec(spec) == expected, spec


def test_gemfile_version_spec_pathological_input_is_fast(tmp_path) -> None:
    from packages.sca.parsers.gemfile import parse_manifest

    hostile = "gem 'foo', '" + " " * 100_000 + "\n"   # quote never closed
    p = tmp_path / "Gemfile"
    p.write_text("gem 'rails', '~> 7.1'\n" + hostile, encoding="utf-8")
    start = time.monotonic()
    deps = parse_manifest(p)
    assert time.monotonic() - start < _TIME_BUDGET_S
    by_name = {d.name: d for d in deps}
    assert by_name["rails"].version == "7.1"
    assert by_name["rails"].pin_style is PinStyle.TILDE
    # The hostile line degrades to an unpinned gem, not a hang.
    assert by_name["foo"].version is None
    assert by_name["foo"].pin_style is PinStyle.WILDCARD


def test_gemfile_spec_extraction_unchanged() -> None:
    from packages.sca.parsers.gemfile import _parse_version_specs

    assert _parse_version_specs("'7.1.2'") == (PinStyle.EXACT, "7.1.2")
    assert _parse_version_specs("'= 7.1.2'") == (PinStyle.EXACT, "7.1.2")
    assert _parse_version_specs("'~> 7.1'") == (PinStyle.TILDE, "7.1")
    assert _parse_version_specs("'>= 7.0'") == (PinStyle.RANGE, "7.0")
    assert _parse_version_specs("'>=7.0'") == (PinStyle.RANGE, "7.0")
    assert _parse_version_specs("'>= 7.0', '< 8.0'") == (PinStyle.RANGE, None)
    assert _parse_version_specs("") == (PinStyle.WILDCARD, None)
    assert _parse_version_specs("'IBM_DB'") == (PinStyle.WILDCARD, None)


# ---------------------------------------------------------------------------
# Bounded reads on migrated call sites.
# ---------------------------------------------------------------------------


def _tighten_read_cap(monkeypatch, max_bytes: int) -> None:
    """Shrink ``read_bounded``'s cap for the duration of a test.
    The default ``max_bytes`` is bound at def time, so patching the
    module constant is not enough — wrap the function instead."""
    from packages.sca.parsers import _safe_read

    orig = _safe_read.read_bounded

    def _capped(path, *, max_bytes=max_bytes, follow_symlinks=True):
        return orig(
            path, max_bytes=max_bytes, follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(_safe_read, "read_bounded", _capped)


def test_composer_lock_oversized_is_refused(tmp_path, monkeypatch) -> None:
    from packages.sca.parsers.composer import parse_lockfile

    _tighten_read_cap(monkeypatch, 16)
    lock = tmp_path / "composer.lock"
    lock.write_text(
        '{"packages": [{"name": "vendor/pkg", "version": "1.2.3"}]}',
        encoding="utf-8",
    )
    assert parse_lockfile(lock) == []


def test_csproj_oversized_is_refused(tmp_path, monkeypatch) -> None:
    from packages.sca.parsers.nuget import parse_msbuild_project

    _tighten_read_cap(monkeypatch, 16)
    csproj = tmp_path / "App.csproj"
    csproj.write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
        '<PackageReference Include="Foo" Version="1.0.0" />'
        '</ItemGroup></Project>',
        encoding="utf-8",
    )
    assert parse_msbuild_project(csproj) == []
