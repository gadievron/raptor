"""Tests for ``packages.sca.parsers._base`` — shared parser helpers."""

from __future__ import annotations

from packages.sca.parsers._base import build_purl


def test_build_purl_basic() -> None:
    assert build_purl("cargo", "serde", "1.0.0") == "pkg:cargo/serde@1.0.0"


def test_build_purl_versionless_on_none_and_empty() -> None:
    assert build_purl("npm", "lodash", None) == "pkg:npm/lodash"
    assert build_purl("npm", "lodash", "") == "pkg:npm/lodash"


def test_build_purl_namespace() -> None:
    assert (
        build_purl("maven", "spring-core", "5.0", namespace="org.springframework")
        == "pkg:maven/org.springframework/spring-core@5.0"
    )


def test_build_purl_empty_namespace_is_preserved() -> None:
    """An empty (but present) group keeps the double slash the
    per-parser copies emitted — byte-compatibility for Maven/Gradle
    rows with a blank group."""
    assert build_purl("maven", "x", "1", namespace="") == "pkg:maven//x@1"


def test_build_purl_npm_scope_verbatim() -> None:
    assert build_purl("npm", "@scope/pkg", "2.0") == "pkg:npm/@scope/pkg@2.0"


def test_lockfile_ladder_shape() -> None:
    from packages.sca.models import PinStyle
    from packages.sca.parsers._base import lockfile_confidence

    kw = {
        "git_reason": "g", "path_reason": "p",
        "unversioned_reason": "u", "resolved_reason": "r",
    }
    c = lockfile_confidence(PinStyle.GIT, "1.0", **kw)
    assert (c.level, c.reason) == ("medium", "g")
    c = lockfile_confidence(PinStyle.PATH, "1.0", **kw)
    assert (c.level, c.reason) == ("medium", "p")
    # A lockfile row without a version is anomalous -> low.
    c = lockfile_confidence(PinStyle.EXACT, None, **kw)
    assert (c.level, c.reason) == ("low", "u")
    c = lockfile_confidence(PinStyle.EXACT, "1.0", **kw)
    assert (c.level, c.reason) == ("high", "r")


def test_manifest_ladder_shape() -> None:
    from packages.sca.models import PinStyle
    from packages.sca.parsers._base import manifest_confidence

    kw = {
        "unrecognised_reason": "u", "git_path_reason": "g",
        "unpinned_reason": "w", "pinned_reason": "s",
    }
    c = manifest_confidence(PinStyle.UNKNOWN, None, **kw)
    assert (c.level, c.reason) == ("low", "u")
    c = manifest_confidence(PinStyle.GIT, "ref", **kw)
    assert (c.level, c.reason) == ("medium", "g")
    c = manifest_confidence(PinStyle.PATH, None, **kw)
    assert (c.level, c.reason) == ("medium", "g")
    # An unpinned manifest entry is normal -> medium, not low.
    c = manifest_confidence(PinStyle.CARET, None, **kw)
    assert (c.level, c.reason) == ("medium", "w")
    c = manifest_confidence(PinStyle.EXACT, "1.0", **kw)
    assert (c.level, c.reason) == ("high", "s")


# ---------------------------------------------------------------------------
# iter_walk_up — the shared bounded ancestor walker
# ---------------------------------------------------------------------------


def test_iter_walk_up_yields_start_then_ancestors_and_stops_at_git(tmp_path) -> None:
    from packages.sca.parsers._base import iter_walk_up

    (tmp_path / ".git").mkdir()
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    # The .git level itself is yielded (candidates there are
    # legitimate); the walk stops after it.
    assert list(iter_walk_up(deep)) == [deep, deep.parent, tmp_path]


def test_iter_walk_up_include_start_false_bound_checks_start(tmp_path) -> None:
    from packages.sca.parsers._base import iter_walk_up

    (tmp_path / ".git").mkdir()
    deep = tmp_path / "a"
    deep.mkdir()
    assert list(iter_walk_up(deep, include_start=False)) == [tmp_path]
    # A start that IS the repo root has no eligible ancestor.
    assert list(iter_walk_up(tmp_path, include_start=False)) == []


def test_iter_walk_up_scan_root_is_yielded_then_stops(tmp_path) -> None:
    from packages.sca.parsers._base import iter_walk_up
    from packages.sca.parsers._safe_read import scan_root_context

    target = tmp_path / "target"
    deep = target / "x"
    deep.mkdir(parents=True)
    with scan_root_context(target):
        assert list(iter_walk_up(deep)) == [deep, target]
    # Without the scan root the walk continues above (up to the cap).
    assert tmp_path in list(iter_walk_up(deep))


def test_iter_walk_up_depth_cap_both_directions(tmp_path) -> None:
    from packages.sca.parsers._base import iter_walk_up

    deep = tmp_path
    for i in range(5):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    got = list(iter_walk_up(deep, max_levels=3))
    assert got == [deep, deep.parent, deep.parent.parent]  # capped
    got6 = list(iter_walk_up(deep, max_levels=6))
    assert len(got6) == 6 and got6[-1] == tmp_path  # cap not undershot


def test_iter_walk_up_file_start_uses_parent(tmp_path) -> None:
    from packages.sca.parsers._base import iter_walk_up

    (tmp_path / ".git").mkdir()
    f = tmp_path / "pkg.json"
    f.write_text("{}")
    assert list(iter_walk_up(f)) == [tmp_path]


# ---------------------------------------------------------------------------
# Scan-root bound on the MSBuild / Gradle consumers (gained with the
# shared walker — previously only .git and the cap bounded them)
# ---------------------------------------------------------------------------


def test_msbuild_chain_stops_at_scan_root(tmp_path) -> None:
    from packages.sca.parsers._safe_read import scan_root_context
    from packages.sca.parsers.directory_packages_props import find_cpm_chain

    (tmp_path / "Directory.Packages.props").write_text("<Project/>")
    target = tmp_path / "extracted"
    proj = target / "src" / "App"
    proj.mkdir(parents=True)

    with scan_root_context(target):
        assert find_cpm_chain(proj) == []
    # A props file INSIDE the scan root is still collected.
    inside = target / "Directory.Packages.props"
    inside.write_text("<Project/>")
    with scan_root_context(target):
        assert find_cpm_chain(proj) == [inside]


def test_gradle_catalog_stops_at_scan_root(tmp_path) -> None:
    from packages.sca.parsers._safe_read import scan_root_context
    from packages.sca.parsers.gradle_dsl import _resolve_catalog

    catalog = tmp_path / "gradle" / "libs.versions.toml"
    catalog.parent.mkdir(parents=True)
    catalog.write_text('[versions]\nokio = "3.9.0"\n')
    target = tmp_path / "extracted"
    proj = target / "app"
    proj.mkdir(parents=True)
    script = proj / "build.gradle"
    script.write_text("")

    with scan_root_context(target):
        assert _resolve_catalog(script) is None
    # A catalog INSIDE the scan root still resolves.
    inner = target / "gradle" / "libs.versions.toml"
    inner.parent.mkdir(parents=True)
    inner.write_text('[versions]\nokio = "3.9.0"\n')
    with scan_root_context(target):
        assert _resolve_catalog(script) is not None


def test_iter_walk_up_out_of_root_start_yields_nothing(tmp_path) -> None:
    """A resolved start OUTSIDE the declared scan root (dir-symlink
    discovery can produce one) made the ``cur == bound`` stop vacuous
    — the walk ran past the root toward ``/`` with only the depth cap
    in the way. Out-of-root starts get no walk at all."""
    from packages.sca.parsers._base import iter_walk_up
    from packages.sca.parsers._safe_read import scan_root_context

    root = tmp_path / "scanroot"
    root.mkdir()
    outside = tmp_path / "elsewhere" / "deep"
    outside.mkdir(parents=True)
    with scan_root_context(root):
        assert list(iter_walk_up(outside)) == []
    # Inside-root walks are unaffected.
    inner = root / "a" / "b"
    inner.mkdir(parents=True)
    with scan_root_context(root):
        assert list(iter_walk_up(inner)) == [inner, inner.parent, root]
