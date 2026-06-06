"""Tests for the Phase 3 allowlist tightening: common npm native-build
output paths (``build/Release/**``, ``lib/binding/**``, ``binding/**``)
are suppressed; ``.so`` files OUTSIDE these conventional paths are
flagged.

These close the FP gap where the old global ``**/*.so`` entry allowed
ANY ``.so`` anywhere — including a deliberate worm payload at the
package root.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain import binary_in_package


def _write_elf(p: Path) -> None:
    """Write a minimal ELF-magic file at ``p`` (creating parents)."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)


def _write_package_json(tmp_path: Path) -> Path:
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name": "victim", "version": "1.0.0"}', encoding="utf-8")
    return pkg


def _clear_allowlist_cache() -> None:
    """Force the lazy allowlist to reload — needed when tests interact
    with each other through module-level cache state."""
    binary_in_package._ALLOWLIST = None


# ---------------------------------------------------------------------------
# Allowlisted build-output paths — suppressed
# ---------------------------------------------------------------------------

def test_so_under_build_release_is_allowlisted(tmp_path: Path) -> None:
    """``build/Release/foo.so`` is node-gyp output — suppress."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(tmp_path / "build" / "Release" / "native.so")
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(
        h.relpath.endswith("native.so") for h in hits
    )


def test_node_module_under_build_release_is_allowlisted(
    tmp_path: Path,
) -> None:
    """``build/Release/<name>.node`` is the canonical node-gyp output."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(tmp_path / "build" / "Release" / "addon.node")
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(
        h.relpath.endswith("addon.node") for h in hits
    )


def test_so_under_lib_binding_is_allowlisted(tmp_path: Path) -> None:
    """``lib/binding/Release/node-v.../foo.so`` is node-pre-gyp's
    install destination."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(
        tmp_path / "lib" / "binding" / "Release"
        / "node-v108-linux-x64" / "foo.so"
    )
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(
        h.relpath.endswith("foo.so") for h in hits
    )


def test_so_under_binding_root_is_allowlisted(tmp_path: Path) -> None:
    """Some packages drop the ``lib/`` prefix — ``binding/...`` is also
    a recognised opt-in path."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(tmp_path / "binding" / "linux-x64" / "addon.so")
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(
        h.relpath.endswith("addon.so") for h in hits
    )


def test_dylib_under_prebuilds_is_allowlisted(tmp_path: Path) -> None:
    """``prebuilds/darwin-arm64/foo.dylib`` — prebuildify's macOS slot."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(tmp_path / "prebuilds" / "darwin-arm64" / "foo.dylib")
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(
        h.relpath.endswith("foo.dylib") for h in hits
    )


# ---------------------------------------------------------------------------
# Negative cases — .so OUTSIDE allowlisted paths should still fire
# ---------------------------------------------------------------------------

def test_so_at_package_root_is_flagged(tmp_path: Path) -> None:
    """The old global ``**/*.so`` rule allowed this — now it does not.
    A worm at the package root with a ``.so`` extension must fire."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(tmp_path / "worm.so")
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert any(h.relpath.endswith("worm.so") for h in hits), (
        "expected worm.so at package root to fire — the previous "
        "global allowlist entry must be gone"
    )


def test_so_under_tools_is_flagged(tmp_path: Path) -> None:
    """``tools/`` is the Iron Worm canonical drop dir — must fire."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(tmp_path / "tools" / "setup.so")
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert any(h.relpath.endswith("setup.so") for h in hits)


def test_so_under_scripts_is_flagged(tmp_path: Path) -> None:
    """``scripts/`` is another common payload drop dir — must fire."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(tmp_path / "scripts" / "install.so")
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert any(h.relpath.endswith("install.so") for h in hits)


def test_binary_in_tests_aligned_with_binary_in_package_allowlist(
    tmp_path: Path,
) -> None:
    """An ELF under ``<sub>/tests/fixtures/binary_oracle/`` must be
    suppressed by BOTH ``binary_in_tests`` (artefacts.py) AND
    ``binary_in_package`` (binary_in_package.py).  Pre-alignment
    the two detectors gave contradictory verdicts on the same
    path — binary_in_package suppressed via allowlist while
    binary_in_tests deliberately fired at low for SBOM awareness.
    Now both consult the same allowlist; only convention-breaking
    placements (e.g. ``tests/setup_bun.js`` at the tests/ root) fire.

    Dogfooded against RAPTOR's own
    ``core/inventory/tests/fixtures/binary_oracle/demo`` fixture.
    """
    from packages.sca.supply_chain import artefacts as _artefacts
    _clear_allowlist_cache()
    # Realistic 20KB ELF in a nested fixture path — same shape as
    # the raptor tree dogfood result.
    payload = tmp_path / "core" / "inventory" / "tests" / "fixtures" \
        / "binary_oracle" / "demo"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20_000)
    # binary_in_package: allowlisted via tests/fixtures/** recursive.
    bip_hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(
        "binary_oracle/demo" in h.relpath for h in bip_hits
    ), "binary_in_package must suppress (allowlist)"
    # binary_in_tests: SAME path, SAME allowlist — must also suppress.
    art_hits = _artefacts.scan_target(tmp_path, [])
    bit_hits = [h for h in art_hits if h.kind == "binary_in_tests"
                and "binary_oracle/demo" in str(h.path)]
    assert not bit_hits, (
        "binary_in_tests must align with the shared allowlist; "
        f"got {[h.detail for h in bit_hits]}"
    )


def test_binary_in_tests_still_fires_on_unconventional_test_drop(
    tmp_path: Path,
) -> None:
    """An ELF dropped directly under ``tests/`` (NOT in a fixtures
    or testdata sub-path) is the attacker shape — must still fire."""
    from packages.sca.supply_chain import artefacts as _artefacts
    _clear_allowlist_cache()
    payload = tmp_path / "tests" / "setup_bun.bin"  # Shai-Hulud-shape
    payload.parent.mkdir()
    payload.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20_000)
    art_hits = _artefacts.scan_target(tmp_path, [])
    bit_hits = [h for h in art_hits if h.kind == "binary_in_tests"]
    assert bit_hits, (
        "binary_in_tests must still fire on attacker placement "
        "outside conventional fixture dirs"
    )


def test_nested_tests_fixtures_path_is_allowlisted(tmp_path: Path) -> None:
    """Monorepo / packages-tree shape: ``<sub>/tests/fixtures/...``.
    Dogfooded against RAPTOR's own
    ``core/inventory/tests/fixtures/binary_oracle/`` tree which
    FP-fired before the recursive pattern was added."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(
        tmp_path / "core" / "inventory" / "tests" / "fixtures"
        / "binary_oracle" / "demo"
    )
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(h.relpath.endswith("demo") for h in hits), (
        "binary under nested tests/fixtures/ must be allowlisted"
    )


def test_nested_test_singular_fixtures_path_allowlisted(
    tmp_path: Path,
) -> None:
    """Same for ``test/`` (singular form, used in some monorepos)."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(
        tmp_path / "pkg" / "sub" / "test" / "fixtures" / "thing.so"
    )
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert not any(h.relpath.endswith("thing.so") for h in hits)


def test_so_under_arbitrary_attacker_dir_is_flagged(
    tmp_path: Path,
) -> None:
    """Attacker drops ``.so`` in an arbitrary non-allowlisted dir."""
    _clear_allowlist_cache()
    _write_package_json(tmp_path)
    _write_elf(tmp_path / "src" / "helpers" / "x.so")
    hits = binary_in_package.scan_target(tmp_path, [], [])
    assert any(h.relpath.endswith("x.so") for h in hits)
