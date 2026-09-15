"""Fingerprint extractor-identity tests for
:mod:`core.analysis._reach_cache`."""
from __future__ import annotations

import sys

import core.analysis._reach_cache as rc_mod
import core.inventory._ts_cache as ts_cache


def _inv():
    return {
        "files": [
            {"path": "a.py", "sha256": "aa" * 32},
            {"path": "b.py", "sha256": "bb" * 32},
        ],
    }


def test_fingerprint_stable_for_same_content_and_extractor():
    fp1 = rc_mod.compute_fingerprint(_inv())
    fp2 = rc_mod.compute_fingerprint(_inv())
    assert fp1 is not None
    assert fp1 == fp2


def test_fingerprint_changes_when_extractor_identity_changes(monkeypatch):
    # Same source shas, different extraction toolchain (a tree-sitter
    # grammar installed since the cache entry was written) must yield
    # a different fingerprint — otherwise a degraded adjacency index
    # keeps being served after parsers become available.
    fp_before = rc_mod.compute_fingerprint(_inv())
    current = rc_mod._extractor_identity()
    monkeypatch.setattr(
        rc_mod, "_EXTRACTOR_IDENTITY", current + ",tree_sitter_extra",
    )
    fp_after = rc_mod.compute_fingerprint(_inv())
    assert fp_before is not None and fp_after is not None
    assert fp_before != fp_after


def test_fingerprint_still_changes_on_content_change():
    inv = _inv()
    fp1 = rc_mod.compute_fingerprint(inv)
    inv["files"][0]["sha256"] = "cc" * 32
    fp2 = rc_mod.compute_fingerprint(inv)
    assert fp1 != fp2


def test_identity_excludes_findable_but_unimportable_grammar(
    tmp_path, monkeypatch,
):
    # A module that is FINDABLE but raises at import time (a
    # dependency-simulation stub, a broken wheel) must not count as
    # available: the extractor probes by import, so an identity that
    # over-claims lets a degraded index be persisted under — and
    # served from — the full-toolchain fingerprint.
    stub_name = "tree_sitter_reachfp_stub"
    (tmp_path / f"{stub_name}.py").write_text(
        'raise ModuleNotFoundError("No module named '
        f'{stub_name}", name="{stub_name}")\n',
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(rc_mod, "_EXTRACTOR_IDENTITY", None)
    monkeypatch.setattr(
        rc_mod, "_GRAMMAR_MODULES", (*rc_mod._GRAMMAR_MODULES, stub_name),
    )
    # Fresh probe state for the stub: neither the shared grammar-import
    # cache nor sys.modules may carry a verdict from another test.
    monkeypatch.delitem(ts_cache._GRAMMAR_CACHE, stub_name, raising=False)
    monkeypatch.delitem(sys.modules, stub_name, raising=False)

    identity = rc_mod._extractor_identity()

    assert stub_name not in identity.split(",")
    # And the real runtime module, when importable, still registers —
    # the probe rejects import failure, not the mechanism itself.
    try:
        import tree_sitter  # noqa: F401
    except ImportError:
        pass
    else:
        assert "tree_sitter" in identity.split(",")


def test_identity_degrades_on_non_importerror_grammar(
    tmp_path, monkeypatch,
):
    # A findable module that raises a NON-ImportError at import time
    # (a corrupted wheel — the class the import-probe exists for)
    # must degrade to unavailable, matching extraction's per-file
    # fail-soft, not crash every reachability consumer out of its
    # documented degrade path.
    stub_name = "tree_sitter_reachfp_syntax_stub"
    (tmp_path / f"{stub_name}.py").write_text("def broken(:\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(rc_mod, "_EXTRACTOR_IDENTITY", None)
    monkeypatch.setattr(
        rc_mod, "_GRAMMAR_MODULES", (*rc_mod._GRAMMAR_MODULES, stub_name),
    )
    monkeypatch.delitem(ts_cache._GRAMMAR_CACHE, stub_name, raising=False)
    monkeypatch.delitem(sys.modules, stub_name, raising=False)

    identity = rc_mod._extractor_identity()
    assert stub_name not in identity.split(",")

    # The whole fingerprint path stays crash-free on this env shape.
    assert rc_mod.compute_fingerprint(_inv()) is not None


def test_header_magic_tracks_cache_version():
    # The comment contract: the header magic's numeric suffix tracks
    # _CACHE_VERSION. Convention-only until pinned here.
    assert str(rc_mod._CACHE_VERSION).encode() in rc_mod._HEADER_MAGIC
