"""Fingerprint extractor-identity tests for
:mod:`core.analysis._reach_cache`."""
from __future__ import annotations

import core.analysis._reach_cache as rc_mod


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
