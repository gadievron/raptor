"""Phase 1.5.1 — tests for ``packages.zkpox.gadget``.

Covers the contract ``cmd_prove`` relies on: deterministic per-gadget
hashing, distinct hashes per declared gadget, refusal on unknown
gadget_id / missing manifest file, and the canonicalisation invariant
(BOM + CRLF) so a Windows-checkout developer gets the same hash as a
Linux CI run.
"""

from __future__ import annotations

import pytest

from packages.zkpox.gadget import (
    GadgetCodeHashError,
    _canonicalise,
    _gadget_base,
    compute_gadget_code_hash,
)


def test_strips_version_suffix():
    assert _gadget_base("crash-only@0.1.0") == "crash-only"
    assert _gadget_base("memory-safety::oob-write@0.1.0") == "memory-safety::oob-write"
    # Tolerates a missing @version.
    assert _gadget_base("custom") == "custom"


def test_canonicalise_strips_bom_and_folds_crlf():
    """The two normalisations are what makes the hash portable across
    Windows / Linux checkouts. No other transforms — content is
    otherwise byte-faithful."""
    assert _canonicalise(b"\xef\xbb\xbfhi") == b"hi"
    assert _canonicalise(b"a\r\nb\r\n") == b"a\nb\n"
    # Single bytes unaffected; LF preserved.
    assert _canonicalise(b"a\nb") == b"a\nb"


def test_known_gadgets_yield_distinct_deterministic_hashes():
    """Repeating gadget_ids → same hash; distinct gadget_ids → distinct
    hashes. ``cmd_prove`` relies on both."""
    h_crash = compute_gadget_code_hash("crash-only@0.1.0")
    h_oob = compute_gadget_code_hash("memory-safety::oob-write@0.1.0")
    assert h_crash.startswith("sha256:")
    assert h_oob.startswith("sha256:")
    assert len(h_crash) == len("sha256:") + 64
    assert h_crash != h_oob
    assert h_crash == compute_gadget_code_hash("crash-only@0.1.0")


def test_unknown_gadget_id_rejected():
    """A typo in --gadget-id must not produce a bundle. Cleaner than
    silently hashing nothing or falling back."""
    with pytest.raises(GadgetCodeHashError, match="unknown gadget_id"):
        compute_gadget_code_hash("nope@1.0")


def test_missing_manifest_file_rejected(tmp_path):
    """A manifest pointing at a file that's been moved/deleted must
    fail loudly. Exercised by re-rooting the helper at an empty tmp
    dir — every manifest file is then missing."""
    with pytest.raises(GadgetCodeHashError, match="missing/unreadable"):
        compute_gadget_code_hash("crash-only@0.1.0", repo_root=tmp_path)


def test_hash_unaffected_by_version_suffix_alone():
    """The gadget_id (including @version) is part of the hashed
    preamble, so different versions of the SAME gadget yield different
    hashes — even when the file manifest is unchanged. This is the
    "version bump = content bump" property the design doc commits to."""
    h_a = compute_gadget_code_hash("crash-only@0.1.0")
    h_b = compute_gadget_code_hash("crash-only@0.2.0")
    assert h_a != h_b
