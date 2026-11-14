"""Precomputed content hashes preserve ordered fingerprint framing."""

import hashlib

import pytest

from core.audit.prep_cache import (
    content_fingerprint,
    content_fingerprint_from_hashes,
    source_fingerprint_from_hashes,
)


@pytest.mark.parametrize("items", [[], [("owned", b"")],
                                   [("first", b"a"), ("second", b"b")],
                                   [("same", b"a"), ("same", b"b")],
                                   [("unicode-\u2603", b"\xff"), ("bad-\udcff", b"owned")]])
def test_ordered_hashes_match_original_content_fingerprint(items):
    hashes = [(name, hashlib.sha256(data).hexdigest()) for name, data in items]
    assert content_fingerprint_from_hashes(hashes) == content_fingerprint(items)


def test_order_sensitive_helper_and_sorted_source_wrapper_keep_their_contracts():
    items = [("z", b"last"), ("a", b"first")]
    hashes = [(name, hashlib.sha256(data).hexdigest()) for name, data in items]
    assert content_fingerprint_from_hashes(hashes) != content_fingerprint_from_hashes(reversed(hashes))
    assert source_fingerprint_from_hashes(dict(hashes)) == content_fingerprint(sorted(items))


@pytest.mark.parametrize("digest", ["", "00", "not-hex", "ff" * 33])
def test_invalid_precomputed_hashes_are_refused(digest):
    with pytest.raises(ValueError):
        content_fingerprint_from_hashes([("owned", digest)])
    with pytest.raises(ValueError):
        source_fingerprint_from_hashes({"owned": digest})
