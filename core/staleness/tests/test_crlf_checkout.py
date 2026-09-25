r"""CRLF-checkout fixtures for the staleness-family span hashes.

An LF and a CRLF checkout of the same code must hash identically:
annotation ``metadata.hash`` stamps, corpus span hashes, and every
other staleness consumer would otherwise demote stored verdicts when
a codebase moves between checkout encodings (e.g. a Windows-side
clone with ``core.autocrlf=true``). ``hash_span`` reads with
universal newlines and ``hash_spans_text`` splits through the
``\n``-only line model, so both encodings collapse to one hash —
these fixtures pin that so a read-mode or splitter change cannot
silently re-hash the fleet.
"""

from __future__ import annotations

import pytest

from core.staleness import hash_span, hash_spans, hash_spans_text

pytestmark = pytest.mark.wsl

_LF = (
    "def check(token):\n"
    "    if token is None:\n"
    "        raise ValueError\n"
    "    return token == SECRET\n"
)
_CRLF = _LF.replace("\n", "\r\n")


def _twin_files(tmp_path):
    lf = tmp_path / "lf.py"
    crlf = tmp_path / "crlf.py"
    lf.write_bytes(_LF.encode("utf-8"))
    crlf.write_bytes(_CRLF.encode("utf-8"))
    return lf, crlf


class TestCrlfCheckoutHashParity:
    def test_hash_span_identical_for_lf_and_crlf(self, tmp_path):
        lf, crlf = _twin_files(tmp_path)
        lf_hash = hash_span(lf, 1, 4)
        assert lf_hash != ""
        assert hash_span(crlf, 1, 4) == lf_hash

    def test_hash_span_interior_span_identical(self, tmp_path):
        lf, crlf = _twin_files(tmp_path)
        assert hash_span(crlf, 2, 3) == hash_span(lf, 2, 3) != ""

    def test_hash_spans_batch_identical(self, tmp_path):
        lf, crlf = _twin_files(tmp_path)
        spans = [(1, 4), (2, 3), (4, 4)]
        lf_hashes = hash_spans(lf, spans)
        assert all(h != "" for h in lf_hashes)
        assert hash_spans(crlf, spans) == lf_hashes

    def test_hash_spans_text_identical(self):
        # The in-memory producer path (inventory stamping) sees raw
        # text — a newline="" read of a CRLF checkout keeps the \r\n,
        # and the \n-only splitter's trailing-\r trim makes the span
        # hash encoding-independent there too.
        spans = [(1, 4), (2, 3)]
        assert hash_spans_text(_CRLF, spans) == hash_spans_text(_LF, spans)
        assert all(h != "" for h in hash_spans_text(_LF, spans))
