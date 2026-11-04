"""Escaped evidence is bounded during construction, not only afterward."""
import pytest

from core.sandbox import triage
from core.security import log_sanitisation


@pytest.mark.parametrize('item', ['', 'ordinary', 'caf\u00e9', '\x1b' * 10000,
                                 '\u202e' * 10000, 'x' * 4095 + '\n' + 'y' * 4096,
                                 'x' * 100000, '\udcff' * 9000])
@pytest.mark.parametrize('limit', [0, 8, 256, 5000])
def test_chunked_output_matches_full_escape_then_cap(monkeypatch, item, limit):
    monkeypatch.setattr(triage, '_MAX_EVIDENCE_ITEM_LEN', limit)
    escaped = log_sanitisation.escape_nonprintable(item)
    expected = escaped
    if len(escaped) > limit:
        expected = escaped[:limit] + f'...[+{len(escaped) - limit} chars]'
    assert triage._cap_evidence([item]) == [expected]


def test_escape_allocations_receive_bounded_chunks(monkeypatch):
    real_escape = log_sanitisation.escape_nonprintable
    lengths = []

    def escape(text):
        lengths.append(len(text))
        assert len(text) <= 4096
        return real_escape(text)

    monkeypatch.setattr(log_sanitisation, 'escape_nonprintable', escape)
    item = '\x1b' * 100000
    result = triage._cap_evidence([item])
    assert sum(lengths) == len(item)
    assert len(lengths) > 1
    assert len(result) == 1
    assert len(result[0]) < triage._MAX_EVIDENCE_ITEM_LEN + 40
