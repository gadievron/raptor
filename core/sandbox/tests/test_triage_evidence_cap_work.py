"""Only evidence selected for display is escaped and materialized."""
import pytest

from core.sandbox import triage
from core.security import log_sanitisation


@pytest.mark.parametrize('count', [0, 1, 3, 4, 10000])
def test_escape_work_is_bounded_by_display_cap(monkeypatch, count):
    monkeypatch.setattr(triage, '_MAX_EVIDENCE_ITEMS', 3)
    calls = []
    real_escape = log_sanitisation.escape_nonprintable

    def escape(item):
        calls.append(item)
        return real_escape(item)

    monkeypatch.setattr(log_sanitisation, 'escape_nonprintable', escape)
    items = [f'item-{i}' for i in range(count)]
    original = list(items)
    result = triage._cap_evidence(items)
    assert calls == items[:3]
    expected = items[:3]
    if count > 3:
        expected = expected + [f'...[+{count - 3} more]']
    assert result == expected
    assert items == original


def test_displayed_items_keep_escape_then_truncate_semantics(monkeypatch):
    monkeypatch.setattr(triage, '_MAX_EVIDENCE_ITEMS', 2)
    monkeypatch.setattr(triage, '_MAX_EVIDENCE_ITEM_LEN', 8)
    items = ['before\x1b[31mafter', 'short', 'omitted']
    escaped = log_sanitisation.escape_nonprintable(items[0])
    assert triage._cap_evidence(items) == [
        escaped[:8] + f'...[+{len(escaped) - 8} chars]', 'short', '...[+1 more]']


def test_repeated_values_and_order_are_preserved(monkeypatch):
    monkeypatch.setattr(triage, '_MAX_EVIDENCE_ITEMS', 3)
    assert triage._cap_evidence(['b', 'a', 'b', 'c']) == ['b', 'a', 'b', '...[+1 more]']
