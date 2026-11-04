"""Streaming preserves pattern priority and bounded temporary storage."""

import tracemalloc

import pytest

from core.audit import protocol_state as ps


def test_pattern_priority_is_preserved_when_sites_are_capped(monkeypatch):
    monkeypatch.setattr(ps, 'MAX_SITES_PER_FIELD', 1)
    source = 'arr[0].hdr.field = 1; obj->field = 2;'
    result = ps.build_state_field_index({'a.c': source})
    # Ordinary chains precede after-closer chains, even when later in text.
    assert result['skipped']
    writes = result['fields']['field']['writes']
    assert len(writes) == 1
    assert (writes[0]['base'], writes[0]['rhs']) == ('obj', '2')


def test_large_line_does_not_retain_all_match_objects():
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    sources = {'a.c': ' '.join('obj->field = 7;' for _ in range(20000))}
    # Warm imports and helper caches outside the measured interval.
    ps.build_state_field_index({'a.c': 'obj->field = 7;'})
    tracemalloc.start()
    try:
        result = ps.build_state_field_index(sources)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(result['fields']['field']['writes']) == ps.MAX_SITES_PER_FIELD
    assert result['skipped']
    assert peak < 1024 * 1024
