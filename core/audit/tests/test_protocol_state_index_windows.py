"""Bounded index searches preserve operator and statement boundaries."""

import pytest

from core.audit import protocol_state as ps


@pytest.mark.parametrize('whitespace', ['', ' ', '\t', '\v', '\f', '\r', '\x1c', '\x85', '\u2003'])
def test_prefix_increment_uses_strip_whitespace_model(whitespace):
    result = ps.build_state_field_index({'a.c': f'++{whitespace}obj->field;'})
    record = result['fields']['field']
    assert len(record['writes']) == len(record['reads']) == 1
    assert record['writes'][0]['rhs_class'] == 'unknown'
    assert record['writes'][0]['rhs'] == ''


def test_rhs_offsets_and_statement_boundaries():
    result = ps.build_state_field_index({
        'a.c': 'obj->alpha = NULL; obj->beta += next(); obj->gamma = other->delta',
    })
    fields = result['fields']
    assert fields['alpha']['writes'][0]['rhs'] == 'NULL'
    assert fields['beta']['writes'][0]['rhs'] == 'next()'
    assert fields['beta']['writes'][0]['rhs_class'] == 'from_call:next'
    assert len(fields['beta']['reads']) == 1
    assert fields['gamma']['writes'][0]['rhs'] == 'other->delta'
    assert len(fields['delta']['reads']) == 1


def test_caps_order_and_code_on_a_long_line(monkeypatch):
    monkeypatch.setattr(ps, 'MAX_SITES_PER_FIELD', 3)
    source = '  ' + ' '.join('obj->field = 7;' for _ in range(1000))
    result = ps.build_state_field_index({'a.c': source})
    writes = result['fields']['field']['writes']
    assert result['skipped']
    assert len(writes) == 3
    assert all(site['rhs'] == '7' and site['code'] == source.strip()[:200]
               for site in writes)
