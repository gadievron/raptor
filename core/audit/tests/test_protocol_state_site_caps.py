"""Read and write caps remain independent for compound updates."""

from core.audit import protocol_state as ps


def test_compound_read_survives_a_full_write_list(monkeypatch):
    monkeypatch.setattr(ps, 'MAX_SITES_PER_FIELD', 1)
    result = ps.build_state_field_index({
        'a.c': 'obj->field = first();\nobj->field += second();',
    })
    record = result['fields']['field']
    assert result['skipped']
    assert [site['line'] for site in record['writes']] == [1]
    assert [site['line'] for site in record['reads']] == [2]
    assert 'rhs' not in record['reads'][0]
    assert 'rhs_class' not in record['reads'][0]


def test_compound_write_survives_a_full_read_list(monkeypatch):
    monkeypatch.setattr(ps, 'MAX_SITES_PER_FIELD', 1)
    result = ps.build_state_field_index({
        'a.c': 'consume(obj->field);\nobj->field += next();',
    })
    record = result['fields']['field']
    # Existing semantics flag truncation of the primary site only.
    assert not result['skipped']
    assert [site['line'] for site in record['reads']] == [1]
    assert [site['line'] for site in record['writes']] == [2]
    assert record['writes'][0]['rhs_class'] == 'from_call:next'


def test_prefix_increment_read_survives_full_write_list(monkeypatch):
    monkeypatch.setattr(ps, 'MAX_SITES_PER_FIELD', 1)
    result = ps.build_state_field_index({
        'a.c': 'obj->field = 0;\n++obj->field;',
    })
    record = result['fields']['field']
    assert result['skipped']
    assert [site['line'] for site in record['writes']] == [1]
    assert [site['line'] for site in record['reads']] == [2]
