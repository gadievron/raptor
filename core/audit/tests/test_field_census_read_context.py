"""Read contexts retain their precedence without suffix copies."""

import pytest

from core.audit import field_census as fc


@pytest.mark.parametrize(('line', 'contexts'), [
    ('return obj->alpha + obj->beta;', ['return', 'return']),
    ('xreturnx obj->alpha;', ['return']),
    ('obj->alpha + return obj->beta;', ['expr', 'expr']),
    ('return obj->alpha \t\u2003 (1) + obj->beta;', ['invoke', 'return']),
    ('local = obj->alpha;', ['alias_assign:local']),
    ('return local = obj->alpha;', ['alias_assign:local']),
    ('obj->alpha; later(1);', ['expr']),
])
def test_read_context_precedence(line, contexts):
    records = {}
    fc._scan_file_regex(line, 'a.c', records, lambda _: True)
    assert [read.context for record in records.values()
            for read in record.reads] == contexts


def test_many_accesses_keep_all_sites_in_order():
    source = 'return ' + ' + '.join(f'obj->field{i}' for i in range(1000)) + ';'
    records = {}
    fc._scan_file_regex(source, 'a.c', records, lambda _: True)
    assert list(records) == [f'field{i}' for i in range(1000)]
    assert all(len(record.reads) == 1 and record.reads[0].context == 'return'
               for record in records.values())
