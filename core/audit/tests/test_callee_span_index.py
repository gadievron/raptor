"""Callee snippets resolve exact occurrences without repeated inventory walks."""

import pytest

from core.audit import context


class Rows(list):
    iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


def write_source(tmp_path, prefix='line'):
    (tmp_path / 'callee.c').write_text(''.join(f'{prefix}{i}\n' for i in range(1, 41)))


@pytest.mark.parametrize('field', ['items', 'functions'])
@pytest.mark.parametrize('name', ['Decode', 'NumberReader.Decode'])
def test_same_name_callee_uses_its_exact_span(tmp_path, field, name):
    write_source(tmp_path)
    checklist = {'files': [{'path': 'callee.c', field: [
        {'name': 'Decode', 'line_start': 2, 'line_end': 4,
         'metadata': {'class_name': 'TextReader'}},
        {'name': 'Decode', 'line_start': 20, 'line_end': 22,
         'metadata': {'class_name': 'NumberReader'}},
    ]}]}
    callees = [{'file': 'callee.c', 'name': name, 'line_start': 20}]
    context._enrich_callees_with_source(callees, tmp_path, checklist, max_lines=10)
    snippet = callees[0]['source_snippet']
    assert len(snippet.splitlines()) == 3
    assert 'line20' in snippet and 'line22' in snippet
    assert 'line23' not in snippet


def test_repeated_callee_walks_inventory_and_items_once(tmp_path):
    write_source(tmp_path)
    items = Rows([{'name': 'helper', 'line_start': 2, 'line_end': 4}])
    files = Rows([{'path': f'unrelated{i}.c', 'items': []} for i in range(1000)])
    files.append({'path': 'callee.c', 'items': items})
    callees = [{'file': 'callee.c', 'name': 'helper', 'line_start': 2} for _ in range(20)]
    context._enrich_callees_with_source(
        callees, tmp_path, {'files': files}, max_total_lines=1000,
    )
    assert len({row['source_snippet'] for row in callees}) == 1
    assert files.iterations == 1
    assert items.iterations == 1


def test_ambiguous_occurrence_uses_bounded_unknown_end_fallback(tmp_path):
    write_source(tmp_path)
    checklist = {'files': [{'path': 'callee.c', 'items': [
        {'name': 'helper', 'line_start': 20, 'line_end': 22},
        {'name': 'helper', 'line_start': 20, 'line_end': 30},
    ]}]}
    callees = [{'file': 'callee.c', 'name': 'helper', 'line_start': 20}]
    context._enrich_callees_with_source(callees, tmp_path, checklist, max_lines=5)
    snippet = callees[0]['source_snippet']
    assert len(snippet.splitlines()) == 5
    assert 'line24' in snippet and 'line25' not in snippet


def test_span_cache_is_local_to_one_enrichment(tmp_path):
    write_source(tmp_path)
    item = {'name': 'helper', 'line_start': 2, 'line_end': 4}
    checklist = {'files': [{'path': 'callee.c', 'items': [item]}]}
    first = [{'file': 'callee.c', 'name': 'helper', 'line_start': 2}]
    context._enrich_callees_with_source(first, tmp_path, checklist)
    item['line_end'] = 5
    second = [{'file': 'callee.c', 'name': 'helper', 'line_start': 2}]
    context._enrich_callees_with_source(second, tmp_path, checklist)
    assert len(first[0]['source_snippet'].splitlines()) == 3
    assert len(second[0]['source_snippet'].splitlines()) == 4


def test_repeated_callee_still_reads_fresh_source(tmp_path, monkeypatch):
    write_source(tmp_path, 'before')
    real_read = context._read_target_line_window
    reads = []

    def read(*args):
        lines = real_read(*args)
        reads.append(args)
        if len(reads) == 1:
            write_source(tmp_path, 'after')
        return lines

    monkeypatch.setattr(context, '_read_target_line_window', read)
    checklist = {'files': [{'path': 'callee.c', 'items': [
        {'name': 'helper', 'line_start': 2, 'line_end': 4},
    ]}]}
    callees = [{'file': 'callee.c', 'name': 'helper', 'line_start': 2} for _ in range(2)]
    context._enrich_callees_with_source(callees, tmp_path, checklist)
    assert len(reads) == 2
    assert 'before2' in callees[0]['source_snippet']
    assert 'after2' in callees[1]['source_snippet']
