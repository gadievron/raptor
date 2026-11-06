"""Pattern guidance avoids unused scans; flow excerpts keep occurrence identity."""

import pytest

from core.audit import context


def test_pattern_summary_does_not_split_the_unused_body():
    splits = []

    class Text(str):
        def __getitem__(self, key):
            return Text(super().__getitem__(key))

        def strip(self, *args):
            return Text(super().strip(*args))

        def split(self, *args, **kwargs):
            splits.append(len(self))
            return super().split(*args, **kwargs)

    text = Text('## 1. Example\n\nSummary line\n```c\n' + 'unused body\n' * 10000 + '```\n')
    result = context._parse_patterns(text)
    assert result[0][0] == 'Example'
    assert result[0][2] == 'Summary line'
    assert result[0][1] == str(text).rstrip()
    assert splits == []


def test_tier_classification_folds_the_title_once():
    calls = []

    class Title(str):
        def lower(self):
            calls.append(1)
            return super().lower()

    assert not context._is_tier1(Title('Example'), {'other', 'unrelated', 'unseen'})
    assert len(calls) == 1


def test_pattern_groups_load_before_processing_and_stay_unchanged(monkeypatch):
    common = [('Common', 'common full', 'common summary', False)]
    language = [('Language', 'lang full', 'lang summary', False)]
    loads = []
    monkeypatch.setattr(context, '_pattern_file_cache', context.BoundedMemo(32))
    monkeypatch.setattr(context, '_patterns_cache', context.BoundedMemo(32))

    def load(name):
        loads.append(name)
        return common if name == 'common' else language

    def trigger(title):
        assert loads == ['common', 'c']
        return None

    monkeypatch.setattr(context, '_load_pattern_file', load)
    monkeypatch.setattr(context, '_match_trigger_keywords', trigger)
    result = context._load_language_patterns('a.c', 'ordinary source')
    assert result == {'tier1': '', 'tier2': '- **Common**: common summary\n- **Language**: lang summary'}
    assert common == [('Common', 'common full', 'common summary', False)]
    assert language == [('Language', 'lang full', 'lang summary', False)]


@pytest.mark.parametrize('field', ['items', 'functions'])
@pytest.mark.parametrize('name', ['Decode', 'NumberReader.Decode'])
def test_flow_excerpt_uses_the_correct_same_name_occurrence(tmp_path, field, name):
    (tmp_path / 'a.c').write_text(''.join(f'line{i}\n' for i in range(1, 41)))
    checklist = {'files': [{'path': 'a.c', field: [
        {'name': 'Decode', 'line_start': 2, 'line_end': 4,
         'metadata': {'class_name': 'TextReader'}},
        {'name': 'Decode', 'line_start': 20, 'line_end': 22,
         'metadata': {'class_name': 'NumberReader'}},
    ]}]}
    result = context._read_flow_node_source(
        tmp_path, {'file': 'a.c', 'name': name, 'line': 20}, checklist, 10,
    )
    assert len(result.splitlines()) == 3
    assert 'line20' in result and 'line22' in result
    assert 'line23' not in result


@pytest.mark.parametrize('start', [None, 18])
def test_flow_excerpt_retains_unique_legacy_and_interior_line_bounds(tmp_path, start):
    (tmp_path / 'a.c').write_text(''.join(f'line{i}\n' for i in range(1, 41)))
    item = {'name': 'Decode', 'line_end': 22}
    if start is not None:
        item['line_start'] = start
    result = context._read_flow_node_source(
        tmp_path, {'file': 'a.c', 'name': 'Decode', 'line': 20},
        {'files': [{'path': 'a.c', 'items': [item]}]}, 10,
    )
    assert len(result.splitlines()) == 3
    assert 'line23' not in result


@pytest.mark.parametrize('line', [0, None])
@pytest.mark.parametrize('name', ['Decode', 'NumberReader.Decode'])
def test_unknown_flow_line_uses_a_unique_recorded_occurrence(tmp_path, line, name):
    (tmp_path / 'a.c').write_text(''.join(f'line{i}\n' for i in range(1, 41)))
    items = [{'name': 'Decode', 'line_start': 20, 'line_end': 22,
              'metadata': {'class_name': 'NumberReader'}}]
    if name != 'Decode':
        items.insert(0, {'name': 'Decode', 'line_start': 2, 'line_end': 4,
                         'metadata': {'class_name': 'TextReader'}})
    node = {'file': 'a.c', 'name': name, 'line': line}
    result = context._read_flow_node_source(
        tmp_path, node, {'files': [{'path': 'a.c', 'items': items}]}, 10,
    )
    assert len(result.splitlines()) == 3
    assert 'line20' in result and 'line22' in result
    assert node['line'] is line
