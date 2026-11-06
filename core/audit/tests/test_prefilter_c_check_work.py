"""C checker work bounds and zero-based source-coordinate regression."""

from types import SimpleNamespace

import pytest

from core.audit import prefilter


@pytest.mark.parametrize('line_start', [0, 1, 17])
@pytest.mark.parametrize('check', ['access', 'stat', 'lstat'])
def test_toctou_keeps_check_at_first_source_line(tmp_path, line_start, check):
    result = prefilter.run_prefilter(
        target_path=tmp_path, file_path='f.c', function_name='f',
        source=f'{check}(path, 0);\nopen(path, 0);', line_start=line_start,
    )
    hits = [hit for hit in result.hits if hit.rule_id == 'toctou-filesystem']
    assert len(hits) == 1
    assert hits[0].line == line_start + 1
    assert f'check at line {line_start} (path)' in hits[0].message
    assert not result.skip_llm


@pytest.mark.parametrize('count', [1, 8, 64])
def test_repeated_array_index_scans_bounds_once_per_variable(monkeypatch, count):
    source = '\n'.join('a[i] = 0;' for _ in range(count))
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    searches = []
    real_re = prefilter.re

    def counted_search(pattern, text):
        searches.append((pattern, text))
        return real_re.search(pattern, text)

    monkeypatch.setattr(prefilter, 're', SimpleNamespace(
        finditer=real_re.finditer, escape=real_re.escape, search=counted_search,
    ))
    prefilter._check_c_missing_bounds(
        result, source, 17, prefilter._GuardViews(result, source),
    )
    assert len(result.hits) == count
    assert {hit.line for hit in result.hits} == set(range(17, 17 + count))
    assert {hit.rule_id for hit in result.hits} == {'array-index-unchecked'}
    assert len(searches) == count


def test_bounds_checks_split_the_code_view_once(monkeypatch):
    splits = []
    real_view = prefilter.sanitized_view_with_status

    class Text(str):
        def splitlines(self, keepends=False):
            splits.append(keepends)
            return super().splitlines(keepends)

    def counted_view(*args, **kwargs):
        view = real_view(*args, **kwargs)
        return view._replace(text=Text(view.text))

    monkeypatch.setattr(prefilter, 'sanitized_view_with_status', counted_view)
    source = 'if (i < n && j < n) {}\na[i] = 0;\na[j] = 0;'
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    prefilter._check_c_missing_bounds(
        result, source, 1, prefilter._GuardViews(result, source),
    )
    assert result.hits == []
    assert splits == [False]


def test_toctou_requires_a_preceding_check(tmp_path):
    result = prefilter.run_prefilter(
        target_path=tmp_path, file_path='f.c', function_name='f',
        source='open(path, 0);', line_start=0,
    )
    assert not any(hit.rule_id == 'toctou-filesystem' for hit in result.hits)
