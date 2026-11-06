"""Dynamic C matchers preserve identifier and assignment boundaries."""

from types import SimpleNamespace

import pytest

from core.audit import prefilter


@pytest.mark.parametrize('operation', ['open', 'fopen', 'creat', 'unlink', 'rename', 'chmod', 'chown'])
@pytest.mark.parametrize('other_path', ['path2', 'path_extra', 'pathology', 'pathé'])
def test_toctou_does_not_consume_a_different_path(operation, other_path):
    source = f'access(path, 0);\n{operation}({other_path}, 0);\n{operation}(path, 0);'
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    prefilter._check_c_toctou(result, source, 0)
    assert len(result.hits) == 1
    assert result.hits[0].rule_id == 'toctou-filesystem'
    assert result.hits[0].line == 2


@pytest.mark.parametrize('comparison', ['a[i] == 0;', 'if (a[i] == 0) return;', 'int value = a[i] == 0;'])
def test_post_loop_comparison_does_not_consume_a_later_write(comparison):
    source = f'for (i = 0; i < cap; i++) {{\n  a[i] = 0;\n}}\n{comparison}\na[i] = 1;'
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    prefilter._check_c_post_loop_oob(
        result, source, 1, prefilter._GuardViews(result, source),
    )
    assert len(result.hits) == 1
    assert result.hits[0].rule_id == 'post-loop-oob-write'
    assert result.hits[0].line == 5


@pytest.mark.parametrize('count', [1, 8, 64])
def test_toctou_escapes_a_path_once_per_check(monkeypatch, count):
    escaped = []
    real_re = prefilter.re

    def escape(name):
        escaped.append(name)
        return real_re.escape(name)

    monkeypatch.setattr(prefilter, 're', SimpleNamespace(
        compile=real_re.compile, escape=escape, search=real_re.search,
    ))
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    source = 'access(path, 0);\n' + 'do_other_work();\n' * count
    prefilter._check_c_toctou(result, source, 1)
    assert result.hits == []
    assert escaped == ['path']


@pytest.mark.parametrize('count', [1, 8, 64])
def test_post_loop_builds_matchers_once_per_index(monkeypatch, count):
    escaped = []
    real_re = prefilter.re

    def escape(name):
        escaped.append(name)
        return real_re.escape(name)

    monkeypatch.setattr(prefilter, 're', SimpleNamespace(
        compile=real_re.compile, escape=escape, search=real_re.search,
    ))
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    source = 'for (i = 0; i < cap; i++) {\n  a[i] = 0;\n}\n' + 'do_other_work();\n' * count
    prefilter._check_c_post_loop_oob(
        result, source, 1, prefilter._GuardViews(result, source),
    )
    assert result.hits == []
    assert escaped == ['i']


def test_toctou_rebuilds_matcher_after_a_different_check():
    source = 'access(first, 0);\ndo_other_work();\nstat(second, 0);\nopen(second, 0);'
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    prefilter._check_c_toctou(result, source, 1)
    assert len(result.hits) == 1
    assert result.hits[0].line == 4
    assert 'check at line 3 (second)' in result.hits[0].message


@pytest.mark.parametrize('indices', [('i', 'j'), ('i', 'i')])
def test_post_loop_matchers_follow_the_current_index(indices):
    source = '\n'.join(
        f'for ({idx} = 0; {idx} < cap; {idx}++) {{\n  a[{idx}] = 0;\n}}\ndo_other_work();\na[{idx}] = 1;'
        for idx in indices
    )
    result = prefilter.PrefilterResult(file='f.c', function='f', language='c')
    prefilter._check_c_post_loop_oob(
        result, source, 1, prefilter._GuardViews(result, source),
    )
    assert [hit.line for hit in result.hits] == [5, 10]
    for hit, idx in zip(result.hits, indices):
        assert f"loop index '{idx}'" in hit.message
