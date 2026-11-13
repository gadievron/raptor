"""Field updates cannot be exempted as tracked local-array accesses."""

import pytest

pytest.importorskip('tree_sitter_java')

from core.analysis.cfg_builder_java import _get_parser, build_java_intraproc_cfg  # noqa: E402
from core.analysis.java_array_escape import build_local_array_index  # noqa: E402


def source(statement):
    return ('class T {\nstatic class H { int count; }\n'
            'void m(H holder) {\nString[] a={"safe"};\n'
            + statement + '\n} }')


def index(text):
    assert not _get_parser().parse(text.encode()).root_node.has_error
    result = build_local_array_index(text, (1, text.count('\n') + 1))
    assert result is not None and result.ok
    assert result.tracked('a')
    return result


def test_field_increment_cannot_borrow_a_tracked_array_line_exemption():
    text = source('int copy=a[0].length(); holder.count++;')
    cfg = build_java_intraproc_cfg(text, 'm')
    assert cfg is not None
    assert next(node for node in cfg.nodes() if node.label == 'holder.count++;').may_escape is True
    assert index(text).exempt_line(5) is False


@pytest.mark.parametrize('store', [
    'holder.count++;', '++holder.count;', 'holder.count--;', '--holder.count;',
    '(holder.count)++;', '++((holder.count));', 'holder.count=1;',
])
def test_field_store_forms_prevent_array_only_exemption(store):
    assert not index(source('int copy=a[0].length(); ' + store)).exempt_line(5)


@pytest.mark.parametrize('read', ['int copy=a[0].length();', 'int copy=a[0].length()+holder.count;'])
def test_array_only_and_field_read_lines_retain_exemptions(read):
    assert index(source(read)).exempt_line(5)


def test_parenthesized_array_increment_remains_a_compound_write():
    text = 'class T { void m() { int[] a={0}; (a[0])++; } }'
    assert not _get_parser().parse(text.encode()).root_node.has_error
    idx = build_local_array_index(text, (1, 1))
    assert idx is not None and idx.ok
    assert not idx.tracked('a')
