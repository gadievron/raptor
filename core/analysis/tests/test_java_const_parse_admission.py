"""Incomplete syntax cannot provide constant-definition or receiver evidence."""

import pytest

pytest.importorskip('tree_sitter_java')

from core.analysis.cfg_builder_java import _get_parser  # noqa: E402
from core.analysis.const_fold_java import JavaConstIndex, REFUSE, fold_expr  # noqa: E402

SOURCE = 'class T {\nvoid m(){\nString value="safe";\n}\n}\n'


def test_error_containing_tree_cannot_supply_a_constant_definition():
    text = SOURCE + 'class Broken { void incomplete( {} }'
    assert _get_parser().parse(text.encode()).root_node.has_error
    idx = JavaConstIndex(text, (1, 5))
    assert idx.ok is False
    assert idx.rhs_at(3, 'value') is None


@pytest.mark.parametrize('text', [
    SOURCE.replace('String value="safe";', 'String value="safe"; ?'),
    SOURCE.replace('String value="safe";', 'String value=;'),
])
def test_selected_method_syntax_errors_refuse_constant_index(text):
    assert _get_parser().parse(text.encode()).root_node.has_error
    assert JavaConstIndex(text, (1, 5)).ok is False


def test_complete_tree_retains_exact_constant_value():
    idx = JavaConstIndex(SOURCE, (1, 5))
    assert idx.ok
    value = idx.rhs_at(3, 'value')
    assert value is not None
    assert fold_expr(value, lambda *args: REFUSE) == 'safe'
