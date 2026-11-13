"""Collection tracking requires a complete Java parse and namespace frame."""

import pytest

pytest.importorskip('tree_sitter_java')

from core.analysis.cfg_builder_java import _get_parser  # noqa: E402
from core.analysis.java_collection_index import build_local_collection_index  # noqa: E402

SOURCE = ('import java.util.ArrayList;\nclass T {\nvoid m(){\n'
          'ArrayList<String> items=new ArrayList<>();\nitems.add("safe");\n} }\n')


def test_error_containing_tree_cannot_certify_collection_tracking():
    text = SOURCE + 'class Broken { void incomplete( {} }'
    assert _get_parser().parse(text.encode()).root_node.has_error
    idx = build_local_collection_index(text, (3, 6))
    assert idx is None or not idx.ok or not idx.tracked('items')


def test_error_in_selected_method_cannot_certify_collection_tracking():
    text = SOURCE.replace('items.add("safe");', 'items.add("safe"); ?')
    assert _get_parser().parse(text.encode()).root_node.has_error
    idx = build_local_collection_index(text, (3, 6))
    assert idx is None or not idx.ok or not idx.tracked('items')


def test_complete_source_keeps_local_collection_tracking():
    assert not _get_parser().parse(SOURCE.encode()).root_node.has_error
    idx = build_local_collection_index(SOURCE, (3, 6))
    assert idx is not None and idx.ok and idx.tracked('items')
