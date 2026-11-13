"""Incomplete Java parse trees cannot establish a complete array write ledger."""

import pytest

pytest.importorskip('tree_sitter_java')

from core.analysis.cfg_builder_java import _get_parser  # noqa: E402
from core.analysis.java_array_escape import build_local_array_index  # noqa: E402


PREFIX = ('import org.owasp.encoder.Encode;\nclass T {\nvoid m(String raw) {\n'
          'String[] a=new String[1];\na[0]=Encode.forHtml(raw);\n')


def test_error_containing_tree_cannot_certify_an_incomplete_array_write_ledger():
    text = PREFIX + '(a[0])=raw;\n} }'
    assert _get_parser().parse(text.encode()).root_node.has_error
    idx = build_local_array_index(text, (1, 7))
    assert idx is None or not idx.ok or not idx.tracked('a')


@pytest.mark.parametrize('text', [
    PREFIX + 'a[0]=;\n} }',
    PREFIX + '} }\nclass Broken { void broken( {} }',
])
def test_syntax_errors_cannot_grant_array_tracking(text):
    assert _get_parser().parse(text.encode()).root_node.has_error
    idx = build_local_array_index(text, (1, 7))
    assert idx is None or not idx.ok or not idx.tracked('a')


def test_complete_tree_tracks_and_records_the_raw_write():
    text = PREFIX + 'a[0]=raw;\n} }'
    assert not _get_parser().parse(text.encode()).root_node.has_error
    idx = build_local_array_index(text, (1, 7))
    assert idx is not None and idx.ok and idx.tracked('a')
    writes = idx.element_writes('a', 0)
    assert len(writes) == 2
    assert not all(idx.write_is_catalog_call(write, {'org.owasp.encoder.Encode.forHtml'}) for write in writes)


def test_complete_sanitizer_only_tree_keeps_tracking():
    text = PREFIX + '} }'
    idx = build_local_array_index(text, (1, 6))
    assert idx is not None and idx.ok and idx.tracked('a')
    assert all(idx.write_is_catalog_call(write, {'org.owasp.encoder.Encode.forHtml'})
               for write in idx.element_writes('a', 0))
