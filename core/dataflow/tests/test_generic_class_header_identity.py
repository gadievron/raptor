"""Owned class-header type parameters cannot denote canonical library roots."""
import pytest

from core.dataflow.source_identity import known_python_identity_conflict


SOURCE = 'import html\nclass Holder[html](html.escape("<owned>")):\n    pass\n'


def test_direct_generic_class_base_receiver_is_not_canonical_library():
    namespace = {'__name__': 'owned_generic_class_header'}
    with pytest.raises(AttributeError, match='escape') as failure:
        exec(compile(SOURCE, '<owned-generic-class-header>', 'exec', dont_inherit=True), namespace)
    assert type(failure.value.obj).__name__ == 'TypeVar'
    assert known_python_identity_conflict(SOURCE, 2, ('html.escape',))


@pytest.mark.parametrize('parameters', ['html', '*html', '**html'],
                         ids=['typevar', 'typevartuple', 'paramspec'])
@pytest.mark.parametrize('header', [
    'html.escape("owned")', 'tag=html.escape("owned")',
    '(html.escape("owned"),)[0]', 'tag=[html.escape("owned")]',
], ids=['base', 'keyword', 'nested-base', 'nested-keyword'])
def test_generic_class_header_parameter_blocks_library_root(parameters, header):
    source = 'import html\nclass Holder[' + parameters + '](' + header + '):\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_direct_generic_class_keyword_receiver_is_a_type_parameter():
    source = 'import html\nclass Holder[html](tag=html.escape("owned")):\n    pass\n'
    with pytest.raises(AttributeError, match='escape') as failure:
        exec(compile(source, '<owned-generic-class-keyword>', 'exec', dont_inherit=True), {})
    assert type(failure.value.obj).__name__ == 'TypeVar'
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_class_header_uses_written_import_spelling():
    source = 'import html as escaped\nclass Holder[escaped](escaped.escape("owned")):\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',))


def test_class_decorator_keeps_defining_library_identity():
    source = ('import html\nseen = []\ndef capture(value):\n'
              '    seen.append(value)\n    return lambda cls: cls\n'
              '@capture(html.escape("<owned>"))\nclass Holder[html]:\n    pass\n')
    namespace = {'__name__': 'owned_class_decorator_identity'}
    exec(compile(source, '<owned-class-decorator-identity>', 'exec', dont_inherit=True), namespace)
    assert namespace['seen'] == ['&lt;owned&gt;']
    assert known_python_identity_conflict(source, 6, ('html.escape',)) is None


def test_other_class_parameter_keeps_existing_module_identity():
    source = 'import html\nclass Holder[other](html.escape("owned")):\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


def test_nongeneric_class_header_keeps_existing_module_identity():
    source = 'import html\nclass Holder(html.escape("owned")):\n    pass\n'
    assert known_python_identity_conflict(source, 2, ('html.escape',)) is None


def test_class_body_retains_its_existing_identity_refusal():
    source = 'import html\nclass Holder[other]:\n    value = html.escape("owned")\n'
    assert known_python_identity_conflict(source, 3, ('html.escape',)) == 'class-body library identity is unsupported'


def test_enclosing_generic_function_still_blocks_decorator_receiver():
    source = ('import html\ndef outer[html]():\n'
              '    @capture(html.escape("owned"))\n    class Holder[other]:\n        pass\n')
    assert known_python_identity_conflict(source, 3, ('html.escape',))
