"""Complete one-line declarations must not borrow the next declaration."""

import pytest

from core.audit import context


@pytest.mark.parametrize('declaration', [
    'typedef unsigned long Token_t;',
    'struct Token_t { int field; };',
    'enum Token_t { TOKEN = 1 };',
    'struct Token_t { const char *text; /* } */ };',
    'struct Token_t { const char *text = "}"; };',
    'typedef const char *Token_t; // }',
])
def test_complete_declaration_stops_on_its_own_line(declaration):
    result = context._extract_type_definition_uncached(
        declaration + '\nvoid unrelated(void) { ignored(); }\n', 'Token_t',
    )
    assert result == {'line': 1, 'source': declaration}


def test_ambiguous_first_line_does_not_shorten_the_legacy_window():
    first = 'struct Token_t { const char *text = "};'
    second = 'int next_field;'
    result = context._extract_type_definition_uncached(first + '\n' + second + '\n', 'Token_t')
    assert result['source'] == first + '\n' + second


@pytest.mark.parametrize('length', [799, 800, 801, 10000])
def test_large_multiline_declaration_preserves_truncation(length):
    source = 'struct Token_t {\n' + 'x' * length + '\n};'
    expected = source if len(source) <= 800 else source[:800] + '\n  /* ... truncated */'
    assert context._extract_type_definition_uncached(source, 'Token_t') == {'line': 1, 'source': expected}


def test_optional_lexical_proof_failure_preserves_the_legacy_window(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError('unavailable optional proof')

    monkeypatch.setattr(context, 'sanitized_view_with_status', fail)
    source = 'struct Token_t { const char *text = "}"; };\nint next_declaration;'
    assert context._extract_type_definition_uncached(source, 'Token_t') == {
        'line': 1, 'source': source,
    }
