"""Normalization must preserve complete conditions and logical records."""

import pytest

from core.smt_solver.canonicalise import canonicalise, MAX_CANONICALISE_CHARS


@pytest.mark.parametrize('tail', [' trailing-data', ' != 0', '"unterminated', ' && invalid'])
def test_oversized_conditions_are_refused_instead_of_returning_a_valid_prefix(tail):
    text = 'Value == 0'.ljust(MAX_CANONICALISE_CHARS) + tail
    with pytest.raises(ValueError, match='canonicalisation limit'):
        canonicalise(text)


def test_exact_limit_is_normalized_without_losing_content():
    text = 'Value is zero'.rjust(MAX_CANONICALISE_CHARS)
    assert canonicalise(text) == 'Value == 0'


@pytest.mark.parametrize('phrase', [
    'is greater than or equal to', 'is less than or equal to',
    'is not equal to', 'does not equal', 'does not exceed',
    'is at least', 'is at most', 'is greater than', 'is less than',
    'is equal to', 'is non zero', 'is non null', 'is null', 'is zero',
    'equals', 'exceeds', 'below', 'up to',
])
@pytest.mark.parametrize('separator', ['\n', '\r\n', '\r'])
def test_alias_rewrites_do_not_consume_line_boundaries(phrase, separator):
    tokens = ['Value', *phrase.split(), '1']
    for position in range(1, len(tokens)):
        text = ' '.join(tokens[:position]) + separator + ' '.join(tokens[position:])
        result = canonicalise(text)
        assert result.count(separator) == text.count(separator), (text, result)
        assert canonicalise(result) == result


def test_quotes_remain_exact_while_adjacent_conditions_are_normalized():
    text = 'Value is zero\ncheck("is\nzero", "a  b") equals 1'
    assert canonicalise(text) == 'Value == 0 \ncheck("is\nzero", "a  b") == 1'


def test_oversized_input_is_refused_before_rewrite_work(monkeypatch):
    import importlib
    module = importlib.import_module('core.smt_solver.canonicalise')

    class ForbiddenPattern:
        def sub(self, *args):
            pytest.fail('oversized input reached regex rewriting')

    monkeypatch.setattr(module, '_REWRITES', ((ForbiddenPattern(), ''),))
    with pytest.raises(ValueError, match='canonicalisation limit'):
        canonicalise('x' * (MAX_CANONICALISE_CHARS + 1))
