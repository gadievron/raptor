"""Exception-message formatting is bounded, recoverable, and cancellation-aware."""
import pytest

from core.security import log_sanitisation as logs


@pytest.mark.parametrize('text', [
    pytest.param('ordinary failure', id='plain'),
    pytest.param('\n\x1b[2J\u202e\udc80', id='controls'),
    pytest.param('x' * 5000, id='long'),
])
@pytest.mark.parametrize('max_len', [256, 8], ids=['default-bound', 'small-bound'])
def test_ordinary_exception_messages_keep_existing_escaping(text, max_len):
    assert logs.sanitise_exception_message(ValueError(text), max_len=max_len) == logs.sanitise_for_terminal(text, max_len=max_len)


@pytest.mark.parametrize('kind', ['runtime', 'value', 'type', 'nonstring'])
@pytest.mark.parametrize('max_len', [256, 8], ids=['default-bound', 'small-bound'])
def test_broken_string_conversion_uses_a_bounded_literal(kind, max_len):
    calls = []
    class Broken(RuntimeError):
        def __str__(self):
            calls.append(True)
            if kind == 'nonstring':
                return None
            raise {'runtime': RuntimeError, 'value': ValueError, 'type': TypeError}[kind]('format failed')

        def __repr__(self):
            raise AssertionError('repr must not be attempted')
    text = logs.sanitise_exception_message(Broken(), max_len=max_len)
    assert text == logs.sanitise_for_terminal('exception message unavailable', max_len=max_len)
    assert text.isprintable() and len(text) < max_len + 40
    assert calls == [True]


@pytest.mark.parametrize('problem', [KeyboardInterrupt('cancel'), SystemExit(17)], ids=['interrupt', 'exit'])
def test_cancellation_during_string_conversion_propagates_unchanged(problem):
    class Interrupted(RuntimeError):
        def __str__(self):
            raise problem
    with pytest.raises(type(problem)) as caught:
        logs.sanitise_exception_message(Interrupted())
    assert caught.value is problem
