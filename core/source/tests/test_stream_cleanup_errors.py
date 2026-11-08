"""IO teardown cannot turn cancellation or a refusal into missing input."""
import os

import pytest

from core.source import contained, gated
from core.source.streams import preserving_stream_error
from core.testing.module_bindings import patch_module_attribute
from core.testing.stream_faults import FaultingStream

PRIMARY = [OSError, ValueError, RuntimeError, KeyboardInterrupt, SystemExit]
CLEANUP = [OSError, RuntimeError, KeyboardInterrupt, SystemExit]
READERS = ['strict-bytes', 'strict-text', 'capped-bytes', 'capped-text', 'contained-bytes', 'contained-text']


@pytest.mark.parametrize('primary_type', PRIMARY)
@pytest.mark.parametrize('cleanup_type', CLEANUP)
def test_original_exception_identity_survives_failed_teardown(tmp_path, primary_type, cleanup_type):
    primary = primary_type('primary')
    cleanup = cleanup_type('cleanup')
    stream = FaultingStream((tmp_path / 'data').open('wb'), cleanup=cleanup)
    with pytest.raises(primary_type) as caught:
        with preserving_stream_error(stream) as value:
            assert value is stream
            raise primary
    assert caught.value is primary
    assert len(stream.exits) == 1
    assert stream.exits[0][0] is primary_type
    assert stream.exits[0][1] is primary
    assert stream.closed
    assert any(cleanup_type.__name__ in note for note in primary.__notes__)


@pytest.mark.parametrize('cleanup_type', CLEANUP)
def test_successful_body_still_requires_successful_close(tmp_path, cleanup_type):
    failure = cleanup_type('close failed')
    stream = FaultingStream((tmp_path / 'data').open('wb'), cleanup=failure)
    with pytest.raises(cleanup_type) as caught:
        with preserving_stream_error(stream) as writer:
            writer.write(b'payload')
    assert caught.value is failure
    assert stream.exits == [(None, None, None)]
    assert stream.closed


def test_normal_return_value_is_preserved_and_teardown_runs_once(tmp_path):
    stream = FaultingStream((tmp_path / 'data').open('wb'))
    with preserving_stream_error(stream) as writer:
        assert writer is stream
        writer.write(b'payload')
    assert stream.closed
    assert stream.exits == [(None, None, None)]
    assert (tmp_path / 'data').read_bytes() == b'payload'


def test_truthy_stream_exit_cannot_suppress_a_body_failure(tmp_path):
    class Stream(FaultingStream):
        def __exit__(self, *details):
            super().__exit__(*details)
            return True
    stream = Stream((tmp_path / 'data').open('wb'))
    error = KeyboardInterrupt('primary')
    with pytest.raises(KeyboardInterrupt) as caught:
        with preserving_stream_error(stream):
            raise error
    assert caught.value is error
    assert stream.closed


def test_failed_diagnostic_attachment_cannot_mask_primary(tmp_path):
    class PrimaryError(Exception):
        def add_note(self, note):
            raise RuntimeError('cannot attach diagnostic')
    error = PrimaryError('primary')
    stream = FaultingStream((tmp_path / 'data').open('wb'), cleanup=OSError('close failed'))
    with pytest.raises(PrimaryError) as caught:
        with preserving_stream_error(stream):
            raise error
    assert caught.value is error
    assert stream.closed


def install_reader(monkeypatch, root, kind, primary, cleanup):
    path = root / 'data'
    path.write_bytes(b'payload')
    observed = []
    def wrap(stream):
        result = FaultingStream(stream, primary=primary, cleanup=cleanup)
        observed.append(result)
        return result
    if kind.startswith('strict'):
        original = gated._open_gated
        def opened(*args, **kwargs):
            stream, info = original(*args, **kwargs)
            return wrap(stream), info
        monkeypatch.setattr(gated, '_open_gated', opened)
    else:
        name = 'open_regular_beneath' if kind.startswith('contained') else 'open_regular'
        original = getattr(contained, name)
        def opened(*args, **kwargs):
            stream = original(*args, **kwargs)
            assert stream is not None
            return wrap(stream)
        monkeypatch.setattr(contained, name, opened)
    def read(cap=1024):
        if kind == 'strict-bytes':
            return gated.read_bytes_gated(path, cap)
        if kind == 'strict-text':
            return gated.read_text_gated(path, cap)
        if kind == 'capped-bytes':
            return contained.read_bytes_capped(path, cap)
        if kind == 'capped-text':
            return contained.read_text_capped(path, cap)
        if kind == 'contained-bytes':
            return contained.read_contained_bytes(root, 'data', max_bytes=cap)
        return contained.read_contained(root, 'data', max_chars=cap)
    return read, observed


@pytest.mark.parametrize('kind', READERS)
@pytest.mark.parametrize('primary_type', [ValueError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, RuntimeError, KeyboardInterrupt])
def test_public_readers_do_not_lose_refusals_or_cancellation(tmp_path, monkeypatch, kind, primary_type, cleanup_type):
    primary = primary_type('primary read failure')
    read, observed = install_reader(monkeypatch, tmp_path, kind, primary, cleanup_type('close failed'))
    with pytest.raises(primary_type) as caught:
        read()
    assert caught.value is primary
    assert len(observed) == 1
    assert observed[0].closed
    assert len(observed[0].exits) == 1


@pytest.mark.parametrize('kind', READERS)
@pytest.mark.parametrize('cleanup_type', CLEANUP)
def test_reader_close_only_errors_keep_each_readers_contract(tmp_path, monkeypatch, kind, cleanup_type):
    error = cleanup_type('close failed')
    read, observed = install_reader(monkeypatch, tmp_path, kind, None, error)
    if not kind.startswith('strict') and cleanup_type is OSError:
        assert read() is None
    else:
        with pytest.raises(cleanup_type) as caught:
            read()
        assert caught.value is error
    assert observed[0].closed
    assert len(observed[0].exits) == 1


@pytest.mark.parametrize('kind', READERS)
def test_read_io_error_keeps_tolerant_contract_even_if_close_is_cancelled(tmp_path, monkeypatch, kind):
    primary = OSError('read failed')
    read, observed = install_reader(monkeypatch, tmp_path, kind, primary, KeyboardInterrupt('close interrupted'))
    if kind.startswith('strict'):
        with pytest.raises(OSError) as caught:
            read()
        assert caught.value is primary
    else:
        assert read() is None
    assert observed[0].closed


@pytest.mark.parametrize('kind', ['strict-bytes', 'strict-text'])
@pytest.mark.parametrize('cleanup_type', CLEANUP)
def test_budget_refusal_is_not_replaced_by_close_error(tmp_path, monkeypatch, kind, cleanup_type):
    read, observed = install_reader(monkeypatch, tmp_path, kind, None, cleanup_type('close failed'))
    with pytest.raises(gated.ReadBudgetExceededError):
        read(cap=1)
    assert observed[0].closed


@pytest.mark.parametrize('phase', ['stat', 'adopt'])
@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_failed_gated_open_preserves_primary_and_releases_fd(tmp_path, monkeypatch, phase, primary_type, cleanup_type):
    path = tmp_path / 'data'
    path.write_bytes(b'payload')
    primary = primary_type('setup failed')
    closed = []
    original_close = os.close
    def failed(*args, **kwargs):
        raise primary
    def close(fd):
        original_close(fd)
        closed.append(fd)
        raise cleanup_type('close failed')
    patch_module_attribute(monkeypatch, gated, 'os', 'fstat' if phase == 'stat' else 'fdopen', failed)
    patch_module_attribute(monkeypatch, gated, 'os', 'close', close)
    with pytest.raises(primary_type) as caught:
        gated.open_regular_gated(path)
    assert caught.value is primary
    assert len(closed) == 1
    with pytest.raises(OSError):
        os.fstat(closed[0])


def test_instance_special_method_shadows_do_not_change_context_protocol(tmp_path, monkeypatch):
    stream = FaultingStream((tmp_path / 'data').open('wb'))
    def shadow(*args):
        raise AssertionError('instance shadow must not run')
    monkeypatch.setattr(stream, '__enter__', shadow)
    monkeypatch.setattr(stream, '__exit__', shadow)
    with preserving_stream_error(stream) as writer:
        writer.write(b'payload')
    assert stream.closed
    assert stream.exits == [(None, None, None)]


def test_failed_entry_does_not_invoke_exit_or_reenter_a_closed_stream(tmp_path):
    stream = FaultingStream((tmp_path / 'data').open('wb'))
    stream.stream.close()
    with pytest.raises(ValueError):
        with preserving_stream_error(stream):
            pytest.fail('closed stream entered')
    assert stream.closed
    assert stream.exits == []


@pytest.mark.parametrize('binding', ['static', 'class', 'callable'])
def test_special_method_binding_matches_a_native_with_statement(tmp_path, binding):
    for wrapped in (False, True):
        stream = (tmp_path / f'{binding}-{wrapped}').open('wb')
        try:
            exits = []
            def enter():
                return stream.__enter__()
            def leave(*details):
                exits.append(details)
                return stream.__exit__(*details)
            if binding == 'static':
                class Context:
                    __enter__ = staticmethod(enter)
                    __exit__ = staticmethod(leave)
            elif binding == 'class':
                class Context:
                    __enter__ = classmethod(lambda cls: enter())
                    __exit__ = classmethod(lambda cls, *details: leave(*details))
            else:
                class Callback:
                    def __init__(self, function):
                        self.function = function
                    def __call__(self, *args):
                        return self.function(*args)
                class Context:
                    __enter__ = Callback(enter)
                    __exit__ = Callback(leave)
            context = Context()
            with preserving_stream_error(context) if wrapped else context as value:
                assert value is stream
                value.write(b'payload')
            assert stream.closed
            assert exits == [(None, None, None)]
        finally:
            if not stream.closed:
                stream.close()
