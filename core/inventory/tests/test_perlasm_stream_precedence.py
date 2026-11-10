"""Read cancellation must survive a secondary stream-close failure."""

import pytest

from core.inventory import perlasm
from core.testing.module_views import scoped_function_imports


def _reader_case(tmp_path, monkeypatch, kind, primary):
    source = tmp_path / 'generator.pl'
    source.write_text('fixture')
    gen = perlasm.PerlasmGenerator(source, source.name, 'arm-xlate', 'a' * 64)
    (tmp_path / 'arm-xlate.pl').write_text('driver')
    cache = tmp_path / 'cache'
    cache.mkdir()
    (cache / 'owned.S').write_text('cached')
    if kind == 'cache':
        monkeypatch.setattr(perlasm, '_cache_key', lambda *args: 'owned')
    original = perlasm.open_regular_gated
    streams = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            raise OSError('secondary close failure')

        def fileno(self):
            if kind == 'cache' and primary is not None:
                raise primary
            return self.stream.fileno()

        def read(self, size):
            if primary is not None:
                raise primary
            return self.stream.read(size)

    def open_reader(path, **kwargs):
        stream = original(path, **kwargs)
        streams.append(stream)
        return Reader(stream)

    monkeypatch.setattr(perlasm, 'open_regular_gated', open_reader)
    return gen, cache, streams


@pytest.mark.parametrize('kind', ['driver', 'cache'])
@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_cancellation_survives_stream_close_failure(tmp_path, monkeypatch, kind, failure):
    import core.sandbox.context as context

    primary = failure('cancelled')
    gen, cache, streams = _reader_case(tmp_path, monkeypatch, kind, primary)

    def unexpected_tool(*args, **kwargs):
        pytest.fail('cancelled reads must never reach generator execution')

    with scoped_function_imports(
        perlasm, ('generate_asm',), {'core.sandbox.context': context},
    ) as imports:
        getattr(imports, 'core.sandbox.context').run_untrusted = unexpected_tool
        try:
            with pytest.raises(failure) as caught:
                perlasm.generate_asm(gen, 'linux64', tmp_path, cache)
            assert caught.value is primary
        finally:
            assert len(streams) == 1 and streams[0].closed


def test_close_failure_without_primary_is_still_reported(tmp_path, monkeypatch):
    gen, _, streams = _reader_case(tmp_path, monkeypatch, 'driver', None)
    with pytest.raises(OSError, match='secondary close failure'):
        perlasm._resolve_driver_sha(gen, tmp_path)
    assert len(streams) == 1 and streams[0].closed
