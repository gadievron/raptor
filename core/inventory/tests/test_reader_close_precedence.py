"""Inventory read cancellation survives secondary stream cleanup failures."""

from pathlib import Path

import pytest

from core.inventory import exclusions, header_api
from core.source import contained
from core.testing.module_views import scoped_function_imports


def _read_case(tmp_path, monkeypatch, reader, primary):
    source = tmp_path / 'owned.h'
    source.write_text('int public_function(void);\n')
    module = header_api if reader == 'header' else exclusions
    streams = []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            raise OSError('secondary close failure')

        def read(self, *args):
            if primary is not None:
                raise primary
            return self.stream.read(*args)

        def seek(self, *args):
            return self.stream.seek(*args)

        def tell(self):
            return self.stream.tell()

    class OwnedPath(type(Path())):
        def open(self, *args, **kwargs):
            stream = super().open(*args, **kwargs)
            assert self == source
            streams.append(stream)
            return Reader(stream)

    # Only these consumers see the replacement class; pathlib stays native.
    monkeypatch.setattr(module, 'Path', OwnedPath)

    def consume():
        if reader == 'header':
            return module.scan_public_api(str(tmp_path))
        def open_binary(path, mode, **kwargs):
            stream = contained.open_regular(path, mode, **kwargs)
            assert path == source and stream is not None
            streams.append(stream)
            return Reader(stream)

        with scoped_function_imports(
            module, ["is_binary_file"], {"core.source.contained": contained},
        ) as imports:
            monkeypatch.setattr(getattr(imports, "core.source.contained"), "open_regular", open_binary)
            return module.is_binary_file(source)

    return consume, streams


@pytest.mark.parametrize('reader', ['header', 'binary'])
@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_read_cancellation_survives_close_failure(tmp_path, monkeypatch, reader, failure):
    primary = failure('cancelled read')
    consume, streams = _read_case(tmp_path, monkeypatch, reader, primary)
    try:
        with pytest.raises(failure) as caught:
            consume()
        assert caught.value is primary
    finally:
        assert len(streams) == 1 and streams[0].closed


@pytest.mark.parametrize('reader', ['header', 'binary'])
@pytest.mark.parametrize('read_fails', [False, True])
def test_ordinary_io_failure_keeps_existing_refusal(tmp_path, monkeypatch, reader, read_fails):
    primary = OSError('read unavailable') if read_fails else None
    consume, streams = _read_case(tmp_path, monkeypatch, reader, primary)
    assert consume() == (frozenset() if reader == 'header' else True)
    assert len(streams) == 1 and streams[0].closed
