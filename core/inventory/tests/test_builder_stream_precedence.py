"""Builder read failures retain precedence while both native owners retire."""

import errno
import os

import pytest

from core.inventory import builder
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit, RuntimeError, None])
def test_read_failure_survives_borrowed_stream_close(tmp_path, monkeypatch, failure):
    source = tmp_path / 'owned.py'
    source.write_text('def entry():\n    return 1\n')
    primary = failure('primary read failure') if failure else None
    original_fdopen = os.fdopen
    streams, identities = [], []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            raise OSError('secondary stream close failure')

        def read(self, size):
            if primary is not None:
                raise primary
            return self.stream.read(size)

    def adopt(fd, mode, **kwargs):
        assert mode == 'rb' and kwargs['closefd'] is False
        stream = original_fdopen(fd, mode, **kwargs)
        info = os.fstat(fd)
        identities.append((fd, info.st_dev, info.st_ino))
        streams.append(stream)
        return Reader(stream)

    patch_module_attribute(monkeypatch, builder, 'os', 'fdopen', adopt)
    try:
        if failure in (KeyboardInterrupt, SystemExit):
            with pytest.raises(failure) as caught:
                builder._process_single_file(source, tmp_path, [])
            assert caught.value is primary
        else:
            result = builder._process_single_file(source, tmp_path, [])
            assert result['_excluded'] and result['_reason'] == 'processing_error'
            assert result['_pattern'] == ('RuntimeError' if failure else 'OSError')
        assert len(streams) == 1 and streams[0].closed
        assert len(identities) == 1
        fd, device, inode = identities[0]
        try:
            info = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            assert (info.st_dev, info.st_ino) != (device, inode)
    finally:
        for stream in streams:
            stream.close()
        # Reclaim only the same native descriptor if a regression leaked it.
        for fd, device, inode in identities:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (device, inode):
                os.close(fd)
