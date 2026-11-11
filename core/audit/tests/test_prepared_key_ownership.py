"""Memo-key readers retire native streams without swallowing cancellation."""

import errno
import os
import hashlib

import pytest
from core.audit import preprocessor_view as source


@pytest.mark.parametrize("body_kind", ["healthy", "cancel", "io", "unexpected"])
@pytest.mark.parametrize("close_kind", ["healthy", "io", "cancel"])
def test_prepared_key_stream_precedence(tmp_path, monkeypatch, body_kind, close_kind):
    path = tmp_path / "owned.c"
    content = b"int owned(void) { return 1; }\n"
    path.write_bytes(content)
    tool = tmp_path / "owned-tool-marker"
    tool.write_bytes(b"not executable; identity metadata only")
    for name in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
                 "GCC_EXEC_PREFIX", "COMPILER_PATH", "DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES"):
        monkeypatch.delenv(name, raising=False)
    real_open = source.open_regular
    primary = {"healthy": None, "cancel": KeyboardInterrupt("owned read interruption"),
               "io": OSError("owned read failure"),
               "unexpected": TypeError("owned unexpected failure")}[body_kind]
    secondary = {"healthy": None, "io": OSError("owned close aftereffect"),
                 "cancel": KeyboardInterrupt("owned close cancellation")}[close_kind]
    streams, events = [], []

    class Observed:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            events.append("close")
            self.stream.__exit__(*args)
            if secondary is not None:
                raise secondary

        def fileno(self):
            return self.fd

        def read(self, size):
            assert self.stream.read(size) == content
            events.append("read")
            if primary is not None:
                raise primary
            return content

    def observe(*args, **kwargs):
        stream = real_open(*args, **kwargs)
        assert stream is not None
        wrapped = Observed(stream)
        streams.append(wrapped)
        return wrapped

    monkeypatch.setattr(source, "open_regular", observe)
    observed = None
    result = None
    try:
        try:
            result = source._prepared_view_key(tmp_path, path, [str(tool), "-E", "-x", "c"], [], [])
        except BaseException as error:
            observed = error
        assert events == ["read", "close"]
        assert len(streams) == 1
        assert streams[0].stream.closed
        try:
            os.fstat(streams[0].fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("owned descriptor survived retirement")
        assert path.read_bytes() == content
        expected = primary if primary is not None else secondary
        if isinstance(expected, (OSError, ValueError)):
            assert observed is None
            assert result is None
        elif expected is not None:
            assert observed is expected
            assert result is None
        else:
            assert observed is None
            assert result is not None
            assert result[6] == hashlib.sha256(content).digest()
    finally:
        for wrapped in streams:
            if not wrapped.stream.closed:
                wrapped.stream.close()
