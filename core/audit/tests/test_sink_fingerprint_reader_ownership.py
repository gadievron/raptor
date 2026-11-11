"""Direct file-fingerprint lifetime with an inert local iterator seam."""
import errno
import os

import pytest
from types import ModuleType
from core.audit import codeql_backend as source
from core.audit.prep_cache import content_fingerprint
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize("body_kind", ["healthy", "cancel", "io", "unexpected"])
@pytest.mark.parametrize("close_kind", ["healthy", "io", "cancel"])
def test_sink_fingerprint_reader_precedence(tmp_path, monkeypatch, body_kind, close_kind):
    path = tmp_path / "owned.c"
    content = b"int owned;\n"
    path.write_bytes(content)
    primary = {"healthy": None, "cancel": KeyboardInterrupt("owned source read interruption"),
               "io": OSError("owned source read failure"),
               "unexpected": TypeError("owned unexpected read error")}[body_kind]
    cleanup = {"healthy": None, "io": OSError("owned close aftereffect"),
               "cancel": KeyboardInterrupt("owned close cancellation")}[close_kind]
    streams, calls = [], []
    real_open = source.open_regular

    class Observed:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if cleanup is not None:
                raise cleanup

        def read(self):
            self.reads += 1
            assert self.stream.read() == content
            if primary is not None:
                raise primary
            return content

    def observe(*args, **kwargs):
        stream = real_open(*args, **kwargs)
        assert stream is not None
        wrapped = Observed(stream)
        streams.append(wrapped)
        return wrapped

    def files(root, *, scope_dirs):
        calls.append((root, scope_dirs))
        return iter(((path, path.name, "c"),))

    provided = ModuleType("core.inventory.sink_discovery")
    provided.iter_discovery_source_files = files
    monkeypatch.setattr(source, "open_regular", observe)
    original = source._sink_discovery_fingerprint
    observed = None
    result = None
    try:
        try:
            with scoped_function_imports(source, ("_sink_discovery_fingerprint",),
                                         {"core.inventory.sink_discovery": provided}):
                result = source._sink_discovery_fingerprint(tmp_path, None)
        except BaseException as error:
            observed = error
        assert source._sink_discovery_fingerprint is original
        assert calls == [(tmp_path, None)]
        assert len(streams) == 1 and streams[0].reads == 1
        assert streams[0].closes == 1 and streams[0].stream.closed
        try:
            os.fstat(streams[0].fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("owned descriptor remained live")
        assert path.read_bytes() == content
        expected = primary if primary is not None else cleanup
        if isinstance(expected, Exception):
            assert observed is None and result is None
        elif expected is not None:
            assert observed is expected and result is None
        else:
            assert observed is None
            assert result == content_fingerprint([(path.name, content)])
    finally:
        for wrapped in streams:
            if not wrapped.stream.closed:
                wrapped.stream.close()
