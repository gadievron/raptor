"""Attribution fallback keeps cancellation primary while retiring its reader."""

import errno
import os

import pytest
from core.audit import findings as source
from core import source as readers
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize("body_kind", ["healthy", "cancel", "io", "unexpected"])
@pytest.mark.parametrize("close_kind", ["healthy", "io", "cancel"])
def test_attribution_stream_precedence(tmp_path, body_kind, close_kind):
    path = tmp_path / "owned.py"
    content = b"def owned():\n    return 1\n"
    path.write_bytes(content)
    real_open = readers.open_regular_beneath
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
            assert self.stream.read(size) == content.decode()
            events.append("read")
            if primary is not None:
                raise primary
            return content.decode()

    def observe(*args, **kwargs):
        stream = real_open(*args, **kwargs)
        assert stream is not None
        wrapped = Observed(stream)
        streams.append(wrapped)
        return wrapped

    checklist = {"files": [{"path": path.name, "items": []}]}
    finding = {"file": path.name, "function": "claimed", "line": 2}
    assert readers.open_regular_beneath is real_open
    observed = None
    try:
        try:
            with scoped_function_imports(source, ("_enclosing_from_source",),
                                         {"core.source": readers}) as imports:
                imports.__dict__["core.source"].open_regular_beneath = observe
                source.stamp_function_attribution(finding, checklist, target_path=tmp_path)
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
        assert readers.open_regular_beneath is real_open
        expected = primary if primary is not None else secondary
        if isinstance(expected, Exception):
            assert observed is None
            assert finding["function"] == "claimed"
        elif expected is not None:
            assert observed is expected
            assert finding["function"] == "claimed"
        else:
            assert observed is None
            assert finding["function"] == "owned"
            assert finding["claimed_function"] == "claimed"
    finally:
        for wrapped in streams:
            if not wrapped.stream.closed:
                wrapped.stream.close()
