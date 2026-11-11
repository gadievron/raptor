"""Hydration reader cancellation and native stream retirement."""
import errno
import os
import pytest
from core.audit import gaps


@pytest.mark.parametrize("stage", ["probe", "text"])
@pytest.mark.parametrize("body_kind", ["healthy", "cancel", "io", "unexpected"])
@pytest.mark.parametrize("close_kind", ["healthy", "io", "cancel"])
def test_hydration_stream_precedence(tmp_path, monkeypatch, stage, body_kind, close_kind):
    path = tmp_path / "owned.py"
    content = b"def owned():\n    return 1\n"
    path.write_bytes(content)
    real_open = gaps.open_regular
    primary = {"healthy": None, "cancel": KeyboardInterrupt("owned hydration interruption"),
               "io": OSError("owned hydration read failure"),
               "unexpected": TypeError("owned hydration unexpected error")}[body_kind]
    cleanup = {"healthy": None, "io": OSError("owned hydration close aftereffect"),
               "cancel": KeyboardInterrupt("owned close cancellation")}[close_kind]
    streams, events = [], []

    class Observed:
        def __init__(self, stream, mode):
            self.stream, self.mode = stream, mode
            self.fd = stream.fileno()
            self.selected = (mode == "rb") == (stage == "probe")
            self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if self.selected and cleanup is not None:
                raise cleanup

        def read(self, size):
            value = self.stream.read(size)
            assert value == content
            events.append((self.mode, "read"))
            if self.selected and primary is not None:
                raise primary
            return value

        def __iter__(self):
            return self

        def __next__(self):
            value = next(self.stream)
            events.append((self.mode, "line"))
            if self.selected and primary is not None:
                raise primary
            return value

    def observe(*args, **kwargs):
        stream = real_open(*args, **kwargs)
        assert stream is not None
        wrapped = Observed(stream, args[1])
        streams.append(wrapped)
        return wrapped

    monkeypatch.setattr(gaps, "open_regular", observe)
    observed = None
    result = None
    try:
        try:
            result = gaps.read_gap_source({"file": path.name, "line_start": 1, "line_end": 2}, tmp_path)
        except BaseException as error:
            observed = error
        failed = primary is not None or cleanup is not None
        assert len(streams) == (1 if stage == "probe" and failed else 2)
        assert events[0] == ("rb", "read")
        if stage == "text":
            assert ("r", "line") in events
        if stage == "probe" and failed:
            assert events == [("rb", "read")]
        for wrapped in streams:
            assert wrapped.closes == 1 and wrapped.stream.closed
            with pytest.raises(OSError) as retired:
                os.fstat(wrapped.fd)
            assert retired.value.errno == errno.EBADF
        assert path.read_bytes() == content
        expected = primary if primary is not None else cleanup
        if isinstance(expected, OSError):
            assert observed is None and result == ""
        elif expected is not None:
            assert observed is expected and result is None
        else:
            assert observed is None and result == content.decode()
    finally:
        for wrapped in streams:
            if not wrapped.stream.closed:
                wrapped.stream.close()
