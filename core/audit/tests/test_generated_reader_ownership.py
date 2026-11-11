"""Generated-artifact reader ownership with an inert downstream observer."""

import errno
import os

import pytest
from core.audit import asm_zero_len_loop as source


@pytest.mark.parametrize("body_kind", ["healthy", "cancel", "io", "unexpected"])
@pytest.mark.parametrize("close_kind", ["healthy", "io", "cancel"])
def test_generated_reader_stream_precedence(tmp_path, monkeypatch, body_kind, close_kind):
    path = tmp_path / "owned-artifact.txt"
    content = b"# owned artifact marker\n"
    path.write_bytes(content)
    real_open = source.open_regular
    primary = {"healthy": None, "cancel": KeyboardInterrupt("owned read interruption"),
               "io": OSError("owned read failure"),
               "unexpected": TypeError("owned unexpected read error")}[body_kind]
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
            assert size == source._MAX_ASM_BYTES
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
    checked = []

    def check(text):
        assert len(streams) == 1 and streams[0].stream.closed
        checked.append(text)
        return []

    monkeypatch.setattr(source, "check_zero_length_loop_entry", check)
    checklist = {"files": [{"language": "asm-generated", "path": "owned-source",
                            "perlasm": {"generated_path": str(path)}}]}
    observed = None
    result = None
    try:
        try:
            result = source.scan_inventory_asm(checklist)
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
        if isinstance(expected, OSError):
            assert observed is None and result == [] and checked == []
        elif expected is not None:
            assert observed is expected and result is None and checked == []
        else:
            assert observed is None and result == []
            assert checked == [content.decode()]
    finally:
        for wrapped in streams:
            if not wrapped.stream.closed:
                wrapped.stream.close()


@pytest.mark.parametrize("case", ["none", "other-language", "no-artifact"])
def test_non_artifact_records_do_not_open_or_check(monkeypatch, case):
    def forbidden(*args, **kwargs):
        raise AssertionError("non-artifact reached file/checker seam")

    monkeypatch.setattr(source, "open_regular", forbidden)
    monkeypatch.setattr(source, "check_zero_length_loop_entry", forbidden)
    checklist = None if case == "none" else {"files": [{
        "language": "other" if case == "other-language" else "asm-generated",
        "perlasm": {},
    }]}
    assert source.scan_inventory_asm(checklist) == []
