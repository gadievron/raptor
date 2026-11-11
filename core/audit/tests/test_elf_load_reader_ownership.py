"""Header-reader ownership using a non-executable ordinary fixture file."""
import errno
import os
import struct

import pytest
from core import source as readers
from core.audit import disasm_xcheck as source
from core.testing.module_views import scoped_function_imports


@pytest.mark.parametrize("stage", ["header", "table"])
@pytest.mark.parametrize("body_kind", ["healthy", "cancel", "io", "unexpected"])
@pytest.mark.parametrize("close_kind", ["healthy", "io", "cancel"])
def test_header_reader_stream_precedence(tmp_path, stage, body_kind, close_kind):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 16, 3)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    table = bytearray(56)
    struct.pack_into("<I", table, 0, 1)
    struct.pack_into("<Q", table, 16, 4096)
    content = bytes(header + table)
    path = tmp_path / "owned-header.data"
    path.write_bytes(content)
    real_open = readers.open_regular
    primary = {"healthy": None, "cancel": KeyboardInterrupt("owned read interruption"),
               "io": OSError("owned header read failure"),
               "unexpected": TypeError("owned unexpected read failure")}[body_kind]
    cleanup = {"healthy": None, "io": OSError("owned close aftereffect"),
               "cancel": KeyboardInterrupt("owned close cancellation")}[close_kind]
    streams, events = [], []

    class Observed:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = 0
            self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if cleanup is not None:
                raise cleanup

        def read(self, size):
            data = self.stream.read(size)
            self.reads += 1
            events.append(("read", size))
            assert data == (bytes(header) if self.reads == 1 else bytes(table))
            if self.reads == (1 if stage == "header" else 2) and primary is not None:
                raise primary
            return data

        def seek(self, offset):
            value = self.stream.seek(offset)
            events.append(("seek", offset))
            return value

    def observe(*args, **kwargs):
        stream = real_open(*args, **kwargs)
        assert stream is not None
        wrapped = Observed(stream)
        streams.append(wrapped)
        return wrapped

    observed = None
    result = None
    try:
        try:
            with scoped_function_imports(source, ("_elf_load_info",),
                                         {"core.source": readers}) as imports:
                imports.__dict__["core.source"].open_regular = observe
                result = source._elf_load_info(path)
        except BaseException as error:
            observed = error
        assert events == ([("read", 64)] if stage == "header" and primary is not None
                          else [("read", 64), ("seek", 64), ("read", 56)])
        assert len(streams) == 1
        assert streams[0].closes == 1 and streams[0].stream.closed
        try:
            os.fstat(streams[0].fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("owned descriptor remained live")
        assert readers.open_regular is real_open
        assert path.read_bytes() == content
        expected = primary if primary is not None else cleanup
        if isinstance(expected, OSError):
            assert observed is None and result is None
        elif expected is not None:
            assert observed is expected and result is None
        else:
            assert observed is None and result == (4096, True)
    finally:
        for wrapped in streams:
            if not wrapped.stream.closed:
                wrapped.stream.close()
