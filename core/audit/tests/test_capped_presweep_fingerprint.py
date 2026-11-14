"""Capped presweep fingerprint parity; no binary oracle or source parsing."""

from types import ModuleType, SimpleNamespace

import pytest

from core.audit import binary_layer0 as source
from core.audit.prep_cache import content_fingerprint
from core.evidence import EvidenceRecord
from core.source import open_regular, read_bytes_capped
import core.source.streams as streams
from core.testing.module_views import scoped_function_imports


def records():
    return [("b", EvidenceRecord(file="owned.c", function="second", kind="function", line_start=4, line_end=5)),
            ("a", EvidenceRecord(file="owned.c", function="first", kind="function", line_start=1, line_end=3))]


def expected(data):
    return content_fingerprint([("record:a", b"function|owned.c|first|1|3"),
                                ("file:owned.c", data), ("record:b", b"function|owned.c|second|4|5")])


@pytest.fixture
def fingerprint(monkeypatch):
    reads, opened, buffers = [], [], []
    state = SimpleNamespace(primary=None, cleanup=None)

    class Observed:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            self.stream.__exit__(*args)
            if state.cleanup is not None:
                raise state.cleanup

        def read(self, size=-1):
            data = self.stream.read(size)
            reads.append((size, len(data)))
            if state.primary is not None:
                raise state.primary
            return data

    def observe_open(*args, **kwargs):
        stream = open_regular(*args, **kwargs)
        if stream is None:
            return None
        opened.append(stream)
        return Observed(stream)

    def observe_buffer(path, cap):
        got = read_bytes_capped(path, cap)
        buffers.append(None if got is None else len(got[0]))
        return got

    provided = ModuleType("core.source")
    provided.open_regular = observe_open
    provided.read_bytes_capped = observe_buffer

    def run(root, cap=16, gated=None):
        monkeypatch.setattr(source, "_MAX_FINGERPRINT_FILE_BYTES", cap)
        with scoped_function_imports(source, ("_presweep_fingerprint",),
                                     {"core.source": provided, "core.source.streams": streams}):
            return source._presweep_fingerprint(records() if gated is None else gated, root)

    return SimpleNamespace(run=run, reads=reads, opened=opened, buffers=buffers, state=state)


@pytest.mark.parametrize("cap,size", [(0, 0), (0, 1), (16, 15), (16, 16), (16, 17),
                                      (262_144, 262_144), (262_144, 262_145), (-1, 0)])
def test_capped_stream_parity_and_bounded_reads(tmp_path, fingerprint, cap, size):
    content = b"x" * size
    (tmp_path / "owned.c").write_bytes(content)
    marker = b"<unreadable>" if cap < 0 else b"<over-cap>" if size > cap else content
    assert fingerprint.run(tmp_path, cap) == expected(marker)
    assert fingerprint.buffers == []
    assert all(0 < request <= 65_536 and returned <= request for request, returned in fingerprint.reads)
    assert sum(returned for _, returned in fingerprint.reads) <= max(0, cap + 1)
    assert len(fingerprint.opened) == (0 if cap < 0 else 1)
    assert all(stream.closed for stream in fingerprint.opened)


@pytest.mark.parametrize("kind", ["missing", "link", "directory"])
def test_unreadable_markers_are_preserved(tmp_path, fingerprint, kind):
    path = tmp_path / "owned.c"
    if kind == "link":
        target = tmp_path / "target.c"
        target.write_bytes(b"owned")
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    assert fingerprint.run(tmp_path) == expected(b"<unreadable>")
    assert fingerprint.reads == []


def test_record_spans_keys_and_order_remain_bound(tmp_path, fingerprint):
    (tmp_path / "owned.c").write_bytes(b"owned")
    gated = records()
    original = fingerprint.run(tmp_path, gated=gated)
    assert original == expected(b"owned")
    assert fingerprint.run(tmp_path, gated=list(reversed(gated))) == original
    gated[0][1].line_end = 6
    assert fingerprint.run(tmp_path, gated=gated) != original


@pytest.mark.parametrize("primary,cleanup", [
    (OSError("owned read"), KeyboardInterrupt("owned close")),
    (ValueError("owned read"), KeyboardInterrupt("owned close")),
    (KeyboardInterrupt("owned read"), OSError("owned close")),
    (TypeError("owned read"), OSError("owned close")),
    (None, OSError("owned close")),
    (None, KeyboardInterrupt("owned close")),
])
def test_read_and_close_precedence(tmp_path, fingerprint, primary, cleanup):
    (tmp_path / "owned.c").write_bytes(b"owned")
    fingerprint.state.primary, fingerprint.state.cleanup = primary, cleanup
    error = primary if primary is not None else cleanup
    if isinstance(error, (OSError, ValueError)):
        assert fingerprint.run(tmp_path) == expected(b"<unreadable>")
    else:
        with pytest.raises(type(error)) as caught:
            fingerprint.run(tmp_path)
        assert caught.value is error
    assert fingerprint.opened and all(stream.closed for stream in fingerprint.opened)
