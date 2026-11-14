"""Detector input fingerprints with owned files and inert candidates."""

from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from core.audit import detector_cache as source
from core.audit.prep_cache import content_fingerprint
from core.source import open_regular
from core.testing.module_views import scoped_function_imports


@pytest.fixture
def fingerprint(monkeypatch):
    reads, opened = [], []
    state = SimpleNamespace(primary=None, cleanup=None)

    class ObservedPath(type(Path())):
        def read_bytes(self):
            data = super().read_bytes()
            reads.append((-1, len(data)))
            return data

    class Stream:
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

    def observe(*args, **kwargs):
        stream = open_regular(*args, **kwargs)
        if stream is None:
            return None
        opened.append(stream)
        return Stream(stream)

    monkeypatch.setattr(source, "open_regular", observe, raising=False)
    supplied = ModuleType("core.inventory.call_graph")

    def compute(root, candidates, cap=2_000_000):
        supplied.CALL_GRAPH_MAX_FILE_BYTES = cap
        supplied.iter_call_graph_candidates = lambda target, checklist: iter(candidates)
        with scoped_function_imports(source, ("call_graph_inputs_fingerprint",),
                                     {"core.inventory.call_graph": supplied}):
            return source.call_graph_inputs_fingerprint(root, None)

    return SimpleNamespace(compute=compute, reads=reads, opened=opened, state=state, path=ObservedPath)


@pytest.mark.parametrize("size", [0, 1, 65_536, 65_537, 262_144])
def test_detector_fingerprint_chunks_preserve_regular_file_keys(tmp_path, fingerprint, size):
    path = fingerprint.path(tmp_path / "owned.c")
    content = b"x" * size
    path.write_bytes(content)
    assert fingerprint.compute(tmp_path, [(path.name, path, "c")]) == content_fingerprint([("owned.c\0c", content)])
    assert fingerprint.reads and all(n == 65_536 and size <= 65_536 for n, size in fingerprint.reads)
    assert sum(size for _, size in fingerprint.reads) == len(content)
    assert all(stream.closed for stream in fingerprint.opened)


@pytest.mark.parametrize("kind", ["oversize", "missing", "link"])
def test_existing_markers_cover_oversize_and_refused_inputs(tmp_path, fingerprint, kind):
    path = tmp_path / "owned.c"
    if kind == "oversize":
        path.write_bytes(b"x" * 17)
        marker = b"<oversized>"
    elif kind == "link":
        target = tmp_path / "target.c"
        target.write_bytes(b"owned")
        path.symlink_to(target)
        marker = b"<unreadable>"
    else:
        marker = b"<unreadable>"
    assert fingerprint.compute(tmp_path, [(path.name, path, "c")], cap=16) == content_fingerprint([("owned.c\0c", marker)])
    assert fingerprint.reads == []


def test_order_and_declared_language_remain_key_inputs(tmp_path, fingerprint):
    first, second = tmp_path / "first.c", tmp_path / "second.c"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    candidates = [(first.name, first, "c"), (second.name, second, "cpp")]
    expected = content_fingerprint([("first.c\0c", b"first"), ("second.c\0cpp", b"second")])
    actual = fingerprint.compute(tmp_path, candidates)
    assert actual == expected
    assert fingerprint.compute(tmp_path, list(reversed(candidates))) != actual
    assert fingerprint.compute(tmp_path, [(first.name, first, "cpp"), candidates[1]]) != actual


@pytest.mark.parametrize("primary,cleanup", [
    (OSError("owned read"), KeyboardInterrupt("owned close")),
    (KeyboardInterrupt("owned read"), OSError("owned close")),
    (TypeError("owned read"), OSError("owned close")),
    (None, OSError("owned close")),
    (None, KeyboardInterrupt("owned close")),
])
def test_stream_failure_precedence_and_closure(tmp_path, fingerprint, primary, cleanup):
    path = tmp_path / "owned.c"
    path.write_bytes(b"owned")
    fingerprint.state.primary, fingerprint.state.cleanup = primary, cleanup
    expected = primary if primary is not None else cleanup
    candidates = [(path.name, path, "c")]
    if isinstance(expected, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt) as caught:
            fingerprint.compute(tmp_path, candidates)
        assert caught.value is expected
    elif isinstance(expected, OSError):
        assert fingerprint.compute(tmp_path, candidates) == content_fingerprint([("owned.c\0c", b"<unreadable>")])
    else:
        assert fingerprint.compute(tmp_path, candidates) is None
    assert fingerprint.opened and all(stream.closed for stream in fingerprint.opened)
