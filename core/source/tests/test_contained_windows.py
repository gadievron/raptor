"""Optional rooted byte windows retain the streaming reader contracts."""

import io
from pathlib import Path

import pytest

from core.source import windows
from core.source.lines import split_lines


def test_rooted_fixture_admission_and_refusal(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    source = root / "source.c"
    raw = b"a\r\nb\rc\n\xff\n"
    source.write_bytes(raw)
    outside = tmp_path / "outside.c"
    outside.write_bytes(b"benign outside fixture")
    for root_arg in (root, str(root)):
        assert windows.read_bytes_prefix_capped(
            source, 4, max_bytes=len(raw), target_root=root_arg,
        ) == (raw[:4], False)
        assert windows.read_line_window_capped(
            source, 1, 3, max_bytes=len(raw), target_root=root_arg,
        ) == (split_lines(raw.decode("utf-8", errors="replace"))[1:3], False)
        assert windows.read_bytes_prefix_capped(
            outside, 1, max_bytes=100, target_root=root_arg,
        ) is None
        assert windows.read_line_window_capped(
            outside, 0, 1, max_bytes=100, target_root=root_arg,
        ) is None
        assert windows.read_line_window_capped(
            root, 0, 1, max_bytes=100, target_root=root_arg,
        ) is None


def test_rooted_dispatch_never_falls_back(monkeypatch):
    calls = []
    streams = []

    def rooted(root, path, mode):
        calls.append((root, path, mode))
        stream = io.BytesIO(b"a\nb\n")
        streams.append(stream)
        return stream

    def unexpected(*args, **kwargs):
        pytest.fail("rooted reader used the by-name opener")

    monkeypatch.setattr(windows, "_open_contained", rooted)
    monkeypatch.setattr(windows, "open_regular", unexpected)
    path, root = Path("file.c"), Path("root")
    assert windows.read_bytes_prefix_capped(path, 1, max_bytes=4, target_root=root) == (b"a", False)
    assert windows.read_line_window_capped(path, 0, 1, max_bytes=4, target_root=root) == (["a"], False)
    assert calls == [(root, path, "rb"), (root, path, "rb")]
    assert all(stream.closed for stream in streams)
    monkeypatch.setattr(windows, "_open_contained", lambda *args: None)
    assert windows.read_bytes_prefix_capped(path, 1, max_bytes=4, target_root=root) is None
    assert windows.read_line_window_capped(path, 0, 1, max_bytes=4, target_root=root) is None


def test_default_dispatch_remains_by_name(monkeypatch):
    calls = []

    def by_name(path, mode):
        calls.append((path, mode))
        return io.BytesIO(b"a\n")

    def unexpected(*args):
        pytest.fail("default reader used the rooted opener")

    monkeypatch.setattr(windows, "open_regular", by_name)
    monkeypatch.setattr(windows, "_open_contained", unexpected)
    path = Path("file.c")
    assert windows.read_bytes_prefix_capped(path, 1, max_bytes=2) == (b"a", False)
    assert windows.read_line_window_capped(path, 0, 1, max_bytes=2) == (["a"], False)
    assert calls == [(path, "rb"), (path, "rb")]


def test_rooted_caps_probe_cap_plus_one_and_close(monkeypatch):
    streams = []

    class TrackingStream(io.BytesIO):
        consumed = 0

        def read(self, size):
            chunk = super().read(size)
            self.consumed += len(chunk)
            return chunk

    def rooted(*args):
        stream = TrackingStream(b"a\nb\nc\nd\n")
        streams.append(stream)
        return stream

    monkeypatch.setattr(windows, "_open_contained", rooted)
    monkeypatch.setattr(windows, "_CHUNK_BYTES", 2)
    assert windows.read_bytes_prefix_capped(
        Path("file"), 1, max_bytes=5, target_root="root",
    ) == (b"", True)
    assert windows.read_line_window_capped(
        Path("file"), 0, 1, max_bytes=5, target_root="root",
    ) == ([], True)
    assert all(stream.closed and stream.consumed == 6 for stream in streams)


def test_rooted_late_errors_refuse_selected_data_and_close(monkeypatch):
    streams = []

    class FailingStream(io.BytesIO):
        def read(self, size):
            if self.tell():
                raise OSError("late fixture read failure")
            return super().read(size)

    def rooted(*args):
        stream = FailingStream(b"a\nb\n")
        streams.append(stream)
        return stream

    monkeypatch.setattr(windows, "_open_contained", rooted)
    monkeypatch.setattr(windows, "_CHUNK_BYTES", 2)
    assert windows.read_bytes_prefix_capped(
        Path("file"), 1, max_bytes=20, target_root="root",
    ) is None
    assert windows.read_line_window_capped(
        Path("file"), 0, 1, max_bytes=20, target_root="root",
    ) is None
    assert all(stream.closed for stream in streams)
