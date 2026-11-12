"""Borrowed-descriptor JSON bounds and ownership, without external I/O."""
from __future__ import annotations

import os

import pytest


def _api():
    # Resolve at call time because lazy-export tests can reset module bindings.
    import core.json.bounded as bounded
    return bounded


class _Borrowed:
    def __init__(self, raw, before_read=None):
        self.raw = raw
        self.before_read = before_read
        self.read_sizes = []
        self.close_calls = 0

    def fileno(self):
        return self.raw.fileno()

    def read(self, size):
        self.read_sizes.append(size)
        if self.before_read is not None:
            self.before_read()
        return self.raw.read(size)

    def close(self):
        self.close_calls += 1
        raise AssertionError("the bounded parser does not own its caller's stream")


def test_success_keeps_the_borrowed_descriptor_open(tmp_path):
    path = tmp_path / "owned.json"
    path.write_bytes(b'{"ok":true}')
    with path.open("rb") as raw:
        borrowed = _Borrowed(raw)
        assert _api().load_json_stream_bounded(borrowed, max_bytes=16) == {"ok": True}
        assert not raw.closed and borrowed.close_calls == 0
        assert borrowed.read_sizes == [17]
        raw.seek(0)
        assert raw.read() == b'{"ok":true}'


def test_size_refusal_precedes_any_borrowed_read(tmp_path):
    path = tmp_path / "owned.json"
    path.write_bytes(b'{"padding":"too much"}')

    def forbidden():
        raise AssertionError("oversized descriptors must not be read")

    with path.open("rb") as raw:
        borrowed = _Borrowed(raw, forbidden)
        with pytest.raises(_api().JsonBudgetExceededError, match="exceeds"):
            _api().load_json_stream_bounded(borrowed, max_bytes=2)
        assert borrowed.read_sizes == [] and borrowed.close_calls == 0
        assert not raw.closed


def test_growth_is_byte_capped_and_refused_without_closing_the_stream(tmp_path):
    path = tmp_path / "owned.json"
    path.write_bytes(b'{}')

    def grow():
        path.write_bytes(b'{"padding":"' + b'x' * 64 + b'"}')

    with path.open("rb") as raw:
        borrowed = _Borrowed(raw, grow)
        with pytest.raises(_api().JsonBudgetExceededError, match="grew past"):
            _api().load_json_stream_bounded(borrowed, max_bytes=16)
        assert borrowed.read_sizes == [17] and borrowed.close_calls == 0
        assert raw.tell() == 17 and not raw.closed


@pytest.mark.parametrize("payload,expected", [
    (b'\xef\xbb\xbf{"a":1}', {"a": 1}),
    (b'{"a":"\xff"}', {"a": "\ufffd"}),
    (b'null', None),
])
def test_bom_replacement_and_null_match_the_path_reader(tmp_path, payload, expected):
    path = tmp_path / "owned.json"
    path.write_bytes(payload)
    with path.open("rb") as raw:
        assert _api().load_json_stream_bounded(raw, max_bytes=len(payload)) == expected
        assert not raw.closed
    assert _api().load_json_bounded(path, max_bytes=len(payload)) == expected


@pytest.mark.parametrize("payload", [b'{broken', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e309}'])
def test_parse_failures_keep_the_borrowed_descriptor_open(tmp_path, payload):
    path = tmp_path / "owned.json"
    path.write_bytes(payload)
    with path.open("rb") as raw:
        borrowed = _Borrowed(raw)
        with pytest.raises(ValueError):
            _api().load_json_stream_bounded(borrowed, max_bytes=64)
        assert not raw.closed and borrowed.close_calls == 0


def test_non_regular_descriptor_is_refused_before_read():
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b'{}')
    finally:
        os.close(write_fd)
    with os.fdopen(read_fd, "rb") as raw:
        borrowed = _Borrowed(raw)
        with pytest.raises(ValueError, match="not a regular file"):
            _api().load_json_stream_bounded(borrowed, max_bytes=16)
        assert borrowed.read_sizes == [] and borrowed.close_calls == 0
        assert not raw.closed


def test_primary_interruption_is_not_swallowed_or_closed(tmp_path):
    path = tmp_path / "owned.json"
    path.write_bytes(b'{}')
    primary = KeyboardInterrupt("owned read interruption")

    def interrupted():
        raise primary

    with path.open("rb") as raw:
        borrowed = _Borrowed(raw, interrupted)
        with pytest.raises(KeyboardInterrupt) as caught:
            _api().load_json_stream_bounded(borrowed, max_bytes=16)
        assert caught.value is primary
        assert borrowed.close_calls == 0 and not raw.closed


def test_stream_entry_point_is_lazily_exported():
    import core.json as package
    bounded = _api()
    assert package.load_json_stream_bounded is bounded.load_json_stream_bounded
    assert "load_json_stream_bounded" in package.__all__
    assert "load_json_stream_bounded" in dir(package)
