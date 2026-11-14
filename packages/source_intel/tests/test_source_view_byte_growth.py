"""Tiny owned read controls; sanitisation is replaced before invocation."""

import pytest

from core.audit import source_view as sanitizer
from packages.source_intel import _source_view as module


def test_non_ascii_growth_after_admission_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "owned.c"
    path.write_bytes(b"a" * 8)
    monkeypatch.setattr(module, "MAX_SOURCE_BYTES", 8)
    monkeypatch.setattr(sanitizer, "sanitized_view", lambda text, *args: text)
    reader = module._sanitized_source_cached.__wrapped__

    def grow_then_read(name, mtime, size):
        assert size == 8
        path.write_text("é" * 8, encoding="utf-8")
        return reader(name, mtime, size)

    monkeypatch.setattr(module, "_sanitized_source_cached", grow_then_read)
    assert module.sanitized_source(str(path)) is None


@pytest.mark.parametrize("content,expected", [
    ("é" * 4, "é" * 4),
    ("a" * 8, "a" * 8),
    (b"\xff", "\ufffd"),
    ("a\r\nb\rc", "a\nb\nc"),
])
def test_within_byte_cap_retains_decoding(tmp_path, monkeypatch, content, expected):
    path = tmp_path / "owned.c"
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    monkeypatch.setattr(module, "MAX_SOURCE_BYTES", 8)
    monkeypatch.setattr(sanitizer, "sanitized_view", lambda text, *args: text)
    assert module.sanitized_source(str(path)) == expected
