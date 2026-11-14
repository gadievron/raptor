"""Owned stream-type controls; no engines, target parsing or processes."""

import hashlib
import os
from pathlib import Path

import pytest

from packages.source_intel import cache


def test_fifo_is_refused_instead_of_hashed(tmp_path, monkeypatch):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO fixture requires POSIX")
    fifo = tmp_path / "owned.c"
    os.mkfifo(fifo)
    anchor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    os.write(anchor, b"x")
    original = Path.open

    def open_path(path, *args, **kwargs):
        nonlocal anchor
        stream = original(path, *args, **kwargs)
        if path == fifo:
            # The legacy blocking open has a writer ready; closing it
            # now gives its read a one-byte stream followed by EOF.
            os.close(anchor)
            anchor = None
        return stream

    monkeypatch.setattr(Path, "open", open_path)
    try:
        assert cache._file_hash(fifo) == "read-error"
    finally:
        if anchor is not None:
            os.close(anchor)


@pytest.mark.parametrize("link", [False, True])
def test_regular_file_and_symlink_keep_content_digest(tmp_path, link):
    path = tmp_path / "owned.c"
    content = b"owned bytes"
    path.write_bytes(content)
    if link:
        alias = tmp_path / "alias.c"
        alias.symlink_to(path)
        path = alias
    assert cache._file_hash(path) == hashlib.sha256(content).hexdigest()
