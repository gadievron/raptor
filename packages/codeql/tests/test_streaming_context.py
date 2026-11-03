"""CodeQL source windows match the capped whole-prefix reader."""

import logging
from itertools import product

import pytest

from core.source import read_text_capped, split_lines
from core.source.windows import read_text_line_window_capped
from packages.codeql import dataflow_validator as module


@pytest.mark.parametrize("raw", [
    b"a\r\nb\n\nc\r\xff\nlast", "é🙂\nfirst\nsecond\npartial tail".encode(),
    b"no newline", b"", b"a\x0cb\nc\n",
])
def test_equivalent_windows(tmp_path, monkeypatch, caplog, raw):
    path = tmp_path / "a.c"
    path.write_bytes(raw)
    validator = module.DataflowValidator.__new__(module.DataflowValidator)
    validator.logger = logging.getLogger("streaming-codeql")
    for cap in (0, 1, 3, 5, 10, 100):
        monkeypatch.setattr(module, "read_text_line_window_capped",
            lambda path, start, end: read_text_line_window_capped(path, start, end, max_chars=cap))
        monkeypatch.setattr(module, "read_text_capped",
            lambda path, **kw: read_text_capped(path, cap, **kw))
        content, truncated = read_text_capped(path, cap, newline="")
        lines = split_lines(content)
        for line, margin in product((-10, -2, 0, 1, 3, 100), (-10, -2, 0, 1, 5)):
            start = max(0, line - margin - 1)
            end = min(len(lines), line + margin)
            expected = "\n".join(
                f'{">>> " if i == line - 1 else "    "}{i + 1:4d}: {lines[i].rstrip()}'
                for i in range(start, end))
            caplog.clear()
            assert validator.read_source_context(str(path), line, margin, tmp_path) == expected
            assert bool(caplog.records) == truncated


def test_reread_and_refusals(tmp_path):
    path = tmp_path / "a.c"
    validator = module.DataflowValidator.__new__(module.DataflowValidator)
    validator.logger = logging.getLogger("streaming-codeql")
    for text in ("old", "new"):
        path.write_text(text)
        assert validator.read_source_context(str(path), 1, 0, tmp_path) == f">>>    1: {text}"
    assert validator.read_source_context("../outside.c", 1, repo_root=tmp_path) == ""
    assert validator.read_source_context(str(tmp_path / "missing"), 1) == ""
    assert validator.read_source_context(str(path), "invalid") == ""
