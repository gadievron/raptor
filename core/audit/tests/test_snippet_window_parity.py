"""Source snippets retain canonical lines and legacy malformed-bound behavior."""

import pytest

import core.source
from core.audit.consistency_verify import _snippet
from core.audit.synthesis_seeds import _snippet_for
from core.source import split_lines


@pytest.mark.parametrize(("start", "end"), [(1, 1), (2, 0), (2, None), (3, 200), (3, -1), (9000, 9001)])
def test_seed_snippet_keeps_existing_bounds_and_character_cap(monkeypatch, tmp_path, start, end):
    text = "first\r\n\r\nembedded\u2028separator\r\r\n" + "body\n" * 5000
    monkeypatch.setattr(core.source, "read_contained", lambda *args, **kwargs: text)
    lines = split_lines(text)
    upper = min(end or start, start + 120, len(lines))
    assert _snippet_for(tmp_path, "a.c", start, end) == "\n".join(lines[start - 1:upper])[:8000]


@pytest.mark.parametrize("line", [0, 1, 2, 3, 5003, 9000, True, False])
def test_consistency_receipt_keeps_line_content_and_empty_results(line):
    text = "first\r\n\r\nembedded\u2028separator\r\r\n" + "body\n" * 5000
    lines = split_lines(text)
    expected = lines[line - 1].strip()[:200] if 1 <= line <= len(lines) else ""
    assert _snippet({"a.c": text}, "a.c", line) == expected
