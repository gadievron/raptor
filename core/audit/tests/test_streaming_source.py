"""Audit streaming integration preserves snippets and budgets."""

import os
from itertools import product

from core.audit import context
from core.source.lines import split_lines


def test_source_renderer_preserves_all_bounds(tmp_path):
    raw = b"a\r\nb\n\nc\r\xff\nlast"
    path = tmp_path / "a.c"
    path.write_bytes(raw)
    lines = split_lines(raw.decode("utf-8", errors="replace"))
    for first, last in product((-2, 0, 1, 2, 100),
                               (None, -2, 0, 1, 4, 100)):
        start = max(0, first - 1)
        end = min(context.fallback_span_end(first, last), len(lines))
        expected = "\n".join(f"{i + 1:4d}  {line}"
                             for i, line in enumerate(lines[start:end], start))
        assert context._read_source(tmp_path, "a.c", first, last) == expected


def test_changed_or_deleted_source_is_not_reused(tmp_path):
    path = tmp_path / "a.c"
    path.write_bytes(b"old\n")
    stamp = path.stat()
    assert context._read_source(tmp_path, "a.c", 1, 1) == "   1  old"
    path.write_bytes(b"new\n")
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert context._read_source(tmp_path, "a.c", 1, 1) == "   1  new"
    path.unlink()
    assert context._read_source(tmp_path, "a.c", 1, 1) == "(file not found)"



def test_caller_windows_match_original_search_and_context(tmp_path, monkeypatch):
    import re
    from core.source import windows

    monkeypatch.setattr(windows, "_CHUNK_BYTES", 17)
    pattern = re.compile(r'\bg\s*\(', re.IGNORECASE)
    path = tmp_path / "a.c"
    for match_line in (0, 2, 80, 81, 199, None):
        source = ["  G(x);" if i == match_line else f"/* line {i} é */"
                  for i in range(200)]
        raw = "\r\n".join(source).encode()
        path.write_bytes(raw)
        lines = split_lines(raw.decode())
        for caller_line, margin in product((-100, -1, 0, 1, 3, 79, 81, 200, 250),
                                            (-2, 0, 1, 3, 100)):
            expected = {"file": "a.c", "name": "f", "line_start": caller_line}
            lo = max(0, caller_line - 1) if caller_line else 0
            hi = min(len(lines), caller_line + context.CALLER_CALL_SEARCH_SPAN_LINES
                     if caller_line else len(lines))
            for i in range(lo, hi):
                if pattern.search(lines[i]):
                    expected["call_site"] = "\n  ".join(
                        f"{j + 1:4d}  {lines[j]}"
                        for j in range(max(0, i - margin),
                                       min(len(lines), i + margin + 1)))
                    break
            caller = {"file": "a.c", "name": "f", "line_start": caller_line}
            context._enrich_callers_with_call_sites([caller], tmp_path, "g", margin)
            assert caller == expected, (match_line, caller_line, margin)


def test_callee_windows_preserve_total_budget_and_empty_ranges(tmp_path):
    from copy import deepcopy

    raw = "\r\n".join(f"line {i} é" for i in range(30)).encode()
    (tmp_path / "a.c").write_bytes(raw)
    lines = split_lines(raw.decode())
    starts = (-2, 0, 1, 3, 29, 31, 100)
    for final, span, total in product((None, -2, 0, 1, 5, 100),
                                      (-1, 0, 1, 5, 20), (0, 1, 2, 3, 7, 150)):
        callees = [{"file": "a.c", "name": f"f{i}", "line_start": first}
                   for i, first in enumerate(starts)]
        checklist = {"files": [{"path": "a.c", "items": [
            {"name": callee["name"], "line_end": final} for callee in callees]}]}
        expected = deepcopy(callees)
        used = 0
        for callee in expected:
            if used >= total:
                break
            first = callee["line_start"]
            end = final if first else None
            start = max(0, first - 1) if first else 0
            end = min(end or min(start + span, len(lines)), start + span, len(lines))
            if used + end - start > total:
                remaining = total - used
                if remaining < 3:
                    break
                end = start + remaining
            snippet = "\n  ".join(f"{j + 1:4d}  {lines[j]}"
                                    for j in range(start, end))
            if snippet:
                callee["source_snippet"] = snippet
                used += end - start
        context._enrich_callees_with_source(callees, tmp_path, checklist, span, total)
        assert callees == expected, (final, span, total)


def test_flow_windows_match_original_ranges(tmp_path):
    raw = b"a\r\nb\n\nc\r\xff\nlast"
    (tmp_path / "a.c").write_bytes(raw)
    lines = split_lines(raw.decode("utf-8", errors="replace"))
    for first, final, span in product((-2, 0, 1, 3, 100),
                                      (None, -2, 0, 1, 4, 100), (-1, 0, 1, 15)):
        checklist = {"files": [{"path": "a.c", "items": [
            {"name": "f", "line_end": final}]}]}
        start = max(0, first - 1) if first else 0
        end = final if first else None
        end = min(end or min(start + span, len(lines)), start + span, len(lines))
        expected = "\n".join(f"{j + 1:4d}  {lines[j]}" for j in range(start, end))
        actual = context._read_flow_node_source(
            tmp_path, {"file": "a.c", "name": "f", "line": first}, checklist, span)
        assert actual == expected, (first, final, span)
