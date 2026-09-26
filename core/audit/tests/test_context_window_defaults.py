"""Caller call-site window limits: defaults wired, boundaries exact,
output byte-identical to the pre-extraction literals.

``core.audit.context`` slices the "1-hop callers with call-site
snippets" view consumed by both the audit review prompt and (through
``collect_caller_call_sites``) /agentic's per-finding classifier. The
window literals (±1 call-site context, 80-line body search span, 10
enriched callers, 50-line fallback source span) are now the named
module constants; the vendored differentials below keep the OLD
literals hardcoded on purpose — a changed default goes red here and
becomes a reviewed behaviour change.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any

from core.audit.context import (
    CALL_SITE_CONTEXT_LINES,
    CALLEE_SNIPPET_SPAN_LINES,
    CALLEE_SNIPPET_TOTAL_LINES,
    CALLER_CALL_SEARCH_SPAN_LINES,
    MAX_CALL_SITE_CALLERS,
    MAX_PROMPT_CALLEES,
    SOURCE_SPAN_FALLBACK_LINES,
    _enrich_callees_with_source,
    _enrich_callers_with_call_sites,
    _read_source,
    collect_caller_call_sites,
    format_context_for_prompt,
)
from core.source.lines import split_lines


def test_defaults_pinned_exactly() -> None:
    assert CALL_SITE_CONTEXT_LINES == 1
    assert CALLER_CALL_SEARCH_SPAN_LINES == 80
    assert MAX_CALL_SITE_CALLERS == 10
    assert MAX_PROMPT_CALLEES == 10
    assert SOURCE_SPAN_FALLBACK_LINES == 50
    assert CALLEE_SNIPPET_SPAN_LINES == 20
    assert CALLEE_SNIPPET_TOTAL_LINES == 150


def test_public_seam_defaults_are_the_constants() -> None:
    sig = inspect.signature(collect_caller_call_sites)
    assert sig.parameters["max_callers"].default == MAX_CALL_SITE_CALLERS
    assert sig.parameters["context_lines"].default == CALL_SITE_CONTEXT_LINES
    enrich_sig = inspect.signature(_enrich_callers_with_call_sites)
    assert (enrich_sig.parameters["context_lines"].default
            == CALL_SITE_CONTEXT_LINES)
    callee_sig = inspect.signature(_enrich_callees_with_source)
    assert (callee_sig.parameters["max_lines"].default
            == CALLEE_SNIPPET_SPAN_LINES)
    assert (callee_sig.parameters["max_total_lines"].default
            == CALLEE_SNIPPET_TOTAL_LINES)


def _write_caller_file(
    tmp_path: Path, call_line: int, n_lines: int = 200,
) -> str:
    """A caller file of numbered marker lines with one call to
    ``target_fn`` at 1-based *call_line*."""
    lines = [f"marker-{i:04d}" for i in range(1, n_lines + 1)]
    lines[call_line - 1] = f"target_fn(arg_{call_line});"
    (tmp_path / "caller.c").write_bytes(
        ("\n".join(lines) + "\n").encode())
    return "caller.c"


class TestCallSiteContextBoundary:
    def test_one_line_each_side_included_second_excluded(
        self, tmp_path: Path,
    ):
        fp = _write_caller_file(tmp_path, call_line=12)
        callers: list[dict[str, Any]] = [
            {"file": fp, "name": "caller_a", "line_start": 10},
        ]
        _enrich_callers_with_call_sites(callers, tmp_path, "target_fn")
        snippet = callers[0]["call_site"]
        w = CALL_SITE_CONTEXT_LINES
        assert f"marker-{12 - w:04d}" in snippet
        assert f"marker-{12 - w - 1:04d}" not in snippet
        assert f"marker-{12 + w:04d}" in snippet
        assert f"marker-{12 + w + 1:04d}" not in snippet


class TestSearchSpanBoundary:
    def test_call_at_span_edge_found(self, tmp_path: Path):
        edge = 1 + CALLER_CALL_SEARCH_SPAN_LINES  # last searched line
        fp = _write_caller_file(tmp_path, call_line=edge)
        callers = [{"file": fp, "name": "caller_a", "line_start": 1}]
        _enrich_callers_with_call_sites(callers, tmp_path, "target_fn")
        assert "call_site" in callers[0]
        assert f"target_fn(arg_{edge});" in callers[0]["call_site"]

    def test_call_one_past_span_not_found(self, tmp_path: Path):
        past = 1 + CALLER_CALL_SEARCH_SPAN_LINES + 1
        fp = _write_caller_file(tmp_path, call_line=past)
        callers = [{"file": fp, "name": "caller_a", "line_start": 1}]
        _enrich_callers_with_call_sites(callers, tmp_path, "target_fn")
        assert "call_site" not in callers[0]


class TestCallersCapBoundary:
    def test_first_cap_callers_enriched_rest_untouched(
        self, tmp_path: Path,
    ):
        fp = _write_caller_file(tmp_path, call_line=5)
        callers = [
            {"file": fp, "name": f"caller_{i}", "line_start": 1}
            for i in range(MAX_CALL_SITE_CALLERS + 2)
        ]
        _enrich_callers_with_call_sites(callers, tmp_path, "target_fn")
        for c in callers[:MAX_CALL_SITE_CALLERS]:
            assert "call_site" in c, c["name"]
        for c in callers[MAX_CALL_SITE_CALLERS:]:
            assert "call_site" not in c, c["name"]


class TestPromptRenderCaps:
    """The 1-hop sections render at most the capped number of rows —
    the cap-th neighbour appears, the cap+1-th does not."""

    @staticmethod
    def _ctx(callers: list[dict[str, Any]],
             callees: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "file": "a.c", "function": "f",
            "line_start": 1, "line_end": 2,
            "source": "int f(void) { return 0; }",
            "callers": callers, "callees": callees,
        }

    def test_callers_render_cap(self):
        callers = [
            {"file": "a.c", "name": f"upfn{i:02d}", "line_start": i + 1}
            for i in range(MAX_CALL_SITE_CALLERS + 2)
        ]
        text = format_context_for_prompt(self._ctx(callers, []))
        assert f"upfn{MAX_CALL_SITE_CALLERS - 1:02d}" in text
        assert f"upfn{MAX_CALL_SITE_CALLERS:02d}" not in text

    def test_callees_render_cap(self):
        callees = [
            {"file": "a.c", "name": f"dnfn{i:02d}", "line_start": i + 1}
            for i in range(MAX_PROMPT_CALLEES + 2)
        ]
        text = format_context_for_prompt(self._ctx([], callees))
        assert f"dnfn{MAX_PROMPT_CALLEES - 1:02d}" in text
        assert f"dnfn{MAX_PROMPT_CALLEES:02d}" not in text


class TestCalleeSnippetSpanBoundary:
    def test_span_when_line_end_unknown(self, tmp_path: Path):
        (tmp_path / "callee.c").write_bytes(
            "".join(f"marker-{i:04d}\n" for i in range(1, 201)).encode())
        callees = [
            {"file": "callee.c", "name": "helper", "line_start": 10},
        ]
        _enrich_callees_with_source(callees, tmp_path, None)
        snippet = callees[0]["source_snippet"]
        last = 10 - 1 + CALLEE_SNIPPET_SPAN_LINES  # 0-based start + span
        assert f"marker-{last:04d}" in snippet
        assert f"marker-{last + 1:04d}" not in snippet
        assert "marker-0010" in snippet
        assert "marker-0009" not in snippet


class TestSourceFallbackSpanBoundary:
    def test_span_when_line_end_unknown(self, tmp_path: Path):
        (tmp_path / "a.c").write_bytes(
            "".join(f"marker-{i:04d}\n" for i in range(1, 201)).encode())
        out = _read_source(tmp_path, "a.c", 10, None)
        last = 10 - 1 + SOURCE_SPAN_FALLBACK_LINES  # 0-based start + span
        assert f"marker-{last:04d}" in out
        assert f"marker-{last + 1:04d}" not in out
        assert "marker-0010" in out
        assert "marker-0009" not in out


# ── Equivalence differential (old literals on purpose) ──────────────


def _old_enrich(
    callers: list[dict[str, Any]],
    target_path: Path,
    function_name: str,
) -> None:
    call_pat = re.compile(
        rf'\b{re.escape(function_name)}\s*\(', re.IGNORECASE,
    )
    for caller in callers[:10]:
        text = (target_path / caller["file"]).read_text()
        lines = split_lines(text)
        caller_line = caller.get("line_start", 0)
        search_start = max(0, caller_line - 1) if caller_line else 0
        search_end = min(
            len(lines), (caller_line + 80) if caller_line else len(lines),
        )
        for i in range(search_start, search_end):
            if call_pat.search(lines[i]):
                start = max(0, i - 1)
                end = min(len(lines), i + 1 + 1)
                caller["call_site"] = "\n  ".join(
                    f"{j + 1:4d}  {lines[j]}" for j in range(start, end)
                )
                break


def _old_read_source(content: str, line_start: int,
                     line_end: int | None) -> str:
    lines = split_lines(content)
    start = max(0, line_start - 1)
    end = line_end if line_end is not None else min(start + 50, len(lines))
    return "\n".join(
        f"{i + 1:4d}  {line}"
        for i, line in enumerate(lines[start:end], start=start)
    )


class TestEquivalenceDifferential:
    def test_call_site_snippets_byte_identical(self, tmp_path: Path):
        # (82, 1) discriminates CALLER_CALL_SEARCH_SPAN_LINES itself:
        # one line past the span, found by neither side today — a
        # span widened by even one line finds it in the new code only
        # and this differential goes red.
        for call_line, caller_start in (
            (5, 1), (12, 10), (81, 1), (82, 1), (1, 1), (150, 120),
        ):
            fp = _write_caller_file(tmp_path, call_line=call_line)
            new = [{"file": fp, "name": "c", "line_start": caller_start}]
            old = [dict(c) for c in new]
            _enrich_callers_with_call_sites(new, tmp_path, "target_fn")
            _old_enrich(old, tmp_path, "target_fn")
            assert new[0].get("call_site") == old[0].get("call_site"), (
                call_line, caller_start,
            )

    def test_read_source_byte_identical(self, tmp_path: Path):
        content = "".join(f"marker-{i:04d}\n" for i in range(1, 201))
        (tmp_path / "a.c").write_bytes(content.encode())
        for line_start, line_end in (
            (10, None), (10, 20), (180, None), (1, None), (200, None),
        ):
            assert (_read_source(tmp_path, "a.c", line_start, line_end)
                    == _old_read_source(content, line_start, line_end)), (
                line_start, line_end,
            )
