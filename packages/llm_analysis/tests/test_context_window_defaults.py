"""Classifier context windows: defaults wired, boundaries exact,
output byte-identical to the pre-extraction literals.

The /agentic and /analyze classifier used to slice its per-finding
context with bare literals (±50 surrounding lines, first-100-lines
fallback, ±5 per dataflow node). Those literals now live in
``core.llm.context_window``. Three properties are pinned here:

- wiring: the defaults ARE the shared constants (not fresh literals);
- boundaries, both directions: a line exactly at the window edge is
  included, one line past it is excluded — for both the leading and
  trailing edge;
- equivalence: for a sample of findings over a synthesized repo, the
  produced context strings equal a vendored copy of the pre-change
  slicing (literals hardcoded here on purpose — if a default changes,
  this differential goes red).
"""

from __future__ import annotations

import inspect
from pathlib import Path

from core.llm.context_window import (
    DATAFLOW_STEP_CONTEXT_LINES,
    FINDING_CONTEXT_LINES,
    NO_LINE_INFO_HEAD_LINES,
)
from core.source import split_lines
from packages.llm_analysis import flow_context_inject
from packages.llm_analysis.agent import VulnerabilityContext

# 200 distinct, greppable lines: "marker-0001" .. "marker-0200".
_N_LINES = 200
_SRC = "".join(f"marker-{i:04d}\n" for i in range(1, _N_LINES + 1))


def _write_repo(tmp_path: Path) -> Path:
    (tmp_path / "vuln.c").write_bytes(_SRC.encode())
    return tmp_path


def _context(
    tmp_path: Path,
    start_line: int | None,
    end_line: int | None = None,
) -> VulnerabilityContext:
    finding = {
        "finding_id": "cw-1", "rule_id": "r", "file": "vuln.c",
        "startLine": start_line, "endLine": end_line,
        "message": "m", "tool": "semgrep",
    }
    return VulnerabilityContext(finding, tmp_path)


class TestSurroundingContextBoundary:
    """finding line S: window covers S-50 .. E+50 (1-based), inclusive."""

    def test_leading_edge_included_one_past_excluded(self, tmp_path: Path):
        _write_repo(tmp_path)
        s = FINDING_CONTEXT_LINES + 60  # line 110: window floor is 60
        ctx = _context(tmp_path, s, s)
        assert ctx.read_vulnerable_code()
        floor = s - FINDING_CONTEXT_LINES
        assert f"marker-{floor:04d}" in ctx.surrounding_context
        assert f"marker-{floor - 1:04d}" not in ctx.surrounding_context

    def test_trailing_edge_included_one_past_excluded(self, tmp_path: Path):
        _write_repo(tmp_path)
        s = 100
        ctx = _context(tmp_path, s, s)
        assert ctx.read_vulnerable_code()
        ceil = s + FINDING_CONTEXT_LINES
        assert f"marker-{ceil:04d}" in ctx.surrounding_context
        assert f"marker-{ceil + 1:04d}" not in ctx.surrounding_context

    def test_no_line_info_head_boundary(self, tmp_path: Path):
        _write_repo(tmp_path)
        ctx = _context(tmp_path, None)
        assert ctx.read_vulnerable_code()
        assert f"marker-{NO_LINE_INFO_HEAD_LINES:04d}" in ctx.full_code
        assert f"marker-{NO_LINE_INFO_HEAD_LINES + 1:04d}" not in ctx.full_code
        assert ctx.surrounding_context == ctx.full_code


class TestDataflowStepWindowBoundary:
    """_read_code_at_location default: line L ± DATAFLOW_STEP lines."""

    def test_default_is_the_shared_constant(self):
        sig = inspect.signature(VulnerabilityContext._read_code_at_location)
        assert (sig.parameters["context_lines"].default
                == DATAFLOW_STEP_CONTEXT_LINES)

    def test_both_edges(self, tmp_path: Path):
        _write_repo(tmp_path)
        ctx = _context(tmp_path, 100, 100)
        line = 100
        snippet = ctx._read_code_at_location("vuln.c", line)
        w = DATAFLOW_STEP_CONTEXT_LINES
        assert f"marker-{line - w:04d}" in snippet
        assert f"marker-{line - w - 1:04d}" not in snippet
        assert f"marker-{line + w:04d}" in snippet
        assert f"marker-{line + w + 1:04d}" not in snippet
        # The flagged line carries the >>> marker.
        assert f">>>  {line} | marker-{line:04d}" in snippet


# ── Equivalence differential ────────────────────────────────────────
# Vendored pre-extraction slicing, literals ON PURPOSE. Keep 50 / 100
# / 5 here even if the constants module changes: this test's job is
# to go red when a default moves, so the move is a reviewed behaviour
# change with the old output visible in the diff.


def _old_read_vulnerable_code(
    content: str, start_line: int | None, end_line: int | None,
) -> tuple[str, str]:
    lines = split_lines(content)
    if start_line:
        e = end_line or start_line
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), e)
        full = "\n".join(lines[start_idx:end_idx])
        cs = max(0, start_idx - 50)
        ce = min(len(lines), end_idx + 50)
        return full, "\n".join(lines[cs:ce])
    head = "\n".join(lines[:100])
    return head, head


def _old_read_code_at_location(content: str, line: int) -> str:
    lines = split_lines(content)
    start = max(0, line - 5 - 1)
    end = min(len(lines), line + 5)
    out = []
    for i in range(start, end):
        marker = ">>>" if i == line - 1 else "   "
        out.append(f"{marker} {i + 1:4d} | {lines[i].rstrip()}")
    return "\n".join(out)


class TestEquivalenceDifferential:
    # Sample covers: mid-file, window clamped at file start, window
    # clamped at file end, multi-line finding, missing endLine,
    # missing line numbers entirely.
    _CASES = [
        (100, 100), (3, 3), (198, 198), (80, 95), (42, None),
        (None, None),
    ]

    def test_read_vulnerable_code_byte_identical(self, tmp_path: Path):
        _write_repo(tmp_path)
        for s, e in self._CASES:
            ctx = _context(tmp_path, s, e)
            assert ctx.read_vulnerable_code(), (s, e)
            old_full, old_ctx = _old_read_vulnerable_code(_SRC, s, e)
            assert ctx.full_code == old_full, (s, e)
            assert ctx.surrounding_context == old_ctx, (s, e)

    def test_read_code_at_location_byte_identical(self, tmp_path: Path):
        _write_repo(tmp_path)
        ctx = _context(tmp_path, 100, 100)
        for line in (1, 3, 100, 196, 200):
            assert (ctx._read_code_at_location("vuln.c", line)
                    == _old_read_code_at_location(_SRC, line)), line


def test_flow_channel_caps_pinned() -> None:
    """The classifier's flow/caller-channel volume caps (named before
    this refactor; pinned with it)."""
    assert flow_context_inject.MAX_TRACES_PER_FINDING == 2
    assert flow_context_inject.MAX_HOPS_PER_TRACE == 8
    assert flow_context_inject.MAX_CALLERS_PER_FINDING == 5
    assert flow_context_inject.MAX_TRACES_CACHED == 50
    assert flow_context_inject._MAX_FIELD_CHARS == 160


class TestCallerChannelSnippetCoupling:
    """The caller channel's snippet-height clip is DERIVED from the
    audit-side call-site window (2 * CALL_SITE_CONTEXT_LINES + 1 — the
    exact height the enricher produces). A hardcoded twin here once
    meant: widen the window and the audit prompt shows the wider
    snippet while this channel silently clips it back, with no red
    test. Both directions are pinned: the channel widens WITH the
    window, and an over-height (hostile/pathological) call_site is
    still clipped to the contract height."""

    @staticmethod
    def _block_for(monkeypatch, tmp_path: Path, caller: dict):
        import core.audit.context as audit_context
        monkeypatch.setattr(
            audit_context, "collect_caller_call_sites",
            lambda *a, **k: [caller],
        )
        return flow_context_inject._build_caller_block(
            {}, "a.c", "fn", tmp_path,
        )

    def test_channel_widens_with_the_window(self, monkeypatch,
                                            tmp_path: Path):
        import core.audit.context as audit_context
        wider = audit_context.CALL_SITE_CONTEXT_LINES + 1
        monkeypatch.setattr(
            audit_context, "CALL_SITE_CONTEXT_LINES", wider,
        )
        height = 2 * wider + 1
        # The snippet the enricher would build at the widened window.
        snippet = "\n".join(f"snipline{j:02d}" for j in range(height))
        caller = {"file": "a.c", "name": "up_fn", "line_start": 1,
                  "call_site": snippet}
        block = self._block_for(monkeypatch, tmp_path, caller)
        assert block is not None
        for j in range(height):
            assert f"snipline{j:02d}" in block.content, j

    def test_over_height_call_site_still_clipped(self, monkeypatch,
                                                 tmp_path: Path):
        import core.audit.context as audit_context
        height = 2 * audit_context.CALL_SITE_CONTEXT_LINES + 1
        snippet = "\n".join(f"snipline{j:02d}" for j in range(height + 10))
        caller = {"file": "a.c", "name": "up_fn", "line_start": 1,
                  "call_site": snippet}
        block = self._block_for(monkeypatch, tmp_path, caller)
        assert block is not None
        assert f"snipline{height - 1:02d}" in block.content
        assert f"snipline{height:02d}" not in block.content
