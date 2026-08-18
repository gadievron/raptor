"""Source hydration for the negative-space detectors.

`discover_conventions` and `check_sibling_negative_space` read
`gap["source"]` and skip any gap without it. Gaps come from the
checklist, which carries line spans but no text, so before this the two
passes silently analysed nothing. These tests pin the end the change
serves, the blast radius it must not exceed, and the bounds that keep it
safe on a large or hostile tree.
"""

from __future__ import annotations

import time

import pytest

from core.audit.gaps import (
    _MAX_HYDRATED_FUNCTION_BYTES,
    _MAX_HYDRATED_FILE_BYTES,
    _read_spans,
    hydrate_live_gaps_for_detectors,
    read_gap_source,
)
from core.audit.negative_space import discover_conventions

# Matches _GENERIC_PATTERNS[CONCERN_AUTH]; four occurrences clear
# MIN_CONVENTION_OCCURRENCES so a convention is actually discovered.
ADHERENT = "def handle_{i}(req):\n    check_auth(req)\n    return run(req)\n"
NON_ADHERENT = "def handle_x(req):\n    return run(req)\n"


def _tree(tmp_path, n=4, body=ADHERENT):
    (tmp_path / "src").mkdir(exist_ok=True)
    for i in range(n):
        (tmp_path / "src" / f"h{i}.py").write_text(body.format(i=i))
    return tmp_path


def _gap(i, dead=False, **kw):
    g = {"file": f"src/h{i}.py", "name": f"handle_{i}",
         "line_start": 1, "line_end": 3}
    if dead:
        g["dead"] = True
    g.update(kw)
    return g


class TestHydrationServesTheDetectors:
    """The end the change exists for."""

    def test_conventions_are_empty_without_hydration(self, tmp_path):
        _tree(tmp_path)
        assert discover_conventions([_gap(i) for i in range(4)]) == []

    def test_conventions_are_found_with_hydration(self, tmp_path):
        _tree(tmp_path)
        hydrated = hydrate_live_gaps_for_detectors(
            [_gap(i) for i in range(4)], tmp_path,
        )
        assert len(hydrated) == 4
        assert [c.concern for c in discover_conventions(hydrated)] == ["auth"]

    def test_body_matches_the_file(self, tmp_path):
        _tree(tmp_path, n=1)
        got = hydrate_live_gaps_for_detectors([_gap(0)], tmp_path)
        assert got[0]["source"] == ADHERENT.format(i=0)


class TestBlastRadiusIsContained:
    """`source` has seven readers; only two are in scope.

    Populating it on the shared gap dicts would also switch on triage's
    generated-file detection — which changes *which functions get
    reviewed* — and spec_inference's extra LLM calls.
    """

    def test_input_gaps_are_not_mutated(self, tmp_path):
        _tree(tmp_path)
        gaps = [_gap(i) for i in range(4)]
        hydrate_live_gaps_for_detectors(gaps, tmp_path)
        assert not any("source" in g for g in gaps)

    def test_returned_gaps_are_copies_not_aliases(self, tmp_path):
        _tree(tmp_path, n=1)
        gaps = [_gap(0)]
        out = hydrate_live_gaps_for_detectors(gaps, tmp_path)
        out[0]["name"] = "mutated"
        assert gaps[0]["name"] == "handle_0"

    def test_other_gap_fields_survive_the_copy(self, tmp_path):
        _tree(tmp_path, n=1)
        out = hydrate_live_gaps_for_detectors(
            [_gap(0, priority=3, strategies=["memory"])], tmp_path,
        )
        assert out[0]["priority"] == 3
        assert out[0]["strategies"] == ["memory"]


class TestDeadGapsAreExcluded:
    """Conventions must not be learned from code the dead-code gate rejected."""

    def test_dead_gaps_are_not_hydrated(self, tmp_path):
        _tree(tmp_path)
        assert hydrate_live_gaps_for_detectors(
            [_gap(i, dead=True) for i in range(4)], tmp_path,
        ) == []

    def test_mixed_keeps_only_live(self, tmp_path):
        _tree(tmp_path)
        out = hydrate_live_gaps_for_detectors(
            [_gap(0), _gap(1, dead=True), _gap(2)], tmp_path,
        )
        assert sorted(g["name"] for g in out) == ["handle_0", "handle_2"]

    def test_dead_gaps_cost_no_io(self, tmp_path, monkeypatch):
        _tree(tmp_path)
        import core.audit.gaps as gaps_mod
        calls = []
        real = gaps_mod._read_spans
        monkeypatch.setattr(
            gaps_mod, "_read_spans",
            lambda *a, **k: (calls.append(a[1]), real(*a, **k))[1],
        )
        hydrate_live_gaps_for_detectors(
            [_gap(i, dead=True) for i in range(4)], tmp_path,
        )
        assert calls == []


class TestReadSpansCorrectness:
    def test_spans_are_inclusive_and_one_indexed(self, tmp_path):
        (tmp_path / "f.py").write_text("".join(f"L{i}\n" for i in range(1, 11)))
        got = _read_spans(tmp_path, "f.py", [(2, 4)])
        assert got[(2, 4)] == "L2\nL3\nL4\n"

    def test_overlapping_spans_each_get_full_text(self, tmp_path):
        (tmp_path / "f.py").write_text("".join(f"L{i}\n" for i in range(1, 11)))
        got = _read_spans(tmp_path, "f.py", [(2, 6), (4, 8)])
        assert got[(2, 6)] == "L2\nL3\nL4\nL5\nL6\n"
        assert got[(4, 8)] == "L4\nL5\nL6\nL7\nL8\n"

    def test_nested_span_is_not_swallowed(self, tmp_path):
        (tmp_path / "f.py").write_text("".join(f"L{i}\n" for i in range(1, 11)))
        got = _read_spans(tmp_path, "f.py", [(1, 10), (3, 4)])
        assert got[(3, 4)] == "L3\nL4\n"
        assert len(got[(1, 10)].splitlines()) == 10

    def test_span_past_eof_is_abandoned(self, tmp_path):
        """A truncated body is worse than none for absence detection.

        If the span never reached its declared end line, the check we
        would report as missing may simply lie in the part not read.
        """
        (tmp_path / "f.py").write_text("L1\nL2\n")
        assert not _read_spans(tmp_path, "f.py", [(1, 99)])

    def test_span_ending_exactly_at_eof_is_kept(self, tmp_path):
        (tmp_path / "f.py").write_text("L1\nL2\n")
        assert _read_spans(tmp_path, "f.py", [(1, 2)])[(1, 2)] == "L1\nL2\n"

    def test_final_line_without_trailing_newline_is_kept(self, tmp_path):
        (tmp_path / "f.py").write_text("L1\nL2")
        assert _read_spans(tmp_path, "f.py", [(1, 2)])[(1, 2)] == "L1\nL2"

    @pytest.mark.parametrize("spans", [
        [], [(0, 5)], [(-1, 5)], [(5, 1)], [(None, 5)], [(1, None)],
        [("1", "5")], [(True, False)],
    ])
    def test_malformed_spans_yield_nothing(self, tmp_path, spans):
        (tmp_path / "f.py").write_text("L1\nL2\n")
        assert not _read_spans(tmp_path, "f.py", spans)


class TestBounds:
    """A large or hostile tree must degrade, not exhaust memory."""

    def test_traversal_is_refused(self, tmp_path):
        assert _read_spans(tmp_path, "../../etc/passwd", [(1, 2)]) is None

    def test_absolute_path_is_refused(self, tmp_path):
        assert _read_spans(tmp_path, "/etc/passwd", [(1, 2)]) is None

    def test_missing_file_is_refused(self, tmp_path):
        assert _read_spans(tmp_path, "nope.py", [(1, 2)]) is None

    def test_binary_looking_file_is_refused(self, tmp_path):
        (tmp_path / "b.py").write_bytes(b"def f():\n" + b"\0" * 100)
        assert _read_spans(tmp_path, "b.py", [(1, 2)]) is None

    def test_oversized_file_is_refused(self, tmp_path):
        (tmp_path / "big.py").write_text("x\n" * ((_MAX_HYDRATED_FILE_BYTES // 2) + 10))
        assert _read_spans(tmp_path, "big.py", [(1, 2)]) is None

    def test_oversized_function_is_abandoned(self, tmp_path):
        line = "y" * 1024 + "\n"
        n = (_MAX_HYDRATED_FUNCTION_BYTES // len(line)) + 50
        (tmp_path / "f.py").write_text(line * n)
        assert not _read_spans(tmp_path, "f.py", [(1, n)])

    def test_budget_is_charged_during_accumulation(self, tmp_path):
        """The ceiling must bound peak, not merely be checked afterwards."""
        (tmp_path / "f.py").write_text("x = 1\n" * 5000)
        spans = [(i * 10 + 1, i * 10 + 5) for i in range(400)]
        got = _read_spans(tmp_path, "f.py", spans, budget_bytes=500)
        retained = sum(len(v.encode("utf-8")) for v in got.values())
        assert retained <= 500

    def test_per_function_line_cap_skips_the_gap(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "h0.py").write_text("x\n" * 5000)
        assert hydrate_live_gaps_for_detectors(
            [_gap(0, line_start=1, line_end=4000)], tmp_path,
        ) == []


@pytest.mark.slow
class TestScalesToManySpans:
    """Guards the active-set sweep against regressing to O(lines x spans)."""

    def test_many_spans_over_a_large_file_is_fast(self, tmp_path):
        (tmp_path / "f.py").write_text("x = 1\n" * 200_000)
        spans = [(i * 10 + 1, i * 10 + 5) for i in range(2000)]
        started = time.monotonic()
        got = _read_spans(tmp_path, "f.py", spans)
        elapsed = time.monotonic() - started
        assert len(got) == 2000
        # The per-line-per-span scan takes ~0.7s here; the sweep ~0.005s.
        # 1.0s gives loaded CI runners headroom while still catching
        # the quadratic O(lines x spans) regression.
        assert elapsed < 1.0, f"took {elapsed:.3f}s — sweep may have regressed"


class TestMalformedInputIsSurvivable:
    """Hydration runs before the review loop; it must not abort the run."""

    @pytest.mark.parametrize("gap", [
        {}, {"file": "src/h0.py"}, {"line_start": 1, "line_end": 3},
        {"file": None, "line_start": 1, "line_end": 3},
        {"file": "src/h0.py", "line_start": None, "line_end": 3},
        {"file": "src/h0.py", "line_start": "1", "line_end": "3"},
        {"file": "src/h0.py", "line_start": 5, "line_end": 1},
        {"file": "src/h0.py", "line_start": True, "line_end": 3},
        {"file": "", "line_start": 1, "line_end": 3},
    ])
    def test_malformed_gap_does_not_raise(self, tmp_path, gap):
        _tree(tmp_path, n=1)
        assert isinstance(hydrate_live_gaps_for_detectors([gap], tmp_path), list)

    def test_one_bad_gap_does_not_discard_the_batch(self, tmp_path):
        _tree(tmp_path, n=2)
        out = hydrate_live_gaps_for_detectors([{}, _gap(0), {"file": None}], tmp_path)
        assert [g["name"] for g in out] == ["handle_0"]

    def test_empty_input(self, tmp_path):
        assert hydrate_live_gaps_for_detectors([], tmp_path) == []


class TestSweepMatchesNaiveExtraction:
    """Differential test of the active-set sweep.

    The sweep exists for speed; correctness must be identical to simply
    slicing the file. Random span configurations cover the cases that
    are easy to get wrong by hand: overlapping, nested, duplicate and
    adjacent spans, spans starting on line 1, spans running past EOF,
    and files with no trailing newline.
    """

    @staticmethod
    def _naive(path, spans):
        """Reference semantics: slice the file; drop spans past EOF.

        Spans that never reach their declared end line are abandoned
        rather than returned partially — see
        ``test_span_past_eof_is_abandoned``.
        """
        lines = path.read_text(errors="replace").splitlines(keepends=True)
        out = {}
        for s, e in sorted({
            (int(a), int(b)) for a, b in spans
            if isinstance(a, int) and not isinstance(a, bool)
            and isinstance(b, int) and not isinstance(b, bool)
            and a > 0 and b >= a
        }):
            if e > len(lines):
                continue
            body = "".join(lines[s - 1:e])
            if body:
                out[(s, e)] = body
        return out

    @pytest.mark.parametrize("seed", range(25))
    def test_matches_naive(self, tmp_path, seed):
        import random
        rng = random.Random(seed)
        n = rng.randint(1, 60)
        text = "".join(f"line{i}\n" for i in range(1, n + 1))
        if seed % 2 and text.endswith("\n"):
            text = text[:-1]                      # no trailing newline
        f = tmp_path / "f.py"
        f.write_text(text)

        spans = [(1, 1), (1, n)]
        for _ in range(rng.randint(1, 12)):
            a = rng.randint(1, n + 3)
            spans.append((a, a + rng.randint(0, n)))   # may run past EOF
        spans += spans[:2]                              # duplicates

        assert (_read_spans(tmp_path, "f.py", spans) or {}) == self._naive(f, spans)


class TestBudgetAccounting:
    """The retained-byte ceiling must reflect what is actually held."""

    def test_duplicate_spans_are_charged_once(self, tmp_path):
        """Several gaps can share one span; they share one string.

        Charging per gap would overstate the total and, with enough
        duplicates, breach the ceiling on paper while nothing extra is
        retained.
        """
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "h0.py").write_text(ADHERENT.format(i=0))
        gaps = [_gap(0, name=f"dup{n}") for n in range(50)]
        out = hydrate_live_gaps_for_detectors(gaps, tmp_path)
        assert len(out) == 50
        bodies = {id(g["source"]) for g in out}
        assert len(bodies) == 1, "duplicates should share one string object"

    def test_abandoned_span_refunds_its_buffered_bytes(self, tmp_path):
        """An abandoned body retains nothing, so it must stop charging.

        Without the refund, oversized spans early in a file starve valid
        later spans in the same file.
        """
        big = "z" * 2048 + "\n"
        (tmp_path / "f.py").write_text(big * 200 + "small\n" * 10)
        oversized = (1, 200)
        small = (201, 205)
        got = _read_spans(
            tmp_path, "f.py", [oversized, small],
            budget_bytes=_MAX_HYDRATED_FUNCTION_BYTES + 1024,
        )
        assert oversized not in got
        assert small in got, "later span starved by an abandoned earlier one"

    def test_tight_budget_is_order_deterministic(self, tmp_path):
        (tmp_path / "f.py").write_text("x = 1\n" * 500)
        spans = [(1, 50), (10, 60), (20, 70)]
        runs = {
            tuple(sorted(_read_spans(tmp_path, "f.py", spans, budget_bytes=200) or {}))
            for _ in range(8)
        }
        assert len(runs) == 1, f"nondeterministic under a tight budget: {runs}"


class TestBinaryProbeIsBestEffort:
    def test_nul_within_probe_window_is_refused(self, tmp_path):
        (tmp_path / "b.py").write_bytes(b"x\n" * 100 + b"\0" + b"y\n" * 100)
        assert _read_spans(tmp_path, "b.py", [(1, 2)]) is None

    def test_nul_past_probe_window_is_not_caught(self, tmp_path):
        """Documents the limitation rather than overclaiming.

        The NUL probe reads the first 8 KiB only. It is a cheap filter,
        not a guarantee — pinned so the docstring stays honest.
        """
        (tmp_path / "b.py").write_bytes(b"x\n" * 8192 + b"\0" * 10)
        assert _read_spans(tmp_path, "b.py", [(1, 2)]) is not None


class TestReadGapSource:
    """Unit tests for the shared read_gap_source() helper."""

    def test_reads_span(self, tmp_path):
        (tmp_path / "a.py").write_text("line1\nline2\nline3\n")
        gap = {"file": "a.py", "line_start": 2, "line_end": 3}
        src = read_gap_source(gap, tmp_path)
        assert "line2" in src
        assert "line3" in src

    def test_missing_file(self, tmp_path):
        gap = {"file": "nope.py", "line_start": 1, "line_end": 2}
        assert read_gap_source(gap, tmp_path) == ""

    def test_path_traversal(self, tmp_path):
        gap = {"file": "../etc/passwd", "line_start": 1, "line_end": 2}
        assert read_gap_source(gap, tmp_path) == ""

    def test_none_line_end(self, tmp_path):
        (tmp_path / "a.py").write_text("hello\n")
        gap = {"file": "a.py", "line_start": 1, "line_end": None}
        assert read_gap_source(gap, tmp_path) == ""

    def test_bool_line_start(self, tmp_path):
        (tmp_path / "a.py").write_text("hello\n")
        gap = {"file": "a.py", "line_start": True, "line_end": 2}
        assert read_gap_source(gap, tmp_path) == ""

    def test_zero_line_start(self, tmp_path):
        (tmp_path / "a.py").write_text("hello\n")
        gap = {"file": "a.py", "line_start": 0, "line_end": 2}
        assert read_gap_source(gap, tmp_path) == ""

    def test_reversed_span(self, tmp_path):
        (tmp_path / "a.py").write_text("line1\nline2\n")
        gap = {"file": "a.py", "line_start": 3, "line_end": 1}
        assert read_gap_source(gap, tmp_path) == ""

    def test_empty_file_path(self, tmp_path):
        gap = {"file": "", "line_start": 1, "line_end": 2}
        assert read_gap_source(gap, tmp_path) == ""

    def test_refuses_binary_file(self, tmp_path):
        (tmp_path / "b.bin").write_bytes(b"\x00" * 100 + b"text\n" * 10)
        gap = {"file": "b.bin", "line_start": 1, "line_end": 2}
        assert read_gap_source(gap, tmp_path) == ""

    def test_no_file_key(self, tmp_path):
        gap = {"line_start": 1, "line_end": 2}
        assert read_gap_source(gap, tmp_path) == ""
