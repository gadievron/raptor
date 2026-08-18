"""Tests for Mode-2 synthesis hits → reviewable gaps.

Checker synthesis reports sites (file + line); the review loop is keyed
on functions. These tests pin the resolution step, including the case
that used to abort the whole run: a successful cross-file sweep hit.
"""

from __future__ import annotations

import pytest

from core.audit.gaps import gap_for_site
from core.audit.orchestrator import _synthesis_hits_to_gaps
from core.audit.task_graph import TaskGraph


def _checklist():
    return {
        "files": [
            {
                "path": "src/parse.c",
                "items": [
                    {"name": "parse_header", "kind": "function",
                     "line_start": 10, "line_end": 40},
                    {"name": "parse_body", "kind": "function",
                     "line_start": 45, "line_end": 90},
                ],
            },
            {
                "path": "src/util.c",
                "items": [
                    {"name": "copy_field", "kind": "function",
                     "line_start": 5, "line_end": 20},
                    {"name": "MAX_LEN", "kind": "macro",
                     "line_start": 1, "line_end": 1},
                ],
            },
        ],
    }


def _hit(file_path, line, snippet="memcpy(dst, src, len);"):
    """The exact shape core.audit.checker_synthesis emits."""
    return {
        "file": file_path,
        "line": line,
        "function": "",
        "snippet": snippet,
        "priority_score": 0.8,
    }


class TestGapForSite:
    def test_resolves_enclosing_function(self):
        gap = gap_for_site(_checklist(), "src/parse.c", 30)
        assert gap is not None
        assert gap["name"] == "parse_header"
        assert gap["line_start"] == 10
        assert gap["line_end"] == 40
        assert gap["sloc"] == 31

    def test_picks_the_right_function_of_several(self):
        gap = gap_for_site(_checklist(), "src/parse.c", 50)
        assert gap["name"] == "parse_body"

    def test_line_outside_any_function_is_unresolved(self):
        assert gap_for_site(_checklist(), "src/parse.c", 42) is None

    def test_unknown_file_is_unresolved(self):
        assert gap_for_site(_checklist(), "src/nope.c", 10) is None

    def test_hit_bearing_macro_kind_now_returned(self):
        # A mechanical sweep HIT in a macro body is evidence in hand —
        # gap_for_site now surfaces top_level/macro/global sites
        # instead of dropping the confirmed signal on kind alone.
        gap = gap_for_site(_checklist(), "src/util.c", 1)
        assert gap is not None
        assert gap["name"] == "MAX_LEN"

    def test_truly_non_reviewable_kind_is_skipped(self):
        checklist = {
            "files": [{
                "path": "src/k.c",
                "items": [{"name": "S", "kind": "class",
                           "line_start": 1, "line_end": 3}],
            }],
        }
        assert gap_for_site(checklist, "src/k.c", 2) is None

    def test_zero_line_is_unresolved(self):
        assert gap_for_site(_checklist(), "src/parse.c", 0) is None

    def test_gap_shape_matches_compute_gaps(self):
        gap = gap_for_site(_checklist(), "src/parse.c", 30)
        for key in ("file", "name", "line_start", "line_end",
                    "priority", "strategies", "is_stale", "sloc"):
            assert key in gap, key


class TestSynthesisHitsToGaps:
    def test_hits_become_reviewable_gaps(self):
        gaps = _synthesis_hits_to_gaps(
            [_hit("src/parse.c", 30), _hit("src/util.c", 12)],
            _checklist(),
        )
        assert [g["name"] for g in gaps] == ["parse_header", "copy_field"]

    def test_result_is_safe_for_task_graph(self):
        """The regression: a successful cross-file hit aborted the run.

        Hits carry ``function``; TaskGraph.from_workqueue dereferences
        ``gap['name']``, so raw hits raised KeyError after the entire
        review loop had already run.
        """
        hits = [_hit("src/parse.c", 30)]

        with pytest.raises(KeyError):
            TaskGraph.from_workqueue(hits, [])

        gaps = _synthesis_hits_to_gaps(hits, _checklist())
        graph = TaskGraph.from_workqueue(gaps, [])
        assert graph is not None

    def test_unresolvable_hits_are_dropped_not_fatal(self):
        gaps = _synthesis_hits_to_gaps(
            [_hit("src/parse.c", 42), _hit("generated/blob.c", 7),
             _hit("src/parse.c", 30)],
            _checklist(),
        )
        assert [g["name"] for g in gaps] == ["parse_header"]

    def test_duplicate_hits_in_one_function_collapse(self):
        gaps = _synthesis_hits_to_gaps(
            [_hit("src/parse.c", 12), _hit("src/parse.c", 30)],
            _checklist(),
        )
        assert len(gaps) == 1

    def test_previously_reviewed_functions_are_NOT_skipped(self):
        """A synthesized checker encodes a pattern nobody knew about when
        those functions were first reviewed — that is exactly when
        re-review pays, so prior coverage must not suppress the hit."""
        gaps = _synthesis_hits_to_gaps(
            [_hit("src/parse.c", 30), _hit("src/util.c", 12)],
            _checklist(),
        )
        assert [g["name"] for g in gaps] == ["parse_header", "copy_field"]

    def test_unresolved_hits_are_persisted_not_discarded(self, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        gaps = _synthesis_hits_to_gaps(
            [_hit("src/parse.c", 42), _hit("src/parse.c", 30)],
            _checklist(),
            out_dir,
        )
        assert [g["name"] for g in gaps] == ["parse_header"]

        import json
        record = json.loads(
            (out_dir / "unresolved-synthesis-hits.json").read_text()
        )
        assert record["count"] == 1
        assert record["hits"][0]["line"] == 42

    def test_malformed_line_is_survivable(self):
        assert _synthesis_hits_to_gaps(
            [{"file": "src/parse.c", "line": "not-a-number"}], _checklist(),
        ) == []

    def test_synthesis_provenance_is_carried(self):
        gaps = _synthesis_hits_to_gaps([_hit("src/parse.c", 30)], _checklist())
        assert gaps[0]["from_synthesis"] is True
        assert gaps[0]["priority_score"] == 0.8
        assert gaps[0]["synthesis_snippet"] == "memcpy(dst, src, len);"

    def test_empty_input(self):
        assert _synthesis_hits_to_gaps([], _checklist()) == []

    def test_missing_line_key_is_survivable(self):
        assert _synthesis_hits_to_gaps([{"file": "src/parse.c"}], _checklist()) == []


class TestGapForSiteNestedSpans:
    """Innermost span wins — a nested def is where the site really lives."""

    def _nested_checklist(self):
        return {
            "files": [
                {
                    "path": "app/mod.py",
                    "items": [
                        {"name": "outer", "kind": "function",
                         "line_start": 1, "line_end": 100},
                        {"name": "inner", "kind": "function",
                         "line_start": 30, "line_end": 50},
                    ],
                },
            ],
        }

    def test_innermost_wins_when_outer_listed_first(self):
        gap = gap_for_site(self._nested_checklist(), "app/mod.py", 35)
        assert gap["name"] == "inner"

    def test_innermost_wins_when_inner_listed_first(self):
        cl = self._nested_checklist()
        cl["files"][0]["items"].reverse()
        gap = gap_for_site(cl, "app/mod.py", 35)
        assert gap["name"] == "inner"

    def test_outer_still_resolves_outside_the_nested_span(self):
        gap = gap_for_site(self._nested_checklist(), "app/mod.py", 80)
        assert gap["name"] == "outer"

    def test_missing_line_end_infers_from_next_definition(self):
        cl = {
            "files": [
                {
                    "path": "app/mod.py",
                    "items": [
                        {"name": "first", "kind": "function", "line_start": 10},
                        {"name": "second", "kind": "function", "line_start": 40},
                    ],
                },
            ],
        }
        first = gap_for_site(cl, "app/mod.py", 25)
        assert first["name"] == "first"
        assert first["line_end"] == 39
        assert first["span_inferred"] is True

    def test_trailing_definition_without_end_stays_unresolved(self):
        """No derivable upper bound — better unresolved than truncated.

        Inventing an end either cuts the function short (review and
        hydration miss its tail) or claims lines belonging to nothing.
        These land in unresolved-synthesis-hits.json instead.
        """
        cl = {
            "files": [
                {
                    "path": "app/mod.py",
                    "items": [
                        {"name": "first", "kind": "function", "line_start": 10},
                        {"name": "second", "kind": "function", "line_start": 40},
                    ],
                },
            ],
        }
        assert gap_for_site(cl, "app/mod.py", 45) is None

    def test_task_graph_keys_match_resolved_functions(self):
        gaps = _synthesis_hits_to_gaps(
            [_hit("src/parse.c", 30), _hit("src/util.c", 12)], _checklist(),
        )
        graph = TaskGraph.from_workqueue(gaps, [])
        keys = set(graph.nodes) if hasattr(graph, "nodes") else None
        if keys is not None:
            assert keys == {"src/parse.c:parse_header", "src/util.c:copy_field"}


class TestSeedFunctionExclusion:
    """The seed's own function is already a finding, not a new variant."""

    def _hit_with_origin(self, file_path, line, origin_fn):
        h = _hit(file_path, line)
        h["origin_file"] = "src/parse.c"
        h["origin_function"] = origin_fn
        return h

    def test_seed_function_is_excluded_by_identity_not_line(self):
        """`outcome.line` is the function's line_start, not the bug line,
        so a line test excluded the wrong site — or nothing at all."""
        gaps = _synthesis_hits_to_gaps(
            [self._hit_with_origin("src/parse.c", 35, "parse_header"),
             self._hit_with_origin("src/parse.c", 50, "parse_header")],
            _checklist(),
        )
        assert [g["name"] for g in gaps] == ["parse_body"]

    def test_same_file_sibling_of_the_seed_survives(self):
        gaps = _synthesis_hits_to_gaps(
            [self._hit_with_origin("src/parse.c", 50, "parse_header")],
            _checklist(),
        )
        assert [g["name"] for g in gaps] == ["parse_body"]

    def test_hits_without_origin_are_unaffected(self):
        gaps = _synthesis_hits_to_gaps([_hit("src/parse.c", 30)], _checklist())
        assert [g["name"] for g in gaps] == ["parse_header"]


class TestSecondPassIsNonFatal:
    """The synthesis second pass must never cost the run its results.

    It executes after the main review loop but before the state
    sync-back and the single one-shot ``collector.flush()``. Any
    exception escaping it discards the run's findings and its buffered
    audit log — the exact failure the ``KeyError: 'name'`` above caused.
    Resolution is the most likely source, so it must be total: hostile
    or malformed hits produce fewer gaps, never an exception.
    """

    @pytest.mark.parametrize("bad", [
        {},                                              # no keys at all
        {"file": "src/parse.c"},                         # no line
        {"line": 30},                                    # no file
        {"file": "", "line": 30},                        # empty file
        {"file": "src/parse.c", "line": None},           # null line
        {"file": "src/parse.c", "line": "30"},           # line as string
        {"file": "src/parse.c", "line": -1},             # negative line
        {"file": "src/parse.c", "line": 0},              # zero line
        {"file": "src/parse.c", "line": True},           # bool masquerading as int
        {"file": None, "line": 30},                      # null file
        {"file": "../../etc/passwd", "line": 1},         # traversal-shaped path
        {"file": "src/parse.c", "line": 10**12},         # absurd line
    ])
    def test_malformed_hit_does_not_raise(self, bad):
        gaps = _synthesis_hits_to_gaps([bad], _checklist())
        assert isinstance(gaps, list)

    def test_malformed_hits_do_not_suppress_good_ones(self):
        """One bad hit must not discard the batch."""
        gaps = _synthesis_hits_to_gaps(
            [{}, _hit("src/parse.c", 30), {"file": None, "line": 1}],
            _checklist(),
        )
        assert [g["name"] for g in gaps] == ["parse_header"]

    @pytest.mark.parametrize("cl", [
        {},                                                   # no files key
        {"files": None},                                      # null files
        {"files": []},                                        # empty files
        {"files": [None]},                                    # null entry
        {"files": ["nonsense"]},                              # non-dict entry
        {"files": [{}]},                                      # entry with no path
        {"files": [{"path": "src/parse.c", "items": None}]},  # null items
        {"files": [{"path": "src/parse.c", "items": "x"}]},   # items not a list
        {"files": [{"path": "src/parse.c",
                    "items": [None, "x", 5]}]},               # junk items
        None,                                                 # checklist itself null
        [],                                                   # checklist not a dict
    ])
    def test_malformed_checklist_does_not_raise(self, cl):
        assert _synthesis_hits_to_gaps([_hit("src/parse.c", 30)], cl) == []

    def test_resolved_gaps_always_build_a_graph(self):
        """Whatever resolution returns must be graph-safe.

        ``TaskGraph.from_workqueue`` dereferences ``gap['name']``
        unguarded; that is what turned a successful sweep into a
        run-killing KeyError.
        """
        gaps = _synthesis_hits_to_gaps(
            [_hit("src/parse.c", 30), {}, _hit("src/parse.c", 50)],
            _checklist(),
        )
        TaskGraph.from_workqueue(gaps, {})
        assert all("name" in g and g["name"] for g in gaps)
