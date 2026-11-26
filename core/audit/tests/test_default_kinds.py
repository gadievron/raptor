"""Default-included item kinds in gap computation.

Module-level code, macros, and globals enter gap computation by
DEFAULT (the extractor built them as reviewable units; the audit used
to drop them unless an undocumented flag opted in). ``--include-kinds``
still overrides: a positive list replaces the default extras, ``-kind``
opts a single kind out, and ``none`` restores functions/methods only.
"""

from __future__ import annotations

from core.audit.gaps import (
    _DEFAULT_EXTRA_KINDS,
    _REVIEWABLE_KINDS,
    _resolve_reviewable_kinds,
    compute_gaps,
)


def _checklist():
    return {
        "files": [{
            "path": "m.c",
            "items": [
                {"name": "handler", "kind": "function",
                 "line_start": 1, "line_end": 30},
                {"name": "UNSAFE_COPY", "kind": "macro",
                 "line_start": 32, "line_end": 36},
                {"name": "g_table", "kind": "global",
                 "line_start": 38, "line_end": 40},
                {"name": "m.c::top_level", "kind": "top_level",
                 "line_start": 42, "line_end": 60},
                {"name": "interstitial:61-70", "kind": "interstitial",
                 "line_start": 61, "line_end": 70},
                {"name": "Widget", "kind": "class",
                 "line_start": 71, "line_end": 90},
                {"name": "tty_flag", "kind": "declaration",
                 "line_start": 91, "line_end": 91},
                {"name": "MKTEMP_NAME", "kind": "constant_macro",
                 "line_start": 93, "line_end": 93},
            ],
        }],
    }


class TestResolveReviewableKinds:
    def test_default_adds_extras(self):
        kinds = _resolve_reviewable_kinds(None)
        assert kinds == _REVIEWABLE_KINDS | _DEFAULT_EXTRA_KINDS

    def test_positive_list_overrides_extras(self):
        kinds = _resolve_reviewable_kinds({"top_level"})
        assert "top_level" in kinds
        assert "macro" not in kinds
        assert "global" not in kinds
        assert "function" in kinds

    def test_exclusion_syntax_opts_out_one_default(self):
        kinds = _resolve_reviewable_kinds({"-macro"})
        assert "macro" not in kinds
        assert "top_level" in kinds
        assert "global" in kinds

    def test_none_restores_functions_only(self):
        assert _resolve_reviewable_kinds({"none"}) == _REVIEWABLE_KINDS

    def test_mixed_include_and_exclude(self):
        kinds = _resolve_reviewable_kinds({"top_level", "-top_level"})
        assert "top_level" not in kinds
        assert "function" in kinds

    def test_extraction_artifact_kinds_excluded_by_default(self):
        # declaration / constant_macro are in NEITHER base set: pure
        # declarations and object-like literal macros are not
        # reviewable code.
        kinds = _resolve_reviewable_kinds(None)
        assert "declaration" not in kinds
        assert "constant_macro" not in kinds

    def test_extraction_artifact_kinds_opt_in(self):
        kinds = _resolve_reviewable_kinds({"declaration", "constant_macro"})
        assert "declaration" in kinds
        assert "constant_macro" in kinds
        assert "function" in kinds


class TestDefaultKindGaps:
    def test_macros_globals_top_level_are_gaps_by_default(self):
        names = {g["name"] for g in compute_gaps(_checklist(), [])}
        assert {"handler", "UNSAFE_COPY", "g_table", "m.c::top_level"} <= names
        # Non-Rust class shells and anonymous residue stay out by default.
        assert "interstitial:61-70" not in names
        assert "Widget" not in names

    def test_opt_out_via_exclusion(self):
        names = {g["name"]
                 for g in compute_gaps(_checklist(), [],
                                       include_kinds={"-macro", "-global"})}
        assert "UNSAFE_COPY" not in names
        assert "g_table" not in names
        assert "m.c::top_level" in names

    def test_declaration_and_constant_macro_not_gaps_by_default(self):
        names = {g["name"] for g in compute_gaps(_checklist(), [])}
        assert "tty_flag" not in names
        assert "MKTEMP_NAME" not in names

    def test_declaration_and_constant_macro_includable(self):
        names = {g["name"]
                 for g in compute_gaps(
                     _checklist(), [],
                     include_kinds={"declaration", "constant_macro"})}
        assert "tty_flag" in names
        assert "MKTEMP_NAME" in names

    def test_batch_path_handles_new_kinds(self):
        """The GLANCE batching path keys on SLOC, not kind — small
        default-included items classify into the batchable GLANCE
        bucket like any small function."""
        from core.audit.triage import TriageBucket, classify_all

        gaps = compute_gaps(_checklist(), [])
        results = classify_all(gaps)
        macro_gap = next(g for g in gaps if g["name"] == "UNSAFE_COPY")
        key = (f"{macro_gap['file']}:{macro_gap['name']}"
               f":{macro_gap['line_start']}")
        assert results[key].bucket == TriageBucket.GLANCE

    def test_new_kinds_carry_priority_and_strategies(self):
        for gap in compute_gaps(_checklist(), []):
            assert isinstance(gap["priority"], int)
            assert isinstance(gap["strategies"], list)


class TestWorkflowStepDispatchExclusion:
    """CI workflow jobs/steps (kind "function", names ``job:<id>`` /
    ``job:<id>.step-<n>``) are scanner territory: the coverage summary
    already excludes them from the review denominator, and they must
    not reach paid review dispatch either (observed live: workflow VM
    jobs got full LLM reviews)."""

    def _checklist(self, tmp_path):
        target = tmp_path / "t"
        (target / ".github" / "workflows").mkdir(parents=True)
        (target / ".github" / "workflows" / "vm.yml").write_text(
            "jobs:\n  omnios:\n    steps:\n      - run: make\n"
        )
        (target / "a.c").write_text("int f(void) { return 1; }\n")
        return target, {
            "target_path": str(target),
            "files": [
                {
                    "path": ".github/workflows/vm.yml",
                    "language": "yaml",
                    "items": [
                        {"name": "job:omnios", "kind": "function",
                         "line_start": 2, "line_end": 4},
                        {"name": "job:omnios.step-1", "kind": "function",
                         "line_start": 4, "line_end": 4},
                    ],
                },
                {
                    "path": "a.c",
                    "language": "c",
                    "items": [
                        {"name": "f", "kind": "function",
                         "line_start": 1, "line_end": 1},
                    ],
                },
            ],
        }

    def test_workflow_items_not_dispatched(self, tmp_path):
        from core.audit.gaps import compute_gaps
        target, checklist = self._checklist(tmp_path)
        gaps = compute_gaps(checklist, [])
        names = {g["name"] for g in gaps}
        assert "f" in names
        assert not any(n.startswith("job:") for n in names), (
            "workflow jobs/steps must not reach review dispatch"
        )

    def test_non_workflow_job_named_function_survives(self, tmp_path):
        """A C function that HAPPENS to be named job:x cannot exist
        (invalid identifier), but a yaml-language gate plus path gate
        means a job:-prefixed name outside workflow contexts is kept."""
        from core.audit.gaps import compute_gaps
        target, checklist = self._checklist(tmp_path)
        checklist["files"].append({
            "path": "tools/pipeline.c",
            "language": "c",
            "items": [
                {"name": "job:handler", "kind": "function",
                 "line_start": 1, "line_end": 3},
            ],
        })
        gaps = compute_gaps(checklist, [])
        assert "job:handler" in {g["name"] for g in gaps}


def test_named_coverage_projection_intake_ignores_malformed_item_lists():
    from core.audit.gaps import _build_covered_set
    for items in (None, 12, {}, 'bad'):
        checklist = {"files": [{"path": "ffi.rs", "items": items}]}
        assert _build_covered_set([], checklist=checklist) == set()
