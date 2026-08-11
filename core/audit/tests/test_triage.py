"""Tests for core.audit.triage — 4-bucket triage classifier."""

from core.audit.prefilter import PrefilterResult
from core.audit.triage import (
    TOKEN_BUDGETS,
    TriageBucket,
    TriageResult,
    classify_all,
    classify_function,
    detect_generated_files,
    format_triage_summary,
)


class TestClassifyFunction:
    def test_prefilter_skip_maps_to_skip(self):
        pf = PrefilterResult(file="a.c", function="f", skip_llm=True, skip_reason="simple accessor")
        r = classify_function(file="a.c", function="f", prefilter=pf)
        assert r.bucket == TriageBucket.SKIP
        assert "prefilter" in r.reasons[0]

    def test_sink_unreachable_small_no_danger_is_skip(self):
        r = classify_function(
            file="a.c", function="f",
            sink_unreachable=True, sloc=10,
            has_dangerous_callees=False,
        )
        assert r.bucket == TriageBucket.SKIP

    def test_sink_unreachable_but_entry_point_not_skip(self):
        r = classify_function(
            file="a.c", function="f",
            sink_unreachable=True, sloc=10,
            is_entry_point=True,
        )
        assert r.bucket != TriageBucket.SKIP

    def test_sink_unreachable_but_large_not_skip(self):
        r = classify_function(
            file="a.c", function="f",
            sink_unreachable=True, sloc=50,
        )
        assert r.bucket != TriageBucket.SKIP

    def test_binary_absent_plus_sink_unreachable_is_skip(self):
        r = classify_function(
            file="a.c", function="f",
            binary_absent=True, sink_unreachable=True, sloc=100,
        )
        assert r.bucket == TriageBucket.SKIP

    def test_entry_point_is_deep_dive(self):
        r = classify_function(file="a.c", function="f", is_entry_point=True)
        assert r.bucket == TriageBucket.DEEP_DIVE
        assert "entry point" in r.reasons

    def test_sink_is_deep_dive(self):
        r = classify_function(file="a.c", function="f", is_sink=True)
        assert r.bucket == TriageBucket.DEEP_DIVE

    def test_trust_boundary_is_deep_dive(self):
        r = classify_function(file="a.c", function="f", is_trust_boundary=True)
        assert r.bucket == TriageBucket.DEEP_DIVE

    def test_joern_flows_is_deep_dive(self):
        r = classify_function(file="a.c", function="f", has_joern_flows=True)
        assert r.bucket == TriageBucket.DEEP_DIVE

    def test_large_function_is_deep_dive(self):
        r = classify_function(file="a.c", function="f", sloc=250)
        assert r.bucket == TriageBucket.DEEP_DIVE
        assert "large" in r.reasons[0]

    def test_high_complexity_is_deep_dive(self):
        r = classify_function(file="a.c", function="f", branch_count=20)
        assert r.bucket == TriageBucket.DEEP_DIVE

    def test_widely_called_sink_is_deep_dive(self):
        r = classify_function(
            file="a.c", function="f",
            is_sink=True, caller_count=10,
        )
        assert r.bucket == TriageBucket.DEEP_DIVE

    def test_taint_path_is_investigate(self):
        r = classify_function(file="a.c", function="f", on_taint_path=True, sloc=15)
        assert r.bucket == TriageBucket.INVESTIGATE

    def test_dangerous_callees_is_investigate(self):
        r = classify_function(
            file="a.c", function="f",
            has_dangerous_callees=True, sloc=15,
        )
        assert r.bucket == TriageBucket.INVESTIGATE

    def test_moderate_size_is_investigate(self):
        r = classify_function(file="a.c", function="f", sloc=50)
        assert r.bucket == TriageBucket.INVESTIGATE

    def test_small_clean_is_glance(self):
        r = classify_function(file="a.c", function="f", sloc=10)
        assert r.bucket == TriageBucket.GLANCE

    def test_zero_sloc_is_glance(self):
        r = classify_function(file="a.c", function="f", sloc=0)
        assert r.bucket == TriageBucket.GLANCE

    def test_token_budgets_match(self):
        for bucket in TriageBucket:
            assert bucket in TOKEN_BUDGETS

    def test_skip_budget_is_zero(self):
        assert TOKEN_BUDGETS[TriageBucket.SKIP] == 0

    def test_deep_dive_budget_largest(self):
        assert TOKEN_BUDGETS[TriageBucket.DEEP_DIVE] > TOKEN_BUDGETS[TriageBucket.INVESTIGATE]
        assert TOKEN_BUDGETS[TriageBucket.INVESTIGATE] > TOKEN_BUDGETS[TriageBucket.GLANCE]
        assert TOKEN_BUDGETS[TriageBucket.GLANCE] > TOKEN_BUDGETS[TriageBucket.SKIP]

    def test_priority_score_preserved(self):
        r = classify_function(file="a.c", function="f", sloc=10, priority_score=42.5)
        assert r.priority_score == 42.5

    def test_multiple_deep_dive_reasons(self):
        r = classify_function(
            file="a.c", function="f",
            is_entry_point=True, is_sink=True, sloc=300,
        )
        assert r.bucket == TriageBucket.DEEP_DIVE
        assert len(r.reasons) >= 3


class TestClassifyAll:
    def test_empty(self):
        assert classify_all([]) == {}

    def test_basic_classification(self):
        gaps = [
            {"file": "a.c", "name": "main", "sloc": 10, "line_start": 1},
            {"file": "b.c", "name": "parse", "sloc": 10, "line_start": 1},
        ]
        results = classify_all(
            gaps,
            entry_points=frozenset({"a.c:main"}),
        )
        assert results["a.c:main:1"].bucket == TriageBucket.DEEP_DIVE
        assert results["b.c:parse:1"].bucket == TriageBucket.GLANCE

    def test_sink_unreachable_from_set(self):
        gaps = [{"file": "a.c", "name": "util", "sloc": 10, "line_start": 5}]
        results = classify_all(
            gaps,
            sink_unreachable_keys=frozenset({"a.c:util"}),
        )
        assert results["a.c:util:5"].bucket == TriageBucket.SKIP

    def test_priority_scores_forwarded(self):
        gaps = [{"file": "a.c", "name": "f", "sloc": 10, "line_start": 1}]
        results = classify_all(
            gaps,
            priority_scores={"a.c:f": 15.0},
        )
        assert results["a.c:f:1"].priority_score == 15.0

    def test_sloc_from_line_range(self):
        gaps = [{"file": "a.c", "name": "big", "line_start": 10, "line_end": 250}]
        results = classify_all(gaps)
        assert results["a.c:big:10"].bucket == TriageBucket.DEEP_DIVE

    def test_all_signals_combined(self):
        gaps = [
            {"file": "a.c", "name": "entry", "sloc": 50, "line_start": 1},
            {"file": "b.c", "name": "leaf", "sloc": 5, "line_start": 1},
            {"file": "c.c", "name": "middle", "sloc": 40, "line_start": 1},
            {"file": "d.c", "name": "dead", "sloc": 15, "line_start": 1},
        ]
        results = classify_all(
            gaps,
            entry_points=frozenset({"a.c:entry"}),
            sink_unreachable_keys=frozenset({"d.c:dead"}),
            taint_path_keys=frozenset({"c.c:middle"}),
        )
        assert results["a.c:entry:1"].bucket == TriageBucket.DEEP_DIVE
        assert results["b.c:leaf:1"].bucket == TriageBucket.GLANCE
        assert results["c.c:middle:1"].bucket == TriageBucket.INVESTIGATE
        assert results["d.c:dead:1"].bucket == TriageBucket.SKIP

    def test_same_name_different_lines_no_collision(self):
        """Methods with the same name at different lines get separate keys."""
        gaps = [
            {"file": "sql.go", "name": "Scan", "sloc": 8, "line_start": 193},
            {"file": "sql.go", "name": "Scan", "sloc": 28, "line_start": 3232},
        ]
        results = classify_all(gaps)
        assert "sql.go:Scan:193" in results
        assert "sql.go:Scan:3232" in results
        assert results["sql.go:Scan:193"].bucket == TriageBucket.GLANCE
        assert results["sql.go:Scan:3232"].bucket == TriageBucket.INVESTIGATE


class TestFormatTriageSummary:
    def test_empty(self):
        assert "no functions" in format_triage_summary({})

    def test_all_buckets(self):
        results = {
            "a:f1": TriageResult(TriageBucket.SKIP, (), 0),
            "a:f2": TriageResult(TriageBucket.SKIP, (), 0),
            "a:f3": TriageResult(TriageBucket.GLANCE, (), 500),
            "a:f4": TriageResult(TriageBucket.INVESTIGATE, (), 6000),
            "a:f5": TriageResult(TriageBucket.DEEP_DIVE, (), 25000),
        }
        summary = format_triage_summary(results)
        assert "5 functions" in summary
        assert "skip=2" in summary
        assert "glance=1" in summary
        assert "investigate=1" in summary
        assert "deep_dive=1" in summary


# ── Generated code detection ─────────────────────────────────────────


class TestGeneratedCode:
    def test_detects_pb2_extension(self):
        gaps = [
            {"name": "f", "file": "schema_pb2.py", "source": "generated code"},
        ]
        assert "schema_pb2.py" in detect_generated_files(gaps)

    def test_detects_marker_in_source(self):
        gaps = [
            {
                "name": "f",
                "file": "client.py",
                "source": "# DO NOT EDIT - generated by openapi-generator\ndef get(): pass",
            },
        ]
        assert "client.py" in detect_generated_files(gaps)

    def test_no_false_positive(self):
        gaps = [
            {"name": "f", "file": "real_code.py", "source": "def handler(): return 42"},
        ]
        assert detect_generated_files(gaps) == []

    def test_deduplicates_files(self):
        gaps = [
            {"name": "f1", "file": "gen_pb2.py", "source": ""},
            {"name": "f2", "file": "gen_pb2.py", "source": ""},
        ]
        assert len(detect_generated_files(gaps)) == 1


class TestGeneratedCodeFromDisk:
    def test_hydrates_from_target_path(self, tmp_path):
        src = tmp_path / "client.py"
        src.write_text("# DO NOT EDIT - generated by codegen\ndef get(): pass\n")
        gaps = [{"name": "get", "file": "client.py"}]
        result = detect_generated_files(gaps, target_path=tmp_path)
        assert "client.py" in result

    def test_skips_when_no_target_path(self):
        gaps = [{"name": "get", "file": "client.py"}]
        result = detect_generated_files(gaps)
        assert result == []

    def test_skips_missing_file(self, tmp_path):
        gaps = [{"name": "get", "file": "gone.py"}]
        result = detect_generated_files(gaps, target_path=tmp_path)
        assert result == []

    def test_skips_path_traversal(self, tmp_path):
        (tmp_path / "outside").mkdir()
        secret = tmp_path / "outside" / "secret.py"
        secret.write_text("# DO NOT EDIT\n")
        gaps = [{"name": "f", "file": "../outside/secret.py"}]
        result = detect_generated_files(gaps, target_path=tmp_path / "repo")
        assert result == []

    def test_prefers_gap_source_over_disk(self, tmp_path):
        src = tmp_path / "real.py"
        src.write_text("# DO NOT EDIT - generated\n")
        gaps = [{"name": "f", "file": "real.py", "source": "def handler(): return 42"}]
        result = detect_generated_files(gaps, target_path=tmp_path)
        assert result == []

    def test_extension_match_skips_disk_read(self, tmp_path):
        gaps = [{"name": "f", "file": "schema_pb2.py"}]
        result = detect_generated_files(gaps, target_path=tmp_path)
        assert "schema_pb2.py" in result
