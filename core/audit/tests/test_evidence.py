"""Tests for core.audit.evidence."""

from __future__ import annotations

from core.evidence import (
    EvidenceRecord,
    _safe_name,
    build_evidence_index,
    format_evidence_prose,
    format_evidence_structured,
    strongest_evidence_tier,
)
from core.evidence import EvidenceTier


class TestSafeName:
    def test_valid_identifier(self):
        assert _safe_name("parse_header") == "parse_header"

    def test_invalid_identifier(self):
        assert _safe_name('"; evil("') == "<invalid-name>"

    def test_empty(self):
        assert _safe_name("") == "<invalid-name>"

    def test_strips_newlines(self):
        assert "\n" not in _safe_name("foo\nbar")

    def test_caps_length(self):
        long_name = "a" * 200
        assert len(_safe_name(long_name)) <= 120


class TestEvidenceRecord:
    def test_has_any_evidence_empty(self):
        rec = EvidenceRecord(file="a.c", function="f")
        assert not rec.has_any_evidence()

    def test_has_any_evidence_with_taint(self):
        rec = EvidenceRecord(file="a.c", function="f")

        class FakeApprox:
            dangerous_flows = {0: [("memcpy", 1)]}
            params = ["buf"]
            has_opaque_flow = False
            def has_any_dangerous(self):
                return True

        rec.taint_approx = FakeApprox()
        assert rec.has_any_evidence()

    def test_all_joern_flows_merges(self):
        rec = EvidenceRecord(file="a.c", function="f")
        rec.joern_flows = ["flow1"]
        rec.imported_joern_flows = ["flow2"]
        assert rec.all_joern_flows() == ["flow1", "flow2"]


class TestFormatEvidenceProse:
    def test_empty_record(self):
        rec = EvidenceRecord(file="a.c", function="f")
        assert format_evidence_prose(rec) == ""

    def test_taint_approx_flows(self):
        rec = EvidenceRecord(file="a.c", function="f")

        class FakeApprox:
            dangerous_flows = {0: [("memcpy", 1)]}
            params = ["buf"]
            has_opaque_flow = False

        rec.taint_approx = FakeApprox()
        prose = format_evidence_prose(rec)
        assert "## Mechanical pre-sweep results" in prose
        assert "`buf`" in prose
        assert "`memcpy`" in prose
        assert "AST-level" in prose

    def test_opaque_flow_noted(self):
        rec = EvidenceRecord(file="a.c", function="f")

        class FakeApprox:
            dangerous_flows = {}
            params = []
            has_opaque_flow = True

        rec.taint_approx = FakeApprox()
        prose = format_evidence_prose(rec)
        assert "opaque flow" in prose

    def test_joern_flows(self):
        rec = EvidenceRecord(file="a.c", function="f")

        class FakeFlow:
            source_method = "parse_header"
            source_param = "len"
            sink_call = "memcpy"
            steps = [1, 2, 3]
            is_inter_procedural = True

        rec.joern_flows = [FakeFlow()]
        prose = format_evidence_prose(rec)
        assert "inter-procedural" in prose
        assert "`len`" in prose
        assert "Joern CPG" in prose

    def test_codeql_alerts(self):
        rec = EvidenceRecord(file="a.c", function="f")
        rec.codeql_alerts = [{"rule_id": "cpp/command-injection", "line": 42, "message": "tainted arg"}]
        prose = format_evidence_prose(rec)
        assert "CodeQL" in prose
        assert "line 42" in prose

    def test_semgrep_hits(self):
        rec = EvidenceRecord(file="a.c", function="f")
        rec.semgrep_hits = [{"rule_id": "xss-001", "line": 55}]
        prose = format_evidence_prose(rec)
        assert "Semgrep" in prose
        assert "line 55" in prose

    def test_unguarded_sinks(self):
        rec = EvidenceRecord(file="a.c", function="f")
        rec.joern_unguarded_sinks = [
            {"sink": "memcpy", "line": 99, "code": "memcpy(dst, src, len)", "guarded": False},
        ]
        prose = format_evidence_prose(rec)
        assert "UNGUARDED" in prose
        assert "`memcpy`" in prose
        assert "line 99" in prose
        assert "Joern CPG" in prose

    def test_sink_args(self):
        rec = EvidenceRecord(file="a.c", function="f")
        rec.joern_sink_args = [
            {"sink": "memcpy", "arg_index": 2, "source_param": "user_input"},
        ]
        prose = format_evidence_prose(rec)
        assert "tainted arg" in prose
        assert "`user_input`" in prose
        assert "`memcpy`" in prose
        assert "arg #2" in prose

    def test_has_any_evidence_with_new_fields(self):
        rec = EvidenceRecord(file="a.c", function="f")
        assert rec.has_any_evidence() is False

        rec.joern_unguarded_sinks = [{"sink": "system"}]
        assert rec.has_any_evidence() is True

        rec2 = EvidenceRecord(file="a.c", function="f")
        rec2.joern_sink_args = [{"sink": "memcpy", "arg_index": 2}]
        assert rec2.has_any_evidence() is True

    def test_invalid_names_sanitized(self):
        rec = EvidenceRecord(file="a.c", function="f")

        class FakeApprox:
            dangerous_flows = {0: [('"; evil("', 1)]}
            params = ["buf"]
            has_opaque_flow = False

        rec.taint_approx = FakeApprox()
        prose = format_evidence_prose(rec)
        assert "<invalid-name>" in prose
        assert "evil" not in prose


    def test_negative_space_rendered(self):
        from core.audit.negative_space import NegativeSpaceFinding
        rec = EvidenceRecord(file="a.c", function="f")
        rec.negative_space = [
            NegativeSpaceFinding(
                check_type="missing_auth",
                expected="check_auth (10 functions)",
                evidence="no auth check",
                cwe="CWE-306",
                confidence="high",
                convention="check_auth",
                strategy="auth",
            ),
        ]
        prose = format_evidence_prose(rec)
        assert "CWE-306" in prose
        assert "Convention deviations" in prose


class TestFormatEvidenceStructured:
    def test_empty_record(self):
        rec = EvidenceRecord(file="a.c", function="f")
        assert format_evidence_structured(rec) == []

    def test_taint_approx_entry(self):
        rec = EvidenceRecord(file="a.c", function="f")

        class FakeApprox:
            dangerous_flows = {0: [("memcpy", 1)]}
            params = ["buf"]

        rec.taint_approx = FakeApprox()
        entries = format_evidence_structured(rec)
        assert len(entries) == 1
        assert entries[0]["tier"] == "taint_approx"
        assert entries[0]["sink"] == "memcpy"
        assert entries[0]["source"] == "this_run"

    def test_imported_joern_has_source_imported(self):
        rec = EvidenceRecord(file="a.c", function="f")

        class FakeFlow:
            source_method = "parse"
            source_param = "len"
            sink_call = "memcpy"
            is_inter_procedural = True

        rec.imported_joern_flows = [FakeFlow()]
        entries = format_evidence_structured(rec)
        assert entries[0]["source"] == "imported"


class TestBuildEvidenceIndex:
    def test_basic_index(self):
        checklist = {
            "files": [
                {"path": "src/a.c", "items": [{"name": "parse_header"}]},
                {"path": "src/b.c", "items": [{"name": "handle_request"}]},
            ],
        }
        index = build_evidence_index(checklist=checklist)
        assert len(index) == 2
        assert "src/a.c:parse_header" in index
        assert "src/b.c:handle_request" in index

    def test_sink_unreachable_when_no_transitive(self):
        checklist = {
            "files": [
                {"path": "src/a.c", "items": [{"name": "safe_fn"}]},
                {"path": "src/b.c", "items": [{"name": "dangerous_fn"}]},
            ],
        }

        class FakeSinkResult:
            class FakeTransitive:
                file = "src/b.c"
                function = "dangerous_fn"
            transitive_reach = [FakeTransitive()]
            direct_sinks = []

        index = build_evidence_index(
            checklist=checklist,
            sink_results=FakeSinkResult(),
        )
        assert index["src/a.c:safe_fn"].sink_unreachable is True
        assert len(index["src/a.c:safe_fn"].sink_narrowed_classes) > 0
        assert "CWE-78" in index["src/a.c:safe_fn"].sink_narrowed_classes
        assert index["src/b.c:dangerous_fn"].sink_unreachable is False
        assert index["src/b.c:dangerous_fn"].sink_narrowed_classes == []

    def test_taint_approx_merged(self):
        checklist = {
            "files": [
                {"path": "src/a.c", "items": [{"name": "parse"}]},
            ],
        }

        class FakeApprox:
            pass

        index = build_evidence_index(
            checklist=checklist,
            taint_approx_results={"src/a.c:parse": FakeApprox()},
        )
        assert index["src/a.c:parse"].taint_approx is not None

    def test_joern_flows_merged(self):
        checklist = {
            "files": [
                {"path": "src/a.c", "items": [{"name": "parse"}]},
            ],
        }
        index = build_evidence_index(
            checklist=checklist,
            joern_flows={"src/a.c:parse": ["flow1", "flow2"]},
        )
        assert len(index["src/a.c:parse"].joern_flows) == 2

    def test_empty_checklist(self):
        index = build_evidence_index(checklist={})
        assert index == {}

    def test_item_kind_carried_onto_record(self):
        # The layer0 source pre-sweep gates on kind: only function/
        # method records are scanned, so a file-wide pattern match can
        # never be attributed to a bare declaration or global symbol.
        checklist = {
            "files": [{
                "path": "src/a.c",
                "items": [
                    {"name": "parse", "kind": "function",
                     "line_start": 10, "line_end": 40},
                    {"name": "tty_flag", "kind": "declaration",
                     "line_start": 5, "line_end": 5},
                    {"name": "legacy_no_kind", "line_start": 50,
                     "line_end": 60},
                ],
            }],
        }
        index = build_evidence_index(checklist=checklist)
        assert index["src/a.c:parse"].kind == "function"
        assert index["src/a.c:tty_flag"].kind == "declaration"
        assert index["src/a.c:legacy_no_kind"].kind == ""


class TestTransitiveTaintEvidence:
    def test_transitive_taint_renders_in_prose(self):
        from core.analysis.taint_approx import TaintPath, TransitiveTaint
        rec = EvidenceRecord(file="a.c", function="f")
        rec.transitive_taint = TransitiveTaint(
            function="f",
            param_sinks={0: [TaintPath(
                hops=["f", "g", "memcpy"],
                sink_name="memcpy",
                sink_arg=0,
            )]},
        )
        prose = format_evidence_prose(rec)
        assert "CROSS-FUNCTION" in prose
        assert "memcpy" in prose
        assert "transitive AST" in prose

    def test_transitive_taint_has_evidence(self):
        from core.analysis.taint_approx import TransitiveTaint
        rec = EvidenceRecord(file="a.c", function="f")
        assert rec.has_any_evidence() is False
        rec.transitive_taint = TransitiveTaint(function="f", param_sinks={})
        assert rec.has_any_evidence() is True


class TestAppSinkEvidence:
    def test_app_sink_renders_in_prose(self):
        rec = EvidenceRecord(file="a.c", function="f")
        rec.app_sink_targets = ["system", "execve"]
        prose = format_evidence_prose(rec)
        assert "APPLICATION SINK" in prose
        assert "system" in prose

    def test_app_sink_populated_from_sink_results(self):
        from unittest.mock import MagicMock
        checklist = {"files": [{"path": "a.c", "items": [
            {"name": "f", "kind": "function"},
        ]}]}
        sink_results = MagicMock()
        sink_results.transitive_reach = []
        sink_results.direct_sinks = [
            MagicMock(file="a.c", function="f", line=1, target="system"),
        ]
        sink_results.unreachable_eligible = None
        index = build_evidence_index(
            checklist=checklist, sink_results=sink_results,
        )
        assert index["a.c:f"].app_sink_targets == ["system"]


class TestSanitizerCallsEvidence:
    def test_sanitizer_renders_in_prose(self):
        rec = EvidenceRecord(file="a.py", function="handle")
        rec.sanitizer_calls = [
            {"callable": "html_escape", "param": "user_input", "arg_idx": "0"},
        ]
        prose = format_evidence_prose(rec)
        assert "SANITIZER" in prose
        assert "html_escape" in prose
        assert "user_input" in prose

    def test_sanitizer_populated_from_taint_summary(self):
        from core.analysis.taint_summaries import TaintSummary
        checklist = {"files": [{"path": "a.py", "items": [
            {"name": "handle", "kind": "function"},
        ]}]}
        summary = TaintSummary(
            function="handle",
            params=("user_input",),
            return_effects=frozenset([(0, "html_escape", 0)]),
        )
        index = build_evidence_index(
            checklist=checklist,
            taint_summary_results={"a.py:handle": summary},
        )
        assert len(index["a.py:handle"].sanitizer_calls) == 1
        assert index["a.py:handle"].sanitizer_calls[0]["callable"] == "html_escape"


class TestEvidenceTierAnnotations:
    """Verify that format_evidence_structured entries carry evidence_tier."""

    def _make_record_with_joern(self):
        rec = EvidenceRecord(file="a.c", function="foo")

        class FakeFlow:
            source_method = "foo"
            source_param = "buf"
            sink_call = "memcpy"
            is_inter_procedural = False

        rec.joern_flows = [FakeFlow()]
        return rec

    def test_joern_entry_has_evidence_tier(self):
        rec = self._make_record_with_joern()
        entries = format_evidence_structured(rec)
        assert len(entries) == 1
        assert entries[0]["evidence_tier"] == "xref_backed"

    def test_semgrep_entry_has_header_backed(self):
        rec = EvidenceRecord(file="a.c", function="foo")
        rec.semgrep_hits = [{"rule_id": "test", "line": 10}]
        entries = format_evidence_structured(rec)
        assert entries[0]["evidence_tier"] == "header_backed"

    def test_codeql_entry_has_xref_backed(self):
        rec = EvidenceRecord(file="a.c", function="foo")
        rec.codeql_alerts = [{"rule_id": "cwe-79", "line": 5}]
        entries = format_evidence_structured(rec)
        assert entries[0]["evidence_tier"] == "xref_backed"


class TestStrongestEvidenceTier:
    def test_empty_returns_heuristic(self):
        assert strongest_evidence_tier([]) == EvidenceTier.HEURISTIC

    def test_single_entry(self):
        entries = [{"evidence_tier": "xref_backed"}]
        assert strongest_evidence_tier(entries) == EvidenceTier.XREF_BACKED

    def test_picks_strongest(self):
        entries = [
            {"evidence_tier": "header_backed"},
            {"evidence_tier": "xref_backed"},
            {"evidence_tier": "heuristic"},
        ]
        assert strongest_evidence_tier(entries) == EvidenceTier.XREF_BACKED

    def test_observed_runtime_wins(self):
        entries = [
            {"evidence_tier": "xref_backed"},
            {"evidence_tier": "observed_runtime"},
        ]
        assert strongest_evidence_tier(entries) == EvidenceTier.OBSERVED_RUNTIME

    def test_skips_entries_without_tier(self):
        entries = [{"tier": "joern"}, {"evidence_tier": "header_backed"}]
        assert strongest_evidence_tier(entries) == EvidenceTier.HEADER_BACKED

    def test_skips_invalid_tier_value(self):
        entries = [{"evidence_tier": "not_a_real_tier"}]
        assert strongest_evidence_tier(entries) == EvidenceTier.HEURISTIC
