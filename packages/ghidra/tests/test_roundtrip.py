"""Tests for finding round-trip to Ghidra."""

import json
from unittest.mock import MagicMock, patch

from packages.ghidra.roundtrip import (
    _exportable,
    collect_agentic_findings,
    collect_journal_findings,
)


def _record(**overrides):
    """A result record in the orchestrated_report.json shape.

    Verdicts are booleans (``is_true_positive`` / ``is_exploitable`` /
    ``exploitable``); the analysis dict may be null on prep-mode
    records; ``metadata.name`` carries the function name.
    """
    rec = {
        "finding_id": "f1",
        "rule_id": "r1",
        "level": "error",
        "message": "stack buffer overflow",
        "is_true_positive": True,
        "is_exploitable": True,
        "exploitable": True,
        "analysis": {
            "reasoning": "unbounded read into fixed stack buffer",
            "attack_scenario": "oversized stdin clobbers return address",
        },
        "metadata": {"name": "vuln_func"},
    }
    rec.update(overrides)
    return rec


class TestExportable:
    def test_address_keyed_passes_through(self):
        findings = [{"address": 0x5000, "summary": "overflow"}]
        assert _exportable(findings) == findings

    def test_name_keyed_passes_through(self):
        # Resolution happens inside Ghidra (import script / pyghidra),
        # not here — the name is enough to submit.
        findings = [{"function": "vuln", "summary": "overflow"}]
        assert _exportable(findings) == findings

    def test_function_name_aliased_to_function(self):
        findings = [{"function_name": "handler", "summary": "x"}]
        out = _exportable(findings)
        assert out[0]["function"] == "handler"

    def test_unplaceable_dropped(self):
        findings = [
            {"summary": "no key at all"},
            {"function": "", "summary": "empty name"},
            {"address": 0x1000, "summary": "kept"},
        ]
        out = _exportable(findings)
        assert len(out) == 1
        assert out[0]["address"] == 0x1000

    def test_input_not_mutated(self):
        finding = {"function_name": "handler", "summary": "x"}
        _exportable([finding])
        assert "function" not in finding


class TestCollectAgentic:
    def test_boolean_verdict_fields(self):
        # The report shape carries boolean verdicts, never a string
        # "exploitability" field.
        out = collect_agentic_findings([_record()])
        assert len(out) == 1
        assert out[0]["function"] == "vuln_func"
        assert "stdin" in out[0]["summary"] or "unbounded" in out[0]["summary"]

    def test_exploitable_alias_accepted(self):
        rec = _record(is_exploitable=False, exploitable=True)
        assert len(collect_agentic_findings([rec])) == 1

    def test_not_true_positive_excluded(self):
        rec = _record(is_true_positive=False)
        assert collect_agentic_findings([rec]) == []

    def test_not_exploitable_excluded(self):
        rec = _record(is_exploitable=False, exploitable=False)
        assert collect_agentic_findings([rec]) == []

    def test_null_analysis_survives(self):
        # Prep-mode records serialize "analysis": null — the collector
        # must not crash and falls back to the scanner message.
        rec = _record(analysis=None)
        out = collect_agentic_findings([rec])
        assert out[0]["summary"] == "stack buffer overflow"

    def test_function_name_fallback(self):
        rec = _record(metadata={}, function_name="alt_func")
        out = collect_agentic_findings([rec])
        assert out[0]["function"] == "alt_func"


class TestCollectJournal:
    def test_reads_review_journal_in_out_dir(self, tmp_path):
        # The journal is review-journal.jsonl directly in the run
        # output directory — no journal/ subdirectory exists.
        try:
            from core.coverage.journal import JOURNAL_FILENAME
        except ImportError:
            import pytest
            pytest.skip("core.coverage.journal unavailable")
        entry = {
            "ts": "2026-01-01T00:00:00Z",
            "run_id": "run1",
            "file": "binary:target",
            "function": "vuln_func",
            "verdict": "finding",
            "source_hash": "abcd1234",
            "body": "unbounded read",
            "cwe": "CWE-121",
        }
        (tmp_path / JOURNAL_FILENAME).write_text(json.dumps(entry) + "\n")
        out = collect_journal_findings(tmp_path)
        assert len(out) == 1
        assert out[0]["function"] == "vuln_func"
        assert out[0]["severity"] == "High"

    def test_no_journal_returns_empty(self, tmp_path):
        assert collect_journal_findings(tmp_path) == []


class TestExportAll:
    def test_empty_out_dir_returns_zero(self, tmp_path):
        from packages.ghidra.roundtrip import export_all_to_ghidra
        gpr = tmp_path / "test.gpr"
        gpr.write_text("")
        counts = export_all_to_ghidra(tmp_path, gpr, [])
        assert counts["total"] == 0

    def test_combined_single_apply(self, tmp_path):
        from packages.ghidra.roundtrip import export_all_to_ghidra
        gpr = tmp_path / "test.gpr"
        gpr.write_text("")
        out = tmp_path / "out"
        out.mkdir()

        mock_bridge = MagicMock()
        # the apply path enters the bridge as a context manager
        mock_bridge.__enter__.return_value = mock_bridge
        mock_bridge.export_enrichments.return_value = tmp_path / "e.gpr"

        with patch(
            "packages.ghidra.bridge.GhidraBridge",
            return_value=mock_bridge,
        ):
            results = [
                _record(),
                _record(is_true_positive=False, metadata={"name": "fp"}),
            ]
            counts = export_all_to_ghidra(out, gpr, results)

        assert counts["agentic"] == 1
        assert counts["total"] == 1
        # ONE apply pass — several would clobber each other's copies.
        mock_bridge.export_enrichments.assert_called_once()
        call = mock_bridge.export_enrichments.call_args
        assert call[0][0] is None
        exported = call[1]["findings"]
        assert exported[0]["function"] == "vuln_func"
        assert exported[0].get("address") is None

    def test_unplaceable_findings_counted_zero(self, tmp_path):
        from packages.ghidra.roundtrip import export_all_to_ghidra
        gpr = tmp_path / "test.gpr"
        gpr.write_text("")
        out = tmp_path / "out"
        out.mkdir()
        counts = export_all_to_ghidra(out, gpr, [_record(metadata={})])
        assert counts["total"] == 0


class TestRedbCacheCandidates:
    """Project-state failures must degrade one candidate at a time —
    a vanished project json (load() → None) or a failing attach-slot
    computation must not discard candidates that are still perfectly
    resolvable."""

    def _candidates(self, tmp_path, *, load_result="project",
                    attach_raises=False):
        from pathlib import Path

        from packages.ghidra.roundtrip import redb_cache_candidates

        project = MagicMock()
        project.output_dir = str(tmp_path / "proj-out")
        mgr = MagicMock()
        mgr.get_active.return_value = "myproj"
        mgr.load.return_value = (
            project if load_result == "project" else None)

        def fake_attach_dir(proj, gpr):
            if attach_raises:
                raise OSError("attach slot unavailable")
            return Path(proj.output_dir) / "attach-slot"

        with patch("core.project.project.ProjectManager",
                   return_value=mgr), \
             patch("packages.ghidra.attach.attach_dir", fake_attach_dir):
            return redb_cache_candidates(tmp_path / "target.gpr")

    def test_all_slots_present_on_healthy_project(self, tmp_path):
        candidates = self._candidates(tmp_path)
        assert [c.name for c in candidates] == ["re-database.json"] * 3
        assert "attach-slot" in str(candidates[0])
        assert "ghidra-target" in str(candidates[1])
        assert "ghidra-import-target" in str(candidates[2])

    def test_vanished_project_degrades_to_global_slot(self, tmp_path):
        """ProjectManager.load() returns None when the registered
        project's state file vanished — the global slot must survive
        without an AttributeError eating the whole try block."""
        candidates = self._candidates(tmp_path, load_result=None)
        assert len(candidates) == 1
        assert "ghidra-import-target" in str(candidates[0])

    def test_attach_failure_keeps_legacy_project_slot(self, tmp_path):
        candidates = self._candidates(tmp_path, attach_raises=True)
        assert len(candidates) == 2
        assert "ghidra-target" in str(candidates[0])
        assert "ghidra-import-target" in str(candidates[1])
