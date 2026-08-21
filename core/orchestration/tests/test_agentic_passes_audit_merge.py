"""Merged validation: /audit post-pass findings join the /agentic
validate selection.

With ``--gap-audit --validate`` one validate pass covers both
pipelines' findings — audit findings (tool-confirmed) take the head of
the selection cap, agentic findings fill the remainder in signal order.
Also covers the audit → validate shape conversion helpers.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.orchestration.agentic_passes import (
    _load_audit_findings,
    convert_audit_to_validate,
    run_validate_postpass,
)
from core.orchestration.tests.test_agentic_passes import (
    _make_lifecycle_dispatcher,
    _patch_passes,
)


def _audit_finding(n: int = 1, **kw) -> dict:
    base = {
        "id": f"AUDIT-{n:03d}",
        "file": "src/a.c",
        "function": "f",
        "line": 10,
        "title": "unchecked length",
        "description": "memcpy with attacker length",
        "severity": "high",
        "origin": "audit",
        "cwe": "CWE-120",
        "vuln_type": "CWE-120",
        "hypothesis": "len unchecked before memcpy",
        "evidence_tool": "smt:check-oob",
    }
    base.update(kw)
    return base


class ConvertAuditToValidateTests(unittest.TestCase):

    def test_field_mapping(self):
        out = convert_audit_to_validate([_audit_finding()])
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f["id"], "AUDIT-001")
        self.assertEqual(f["file"], "src/a.c")
        self.assertEqual(f["line"], 10)
        self.assertEqual(f["cwe_id"], "CWE-120")
        self.assertEqual(f["origin"], "audit")
        # normalize_audit_findings derives confidence from the
        # evidence tool and packs audit context for Stage A.
        self.assertIn("confidence", f)
        self.assertEqual(f["audit_context"]["hypothesis"],
                         "len unchecked before memcpy")

    def test_description_falls_back_to_title(self):
        out = convert_audit_to_validate([
            _audit_finding(description="", title="the title"),
        ])
        self.assertEqual(out[0]["description"], "the title")

    def test_non_dict_entries_skipped(self):
        out = convert_audit_to_validate([None, "x", _audit_finding()])
        self.assertEqual(len(out), 1)


class LoadAuditFindingsTests(unittest.TestCase):

    def test_bare_list(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(
                json.dumps([_audit_finding()]))
            self.assertEqual(len(_load_audit_findings(tmp)), 1)

    def test_wrapped_dict(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(
                json.dumps({"findings": [_audit_finding(), "junk"]}))
            self.assertEqual(len(_load_audit_findings(tmp)), 1)

    def test_missing_dir_or_file(self):
        self.assertEqual(_load_audit_findings(None), [])
        with TemporaryDirectory() as tmp:
            self.assertEqual(_load_audit_findings(Path(tmp)), [])


class MergedSelectionTests(unittest.TestCase):

    def _make_report(self, dir_: Path, results: list) -> Path:
        path = dir_ / "autonomous_analysis_report.json"
        path.write_text(json.dumps({"results": results}))
        return path

    def _make_audit_dir(self, tmp: Path, count: int) -> Path:
        audit_dir = tmp / "audit_run"
        audit_dir.mkdir()
        (audit_dir / "findings.json").write_text(json.dumps(
            [_audit_finding(i) for i in range(1, count + 1)]))
        return audit_dir

    def test_audit_findings_lead_the_selection(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._make_report(tmp, [
                {"finding_id": "FINDING-F1", "is_exploitable": True},
            ])
            audit_dir = self._make_audit_dir(tmp, 2)
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            with _patch_passes(dispatcher):
                result = run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp, analysis_report=report,
                    claude_bin="/fake/claude", audit_dir=audit_dir,
                )
            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertEqual(result.selected_count, 3)

            data = json.loads(
                (validate_dir / "selected-findings.json").read_text())
            ids = [f["id"] for f in data["findings"]]
            self.assertEqual(ids[:2], ["AUDIT-001", "AUDIT-002"])
            self.assertIn("FINDING-F1", ids)

    def test_audit_findings_alone_still_run(self):
        """No analysis report (prep failed / nothing qualified) must not
        skip the pass when audit findings exist."""
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            audit_dir = self._make_audit_dir(tmp, 1)
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            with _patch_passes(dispatcher):
                result = run_validate_postpass(
                    target=tmp, agentic_out_dir=tmp,
                    analysis_report=tmp / "missing.json",
                    claude_bin="/fake/claude", audit_dir=audit_dir,
                )
            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertEqual(result.selected_count, 1)

    def test_no_audit_dir_preserves_existing_behaviour(self):
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            result = run_validate_postpass(
                target=tmp, agentic_out_dir=tmp,
                analysis_report=tmp / "missing.json",
                claude_bin="/fake/claude",
            )
        self.assertFalse(result.ran)
        self.assertIn("not found", result.skipped_reason)

    def test_cap_prefers_audit_findings(self):
        from core.orchestration import agentic_passes
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            report = self._make_report(tmp, [
                {"finding_id": "FINDING-F1", "is_exploitable": True},
                {"finding_id": "FINDING-F2", "is_exploitable": True},
            ])
            audit_dir = self._make_audit_dir(tmp, 3)
            validate_dir = tmp / "validate_run"
            dispatcher = _make_lifecycle_dispatcher(start_dir=validate_dir)
            old_cap = agentic_passes._MAX_VALIDATE_FINDINGS
            agentic_passes._MAX_VALIDATE_FINDINGS = 4
            try:
                with _patch_passes(dispatcher):
                    result = run_validate_postpass(
                        target=tmp, agentic_out_dir=tmp,
                        analysis_report=report,
                        claude_bin="/fake/claude", audit_dir=audit_dir,
                    )
            finally:
                agentic_passes._MAX_VALIDATE_FINDINGS = old_cap
            self.assertTrue(result.ran, msg=result.skipped_reason)
            self.assertEqual(result.selected_count, 4)
            data = json.loads(
                (validate_dir / "selected-findings.json").read_text())
            ids = [f["id"] for f in data["findings"]]
            self.assertEqual(
                ids[:3], ["AUDIT-001", "AUDIT-002", "AUDIT-003"])
            self.assertEqual(len(ids), 4)


if __name__ == "__main__":
    unittest.main()
