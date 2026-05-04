"""Regression test for BUG-R-011: OpenAnt findings must reach Phase 3.

Pre-fix behavior: openant_extra_findings was populated and saved to
openant_findings.json but never merged into validation/findings.json,
so Phase 3 analysis read SARIF-only findings and ignored OpenAnt's.

Post-fix: After run_validation_phase, OpenAnt findings are appended to
validation/findings.json. Phase 3 reads that file and consumes them.

The behavior we test here is the "merge" semantics — does the merge code
in raptor_agentic.py:Phase 1b correctly extend an existing findings list?
We don't drive the full agentic pipeline (too costly); we replay the merge
logic in isolation.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[4]))  # repo root


def _replay_merge(out_dir: Path, openant_findings: list) -> int:
    """Mirror the merge logic from raptor_agentic.py post-Phase-2."""
    from core.json import load_json, save_json
    validation_findings_path = out_dir / "validation" / "findings.json"
    if validation_findings_path.exists():
        existing = load_json(validation_findings_path) or []
        existing.extend(openant_findings)
        save_json(validation_findings_path, existing)
    else:
        (out_dir / "validation").mkdir(exist_ok=True)
        save_json(validation_findings_path, openant_findings)
    return len(openant_findings)


class TestBugR011OpenantFindingsMerge(unittest.TestCase):

    def test_merge_into_existing_findings_file(self):
        """SARIF findings already in validation/findings.json + OpenAnt
        findings → merged list contains both."""
        from core.json import save_json, load_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            sarif_findings = [{"finding_id": "sarif-1", "tool": "semgrep"}]
            save_json(out_dir / "validation" / "findings.json", sarif_findings)

            openant_findings = [
                {"finding_id": "openant:VULN-001", "tool": "openant"},
                {"finding_id": "openant:VULN-002", "tool": "openant"},
            ]
            count = _replay_merge(out_dir, openant_findings)

            merged = load_json(out_dir / "validation" / "findings.json")
            self.assertEqual(count, 2)
            self.assertEqual(len(merged), 3)
            tools = {f["tool"] for f in merged}
            self.assertSetEqual(tools, {"semgrep", "openant"})

    def test_merge_when_no_findings_file_exists(self):
        """OpenAnt findings only (e.g., --openant-only mode) → file is
        created with just the OpenAnt findings."""
        from core.json import load_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            openant_findings = [{"finding_id": "openant:V1", "tool": "openant"}]

            count = _replay_merge(out_dir, openant_findings)
            self.assertEqual(count, 1)
            merged = load_json(out_dir / "validation" / "findings.json")
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["tool"], "openant")

    def test_merge_when_findings_file_is_empty(self):
        """validation/findings.json exists but is empty list → OpenAnt
        findings appended cleanly."""
        from core.json import save_json, load_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            save_json(out_dir / "validation" / "findings.json", [])

            openant_findings = [{"finding_id": "openant:V1", "tool": "openant"}]
            count = _replay_merge(out_dir, openant_findings)

            merged = load_json(out_dir / "validation" / "findings.json")
            self.assertEqual(count, 1)
            self.assertEqual(len(merged), 1)


class TestBugR011RaptorAgenticMergeBlock(unittest.TestCase):
    """Static check: raptor_agentic.py contains the merge block.

    A future regression that removes the merge would be caught here even if
    no integration test runs the full agentic pipeline.
    """

    def test_merge_block_present(self):
        agentic = Path(__file__).parents[3] / "raptor_agentic.py"
        text = agentic.read_text()
        # The merge block uses these distinctive identifiers
        self.assertIn("openant_extra_findings", text)
        self.assertIn("validation_findings_path", text)
        self.assertIn("Merged", text,
                     "Merge log message must be present")


if __name__ == "__main__":
    unittest.main()
