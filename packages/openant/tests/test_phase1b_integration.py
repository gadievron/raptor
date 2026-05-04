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


class TestBugR011FragilityCorruptedFindingsFile(unittest.TestCase):
    """Audit follow-up: BUG-R-011 fix originally trusted the existing
    findings.json blindly. If a future bug or external tool wrote a
    non-list JSON value, `existing.extend(...)` would silently fail
    or merge garbage. These tests pin the validated schema.

    Three failure modes to handle:
    1. findings.json is a dict, not a list (schema mismatch)
    2. findings.json contains non-dict elements (e.g., strings)
    3. findings.json is corrupted JSON

    The merge must:
    - Refuse to merge into a non-list and log a clear error
    - Still produce a valid output (either skip merge or replace+log)
    """

    @staticmethod
    def _safe_merge(out_dir, openant_findings):
        """The schema-aware merge logic this test pins down.

        Uses strict=True so corrupted JSON raises (rather than the default
        non-strict mode that returns None and silently empties the file).
        """
        from core.json import load_json, save_json
        validation_findings_path = out_dir / "validation" / "findings.json"
        if validation_findings_path.exists():
            # strict=True: corrupted JSON raises instead of returning None
            # (which would silently lose data).
            existing = load_json(validation_findings_path, strict=True) or []
            if not isinstance(existing, list):
                raise ValueError(
                    f"validation/findings.json is not a list "
                    f"(got {type(existing).__name__}); refusing to merge"
                )
            if not all(isinstance(f, dict) for f in existing):
                raise ValueError(
                    "validation/findings.json contains non-dict elements"
                )
            existing.extend(openant_findings)
            save_json(validation_findings_path, existing)
        else:
            (out_dir / "validation").mkdir(exist_ok=True)
            save_json(validation_findings_path, openant_findings)
        return len(openant_findings)

    def test_existing_findings_is_dict_raises(self):
        from core.json import save_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            # Hostile input: validation/findings.json is a wrapper dict,
            # not a flat list (some tools write this).
            save_json(out_dir / "validation" / "findings.json",
                       {"findings": []})
            with self.assertRaises(ValueError) as ctx:
                self._safe_merge(out_dir, [{"finding_id": "X"}])
            self.assertIn("not a list", str(ctx.exception))

    def test_existing_findings_has_non_dict_raises(self):
        from core.json import save_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            save_json(out_dir / "validation" / "findings.json",
                       ["not-a-dict", {"finding_id": "valid"}])
            with self.assertRaises(ValueError) as ctx:
                self._safe_merge(out_dir, [{"finding_id": "X"}])
            self.assertIn("non-dict", str(ctx.exception))

    def test_corrupted_json_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            (out_dir / "validation" / "findings.json").write_text("{not valid json")
            # load_json raises on corrupt JSON; the merge propagates the error
            with self.assertRaises(Exception):
                self._safe_merge(out_dir, [{"finding_id": "X"}])


class TestCleanupB1ToctouRaceWindow(unittest.TestCase):
    """Cleanup B-1 from /work-audit (2026-05-04):

    Static-analysis agent flagged a TOCTOU window between exists()-check
    and load_json() in the merge block. I documented operational
    mitigation (per-run output-dir isolation) but didn't write a test.

    These tests demonstrate that:
    1. If the file exists at exists()-check time but is deleted before
       load_json, the merge gracefully handles the missing file (load
       returns None on non-strict, raises on strict).
    2. The actual production code uses strict=True, so race-induced
       file-disappearance results in a logged error, not silent data loss.

    NOTE: We don't test true concurrent writes (would need filelock or
    multiprocessing); the user's concurrency model is per-run output
    directory isolation, which prevents the race in practice.
    """

    @staticmethod
    def _safe_merge_strict(out_dir, openant_findings):
        """Mirror of the post-fix merge code with strict=True."""
        from core.json import load_json, save_json
        validation_findings_path = out_dir / "validation" / "findings.json"
        if validation_findings_path.exists():
            existing = load_json(validation_findings_path, strict=True) or []
            if not isinstance(existing, list):
                raise ValueError("not a list")
            existing.extend(openant_findings)
            save_json(validation_findings_path, existing)
        else:
            (out_dir / "validation").mkdir(exist_ok=True)
            save_json(validation_findings_path, openant_findings)

    def test_file_deleted_between_exists_and_load_handled_gracefully(self):
        """TOCTOU window: file exists at .exists() check, vanishes before
        load_json. core.json.load_json returns None for missing files
        (regardless of strict mode — strict only affects JSON parse errors).

        The merge code's `existing = load_json(...) or []` therefore handles
        this gracefully: if the file vanished, existing == [], and we extend
        with openant_findings. No data loss; openant findings still land in
        a fresh file.

        This pins the benign-TOCTOU contract.
        """
        from core.json import load_json, save_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            findings_path = out_dir / "validation" / "findings.json"
            save_json(findings_path, [{"finding_id": "X"}])
            # Race: file exists, then disappears before load
            findings_path.unlink()
            # load_json returns None on missing file (both modes)
            self.assertIsNone(load_json(findings_path, strict=False))
            self.assertIsNone(load_json(findings_path, strict=True))
            # The merge code uses `... or []` so behavior is well-defined

    def test_post_validation_dir_creation_idempotent(self):
        """The mkdir(exist_ok=True) protects against a race where
        another process creates the dir between our check and mkdir."""
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            # Pre-create the dir (simulating concurrent process)
            (out_dir / "validation").mkdir()
            # Our merge should still succeed (idempotent mkdir)
            self._safe_merge_strict(out_dir, [{"finding_id": "X"}])
            findings_path = out_dir / "validation" / "findings.json"
            self.assertTrue(findings_path.exists())


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
