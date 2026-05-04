"""Regression tests for BUG-R-011 and BUG-R-016: OpenAnt findings must reach Phase 3.

BUG-R-011 (original): openant_extra_findings was saved to openant_findings.json
but never merged into validation/findings.json, so Phase 3 ignored OpenAnt output.

BUG-R-016 (follow-up): the merge block used isinstance(existing, list) which always
rejected Raptor's actual format: {"stage":"A","timestamp":...,"findings":[]}.
convert_sarif_to_findings() writes a wrapped dict, not a plain list. Fix: detect
both formats and extract/extend the "findings" list from the dict.

These tests replay the merge logic in isolation (not the full agentic pipeline).
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[4]))  # repo root


def _replay_merge(out_dir: Path, openant_findings: list) -> int:
    """Mirror the merge logic from raptor_agentic.py post-Phase-2.

    Handles both:
    (a) Raptor's wrapped dict format: {"stage":..., "findings":[...]}
    (b) plain list format (backward compat)

    Returns count of merged findings, or raises on schema errors.
    """
    from core.json import load_json, save_json
    validation_findings_path = out_dir / "validation" / "findings.json"
    if validation_findings_path.exists():
        existing = load_json(validation_findings_path, strict=True) or []
        if isinstance(existing, dict) and "findings" in existing:
            findings_list = existing.get("findings", [])
            if not all(isinstance(f, dict) for f in findings_list):
                raise ValueError("validation/findings.json findings list contains non-dict elements")
            findings_list.extend(openant_findings)
            existing["findings"] = findings_list
            save_json(validation_findings_path, existing)
        elif isinstance(existing, list):
            if not all(isinstance(f, dict) for f in existing):
                raise ValueError("validation/findings.json contains non-dict elements")
            existing.extend(openant_findings)
            save_json(validation_findings_path, existing)
        else:
            raise ValueError(
                f"validation/findings.json has unrecognized format (got {type(existing).__name__})"
            )
    else:
        (out_dir / "validation").mkdir(exist_ok=True)
        save_json(validation_findings_path, openant_findings)
    return len(openant_findings)


class TestBugR011OpenantFindingsMerge(unittest.TestCase):
    """BUG-R-011: OpenAnt findings merged into validation output for Phase 3."""

    def test_merge_into_plain_list_findings_file(self):
        """SARIF findings as plain list + OpenAnt findings → merged flat list."""
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
        """--openant-only mode: no prior findings.json → created with OpenAnt findings."""
        from core.json import load_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            openant_findings = [{"finding_id": "openant:V1", "tool": "openant"}]

            count = _replay_merge(out_dir, openant_findings)
            self.assertEqual(count, 1)
            merged = load_json(out_dir / "validation" / "findings.json")
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["tool"], "openant")

    def test_merge_when_findings_file_is_empty_list(self):
        """findings.json exists as empty list → OpenAnt findings appended cleanly."""
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


class TestBugR016DictFormatMerge(unittest.TestCase):
    """BUG-R-016: Raptor's convert_sarif_to_findings() writes a wrapped dict.

    Pre-fix: isinstance(existing, list) always rejected the dict and logged
    "[ERROR] validation/findings.json is not a list (got dict); skipping merge".
    OpenAnt findings were silently dropped — never reached Phase 3.

    Post-fix: detect dict with "findings" key and extend the inner list.
    """

    def _make_raptor_findings_json(self, out_dir, sarif_findings=None):
        """Create validation/findings.json in Raptor's actual dict format."""
        from core.json import save_json
        (out_dir / "validation").mkdir(exist_ok=True)
        wrapped = {
            "stage": "A",
            "timestamp": "2026-05-05T00:21:22.959441",
            "target_path": "/tmp/test-repo",
            "source": "sarif",
            "findings": sarif_findings or [],
        }
        save_json(out_dir / "validation" / "findings.json", wrapped)
        return wrapped

    def test_dict_format_with_empty_sarif_findings(self):
        """Raptor dict format + 0 SARIF findings → OpenAnt findings injected."""
        from core.json import load_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            self._make_raptor_findings_json(out_dir, sarif_findings=[])

            openant_findings = [
                {"finding_id": "openant:V1", "tool": "openant"},
                {"finding_id": "openant:V2", "tool": "openant"},
            ]
            count = _replay_merge(out_dir, openant_findings)

            self.assertEqual(count, 2)
            result = load_json(out_dir / "validation" / "findings.json")
            # Outer structure preserved
            self.assertIsInstance(result, dict)
            self.assertIn("stage", result)
            self.assertIn("findings", result)
            # Inner findings contain OpenAnt results
            self.assertEqual(len(result["findings"]), 2)
            tools = {f["tool"] for f in result["findings"]}
            self.assertSetEqual(tools, {"openant"})

    def test_dict_format_with_existing_sarif_findings(self):
        """Raptor dict format + existing SARIF findings → both preserved."""
        from core.json import load_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            sarif = [{"finding_id": "sarif-001", "tool": "semgrep"}]
            self._make_raptor_findings_json(out_dir, sarif_findings=sarif)

            openant_findings = [{"finding_id": "openant:V1", "tool": "openant"}]
            count = _replay_merge(out_dir, openant_findings)

            self.assertEqual(count, 1)
            result = load_json(out_dir / "validation" / "findings.json")
            self.assertEqual(len(result["findings"]), 2)
            tools = {f["tool"] for f in result["findings"]}
            self.assertSetEqual(tools, {"semgrep", "openant"})
            # Outer metadata unchanged
            self.assertEqual(result["stage"], "A")
            self.assertEqual(result["source"], "sarif")

    def test_dict_format_preserves_metadata_fields(self):
        """Outer dict metadata (stage, timestamp, target_path, source) must not
        be overwritten when extending the inner findings list."""
        from core.json import load_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            self._make_raptor_findings_json(out_dir)

            _replay_merge(out_dir, [{"finding_id": "openant:V1", "tool": "openant"}])

            result = load_json(out_dir / "validation" / "findings.json")
            self.assertEqual(result["stage"], "A")
            self.assertEqual(result["timestamp"], "2026-05-05T00:21:22.959441")
            self.assertEqual(result["target_path"], "/tmp/test-repo")
            self.assertEqual(result["source"], "sarif")

    def test_dict_without_findings_key_raises(self):
        """A dict that lacks 'findings' key is unrecognized; must raise, not silently drop."""
        from core.json import save_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            # A dict without the expected "findings" key
            save_json(out_dir / "validation" / "findings.json",
                      {"stage": "A", "data": []})

            with self.assertRaises((ValueError, KeyError)):
                _replay_merge(out_dir, [{"finding_id": "openant:V1"}])

    def test_raptor_agentic_merge_block_handles_dict_format(self):
        """Static check: raptor_agentic.py contains dict-format handling.

        The merge block must contain both the dict-branch and list-branch checks
        so both formats are handled without skipping OpenAnt findings.
        """
        agentic = Path(__file__).parents[3] / "raptor_agentic.py"
        text = agentic.read_text()
        self.assertIn(
            'isinstance(existing, dict) and "findings" in existing',
            text,
            "Merge block must handle Raptor's wrapped dict format (BUG-R-016)",
        )
        self.assertIn(
            'isinstance(existing, list)',
            text,
            "Merge block must also handle plain list format (backward compat)",
        )


class TestBugR011FragilityCorruptedFindingsFile(unittest.TestCase):
    """Audit follow-up: corrupted or schema-invalid findings.json must be handled
    defensively — refuse to merge rather than silently corrupt data.

    Three failure modes:
    1. findings.json contains non-dict elements (e.g., strings in the list)
    2. findings.json is corrupted JSON
    3. findings.json is a dict without the "findings" key (truly unrecognized)
    """

    def test_plain_list_with_non_dict_elements_raises(self):
        """Plain list containing strings → must raise, not silently merge garbage."""
        from core.json import save_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            save_json(out_dir / "validation" / "findings.json",
                      ["not-a-dict", {"finding_id": "valid"}])
            with self.assertRaises(ValueError):
                _replay_merge(out_dir, [{"finding_id": "X"}])

    def test_dict_with_non_dict_findings_raises(self):
        """Dict format where findings list contains non-dict elements → raise."""
        from core.json import save_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            save_json(out_dir / "validation" / "findings.json",
                      {"stage": "A", "findings": ["not-a-dict"]})
            with self.assertRaises(ValueError):
                _replay_merge(out_dir, [{"finding_id": "X"}])

    def test_corrupted_json_raises(self):
        """Corrupted JSON in findings.json → load_json raises; merge propagates."""
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            (out_dir / "validation" / "findings.json").write_text("{not valid json")
            with self.assertRaises(Exception):
                _replay_merge(out_dir, [{"finding_id": "X"}])


class TestCleanupB1ToctouRaceWindow(unittest.TestCase):
    """Cleanup B-1 from /work-audit: TOCTOU window between exists() and load_json().

    Operational mitigation: per-run output-dir isolation means no concurrent
    writers to the same findings.json. These tests pin the benign-TOCTOU contract.
    """

    def test_file_deleted_between_exists_and_load_handled_gracefully(self):
        """If findings.json vanishes between the exists() check and load_json(),
        load_json returns None → merge code uses `or []` → openant findings land
        in a fresh file. No data loss."""
        from core.json import load_json, save_json
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()
            findings_path = out_dir / "validation" / "findings.json"
            save_json(findings_path, [{"finding_id": "X"}])
            findings_path.unlink()
            # load_json returns None on missing file (both strict and non-strict)
            self.assertIsNone(load_json(findings_path, strict=False))
            self.assertIsNone(load_json(findings_path, strict=True))

    def test_post_validation_dir_creation_idempotent(self):
        """mkdir(exist_ok=True) is safe if another process created the dir first."""
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "validation").mkdir()  # pre-create
            _replay_merge(out_dir, [{"finding_id": "X"}])
            self.assertTrue((out_dir / "validation" / "findings.json").exists())


class TestBugR011RaptorAgenticMergeBlock(unittest.TestCase):
    """Static checks: raptor_agentic.py merge block is present and complete."""

    def test_merge_block_present(self):
        agentic = Path(__file__).parents[3] / "raptor_agentic.py"
        text = agentic.read_text()
        self.assertIn("openant_extra_findings", text)
        self.assertIn("validation_findings_path", text)
        self.assertIn("Merged", text, "Merge log message must be present")

    def test_merge_block_references_bug_r016(self):
        """The comment in the merge block must call out BUG-R-016 so future
        readers understand why both dict and list formats are handled."""
        agentic = Path(__file__).parents[3] / "raptor_agentic.py"
        text = agentic.read_text()
        self.assertIn(
            "BUG-R-016",
            text,
            "Merge block comment must reference BUG-R-016 for traceability",
        )


if __name__ == "__main__":
    unittest.main()
