"""Tests for OpenAnt → Raptor finding schema translator."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[4]))  # repo root

from packages.openant.translator import (
    translate_pipeline_output,
    deduplicate_with_sarif,
    _compute_level,
)


def _finding(**kwargs) -> dict:
    base = {
        "id": "VULN-001",
        "stage1_verdict": "vulnerable",
        "stage2_verdict": "",
        "location": {"file": "app/views.py", "function": "app/views.py:execute_query"},
        "cwe_id": 89,
        "cwe_name": "SQL Injection",
        "description": "User input flows to SQL query",
        "impact": "Remote attacker can read/write database",
        "vulnerable_code": "cursor.execute(query % user_input)",
    }
    base.update(kwargs)
    return base


def _pipeline(findings=None) -> dict:
    return {
        "repository": {"name": "myapp", "language": "python"},
        "findings": findings or [],
    }


class TestComputeLevel(unittest.TestCase):
    def test_vulnerable_no_stage2(self):
        self.assertEqual(_compute_level("vulnerable", {}), "warning")

    def test_vulnerable_confirmed(self):
        self.assertEqual(
            _compute_level("vulnerable", {"stage2_verdict": "confirmed"}), "error"
        )

    def test_vulnerable_agreed(self):
        self.assertEqual(
            _compute_level("vulnerable", {"stage2_verdict": "agreed"}), "error"
        )

    def test_vulnerable_rejected(self):
        self.assertEqual(
            _compute_level("vulnerable", {"stage2_verdict": "rejected"}), "note"
        )

    def test_bypassable_no_stage2(self):
        self.assertEqual(_compute_level("bypassable", {}), "note")

    def test_safe_suppressed(self):
        self.assertIsNone(_compute_level("safe", {}))

    def test_protected_suppressed_to_note(self):
        self.assertEqual(_compute_level("protected", {}), "note")

    def test_inconclusive_note(self):
        self.assertEqual(_compute_level("inconclusive", {}), "note")

    def test_empty_verdict_kept_visible(self):
        # A missing verdict must not behave like "safe" — kept at note.
        self.assertEqual(_compute_level("", {}), "note")

    def test_unknown_verdict_kept_visible(self):
        # Schema drift (renamed verdict upstream) must not silently
        # zero the run's findings — kept at note, warned with counts.
        self.assertEqual(_compute_level("garbage", {}), "note")


class TestTranslatePipelineOutput(unittest.TestCase):
    def test_empty_input_returns_empty(self):
        self.assertEqual(translate_pipeline_output({}), [])

    def test_no_findings_returns_empty(self):
        self.assertEqual(translate_pipeline_output(_pipeline([])), [])

    def test_vulnerable_confirmed_gives_error(self):
        f = _finding(stage1_verdict="vulnerable", stage2_verdict="confirmed")
        results = translate_pipeline_output(_pipeline([f]))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[0]["tool"], "openant")

    def test_safe_is_suppressed(self):
        f = _finding(stage1_verdict="safe")
        results = translate_pipeline_output(_pipeline([f]))
        self.assertEqual(results, [])

    def test_protected_included_as_note(self):
        f = _finding(stage1_verdict="protected")
        results = translate_pipeline_output(_pipeline([f]))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["level"], "note")

    def test_finding_id_uses_openant_id(self):
        f = _finding(id="VULN-007")
        results = translate_pipeline_output(_pipeline([f]))
        self.assertEqual(results[0]["finding_id"], "openant:VULN-007")

    def test_cwe_str_formatting(self):
        f = _finding(cwe_id=78)
        results = translate_pipeline_output(_pipeline([f]))
        self.assertEqual(results[0]["cwe_id"], "CWE-78")
        self.assertEqual(results[0]["rule_id"], "openant/CWE-78")

    def test_file_propagated(self):
        f = _finding(location={"file": "src/handler.py", "function": "src/handler.py:run"})
        results = translate_pipeline_output(_pipeline([f]))
        self.assertEqual(results[0]["file"], "src/handler.py")

    def test_metadata_fields(self):
        f = _finding(stage1_verdict="vulnerable", stage2_verdict="agreed")
        results = translate_pipeline_output(_pipeline([f]))
        meta = results[0]["metadata"]
        self.assertEqual(meta["stage1_verdict"], "vulnerable")
        self.assertEqual(meta["stage2_verdict"], "agreed")

    def test_none_cwe_id(self):
        f = _finding(cwe_id=None)
        results = translate_pipeline_output(_pipeline([f]))
        self.assertIsNone(results[0]["cwe_id"])
        self.assertEqual(results[0]["rule_id"], "openant/unknown")

    def test_multiple_findings(self):
        findings = [
            _finding(id="V-001", stage1_verdict="vulnerable"),
            _finding(id="V-002", stage1_verdict="safe"),
            _finding(id="V-003", stage1_verdict="bypassable"),
        ]
        results = translate_pipeline_output(_pipeline(findings))
        self.assertEqual(len(results), 2)  # safe suppressed


class TestDeduplicateWithSarif(unittest.TestCase):
    def _raptor_finding(self, file, line, cwe):
        return {"file": file, "startLine": line, "cwe_id": cwe, "tool": "semgrep"}

    def _openant_finding(self, file, cwe):
        return {"file": file, "cwe_id": cwe, "tool": "openant"}

    def test_no_overlap_keeps_all(self):
        sarif = [self._raptor_finding("a.py", 10, "CWE-89")]
        oa = [self._openant_finding("b.py", "CWE-78")]
        merged, dropped = deduplicate_with_sarif(oa, sarif)
        self.assertEqual(dropped, 0)
        self.assertEqual(len(merged), 2)

    def test_same_file_same_cwe_drops_openant(self):
        sarif = [self._raptor_finding("a.py", 10, "CWE-89")]
        oa = [self._openant_finding("a.py", "CWE-89")]
        merged, dropped = deduplicate_with_sarif(oa, sarif)
        self.assertEqual(dropped, 1)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["tool"], "semgrep")

    def test_different_cwe_keeps_both(self):
        sarif = [self._raptor_finding("a.py", 10, "CWE-89")]
        oa = [self._openant_finding("a.py", "CWE-78")]
        merged, dropped = deduplicate_with_sarif(oa, sarif)
        self.assertEqual(dropped, 0)
        self.assertEqual(len(merged), 2)

    def test_empty_openant(self):
        sarif = [self._raptor_finding("a.py", 10, "CWE-89")]
        merged, dropped = deduplicate_with_sarif([], sarif)
        self.assertEqual(dropped, 0)
        self.assertEqual(merged, sarif)

    def test_empty_sarif(self):
        oa = [self._openant_finding("a.py", "CWE-89")]
        merged, dropped = deduplicate_with_sarif(oa, [])
        self.assertEqual(dropped, 0)
        self.assertEqual(len(merged), 1)


if __name__ == "__main__":
    unittest.main()


class TestUnknownVerdictsStayVisible(unittest.TestCase):
    """Only 'safe' suppresses. A verdict spelling the map does not
    know (schema drift in a newer OpenAnt) must be kept at level=note
    and warned — never silently dropped like 'safe'."""

    def _pipeline(self, verdict):
        return {"findings": [{
            "id": "VULN-001",
            "stage1_verdict": verdict,
            "location": {"file": "a.py", "function": "f"},
            "cwe_id": 78,
            "description": "d",
        }]}

    def test_unknown_verdict_kept_at_note(self):
        out = translate_pipeline_output(self._pipeline("exploitable_v2"))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["level"], "note")

    def test_missing_verdict_kept_at_note(self):
        out = translate_pipeline_output(self._pipeline(""))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["level"], "note")

    def test_safe_still_suppresses(self):
        out = translate_pipeline_output(self._pipeline("safe"))
        self.assertEqual(out, [])

    def test_known_verdicts_unchanged(self):
        out = translate_pipeline_output(self._pipeline("vulnerable"))
        self.assertEqual(out[0]["level"], "warning")


class TestDedupKeyRelativisation(unittest.TestCase):
    """SARIF findings carry absolute resolved URIs (CodeQL %SRCROOT%),
    OpenAnt findings carry repo-relative paths — the dedup key must
    relativise both sides or the join is vacuous (duplicates
    double-reported)."""

    def test_absolute_sarif_path_matches_relative_openant_path(self):
        oa = [{"tool": "openant", "file": "src/app.py", "cwe_id": "CWE-78"}]
        sarif = [{"tool": "codeql", "file": "/work/repo/src/app.py",
                  "cwe_id": "CWE-78"}]
        merged, dropped = deduplicate_with_sarif(oa, sarif,
                                                 repo_path="/work/repo")
        self.assertEqual(dropped, 1)
        self.assertEqual([f["tool"] for f in merged], ["codeql"])

    def test_outside_repo_sarif_path_never_matches(self):
        oa = [{"tool": "openant", "file": "src/app.py", "cwe_id": "CWE-78"}]
        sarif = [{"tool": "codeql", "file": "/elsewhere/src/app.py",
                  "cwe_id": "CWE-78"}]
        merged, dropped = deduplicate_with_sarif(oa, sarif,
                                                 repo_path="/work/repo")
        self.assertEqual(dropped, 0)
        self.assertEqual(len(merged), 2)

    def test_no_repo_path_keeps_relative_matching(self):
        oa = [{"tool": "openant", "file": "src/app.py", "cwe_id": "CWE-78"}]
        sarif = [{"tool": "codeql", "file": "src/app.py", "cwe_id": "CWE-78"}]
        merged, dropped = deduplicate_with_sarif(oa, sarif)
        self.assertEqual(dropped, 1)


class TestDedupKeyUriNormalization(unittest.TestCase):
    """CodeQL SARIF resolved against a file:// originalUriBaseIds base
    (%SRCROOT% — the shape core/sarif's own tests model) keeps the
    scheme in the finding's file field; the join must strip it (and
    unquote percent-encoding) or the key populations never meet and
    every CodeQL duplicate double-enters openant_findings.json and
    /validate."""

    def test_file_scheme_sarif_uri_matches_relative_openant_path(self):
        oa = [{"tool": "openant", "file": "src/app.py", "cwe_id": "CWE-78"}]
        sarif = [{"tool": "codeql",
                  "file": "file:///work/repo/src/app.py",
                  "cwe_id": "CWE-78"}]
        merged, dropped = deduplicate_with_sarif(oa, sarif,
                                                 repo_path="/work/repo")
        self.assertEqual(dropped, 1)
        self.assertEqual([f["tool"] for f in merged], ["codeql"])

    def test_percent_encoded_sarif_uri_matches_decoded_path(self):
        oa = [{"tool": "openant", "file": "src/my app.py",
               "cwe_id": "CWE-78"}]
        sarif = [{"tool": "codeql",
                  "file": "file:///work/repo/src/my%20app.py",
                  "cwe_id": "CWE-78"}]
        merged, dropped = deduplicate_with_sarif(oa, sarif,
                                                 repo_path="/work/repo")
        self.assertEqual(dropped, 1)

    def test_file_scheme_outside_repo_never_matches(self):
        oa = [{"tool": "openant", "file": "src/app.py", "cwe_id": "CWE-78"}]
        sarif = [{"tool": "codeql",
                  "file": "file:///elsewhere/src/app.py",
                  "cwe_id": "CWE-78"}]
        merged, dropped = deduplicate_with_sarif(oa, sarif,
                                                 repo_path="/work/repo")
        self.assertEqual(dropped, 0)
        self.assertEqual(len(merged), 2)

    def test_dotdot_prefixed_name_is_inside_root(self):
        """`..data/x.py` is a NAME, not a parent traversal — the old
        startswith('..') test kept it absolute and then lstrip-mangled
        it, voiding the join for that file both ways."""
        from packages.openant.translator import _normalize_path
        self.assertEqual(
            _normalize_path("/repo/..data/x.py", Path("/repo")),
            "..data/x.py")
        oa = [{"tool": "openant", "file": "..data/x.py",
               "cwe_id": "CWE-78"}]
        sarif = [{"tool": "codeql", "file": "/repo/..data/x.py",
                  "cwe_id": "CWE-78"}]
        merged, dropped = deduplicate_with_sarif(oa, sarif,
                                                 repo_path="/repo")
        self.assertEqual(dropped, 1)

    def test_genuine_parent_traversal_keeps_absolute_spelling(self):
        """An outside-root path keeps its absolute spelling — the old
        lstrip(os.sep) rewrote `/other/x.py` to `other/x.py`, a
        manufactured collision with a genuinely relative name."""
        from packages.openant.translator import _normalize_path
        self.assertEqual(
            _normalize_path("/other/x.py", Path("/repo")), "/other/x.py")
