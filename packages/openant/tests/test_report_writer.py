"""Regression tests for the openant-report.md writer.

The report interpolates hostile-influenced values: ``snippet`` is
verbatim target code, ``message`` / ``vuln_name`` are OpenAnt LLM
output that can quote target text. A snippet containing ``` must not
terminate the report's fence and inject live markdown.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

import tempfile

import raptor_openant


def _hostile_finding() -> dict:
    return {
        "finding_id": "openant:VULN-001",
        "cwe_id": "CWE-78",
        "file": "src/evil\x1b[31m.py",
        "level": "warning",
        "message": "look ![beacon](https://evil.example/x)\n# FORGED SECTION",
        "snippet": "os.system(cmd)\n```\n# INJECTED HEADING\n<img src=//evil>",
        "metadata": {
            "function": "run|`tick`",
            "vuln_name": "evil\n# forged",
            "stage1_verdict": "vulnerable",
            "stage2_verdict": "",
        },
    }


class TestMarkdownReportFenceEscape(unittest.TestCase):

    def _render(self, findings) -> str:
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            raptor_openant._write_markdown_report(
                out_dir, findings, Path("/repo"), 1.0,
            )
            return (out_dir / "openant-report.md").read_text()

    def test_snippet_cannot_terminate_fence(self):
        out = self._render([_hostile_finding()])
        # Exactly the writer's own fence pair survives as a parseable
        # fence; the snippet's embedded ``` run is defanged (ZWSP).
        self.assertEqual(out.count("```"), 2)
        # The snippet content itself is still visible to the reader.
        self.assertIn("os.system(cmd)", out)

    def test_message_markdown_is_defanged(self):
        out = self._render([_hostile_finding()])
        self.assertNotIn("![beacon](", out)
        self.assertNotIn("\n# FORGED SECTION", out)

    def test_heading_slots_are_single_line(self):
        out = self._render([_hostile_finding()])
        # vuln_name's newline cannot open a forged heading line.
        self.assertNotIn("\n# forged", out)
        for line in out.splitlines():
            if line.startswith("### "):
                self.assertNotIn("\x1b", line)

    def test_file_slot_escapes_control_bytes(self):
        out = self._render([_hostile_finding()])
        self.assertNotIn("\x1b", out)

    def test_empty_findings_shape_unchanged(self):
        out = self._render([])
        self.assertIn("No findings after suppression.", out)


class TestReportSeverityFirstCut(unittest.TestCase):
    """The report cap selects severity-first (error > warning > note,
    stable within a level) and states the truncation with the TRUE
    total in the header."""

    @staticmethod
    def _finding(i: int, level: str) -> dict:
        return {"finding_id": f"openant:VULN-{i:03d}", "cwe_id": "CWE-78",
                "file": "a.py", "level": level, "message": "m",
                "snippet": "", "metadata": {"function": "f",
                                            "vuln_name": "n",
                                            "stage1_verdict": "vulnerable",
                                            "stage2_verdict": ""}}

    def test_selection_is_severity_first_and_stable(self):
        findings = ([self._finding(i, "warning") for i in range(4)]
                    + [self._finding(i, "error") for i in range(4, 6)]
                    + [self._finding(6, "note")])
        cut = raptor_openant._report_selection(findings, 3)
        self.assertEqual(
            [f["finding_id"] for f in cut],
            ["openant:VULN-004", "openant:VULN-005", "openant:VULN-000"])

    def test_truncation_note_and_true_total(self):
        findings = ([self._finding(i, "warning") for i in range(3)]
                    + [self._finding(3, "error")])
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            raptor_openant._write_markdown_report(
                out_dir, findings, Path("/repo"), 1.0, max_findings=2)
            out = (out_dir / "openant-report.md").read_text()
        self.assertIn("**Findings:** 4", out)
        self.assertIn("top 2 of 4", out)
        self.assertIn("## High (1)", out)

    def test_no_truncation_note_when_under_cap(self):
        findings = [self._finding(0, "warning")]
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            raptor_openant._write_markdown_report(
                out_dir, findings, Path("/repo"), 1.0, max_findings=50)
            out = (out_dir / "openant-report.md").read_text()
        self.assertNotIn("Report truncated", out)


class TestReportWriteSurvivesCLocale(unittest.TestCase):
    """The fence defang inserts ZWSP, so the report is non-ASCII
    exactly when hostile content fired the defence — an encoding-less
    write_text crashed under a C locale (PYTHONCOERCECLOCALE=0
    PYTHONUTF8=0 LC_ALL=C)."""

    def test_report_written_under_c_locale(self):
        import os
        import subprocess
        import sys as _sys
        repo_root = Path(__file__).parents[3]
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import raptor_openant\n"
            "f = {'finding_id': 'openant:V1', 'cwe_id': 'CWE-78',\n"
            "     'file': 'a.py', 'level': 'warning', 'message': 'm',\n"
            "     'snippet': 'a\\n```\\nb',\n"
            "     'metadata': {'function': 'f', 'vuln_name': 'n',\n"
            "                  'stage1_verdict': 'vulnerable',\n"
            "                  'stage2_verdict': ''}}\n"
            "raptor_openant._write_markdown_report(\n"
            "    Path(sys.argv[2]), [f], Path('/repo'), 1.0)\n"
        )
        env = {**os.environ, "PYTHONCOERCECLOCALE": "0",
               "PYTHONUTF8": "0", "LC_ALL": "C", "LANG": "C"}
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run(
                [_sys.executable, "-c", script, str(repo_root), td],
                capture_output=True, text=True, timeout=60,
                cwd=str(repo_root), env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = (Path(td) / "openant-report.md").read_bytes()
        self.assertIn("\u200b".encode("utf-8"), data,
                      "defang ZWSP expected in the fence-carrying report")

    def test_stderr_log_write_names_utf8(self):
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        block = scanner_src.split("def _persist_stderr")[1].split(
            "def _find_venv_python")[0]
        self.assertIn("openant.stderr.log", block)
        self.assertIn('encoding="utf-8"', block)


class TestUnknownLevelRendered(unittest.TestCase):
    """A finding with a level outside the known universe must render
    in the report body (its own section), not vanish while the header
    counts it."""

    def test_unknown_level_gets_a_section(self):
        f = {"finding_id": "openant:V1", "cwe_id": "CWE-78",
             "file": "a.py", "level": "critical", "message": "m",
             "snippet": "", "metadata": {"function": "f",
                                         "vuln_name": "n",
                                         "stage1_verdict": "vulnerable",
                                         "stage2_verdict": ""}}
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            raptor_openant._write_markdown_report(
                out_dir, [f], Path("/repo"), 1.0)
            out = (out_dir / "openant-report.md").read_text()
        self.assertIn("**Findings:** 1", out)
        self.assertIn("Other (critical)", out)
        self.assertIn("openant:V1", out)


class TestRecoveredVerdictSection(unittest.TestCase):
    """Recovered checkpoint verdicts render in their OWN section with
    their own header count — never blended into the findings count —
    and every hostile-influenced slot stays escaped."""

    @staticmethod
    def _recovered(i: int = 0, **overrides) -> dict:
        rec = {
            "finding_id": f"openant-recovered:app/db.py:q{i}",
            "cwe_id": "CWE-89",
            "file": "app/db.py",
            "level": "note",
            "message": "reasoning text",
            "snippet": "",
            "metadata": {
                "function": f"q{i}",
                "vuln_name": "SQL Injection",
                "stage1_verdict": "vulnerable",
                "stage2_verdict": "",
                "provenance_tier": "recovered_checkpoint_verdict",
                "recovery_source": "dedup_rederivation",
                "deduplicated_into": "app/api.py:handle",
            },
        }
        rec.update(overrides)
        return rec

    def _render(self, findings, recovered, max_findings=None) -> str:
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            raptor_openant._write_markdown_report(
                out_dir, findings, Path("/repo"), 1.0,
                max_findings=max_findings, recovered=recovered)
            return (out_dir / "openant-report.md").read_text()

    def test_section_and_header_count_separately(self):
        f = {"finding_id": "openant:V1", "cwe_id": "CWE-78",
             "file": "a.py", "level": "warning", "message": "m",
             "snippet": "", "metadata": {"function": "f",
                                         "vuln_name": "n",
                                         "stage1_verdict": "vulnerable",
                                         "stage2_verdict": ""}}
        out = self._render([f], [self._recovered()])
        self.assertIn("**Findings:** 1", out)
        self.assertIn("**Recovered checkpoint verdicts:** 1", out)
        self.assertIn("## Recovered checkpoint verdicts (1)", out)
        self.assertIn("openant-recovered:app/db.py:q0", out)
        self.assertIn("**Deduplicated into:**", out)
        # The recovered record renders ONLY in its section, not in the
        # level sections.
        self.assertNotIn("## Low/Informational", out)

    def test_zero_recovered_renders_nothing(self):
        out = self._render([], [])
        self.assertNotIn("Recovered checkpoint verdicts", out)

    def test_recovered_slots_are_escaped(self):
        hostile = self._recovered(
            message="![beacon](https://evil.example/x)\n# FORGED",
            file="app/ev\x1bil.py",
        )
        hostile["metadata"]["vuln_name"] = "bad\n# forged"
        hostile["metadata"]["deduplicated_into"] = "x\x1b[31m:y"
        out = self._render([], [hostile])
        self.assertNotIn("\x1b", out)
        self.assertNotIn("![beacon](", out)
        self.assertNotIn("\n# FORGED", out)
        self.assertNotIn("\n# forged", out)

    def test_recovered_section_truncates_with_stated_cut(self):
        recovered = [self._recovered(i) for i in range(5)]
        out = self._render([], recovered, max_findings=2)
        self.assertIn("## Recovered checkpoint verdicts (5)", out)
        self.assertIn("showing 2 of 5 recovered", out)


if __name__ == "__main__":
    unittest.main()
