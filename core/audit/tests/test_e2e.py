"""End-to-end test for /audit pipeline.

Exercises: checklist build → gaps → context → sweep → record → report
on a synthetic target. No LLM calls. Verifies findings.json emission,
gate enforcement, and report accuracy.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_AUDIT_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-audit")
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")

# G2's receipt gate demands an EXECUTED confirmed sweep — a missing
# semgrep binary turns every sweep into outcome=error, so the record/
# report/feedback chains below cannot be exercised at all. semgrep is
# deliberately not a Python requirement (same treatment as the other
# optional tools); skip-with-reason instead of failing red on hosts
# without it. The nightly workflow installs semgrep so these run in CI.
needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed",
)


def _run(args, **kwargs):
    env = dict(os.environ, CLAUDECODE="1", _RAPTOR_TRUSTED="1",
               PYTHONPATH=str(_RAPTOR_DIR))
    return subprocess.run(
        [sys.executable] + args,
        env=env, capture_output=True, text=True, check=False, **kwargs,
    )


def _write_target(tmp_path):
    """Create a small C target with a known bug and a clean function."""
    target = tmp_path / "target"
    target.mkdir()
    src = target / "vuln.c"
    src.write_text("""\
#include <stdio.h>
#include <string.h>

void safe_fn(const char *msg) {
    printf("%.100s\\n", msg);
}

void vuln_fn(char *user_input) {
    char buf[64];
    sprintf(buf, user_input);
}

int main(int argc, char **argv) {
    safe_fn(argv[1]);
    vuln_fn(argv[1]);
    return 0;
}
""")
    return target


def _write_semgrep_rule(out_dir):
    rules_dir = out_dir / "sweep-rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_path = rules_dir / "sprintf-format-string.yaml"
    rule_path.write_text("""\
rules:
  - id: sprintf-format-string
    pattern: sprintf($BUF, $FMT)
    message: "sprintf with format string from variable"
    languages: [c]
    severity: ERROR
""")
    return str(rule_path)


@pytest.mark.slow
class TestAuditE2E:

    @pytest.fixture()
    def setup(self, tmp_path):
        target = _write_target(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        return target, out_dir

    def test_checklist_build(self, setup):
        target, out_dir = setup
        r = _run([_CHECKLIST_CLI, str(target), str(out_dir)])
        assert r.returncode == 0, r.stderr
        cl = json.loads((out_dir / "checklist.json").read_text())
        assert cl["total_files"] >= 1
        names = {
            item["name"]
            for f in cl["files"]
            for item in f.get("items", [])
        }
        assert "vuln_fn" in names
        assert "safe_fn" in names

    def test_gaps_auto_builds_checklist(self, setup):
        target, out_dir = setup
        r = _run([_AUDIT_CLI, "gaps", "--out", str(out_dir),
                  "--target", str(target)])
        assert r.returncode == 0, r.stderr
        assert (out_dir / "checklist.json").exists()
        assert (out_dir / "gaps.json").exists()
        gaps = json.loads((out_dir / "gaps.json").read_text())
        assert gaps["count"] >= 2

    def test_gaps_warns_no_context_map(self, setup):
        target, out_dir = setup
        r = _run([_AUDIT_CLI, "gaps", "--out", str(out_dir),
                  "--target", str(target)])
        assert "no context-map.json" in r.stderr

    def test_context_assembly(self, setup):
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])
        r = _run([_AUDIT_CLI, "context", "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--line", "8", "--out", str(out_dir)])
        assert r.returncode == 0, r.stderr
        assert "sprintf" in r.stdout

    @needs_semgrep
    def test_record_finding_emits_findings_json(self, setup):
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])

        rule_path = _write_semgrep_rule(out_dir)
        _run([_AUDIT_CLI, "sweep",
              "--rule-file", rule_path,
              "--tool", "semgrep",
              "--file", "vuln.c", "--function", "vuln_fn",
              "--out", str(out_dir), "--target", str(target)])

        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--status", "finding",
                  "--hypothesis", "user_input flows to sprintf format arg",
                  "--evidence-tool", "semgrep",
                  "--vuln-type", "CWE-134",
                  "--body", "Semgrep confirmed sprintf(buf, user_input)",
                  "--line-start", "8",
                  "--reach-via", "called from main"])
        assert r.returncode == 0, r.stderr
        assert "Finding" in r.stdout

        findings_path = out_dir / "findings.json"
        assert findings_path.exists(), "findings.json not created"
        findings = json.loads(findings_path.read_text())
        assert len(findings) == 1
        assert findings[0]["file"] == "vuln.c"
        assert findings[0]["function"] == "vuln_fn"
        assert findings[0]["cwe"] == "CWE-134"

    def test_record_clean_no_findings_json(self, setup):
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "safe_fn",
              "--line", "4", "--out", str(out_dir)])

        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "safe_fn",
                  "--status", "clean",
                  "--body", "printf with %.100s truncation, safe"])
        assert r.returncode == 0, r.stderr
        findings_path = out_dir / "findings.json"
        if findings_path.exists():
            findings = json.loads(findings_path.read_text())
            assert not any(f["function"] == "safe_fn" for f in findings)

    def test_g5_blocks_without_context(self, setup):
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--status", "clean", "--body", "test"])
        assert r.returncode != 0
        assert "G5 READ-FIRST" in r.stderr

    @needs_semgrep
    def test_g7_blocks_finding_no_reach_via(self, setup):
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        # Supply an inventory where vuln_fn has zero callers so
        # _has_any_callers returns False (confirmed) not None (unknown).
        inv = {"files": [{"path": "vuln.c", "functions": [
            {"name": "vuln_fn", "line_start": 8, "callers": []},
        ]}]}
        (out_dir / "inventory.json").write_text(json.dumps(inv))

        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])

        rule_path = _write_semgrep_rule(out_dir)
        _run([_AUDIT_CLI, "sweep",
              "--rule-file", rule_path,
              "--tool", "semgrep",
              "--file", "vuln.c", "--function", "vuln_fn",
              "--out", str(out_dir), "--target", str(target)])

        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--status", "finding",
                  "--hypothesis", "format string",
                  "--evidence-tool", "semgrep",
                  "--vuln-type", "CWE-134",
                  "--body", "confirmed"])
        assert r.returncode != 0
        assert "G7 REACHABILITY" in r.stderr

    @needs_semgrep
    def test_report_counts_match(self, setup):
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        for fn, line, status in [("safe_fn", "4", "clean"),
                                 ("main", "13", "clean")]:
            _run([_AUDIT_CLI, "context", "--target", str(target),
                  "--file", "vuln.c", "--function", fn,
                  "--line", line, "--out", str(out_dir)])
            _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", fn,
                  "--status", status, "--body", "reviewed"])

        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])
        rule_path = _write_semgrep_rule(out_dir)
        _run([_AUDIT_CLI, "sweep",
              "--rule-file", rule_path,
              "--tool", "semgrep",
              "--file", "vuln.c", "--function", "vuln_fn",
              "--out", str(out_dir), "--target", str(target)])
        _run([_AUDIT_CLI, "record",
              "--out", str(out_dir), "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--status", "finding",
              "--hypothesis", "format string",
              "--evidence-tool", "semgrep",
              "--vuln-type", "CWE-134",
              "--body", "confirmed",
              "--line-start", "8",
              "--reach-via", "called from main"])

        r = _run([_AUDIT_CLI, "report",
                  "--out", str(out_dir), "--target", str(target)])
        assert r.returncode == 0, r.stderr
        assert "Functions LLM-reviewed: 3" in r.stdout
        assert "Clean: 2" in r.stdout
        assert "Finding: 1" in r.stdout
        assert "Tool-confirmed findings: 1" in r.stdout

    @needs_semgrep
    def test_critique_identifies_mode2_gap(self, setup):
        """Critique identifies confirmed findings without codebase-wide rules."""
        target, out_dir = setup
        r = _run([_CHECKLIST_CLI, str(target), str(out_dir)])
        assert r.returncode == 0, r.stderr

        # Review vuln_fn: context → sweep → finding
        r = _run([_AUDIT_CLI, "context", "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--line", "8", "--out", str(out_dir)])
        assert r.returncode == 0, r.stderr
        rule_path = _write_semgrep_rule(out_dir)
        r = _run([_AUDIT_CLI, "sweep",
                  "--rule-file", rule_path,
                  "--tool", "semgrep",
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--out", str(out_dir), "--target", str(target)])
        assert r.returncode == 0, r.stderr
        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--status", "finding",
                  "--hypothesis", "format string",
                  "--evidence-tool", "semgrep",
                  "--vuln-type", "CWE-134",
                  "--body", "confirmed",
                  "--line-start", "8",
                  "--reach-via", "called from main"])
        assert r.returncode == 0, r.stderr

        # Review safe_fn: context → clean (only 0 sweeps)
        r = _run([_AUDIT_CLI, "context", "--target", str(target),
                  "--file", "vuln.c", "--function", "safe_fn",
                  "--line", "4", "--out", str(out_dir)])
        assert r.returncode == 0, r.stderr
        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "safe_fn",
                  "--status", "clean", "--body", "reviewed"])
        assert r.returncode == 0, r.stderr

        r = _run([_AUDIT_CLI, "critique", "--out", str(out_dir)])
        assert r.returncode == 0, r.stderr
        # Should flag vuln_fn as Mode 2 gap (finding without rule)
        assert "Mode 2 gap" in r.stdout
        assert "vuln_fn" in r.stdout
        # Should flag safe_fn as low sweep coverage
        assert "Low tool coverage" in r.stdout

    def test_smt_sweep_manual(self, setup):
        """SMT sweep logs a manual entry when no auto-run is possible."""
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])

        r = _run([_AUDIT_CLI, "sweep",
                  "--tool", "smt",
                  "--smt-verb", "check-overflow",
                  "--smt-args",
                  '{"var":"len","type":"int32","op":"len*4"}',
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--out", str(out_dir), "--target", str(target)])
        assert r.returncode == 0, r.stderr
        assert "smt:check-overflow" in r.stdout

    def test_context_includes_strategy_exemplars(self, setup):
        """Context assembly includes per-strategy CVE exemplars."""
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        r = _run([_AUDIT_CLI, "context", "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--line", "8", "--out", str(out_dir)])
        assert r.returncode == 0, r.stderr
        # General strategy exemplars should always appear
        assert "CVE-2022-0995" in r.stdout or "Strategy exemplars" in r.stdout

    @needs_semgrep
    def test_feedback_downgrades_disproven_finding(self, setup):
        """Feedback loop: /validate disproved → annotation downgraded."""
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        # Review vuln_fn as finding
        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])
        rule_path = _write_semgrep_rule(out_dir)
        _run([_AUDIT_CLI, "sweep",
              "--rule-file", rule_path,
              "--tool", "semgrep",
              "--file", "vuln.c", "--function", "vuln_fn",
              "--out", str(out_dir), "--target", str(target)])
        _run([_AUDIT_CLI, "record",
              "--out", str(out_dir), "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--status", "finding",
              "--hypothesis", "format string",
              "--evidence-tool", "semgrep",
              "--vuln-type", "CWE-134",
              "--body", "confirmed format string",
              "--line-start", "8",
              "--reach-via", "called from main"])

        # Write a fake /validate report that disproves it
        validate_report = out_dir / "validate-findings.json"
        import json as _json
        validate_report.write_text(_json.dumps([{
            "file": "vuln.c",
            "function": "vuln_fn",
            "ruling": {
                "status": "ruled_out",
                "disqualifier": "D-1",
                "reason": "test-only code, not production",
            },
            "is_true_positive": False,
        }]))

        ann_dir = out_dir / "annotations"
        r = _run([_AUDIT_CLI, "feedback",
                  "--validation-report", str(validate_report),
                  "--annotations-dir", str(ann_dir),
                  "--audit-out", str(out_dir)])
        assert r.returncode == 0, r.stderr
        assert "Downgraded: 1" in r.stdout

        # Verify journal carries the corrected verdict
        journal_path = out_dir / "review-journal.jsonl"
        assert journal_path.exists(), "review-journal.jsonl not created"
        entries = json.loads("[" + ",".join(
            journal_path.read_text().strip().splitlines()
        ) + "]")
        correction = [
            e for e in entries
            if e.get("function") == "vuln_fn"
            and e.get("prior_review")
        ]
        assert correction, "no correction entry in journal"
        assert correction[-1]["verdict"] == "clean"
        assert correction[-1]["prior_review"] == "finding"

    def test_feedback_upgrades_missed_clean(self, setup):
        """Feedback loop: /validate confirms → clean upgraded to finding."""
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        # Review safe_fn as clean
        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "safe_fn",
              "--line", "4", "--out", str(out_dir)])
        _run([_AUDIT_CLI, "record",
              "--out", str(out_dir), "--target", str(target),
              "--file", "vuln.c", "--function", "safe_fn",
              "--status", "clean", "--body", "looks safe"])

        # /validate says it's actually exploitable
        validate_report = out_dir / "validate-findings.json"
        import json as _json
        validate_report.write_text(_json.dumps([{
            "file": "vuln.c",
            "function": "safe_fn",
            "ruling": {"status": "exploitable"},
            "is_true_positive": True,
        }]))

        ann_dir = out_dir / "annotations"
        r = _run([_AUDIT_CLI, "feedback",
                  "--validation-report", str(validate_report),
                  "--annotations-dir", str(ann_dir),
                  "--audit-out", str(out_dir)])
        assert r.returncode == 0, r.stderr
        assert "Upgraded: 1" in r.stdout

        # Verify journal carries the upgraded verdict
        journal_path = out_dir / "review-journal.jsonl"
        assert journal_path.exists(), "review-journal.jsonl not created"
        entries = json.loads("[" + ",".join(
            journal_path.read_text().strip().splitlines()
        ) + "]")
        correction = [
            e for e in entries
            if e.get("function") == "safe_fn"
            and e.get("prior_review")
        ]
        assert correction, "no correction entry in journal"
        assert correction[-1]["verdict"] == "finding"
        assert correction[-1]["prior_review"] == "clean"

    def test_g1_blocks_finding_without_hypothesis(self, setup):
        """G1: finding without --hypothesis is rejected."""
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])

        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--status", "finding",
                  "--evidence-tool", "semgrep",
                  "--vuln-type", "CWE-134",
                  "--body", "format string",
                  "--line-start", "8",
                  "--reach-via", "called from main"])
        assert r.returncode != 0
        assert "G1" in r.stderr

    def test_g2_blocks_finding_without_evidence_tool(self, setup):
        """G2: finding without --evidence-tool is rejected."""
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])

        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "vuln_fn",
                  "--status", "finding",
                  "--hypothesis", "format string",
                  "--vuln-type", "CWE-134",
                  "--body", "format string",
                  "--line-start", "8",
                  "--reach-via", "called from main"])
        assert r.returncode != 0
        assert "G2" in r.stderr

    def test_related_to_same_file(self, setup):
        """--related-to allows recording sibling functions."""
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        # Read context for vuln_fn
        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])

        # Record safe_fn with --related-to vuln_fn (same file)
        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "vuln.c", "--function", "safe_fn",
                  "--status", "clean", "--body", "reviewed as sibling",
                  "--related-to", "vuln.c:vuln_fn"])
        assert r.returncode == 0, r.stderr

    def test_related_to_different_file_blocked(self, setup):
        """--related-to rejects cross-file references."""
        target, out_dir = setup
        _run([_CHECKLIST_CLI, str(target), str(out_dir)])

        _run([_AUDIT_CLI, "context", "--target", str(target),
              "--file", "vuln.c", "--function", "vuln_fn",
              "--line", "8", "--out", str(out_dir)])

        r = _run([_AUDIT_CLI, "record",
                  "--out", str(out_dir), "--target", str(target),
                  "--file", "other.c", "--function", "other_fn",
                  "--status", "clean", "--body", "cross-file",
                  "--related-to", "vuln.c:vuln_fn"])
        assert r.returncode != 0
        assert "different file" in r.stderr

    def test_rules_save_and_list(self, setup):
        """Rules subcommand: save and list."""
        _target, out_dir = setup

        rule_content = (
            "rules:\n"
            "  - id: test-rule\n"
            "    pattern: printf($FMT)\n"
            "    message: potential format string\n"
            "    severity: WARNING\n"
            "    languages: [c]\n"
        )
        rule_file = out_dir / "test-rule.yaml"
        rule_file.write_text(rule_content)

        r = _run([_AUDIT_CLI, "rules", "save",
                  "--rule-id", "format-string-check",
                  "--tool", "semgrep",
                  "--content-file", str(rule_file),
                  "--out", str(out_dir)])
        assert r.returncode == 0, r.stderr

        r = _run([_AUDIT_CLI, "rules", "list",
                  "--out", str(out_dir)])
        assert r.returncode == 0, r.stderr
        assert "format-string-check" in r.stdout

    def test_gaps_prioritize_flag(self, setup):
        """--prioritize scores and re-sorts gaps by attack surface."""
        target, out_dir = setup

        context_map = {
            "entry_points": [{"file": "vuln.c", "name": "vuln_fn"}],
            "sinks": [],
        }
        (out_dir / "context-map.json").write_text(
            json.dumps(context_map)
        )

        r = _run([_AUDIT_CLI, "gaps",
                  "--out", str(out_dir),
                  "--target", str(target),
                  "--prioritize"])
        assert r.returncode == 0, r.stderr
        assert "gaps:" in r.stdout

        gaps = json.loads((out_dir / "gaps.json").read_text())
        scored = [g for g in gaps["gaps"] if "priority_score" in g]
        assert len(scored) > 0

    def test_context_annotations_dir(self, setup):
        """--annotations-dir lets context use a custom dir."""
        target, out_dir = setup

        ann_dir = out_dir / "custom-ann"
        ann_dir.mkdir()

        r = _run([_AUDIT_CLI, "context",
                  "--target", str(target),
                  "--file", "vuln.c",
                  "--function", "vuln_fn",
                  "--annotations-dir", str(ann_dir),
                  "--out", str(out_dir),
                  "--json"])
        assert r.returncode == 0, r.stderr
