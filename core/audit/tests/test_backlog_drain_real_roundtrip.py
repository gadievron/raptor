"""Witness-backlog drain — real synthesized-checker round-trip.

Only the LLM is faked (a canned Semgrep rule + fixtures); everything
downstream is real: ``synthesise_and_run`` writes the rule, the real
Semgrep engine runs the positive control against the synthetic target
and the dual control against the fixtures, and the drain routes the
result through the real journal-write path.

Both directions:
* a trivially semgrep-able dark row (``os.system(cmd)``) earns a
  confirmed receipt -> journal row with tool evidence, row leaves the
  backlog;
* a rule that cannot match the seed fails the positive control ->
  the row stays dark with a drain-attempt record.

Evidence tier: requires the ``semgrep`` binary (skipped when absent,
or when the sandboxed adapter cannot execute it on this host).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit.backlog_drain import (
    BACKLOG_FILENAME,
    DRAIN_REPORT_FILENAME,
    drain,
)

HAVE_SEMGREP = shutil.which("semgrep") is not None

needs_semgrep = pytest.mark.skipif(
    not HAVE_SEMGREP, reason="semgrep not installed",
)

_MATCHING_RULE = (
    "rules:\n"
    "  - id: drain.os-system\n"
    "    message: user data reaches os.system\n"
    "    languages: [python]\n"
    "    severity: ERROR\n"
    "    pattern: os.system(...)\n"
)

_NON_MATCHING_RULE = (
    "rules:\n"
    "  - id: drain.eval-only\n"
    "    message: eval call\n"
    "    languages: [python]\n"
    "    severity: ERROR\n"
    "    pattern: eval(...)\n"
)

_TEST_POSITIVE = "import os\n\n\ndef bad(c):\n    os.system(c)\n"
_TEST_NEGATIVE = (
    "import subprocess\n\n\ndef ok(c):\n    subprocess.run([c])\n"
)


def _probe_or_skip_semgrep(tmp_path: Path) -> None:
    """Skip when the sandboxed adapter cannot run semgrep at all —
    this file verifies the drain round-trip, not sandbox
    availability (same pattern as the substrate's engine-truth
    tests)."""
    from packages.checker_synthesis.synthesise import _run_semgrep
    rule = tmp_path / "probe.yaml"
    rule.write_text(_MATCHING_RULE, encoding="utf-8")
    target = tmp_path / "probe.py"
    target.write_text("import os\nos.system('x')\n", encoding="utf-8")
    matches, errors = _run_semgrep(rule, target)
    if errors or not matches:
        pytest.skip(f"semgrep adapter probe failed on this host: {errors}")


def _fixtures(tmp_path: Path) -> tuple[Path, Path]:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    target = tmp_path / "target"
    (target / "app").mkdir(parents=True)
    (target / "app" / "run.py").write_text(
        "import os\n" + "\n" * 9
        + "def launch(cmd):\n    os.system(cmd)\n",
        encoding="utf-8",
    )
    (run_dir / BACKLOG_FILENAME).write_text(json.dumps({
        "source_file": "findings-graded.json",
        "total": 1,
        "clusters": [{
            "class": "CWE-78",
            "count": 1,
            "sites": [{
                "id": "app/run.py:launch:12",
                "file": "app/run.py",
                "function": "launch",
                "line": 12,
                "title": ("user-controlled cmd reaches os.system "
                          "without sanitisation (command injection)"),
            }],
        }],
    }), encoding="utf-8")
    return run_dir, target


def _fake_llm(monkeypatch, tmp_path: Path, rule_body: str) -> None:
    """Fake ONLY the LLM: the callable returns a canned synthesis
    response; the engine, controls, and journal path stay real. The
    rule library is redirected to a tmp dir (hermeticity)."""

    def fake_callable(prompt: str, schema: dict, system_prompt: str):
        fake_callable.cost_usd += 0.01
        return {
            "rule_body": rule_body,
            "rationale": "canned rule for the round-trip test",
            "test_positive": _TEST_POSITIVE,
            "test_negative": _TEST_NEGATIVE,
        }

    fake_callable.cost_usd = 0.0
    monkeypatch.setattr(
        "core.audit.checker_synthesis._build_llm_callable",
        lambda config: (
            fake_callable, SimpleNamespace(model_name="canned"),
        ),
    )
    monkeypatch.setattr(
        "packages.checker_synthesis.library._default_library_dir",
        lambda: tmp_path / "rule-library",
    )


@needs_semgrep
class TestRealRoundTrip:
    def test_semgrepable_dark_row_is_witnessed(self, tmp_path, monkeypatch):
        _probe_or_skip_semgrep(tmp_path)
        run_dir, target = _fixtures(tmp_path)
        _fake_llm(monkeypatch, tmp_path, _MATCHING_RULE)

        report = drain(run_dir, target, 1.0)

        if report.witnessed != 1:
            # The drain report collapses failure identity — a rule the
            # controls refused and an engine the loaded runtime failed
            # to carry both read "still dark". Re-probe the adapter:
            # a degraded engine skips with the probe's identity; a
            # healthy one falls through to the hard failures below.
            _probe_or_skip_semgrep(tmp_path)
        assert report.witnessed == 1
        assert report.attempted == 0
        assert report.spent_usd > 0

        # The rule really landed on disk via the substrate.
        checkers = list((run_dir / "checkers").glob("*.yml"))
        assert checkers, "synthesised rule file missing"

        # Journal row through the real write path, with the real
        # receipt (self-matched: no confirming-evidence stamp).
        journal = (run_dir / "review-journal.jsonl").read_text(
            encoding="utf-8")
        entries = [json.loads(x) for x in journal.splitlines() if x.strip()]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["verdict"] == "suspicious"
        assert entry["producer"] == "backlog-drain"
        assert entry["file"] == "app/run.py"
        assert ":synth-" in entry["body"]
        assert not entry.get("evidence_tools")

        artifact = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert artifact["total"] == 0
        assert artifact["clusters"][0]["sites"] == []

        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        row = next(r for r in report_data["rows"]
                   if r.get("action") == "witnessed")
        assert row["engine"] == "semgrep"
        assert row["self_match"] is True

    def test_unmatchable_rule_leaves_row_dark(self, tmp_path, monkeypatch):
        _probe_or_skip_semgrep(tmp_path)
        run_dir, target = _fixtures(tmp_path)
        # The canned rule cannot match the seed site: the positive
        # control refuses, no receipt is earned, the row stays dark.
        _fake_llm(monkeypatch, tmp_path, _NON_MATCHING_RULE)

        report = drain(run_dir, target, 1.0)

        # Vacuity fence: a still-dark row is ALSO what a dead engine
        # produces, so this receipt proves nothing unless the adapter
        # can still carry a known-matching rule. (A transient that
        # degraded only the in-drain run and healed by now is not
        # detectable on this surface — the drain report carries no
        # error identity.)
        _probe_or_skip_semgrep(tmp_path)
        assert report.witnessed == 0
        assert report.attempted == 1
        assert not (run_dir / "review-journal.jsonl").exists()

        artifact = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert artifact["total"] == 1
        site = artifact["clusters"][0]["sites"][0]
        assert site["drain_attempts"] == 1

        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        row = next(r for r in report_data["rows"]
                   if r.get("action") == "attempted")
        assert "still dark" in row["reason"]
