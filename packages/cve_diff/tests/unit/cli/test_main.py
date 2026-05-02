"""Tests for cli/main.py — budget-extension helper + the run() command.

Adds end-to-end coverage for the `cve-diff run` CLI command using
typer's CliRunner. Previously only ``_budget_reason`` (a ~10-line
helper) was tested; the actual ``run()`` command + its 6 exit codes
+ artefact emission were untested. Closes the audit gap from
2026-04-30 ("Add tests for cve-diff run CLI command, currently
untested. Also test budget-extension prompts and --with-root-cause
flag.").
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cve_diff.agent.types import AgentOutput, AgentSurrender
from cve_diff.cli.main import _budget_reason, app
from cve_diff.core.models import CommitSha, PatchTuple


@pytest.mark.parametrize("text,expected", [
    ("DiscoveryError: CVE-X: agent surrendered (budget_cost_usd): ...", "budget_cost_usd"),
    ("DiscoveryError: CVE-X: agent surrendered (budget_iterations): foo", "budget_iterations"),
    ("DiscoveryError: CVE-X: agent surrendered (budget_tokens): bar", "budget_tokens"),
    ("DiscoveryError: CVE-X: agent surrendered (budget_s): elapsed", "budget_s"),
    # Non-budget surrenders should not match — we don't extend on those.
    ("DiscoveryError: CVE-X: agent surrendered (no_evidence): ...", None),
    ("DiscoveryError: CVE-X: agent surrendered (UnsupportedSource): ...", None),
    ("DiscoveryError: CVE-X: agent surrendered (llm_error): ...", None),
    # Other error classes should not match either.
    ("AcquisitionError: clone failed", None),
    ("", None),
])
def test_budget_reason_extracts_only_budget_family(text: str, expected: str | None) -> None:
    assert _budget_reason(text) == expected


# ---------- end-to-end: `cve-diff run` ----------

def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, check=True)
    return r.stdout.strip()


def _make_origin(tmp_path: Path) -> tuple[Path, str]:
    """A two-commit local repo we can clone via file://."""
    repo = tmp_path / "origin"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "f.txt").write_text("a\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "vulnerable")
    (repo / "f.txt").write_text("b\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "fix")
    return repo, _git(repo, "rev-parse", "HEAD")


def _patch_agent_loop(monkeypatch, result):
    """Monkey-patch ``AgentLoop.run`` to return a canned ``AgentResult``.

    Pipeline's ``agent: AgentLoop = field(default_factory=AgentLoop)``
    captures the AgentLoop class reference at class-definition time, so
    patching the module-level name doesn't help. Patching the bound
    method directly does — every Pipeline gets a real AgentLoop instance,
    but ``.run()`` is now our stub.
    """
    from cve_diff.agent.loop import AgentLoop

    def stub_run(self, _config, _ctx):
        self.last_telemetry = {
            "iterations": 2, "tokens": 100, "cost_usd": 0.01,
            "elapsed_s": 0.1,
            "tool_calls": ["osv_raw", "submit_result"],
            "tool_calls_with_args": [
                ("osv_raw", '{"cve_id": "CVE-X"}'),
                ("submit_result", '{"outcome": "rescued"}'),
            ],
            "llm_retries": 0,
        }
        return result
    monkeypatch.setattr(AgentLoop, "run", stub_run)


def test_run_pass_emits_all_six_artifacts(tmp_path, monkeypatch):
    """`cve-diff run CVE-X --output-dir TMP` on the PASS path emits:
       <cve>.osv.json, <cve>.md, <cve>.flow.jsonl, <cve>.flow.md,
       <cve>.clone.patch, and (when API extraction ran) the API patch.
    """
    origin, fix_sha = _make_origin(tmp_path)
    out = tmp_path / "out"

    _patch_agent_loop(monkeypatch, AgentOutput(
        value=PatchTuple(
            repository_url=f"file://{origin}",
            fix_commit=CommitSha(fix_sha),
            introduced=None,
        ),
        rationale="stub",
    ))

    runner = CliRunner()
    result = runner.invoke(app, [
        "run", "CVE-2024-99001",
        "--output-dir", str(out),
        "--disk-limit-pct", "99.9",
        "--quiet",  # suppress the API-key banner so output is deterministic
    ])
    assert result.exit_code == 0, result.output

    # Core artifacts always emitted.
    assert (out / "CVE-2024-99001.osv.json").exists()
    assert (out / "CVE-2024-99001.md").exists()
    # Flow artifacts (shipped 2026-04-30).
    assert (out / "CVE-2024-99001.flow.jsonl").exists()
    assert (out / "CVE-2024-99001.flow.md").exists()
    # Outcome patch — the clone diff (always present on PASS).
    assert (out / "CVE-2024-99001.clone.patch").exists()
    # API extraction skipped for file:// (non-GitHub) — no .github_api.patch.
    assert not list(out.glob("CVE-2024-99001.*api*.patch"))


def test_run_unsupported_exits_4(tmp_path, monkeypatch):
    """Agent surrendering UnsupportedSource → exit code 4 + failure md."""
    _patch_agent_loop(monkeypatch, AgentSurrender(
        reason="UnsupportedSource",
        detail="closed-source firmware",
    ))
    out = tmp_path / "out"
    result = CliRunner().invoke(app, [
        "run", "CVE-2024-99002",
        "--output-dir", str(out),
        "--disk-limit-pct", "99.9",
        "--quiet",
    ])
    assert result.exit_code == 4
    # Failure md should still exist for human review.
    assert (out / "CVE-2024-99002.md").exists()
    # Flow files should also exist on the failure path.
    assert (out / "CVE-2024-99002.flow.jsonl").exists()
    assert (out / "CVE-2024-99002.flow.md").exists()


def test_run_no_evidence_exits_5(tmp_path, monkeypatch):
    """Agent surrendering no_evidence → exit code 5 + failure md."""
    _patch_agent_loop(monkeypatch,
                      AgentSurrender(reason="no_evidence", detail="empty"))
    out = tmp_path / "out"
    result = CliRunner().invoke(app, [
        "run", "CVE-2024-99003",
        "--output-dir", str(out),
        "--disk-limit-pct", "99.9",
        "--quiet",
    ])
    assert result.exit_code == 5
    assert (out / "CVE-2024-99003.md").exists()
    assert (out / "CVE-2024-99003.flow.md").exists()


def test_run_writes_flow_md_with_pipeline_trace(tmp_path, monkeypatch):
    """End-to-end check that the rich pipeline-trace format
    (`Stage 1 — DISCOVER ✓`, `Stage 2 — ACQUIRE ✓`, etc.) actually
    lands in flow.md on a PASS — not just the legacy per-tool list."""
    origin, fix_sha = _make_origin(tmp_path)
    out = tmp_path / "out"
    _patch_agent_loop(monkeypatch, AgentOutput(
        value=PatchTuple(
            repository_url=f"file://{origin}",
            fix_commit=CommitSha(fix_sha),
            introduced=None,
        ),
        rationale="stub",
    ))
    CliRunner().invoke(app, [
        "run", "CVE-2024-99004",
        "--output-dir", str(out),
        "--disk-limit-pct", "99.9",
        "--quiet",
    ])
    flow_md = (out / "CVE-2024-99004.flow.md").read_text()
    # 5-stage rendering present
    assert "Stage 1 — DISCOVER" in flow_md
    assert "Stage 2 — ACQUIRE" in flow_md
    assert "Stage 3 — RESOLVE" in flow_md
    assert "Stage 4 — DIFF" in flow_md
    assert "Stage 5 — RENDER" in flow_md
    # Outcome marker
    assert "✓ PASS" in flow_md


def test_run_prints_flow_md_to_stdout_by_default(tmp_path, monkeypatch):
    """A user running `cve-diff run` without --quiet sees the rich
    pipeline-trace summary on stdout — not just `wrote /path` lines.
    The on-disk flow.md file is read back so screen and disk stay in sync."""
    origin, fix_sha = _make_origin(tmp_path)
    out = tmp_path / "out"
    _patch_agent_loop(monkeypatch, AgentOutput(
        value=PatchTuple(
            repository_url=f"file://{origin}",
            fix_commit=CommitSha(fix_sha),
            introduced=None,
        ),
        rationale="stub",
    ))
    result = CliRunner().invoke(app, [
        "run", "CVE-2024-99005",
        "--output-dir", str(out),
        "--disk-limit-pct", "99.9",
        # NOTE: no --quiet — the report should be printed.
    ])
    assert result.exit_code == 0, result.output
    # Pipeline-trace banner + content lands on stdout.
    assert "=== CVE-2024-99005 — pipeline trace ===" in result.output
    assert "Stage 1 — DISCOVER" in result.output
    assert "✓ PASS" in result.output
    # Artifact divider precedes the file paths.
    assert "=== Artifacts ===" in result.output


def test_run_quiet_suppresses_flow_md_on_stdout(tmp_path, monkeypatch):
    """With --quiet, the pipeline trace is NOT printed to stdout — only
    the `wrote /path` lines remain. flow.md still lands on disk for
    later inspection."""
    origin, fix_sha = _make_origin(tmp_path)
    out = tmp_path / "out"
    _patch_agent_loop(monkeypatch, AgentOutput(
        value=PatchTuple(
            repository_url=f"file://{origin}",
            fix_commit=CommitSha(fix_sha),
            introduced=None,
        ),
        rationale="stub",
    ))
    result = CliRunner().invoke(app, [
        "run", "CVE-2024-99006",
        "--output-dir", str(out),
        "--disk-limit-pct", "99.9",
        "--quiet",
    ])
    assert result.exit_code == 0, result.output
    # No trace on stdout under --quiet.
    assert "pipeline trace" not in result.output
    assert "Stage 1 — DISCOVER" not in result.output
    assert "=== Artifacts ===" not in result.output
    # But flow.md still exists on disk.
    assert (out / "CVE-2024-99006.flow.md").exists()
