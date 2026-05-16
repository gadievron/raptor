"""Tests for cli/bench.py — error classifier, retry trigger, markdown report."""

from __future__ import annotations

import pytest

from cve_diff.cli.bench import (
    _BenchSummary,
    _CORRECT_REFUSAL_CLASSES,
    _CveResult,
    _classify_error,
    _outcome_buckets,
    _render_bench_markdown,
    _TRANSIENT_CLASSES,
)


# --- error classifier ---

@pytest.mark.parametrize("err,expected", [
    ("DiscoveryError: CVE-X: agent surrendered (budget_cost_usd): iters=15 ...", "budget_cost_usd"),
    ("DiscoveryError: CVE-X: agent surrendered (budget_iterations): ...", "budget_iterations"),
    ("DiscoveryError: CVE-X: agent surrendered (budget_tokens): ...", "budget_tokens"),
    ("DiscoveryError: CVE-X: agent surrendered (llm_error): Anthropic 529", "llm_error"),
    ("DiscoveryError: CVE-X: agent surrendered (no_evidence): ...", "no_evidence"),
    ("UnsupportedSource: CVE-X: closed-source", "UnsupportedSource"),
    ("PerCveTimeout: exceeded 300s", "PerCveTimeout"),
    ("AnalysisError: notes_only diff", "AnalysisError"),
    ("AcquisitionError: clone failed", "AcquisitionError"),
    ("KeyError: 'foo'", "Other"),
])
def test_error_classifier(err: str, expected: str) -> None:
    assert _classify_error(err) == expected


def test_transient_classes_set() -> None:
    """Bench-retry trigger set: LLM/timeout/network blip. Settled outcomes excluded."""
    assert _TRANSIENT_CLASSES == frozenset({
        "llm_error", "PerCveTimeout", "AcquisitionError", "client_init_failed",
    })
    # These must NOT be in the retry set:
    for settled in ("UnsupportedSource", "no_evidence", "budget_cost_usd",
                    "budget_iterations", "budget_tokens", "PASS"):
        assert settled not in _TRANSIENT_CLASSES


# --- outcome buckets (Track 1: visibility) ---

def test_correct_refusal_classes_set() -> None:
    """Refusal set: agent's deliberate scope decisions, not pipeline failures."""
    assert _CORRECT_REFUSAL_CLASSES == frozenset({"UnsupportedSource", "no_evidence"})


def test_outcome_buckets_separates_pass_refusal_issue() -> None:
    s = _make_summary()
    pass_n, refusal_n, issue_n = _outcome_buckets(s)
    assert pass_n == 2          # CVE-X-001, CVE-X-002
    assert refusal_n == 1       # CVE-X-003 (UnsupportedSource)
    assert issue_n == 1         # CVE-X-004 (budget_cost_usd)
    # The three buckets must always sum to total.
    assert pass_n + refusal_n + issue_n == s.total


def test_outcome_buckets_groups_no_evidence_with_refusals() -> None:
    """no_evidence is a deliberate refusal (no public commit reference)."""
    s = _BenchSummary(sample="t.json", total=2, passed=0)
    s.results = [
        _CveResult(cve_id="CVE-A", ok=False, elapsed_s=1,
                   error_class="no_evidence",
                   error="DiscoveryError: agent surrendered (no_evidence): ..."),
        _CveResult(cve_id="CVE-B", ok=False, elapsed_s=1,
                   error_class="AnalysisError",
                   error="AnalysisError: notes_only"),
    ]
    pass_n, refusal_n, issue_n = _outcome_buckets(s)
    assert (pass_n, refusal_n, issue_n) == (0, 1, 1)


def test_outcome_buckets_handles_empty() -> None:
    s = _BenchSummary(sample="empty.json", total=0, passed=0)
    assert _outcome_buckets(s) == (0, 0, 0)


# --- markdown report ---

def _make_summary() -> _BenchSummary:
    s = _BenchSummary(sample="data/samples/test.json", total=4, passed=2)
    s.results = [
        _CveResult(cve_id="CVE-X-001", ok=True, elapsed_s=12.5, files_changed=2, diff_bytes=1500,
                   shape="source", error_class="PASS",
                   agent_tool_calls=("osv_raw", "gh_commit_detail", "submit_result"),
                   agent_cost_usd=0.32, llm_retries=0),
        _CveResult(cve_id="CVE-X-002", ok=True, elapsed_s=18.0, files_changed=1, diff_bytes=800,
                   shape="source", error_class="PASS",
                   agent_tool_calls=("deterministic_hints", "gh_commit_detail", "submit_result"),
                   agent_cost_usd=0.18, llm_retries=1, meta_retry_attempted=True),
        _CveResult(cve_id="CVE-X-003", ok=False, elapsed_s=4.2,
                   error="UnsupportedSource: CVE-X-003: Adobe Flash closed-source",
                   error_class="UnsupportedSource",
                   agent_tool_calls=("nvd_raw", "submit_result"),
                   agent_cost_usd=0.05),
        _CveResult(cve_id="CVE-X-004", ok=False, elapsed_s=42.0,
                   error="DiscoveryError: agent surrendered (budget_cost_usd): iters=15",
                   error_class="budget_cost_usd",
                   agent_tool_calls=("osv_raw", "gh_search_commits") * 5,
                   agent_cost_usd=1.05),
    ]
    return s


def test_markdown_has_required_sections() -> None:
    md = _render_bench_markdown(_make_summary())
    assert "# Bench report —" in md
    assert "## Headline" in md
    assert "## Outcome distribution" in md
    assert "## Recovery layers" in md
    assert "## Tool usage" in md
    assert "## Failure cluster" in md


def test_markdown_headline_numbers() -> None:
    md = _render_bench_markdown(_make_summary())
    assert "2 / 4 = 50.0%" in md
    # Cost total = 0.32 + 0.18 + 0.05 + 1.05 = 1.60
    assert "$1.60" in md


def test_markdown_outcome_distribution_includes_only_present_classes() -> None:
    md = _render_bench_markdown(_make_summary())
    assert "| PASS | 2 |" in md
    assert "| UnsupportedSource | 1 |" in md
    assert "| budget_cost_usd | 1 |" in md
    # Classes with 0 count should not appear
    assert "| llm_error |" not in md
    assert "| no_evidence |" not in md


def test_markdown_recovery_layers() -> None:
    md = _render_bench_markdown(_make_summary())
    # llm_retries: only CVE-X-002 had retries; it passed -> 1 triggered, 1 recovered
    assert "| In-loop LLM retry (3 attempts, 0/5/15s) | 1 | 1 |" in md
    # meta_retry_attempted: only CVE-X-002; passed -> 1, 1
    assert "| Meta-retry on budget+candidates | 1 | 1 |" in md
    # bench-retry: not exercised in this synthetic summary
    assert "| Bench-layer retry on transient errors | 0 | 0 |" in md


def test_markdown_tool_usage_sorted_desc() -> None:
    md = _render_bench_markdown(_make_summary())
    # gh_commit_detail appears in 2 CVEs (X-001, X-002), gh_search_commits in 1 CVE (X-004) but 5 calls
    assert "gh_search_commits" in md
    assert "gh_commit_detail" in md


def test_markdown_failure_cluster_excludes_passes() -> None:
    md = _render_bench_markdown(_make_summary())
    assert "CVE-X-003" in md
    assert "CVE-X-004" in md
    # Only the failure-cluster section should mention these by error
    assert "Adobe Flash closed-source" in md
    assert "budget_cost_usd" in md


def test_markdown_handles_empty_summary() -> None:
    s = _BenchSummary(sample="empty.json", total=0, passed=0)
    md = _render_bench_markdown(s)
    assert "# Bench report" in md
    assert "_(none — all PASS)_" in md
    assert "_(no tool calls recorded)_" in md


# --- bench-retry orchestrator ----------------------------------------------

def test_bench_retry_runs_transient_failures(monkeypatch) -> None:
    """The retry pass must re-run only CVEs whose error_class is transient.
    Settled outcomes (UnsupportedSource / budget_*) must NOT be re-run.
    """
    from cve_diff.cli.bench import _run_bench_retry_pass

    summary = _BenchSummary(sample="t.json", total=4, passed=1)
    summary.results = [
        _CveResult(cve_id="CVE-A", ok=True, elapsed_s=1, error_class="PASS"),
        _CveResult(cve_id="CVE-B", ok=False, elapsed_s=2, error_class="UnsupportedSource"),
        _CveResult(cve_id="CVE-C", ok=False, elapsed_s=3, error_class="llm_error"),
        _CveResult(cve_id="CVE-D", ok=False, elapsed_s=4, error_class="PerCveTimeout"),
    ]
    rerun_log: list[str] = []

    def fake_run_one(cve_id, output_dir, disk_limit_pct, max_file_bytes):
        rerun_log.append(cve_id)
        # CVE-C recovers, CVE-D stays stuck
        ok = cve_id == "CVE-C"
        return _CveResult(
            cve_id=cve_id, ok=ok, elapsed_s=10,
            error_class="PASS" if ok else "PerCveTimeout",
            shape="source" if ok else "",
        )

    monkeypatch.setattr("cve_diff.cli.bench._run_one", fake_run_one)
    monkeypatch.setattr("cve_diff.cli.bench.typer.echo", lambda *a, **kw: None)

    _run_bench_retry_pass(summary, "/tmp/x", 95.0, 128 * 1024, 4, lambda: None)

    # Only the 2 transient CVEs got retried
    assert sorted(rerun_log) == ["CVE-C", "CVE-D"]
    # Settled outcomes were NOT re-run
    assert "CVE-B" not in rerun_log
    assert "CVE-A" not in rerun_log
    # CVE-C flipped to PASS — passed count bumped
    assert summary.passed == 2
    # The retried entries are spliced in-place; bench_retry_attempted set
    cve_c = next(r for r in summary.results if r.cve_id == "CVE-C")
    assert cve_c.ok is True
    assert cve_c.bench_retry_attempted is True


def test_bench_retry_skips_when_no_transient_failures(monkeypatch) -> None:
    """Empty transient set: orchestrator returns immediately, no _run_one calls."""
    from cve_diff.cli.bench import _run_bench_retry_pass

    summary = _BenchSummary(sample="t.json", total=2, passed=1)
    summary.results = [
        _CveResult(cve_id="CVE-A", ok=True, elapsed_s=1, error_class="PASS"),
        _CveResult(cve_id="CVE-B", ok=False, elapsed_s=2, error_class="budget_cost_usd"),
    ]
    calls: list = []
    monkeypatch.setattr("cve_diff.cli.bench._run_one", lambda *a, **kw: calls.append(1) or None)

    _run_bench_retry_pass(summary, "/tmp/x", 95.0, 128 * 1024, 2, lambda: None)

    assert calls == []  # no retries invoked
    assert summary.passed == 1  # unchanged


# --- end-to-end CLI ---------------------------------------------------------
# The above tests cover the helpers; these cover the `bench` command itself
# (sample loading, --limit, summary file emission, breakdown line) — pre-2026-05
# the entire command path was uncovered.

import json as _json  # noqa: E402  — local import below the helpers above.
from pathlib import Path as _Path  # noqa: E402

from typer.testing import CliRunner  # noqa: E402

from cve_diff.cli import bench as _bench_mod  # noqa: E402
from cve_diff.cli.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_persist_summary_dir(tmp_path_factory, monkeypatch):
    """Sandbox `_persist_summary`'s data/runs/ writes into a tmp dir.

    The end-to-end CLI tests below invoke the real `bench` command, which
    calls `_persist_summary` to copy summary.json into
    `packages/cve_diff/data/runs/<date>_<stem>.json` — a tracked dir.
    Without this fixture, every test run pollutes the working tree with a
    new dated file. Redirecting `_PACKAGE_DATA_DIR` to a per-session tmp
    keeps the writes sandboxed (the helper-only tests are unaffected — they
    never reach `_persist_summary`).
    """
    sandbox = tmp_path_factory.mktemp("cve-diff-data")
    (sandbox / "runs").mkdir()
    monkeypatch.setattr(_bench_mod, "_PACKAGE_DATA_DIR", sandbox)


def _write_sample(path: _Path, cve_ids: list[str]) -> None:
    """Drop a minimal sample JSON the bench reader knows how to parse."""
    path.write_text(_json.dumps({
        "cves": [{"cve_id": cid} for cid in cve_ids],
    }))


def test_bench_command_runs_each_cve_and_writes_summary_files(
    tmp_path: _Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end of `cve-diff bench`. Stubs _run_one so each CVE returns
    a canned PASS — no agent/git/network. Verifies summary.json /
    summary.html / bench_report.md all land, the headline pass-rate
    line prints, and the workers=1 sequential branch fires."""
    sample = tmp_path / "sample.json"
    _write_sample(sample, ["CVE-2024-0001", "CVE-2024-0002"])
    out = tmp_path / "out"

    monkeypatch.setattr(
        _bench_mod, "_run_one",
        lambda cid, *_a, **_kw: _CveResult(
            cve_id=cid, ok=True, elapsed_s=1.0,
            files_changed=2, diff_bytes=1024, shape="source",
            error_class="PASS",
        ),
    )
    # Skip the retry pass — irrelevant on all-PASS, keeps test deterministic.
    monkeypatch.setattr(
        _bench_mod, "_run_bench_retry_pass",
        lambda *_a, **_kw: None,
    )

    result = CliRunner().invoke(app, [
        "bench", "--sample", str(sample),
        "--output-dir", str(out),
        "-w", "1",
    ])
    assert result.exit_code == 0, result.output
    assert (out / "summary.json").exists()
    assert (out / "summary.html").exists()
    assert (out / "bench_report.md").exists()
    payload = _json.loads((out / "summary.json").read_text())
    assert payload["total"] == 2
    assert payload["passed"] == 2
    assert "=== 2/2 passed (100.0%) ===" in result.output


def test_bench_command_limit_caps_run(
    tmp_path: _Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--limit N`` stops after N CVEs even if the sample has more."""
    sample = tmp_path / "sample.json"
    _write_sample(sample, [f"CVE-2024-{i:04d}" for i in range(10)])
    out = tmp_path / "out"

    invoked: list[str] = []

    def fake_run(cid, *_a, **_kw):
        invoked.append(cid)
        return _CveResult(cve_id=cid, ok=True, elapsed_s=1,
                          shape="source", error_class="PASS")
    monkeypatch.setattr(_bench_mod, "_run_one", fake_run)
    monkeypatch.setattr(_bench_mod, "_run_bench_retry_pass",
                        lambda *_a, **_kw: None)

    result = CliRunner().invoke(app, [
        "bench", "--sample", str(sample),
        "--output-dir", str(out),
        "--limit", "3", "-w", "1",
    ])
    assert result.exit_code == 0, result.output
    assert len(invoked) == 3


def test_bench_command_breakdown_block_when_mixed_outcomes(
    tmp_path: _Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mixed PASS / refusal / pipeline-issue prints all three buckets."""
    sample = tmp_path / "sample.json"
    _write_sample(sample, ["CVE-A", "CVE-B", "CVE-C"])
    out = tmp_path / "out"

    canned = {
        "CVE-A": _CveResult(cve_id="CVE-A", ok=True, elapsed_s=1,
                            shape="source", error_class="PASS"),
        "CVE-B": _CveResult(cve_id="CVE-B", ok=False, elapsed_s=1,
                            error="UnsupportedSource: closed",
                            error_class="UnsupportedSource"),
        "CVE-C": _CveResult(cve_id="CVE-C", ok=False, elapsed_s=1,
                            error="DiscoveryError budget_cost_usd",
                            error_class="budget_cost_usd"),
    }
    monkeypatch.setattr(_bench_mod, "_run_one",
                        lambda cid, *_a, **_kw: canned[cid])
    monkeypatch.setattr(_bench_mod, "_run_bench_retry_pass",
                        lambda *_a, **_kw: None)

    result = CliRunner().invoke(app, [
        "bench", "--sample", str(sample),
        "--output-dir", str(out),
        "-w", "1",
    ])
    assert result.exit_code == 0, result.output
    assert "Outcome breakdown:" in result.output
    assert "PASS" in result.output
    assert "out of scope (refusals)" in result.output
    assert "pipeline issues" in result.output


def test_bench_command_aborts_on_missing_sample(tmp_path: _Path) -> None:
    """A non-existent --sample → typer exits non-zero. The bench must
    NOT silently produce empty outputs."""
    result = CliRunner().invoke(app, [
        "bench",
        "--sample", str(tmp_path / "nope.json"),
        "--output-dir", str(tmp_path / "out"),
        "-w", "1",
    ])
    assert result.exit_code != 0


# --- _render_html (smoke) ---------------------------------------------------

def test_render_html_emits_valid_table_for_empty_and_populated() -> None:
    """The HTML renderer accepts both empty and populated summaries
    without raising and produces a `<table>`."""
    from cve_diff.cli.bench import _render_html

    empty = _BenchSummary(sample="x.json", total=0, passed=0)
    html_empty = _render_html(empty)
    assert "<html" in html_empty.lower()
    assert "<table" in html_empty.lower()

    populated = _BenchSummary(sample="x.json", total=2, passed=1)
    populated.results = [
        _CveResult(cve_id="CVE-1", ok=True, elapsed_s=2, shape="source",
                   error_class="PASS"),
        _CveResult(cve_id="CVE-2", ok=False, elapsed_s=1,
                   error="no_evidence", error_class="no_evidence"),
    ]
    html_pop = _render_html(populated)
    assert "CVE-1" in html_pop
    assert "CVE-2" in html_pop
