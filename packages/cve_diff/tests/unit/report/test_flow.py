"""Tests for cve_diff/report/flow.py — shared write_flow_files helper.

Promoted from cli/bench.py::_write_flow so both `cve-diff run` (single
CVE) and `cve-diff bench` produce the per-tool flow files. Tests
written first (RED) so the move isn't a silent regression.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# ----- the helper under test -----

def test_write_flow_files_creates_jsonl_and_md_for_pass(tmp_path: Path) -> None:
    """Successful CVE: flow.jsonl has one line per tool call;
    flow.md ends with a ✓ PASS outcome line."""
    from cve_diff.report.flow import write_flow_files

    write_flow_files(
        tmp_path, "CVE-1999-0001",
        tool_calls_with_args=[
            ("osv_raw", '{"cve_id": "CVE-1999-0001"}'),
            ("gh_commit_detail", '{"slug": "a/b", "sha": "deadbeef"}'),
            ("submit_result",
             '{"outcome": "rescued", "fix_commit": "deadbeef", "rationale": "ok"}'),
        ],
        ok=True,
        error_class="PASS",
    )

    flow_jsonl = tmp_path / "CVE-1999-0001.flow.jsonl"
    flow_md = tmp_path / "CVE-1999-0001.flow.md"
    assert flow_jsonl.exists()
    assert flow_md.exists()

    lines = flow_jsonl.read_text().strip().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["tool"] == "osv_raw"
    assert json.loads(lines[1])["tool"] == "gh_commit_detail"
    assert json.loads(lines[2])["tool"] == "submit_result"

    md = flow_md.read_text()
    assert "CVE-1999-0001" in md
    assert "✓ PASS" in md


def test_write_flow_files_fail_path(tmp_path: Path) -> None:
    """Failed CVE: flow.md ends with ✗ FAIL line referencing error_class."""
    from cve_diff.report.flow import write_flow_files

    write_flow_files(
        tmp_path, "CVE-2099-0001",
        tool_calls_with_args=[
            ("osv_raw", '{"cve_id": "CVE-2099-0001"}'),
            ("nvd_raw", '{"cve_id": "CVE-2099-0001"}'),
        ],
        ok=False,
        error_class="no_evidence",
    )
    md = (tmp_path / "CVE-2099-0001.flow.md").read_text()
    assert "✗ FAIL" in md
    assert "no_evidence" in md


def test_write_flow_files_handles_empty_tool_calls(tmp_path: Path) -> None:
    """Edge case: no tool calls (e.g., agent never started). Still writes
    both files; flow.md notes the absence; flow.jsonl is empty."""
    from cve_diff.report.flow import write_flow_files

    write_flow_files(
        tmp_path, "CVE-2099-0002",
        tool_calls_with_args=[],
        ok=False,
        error_class="client_init_failed",
    )
    assert (tmp_path / "CVE-2099-0002.flow.jsonl").exists()
    assert (tmp_path / "CVE-2099-0002.flow.md").exists()
    md = (tmp_path / "CVE-2099-0002.flow.md").read_text()
    assert "no tool calls" in md.lower()


def test_write_flow_files_swallows_errors(tmp_path: Path) -> None:
    """Best-effort write: a bogus output_dir must not raise (the caller's
    bench/cli must always complete cleanly even if the report write fails)."""
    from cve_diff.report.flow import write_flow_files

    bogus = tmp_path / "does/not/exist/yet"
    # Should NOT raise. The function silently no-ops on filesystem errors.
    write_flow_files(
        bogus, "CVE-2099-0003",
        tool_calls_with_args=[("osv_raw", '{}')],
        ok=True,
        error_class="PASS",
    )
    # No files should exist; no exception bubbled.
    assert not (bogus / "CVE-2099-0003.flow.jsonl").exists()


def test_write_flow_files_preserves_arg_truncation_safety(tmp_path: Path) -> None:
    """Args that don't start with `{` (e.g. truncated JSON) get stored
    under `_raw` instead of crashing the JSON parser."""
    from cve_diff.report.flow import write_flow_files

    write_flow_files(
        tmp_path, "CVE-2099-0004",
        tool_calls_with_args=[
            ("http_fetch", "{partial-json-truncated-at-120-chars-no-closing-brace"),
        ],
        ok=True,
        error_class="PASS",
    )
    line = (tmp_path / "CVE-2099-0004.flow.jsonl").read_text().strip()
    obj = json.loads(line)
    assert obj["tool"] == "http_fetch"
    # Either parsed (unlikely on the truncated input) or the _raw fallback.
    # Whichever happens, it must NOT raise.
    assert "args" in obj


# ----- new pipeline-trace render (UX-richer flow.md) -----

def test_render_flow_groups_adjacent_same_intent_calls(tmp_path: Path) -> None:
    """Adjacent calls with the same intent (e.g. two LOOKUP calls in a
    row) collapse into one numbered step so the trace reads like a
    high-level strategy, not a raw tool log."""
    from cve_diff.report.markdown import render_flow

    lines = [
        json.dumps({"i": 0, "tool": "deterministic_hints", "args": {"cve_id": "CVE-X"}}),
        json.dumps({"i": 1, "tool": "osv_raw", "args": {"cve_id": "CVE-X"}}),
        json.dumps({"i": 2, "tool": "gh_commit_detail",
                    "args": {"slug": "a/b", "sha": "deadbeef"}}),
        json.dumps({"i": 3, "tool": "submit_result",
                    "args": {"outcome": "rescued"}}),
    ]
    md = render_flow("CVE-X", lines, ok=True, error_class="PASS")
    # Adjacent LOOKUP calls (deterministic_hints + osv_raw) should be
    # one step labelled with the intent
    assert "Look up known data" in md or "look up" in md.lower()
    # The two LOOKUP tool names should be on the same step line
    lookup_line = next((ln for ln in md.splitlines()
                        if "deterministic_hints" in ln), "")
    assert "osv_raw" in lookup_line
    # Verify step appears separately
    assert "Verify" in md or "verify" in md.lower()
    assert "gh_commit_detail" in md


def test_render_flow_pass_shows_all_5_pipeline_stages(tmp_path: Path) -> None:
    """For a PASS run with stage_signals provided, all 5 pipeline stages
    (discover/acquire/resolve/diff/render) are headlined with status
    + the method picked at each."""
    from cve_diff.report.markdown import render_flow

    lines = [
        json.dumps({"i": 0, "tool": "deterministic_hints",
                    "args": {"cve_id": "CVE-X"}}),
        json.dumps({"i": 1, "tool": "submit_result",
                    "args": {"outcome": "rescued",
                             "fix_commit": "deadbeef"}}),
    ]
    stage_signals = {
        "acquire": {"layer": "targeted_fetch", "elapsed_s": 2.1},
        "resolve": {"before": "09e25b9d94f4", "after": "fb4415d8aee6"},
        "diff": {"shape": "source", "files_changed": 3,
                 "diff_bytes": 3433, "elapsed_s": 0.6},
        "render": {"extraction_agreement": "agree",
                   "consensus_count": 1},
    }
    md = render_flow("CVE-X", lines, ok=True, error_class="PASS",
                     stage_signals=stage_signals)
    assert "DISCOVER" in md or "Discover" in md
    assert "ACQUIRE" in md or "Acquire" in md
    assert "targeted_fetch" in md
    assert "RESOLVE" in md or "Resolve" in md
    assert "09e25b9d94f4" in md  # before SHA
    assert "DIFF" in md or "Diff" in md
    assert "3,433" in md or "3433" in md
    assert "RENDER" in md or "Render" in md
    assert "agree" in md  # extraction agreement


# ----- Stage 4: per-source diff agreement (the user's primary success metric) -----

def test_render_flow_diff_shows_three_sources_when_all_three_extractors_ran(
    tmp_path: Path,
) -> None:
    """When clone + GitHub API + patch URL all extracted the diff, Stage 4
    lists ALL THREE sources with independent counts plus a 3-way verdict.

    The patch-URL extractor was added 2026-04-30 so we always get
    real triangulation on GitHub (same forge, three reads via three
    different paths)."""
    from cve_diff.report.markdown import render_flow

    lines = [
        json.dumps({"i": 0, "tool": "submit_result",
                    "args": {"outcome": "rescued"}}),
    ]
    # New N-source agreement payload: `sources` list + top-level verdict
    stage_signals = {
        "acquire": {"layer": "targeted_fetch"},
        "resolve": {"before": "b04967b52eb1", "after": "c0e194d44933"},
        "diff": {
            "shape": "source", "files_changed": 2, "diff_bytes": 2244,
            "extraction_agreement": {
                "verdict": "agree",
                "sources": [
                    {"name": "clone", "files": 2, "bytes": 2244},
                    {"name": "github_api", "files": 2, "bytes": 2185},
                    {"name": "patch_url", "files": 2, "bytes": 2244},
                ],
                "pairwise": {
                    "clone:github_api": "agree",
                    "clone:patch_url": "agree",
                    "github_api:patch_url": "agree",
                },
            },
            "slug": "socketio/engine.io",
            "sha": "c0e194d44933",
        },
        "render": {"consensus_count": 2},
    }
    md = render_flow("CVE-X", lines, ok=True, error_class="PASS",
                     stage_signals=stage_signals)
    # A "Sources:" block listing all THREE extractors
    assert "Sources:" in md
    assert "Clone" in md
    assert "git diff fix^..fix" in md
    assert "GitHub API" in md or "github_api" in md
    assert "Patch URL" in md or "patch_url" in md
    # The slug+sha is mentioned (replay info for the user)
    assert "socketio/engine.io" in md
    assert "c0e194d44933" in md
    # 3-way verdict line
    assert "Verdict:" in md
    assert "3/3" in md or "all sources" in md.lower()
    assert "agree" in md


def test_render_flow_diff_shows_two_sources_clone_plus_patch_url_for_cgit(
    tmp_path: Path,
) -> None:
    """cgit (kernel.org) has no JSON API but DOES have a patch URL. After
    the third-source change, cgit CVEs go from "single source" to TWO
    rows (clone + patch URL) — first-time cross-check coverage on
    kernel.org. The API row says ``skipped`` for the missing JSON
    extractor."""
    from cve_diff.report.markdown import render_flow

    lines = [
        json.dumps({"i": 0, "tool": "submit_result",
                    "args": {"outcome": "rescued"}}),
    ]
    stage_signals = {
        "acquire": {"layer": "shallow_clone"},
        "resolve": {"before": "deadbeef0000", "after": "cafebabe0000"},
        "diff": {
            "shape": "source", "files_changed": 5, "diff_bytes": 12000,
            "extraction_agreement": {
                "verdict": "agree",
                "sources": [
                    {"name": "clone", "files": 5, "bytes": 12000},
                    {"name": "patch_url", "files": 5, "bytes": 12000},
                ],
                "pairwise": {"clone:patch_url": "agree"},
            },
            "slug": "git.kernel.org/torvalds/linux",
            "sha": "cafebabe0000",
        },
        "render": {"consensus_count": 1},
    }
    md = render_flow("CVE-X", lines, ok=True, error_class="PASS",
                     stage_signals=stage_signals)
    # Both rows render
    assert "Clone" in md
    assert "Patch URL" in md or "patch_url" in md
    # API row explicitly marked as skipped (so the user knows it's not
    # a missing-data bug — the forge just doesn't expose JSON)
    assert "skipped" in md.lower()
    assert "API" in md
    # 2-way verdict
    assert "2/2" in md or "all sources" in md.lower()
    assert "agree" in md


def test_render_flow_diff_shows_skipped_row_when_no_second_source(
    tmp_path: Path,
) -> None:
    """For truly unsupported forges (bitbucket, file://), neither API
    nor patch URL works. Trace shows clone + a single `skipped` row +
    a `single source` verdict. Never just the cryptic token."""
    from cve_diff.report.markdown import render_flow

    lines = [
        json.dumps({"i": 0, "tool": "submit_result",
                    "args": {"outcome": "rescued"}}),
    ]
    stage_signals = {
        "acquire": {"layer": "shallow_clone"},
        "resolve": {"before": "deadbeef0000", "after": "cafebabe0000"},
        "diff": {
            "shape": "source", "files_changed": 5, "diff_bytes": 12000,
            "extraction_agreement": None,  # no second source available
            "slug": "https://bitbucket.org/foo/bar",
            "sha": "cafebabe0000",
        },
        "render": {"consensus_count": 1},
    }
    md = render_flow("CVE-X", lines, ok=True, error_class="PASS",
                     stage_signals=stage_signals)
    assert "Sources:" in md
    assert "Clone" in md
    assert "skipped" in md.lower()
    assert "Verdict:" in md
    assert "single source" in md.lower()


def test_render_flow_diff_shows_disagreement_with_outlier(
    tmp_path: Path,
) -> None:
    """When two of three sources agree and one differs, the verdict
    line names the OUTLIER so the user knows which to investigate."""
    from cve_diff.report.markdown import render_flow

    lines = [
        json.dumps({"i": 0, "tool": "submit_result",
                    "args": {"outcome": "rescued"}}),
    ]
    stage_signals = {
        "acquire": {"layer": "targeted_fetch"},
        "resolve": {"before": "aaaa11112222", "after": "bbbb33334444"},
        "diff": {
            "shape": "source", "files_changed": 5, "diff_bytes": 8000,
            "extraction_agreement": {
                "verdict": "majority_agree",
                "sources": [
                    {"name": "clone", "files": 5, "bytes": 8000},
                    {"name": "github_api", "files": 3, "bytes": 4232},
                    {"name": "patch_url", "files": 5, "bytes": 8000},
                ],
                "pairwise": {
                    "clone:github_api": "disagree",
                    "clone:patch_url": "agree",
                    "github_api:patch_url": "disagree",
                },
                "outliers": ["github_api"],
            },
            "slug": "owner/repo",
            "sha": "bbbb33334444",
        },
        "render": {"consensus_count": 1},
    }
    md = render_flow("CVE-X", lines, ok=True, error_class="PASS",
                     stage_signals=stage_signals)
    assert "Verdict:" in md
    # 2/3 form
    assert "2/3" in md
    # Outlier method name surfaced in the verdict line
    assert "github_api" in md or "GitHub API" in md


def test_render_flow_fail_no_evidence_shows_only_discover(tmp_path: Path) -> None:
    """For no_evidence FAIL, only the discover stage is rendered.
    Subsequent stages are correctly omitted."""
    from cve_diff.report.markdown import render_flow

    lines = [
        json.dumps({"i": 0, "tool": "osv_raw", "args": {}}),
        json.dumps({"i": 1, "tool": "nvd_raw", "args": {}}),
    ]
    md = render_flow("CVE-X", lines, ok=False, error_class="no_evidence")
    assert "DISCOVER" in md or "Discover" in md
    assert "✗" in md
    assert "no_evidence" in md
    # No subsequent stage should claim success
    assert "Acquire ✓" not in md
    assert "ACQUIRE ✓" not in md


# ----- ALWAYS-EMIT guard: every PASS *and* FAIL renders all 5 stage headers -----
#
# User-stated requirement (2026-05-01): "all stages must show in the report,
# every time. We've missed this in the past — make sure it actually happens."
# These tests verify the literal Stage 1..5 headers appear in EVERY exit path.

def test_render_flow_no_evidence_fail_still_shows_all_5_stage_headers() -> None:
    """When the agent surrenders with no_evidence at Stage 1, the trace
    must STILL render Stage 2-5 headers as `(not reached)` — so the user
    can see WHERE the pipeline stopped, not just that it stopped."""
    from cve_diff.report.markdown import render_flow

    lines = [json.dumps({"i": 0, "tool": "osv_raw", "args": {}})]
    md = render_flow("CVE-X", lines, ok=False, error_class="no_evidence",
                     stage_status={"discover": {"status": "fail",
                                                "reason": "no_evidence"}})
    # All 5 stage headers must appear, regardless of outcome.
    assert "Stage 1 — DISCOVER" in md
    assert "Stage 2 — ACQUIRE" in md
    assert "Stage 3 — RESOLVE" in md
    assert "Stage 4 — DIFF" in md
    assert "Stage 5 — RENDER" in md
    # And the failed stage is marked ✗; subsequent ones marked not-reached.
    assert "DISCOVER ✗" in md
    assert "not reached" in md.lower()


def test_render_flow_acquisition_fail_shows_stage1_ok_stage2_fail_rest_not_reached() -> None:
    """When Stage 2 (acquire) fails, the trace shows Stage 1 ✓, Stage 2 ✗,
    Stages 3-5 `(not reached)`. The user sees exactly where the pipeline
    broke — they don't have to guess from the error message."""
    from cve_diff.report.markdown import render_flow

    lines = [json.dumps({"i": 0, "tool": "submit_result",
                         "args": {"outcome": "rescued"}})]
    stage_status = {
        "discover": {"status": "ok"},
        "acquire": {"status": "fail",
                    "reason": "clone cascade failed: 404 on all layers"},
    }
    md = render_flow("CVE-X", lines, ok=False, error_class="AcquisitionError",
                     stage_status=stage_status)
    assert "Stage 1 — DISCOVER ✓" in md
    assert "Stage 2 — ACQUIRE ✗" in md
    assert "clone cascade failed" in md
    # Stages 3-5 must still render — but as not-reached (no false ✓).
    assert "Stage 3 — RESOLVE" in md
    assert "Stage 4 — DIFF" in md
    assert "Stage 5 — RENDER" in md
    assert "not reached" in md.lower()
    assert "RESOLVE ✓" not in md
    assert "DIFF ✓" not in md


def test_render_flow_pass_still_shows_all_5_stages_with_check_marks() -> None:
    """Regression guard: after the FAIL-path change, PASS runs must still
    render all 5 stage headers with ✓ markers. (Today's PASS test
    already covers this; keep one explicit always-emit assertion.)"""
    from cve_diff.report.markdown import render_flow

    lines = [json.dumps({"i": 0, "tool": "submit_result",
                         "args": {"outcome": "rescued"}})]
    stage_signals = {
        "acquire": {"layer": "targeted_fetch"},
        "resolve": {"before": "abc", "after": "def"},
        "diff": {"shape": "source", "files_changed": 1, "diff_bytes": 100},
        "render": {"consensus_count": 2},
    }
    md = render_flow("CVE-X", lines, ok=True, error_class="PASS",
                     stage_signals=stage_signals)
    for header in ("Stage 1 — DISCOVER ✓", "Stage 2 — ACQUIRE ✓",
                   "Stage 3 — RESOLVE ✓", "Stage 4 — DIFF ✓",
                   "Stage 5 — RENDER ✓"):
        assert header in md, f"missing header: {header!r}"


def test_render_flow_backward_compatible_without_stage_signals(tmp_path: Path) -> None:
    """Existing callers that don't pass stage_signals must still produce
    a useful PASS trace (just without the post-discover stage detail)."""
    from cve_diff.report.markdown import render_flow

    lines = [
        json.dumps({"i": 0, "tool": "submit_result",
                    "args": {"outcome": "rescued"}}),
    ]
    md = render_flow("CVE-X", lines, ok=True, error_class="PASS")
    assert "✓" in md
    assert "PASS" in md


# ----- write_outcome_patches: per-method diff bodies as audit files -----

def test_write_outcome_patches_writes_clone_only_when_no_api(tmp_path: Path) -> None:
    """When no API/forge bundle is available (e.g. cgit-only repo), only
    the clone patch lands. The user has one diff to review."""
    from cve_diff.report.flow import write_outcome_patches
    write_outcome_patches(
        tmp_path, "CVE-2099-0001",
        clone_diff_text="diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n",
        api_diff_text=None,
        api_method=None,
    )
    assert (tmp_path / "CVE-2099-0001.clone.patch").exists()
    assert not list(tmp_path.glob("CVE-2099-0001.*.api.patch"))


def test_write_outcome_patches_writes_both_for_github(tmp_path: Path) -> None:
    """When the GitHub API extraction ran, both .clone.patch and
    .api.patch land — user can diff them to see what disagrees."""
    from cve_diff.report.flow import write_outcome_patches
    write_outcome_patches(
        tmp_path, "CVE-2099-0002",
        clone_diff_text="clone-extracted-body\n",
        api_diff_text="api-extracted-body\n",
        api_method="github_api",
    )
    assert (tmp_path / "CVE-2099-0002.clone.patch").read_text() == "clone-extracted-body\n"
    assert (tmp_path / "CVE-2099-0002.github_api.patch").read_text() == "api-extracted-body\n"


def test_write_outcome_patches_uses_method_in_filename(tmp_path: Path) -> None:
    """For GitLab repos the file is named ``<cve>.gitlab_api.patch`` so
    a glance at the directory tells you which forge produced the diff."""
    from cve_diff.report.flow import write_outcome_patches
    write_outcome_patches(
        tmp_path, "CVE-2099-0003",
        clone_diff_text="A\n", api_diff_text="B\n",
        api_method="gitlab_api",
    )
    assert (tmp_path / "CVE-2099-0003.gitlab_api.patch").exists()
    assert not (tmp_path / "CVE-2099-0003.github_api.patch").exists()


def test_write_outcome_patches_swallows_errors(tmp_path: Path) -> None:
    """Bogus output_dir must not raise — patch writes are best-effort."""
    from cve_diff.report.flow import write_outcome_patches
    bogus = tmp_path / "does/not/exist"
    write_outcome_patches(
        bogus, "CVE-X",
        clone_diff_text="A\n", api_diff_text=None, api_method=None,
    )
    # No exception bubbled.
    assert not bogus.exists()
