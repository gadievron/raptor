"""
Pipeline orchestrator tests — wire ``agent_discover → acquire → resolve →
diff`` against a local file:// repo and a stubbed ``AgentLoop``.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from cve_diff.acquisition.layers import (
    CascadingRepoAcquirer,
    ShallowCloneLayer,
    TargetedFetchLayer,
)
from cve_diff.agent.types import AgentOutput, AgentResult, AgentSurrender
from cve_diff.core.exceptions import (
    AcquisitionError,
    AnalysisError,
    DiscoveryError,
    UnsupportedSource,
)
from cve_diff.core.models import CommitSha, PatchTuple
from cve_diff.pipeline import Pipeline


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return r.stdout.strip()


def _make_origin(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "origin"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "f.txt").write_text("a\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "vulnerable")
    introduced = _git(repo, "rev-parse", "HEAD")
    (repo / "f.txt").write_text("b\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "fix")
    fixed = _git(repo, "rev-parse", "HEAD")
    return repo, introduced, fixed


@dataclass
class _StubAgent:
    """Bypasses the real Anthropic client. Returns a canned ``AgentResult``."""
    result: AgentResult

    def run(self, config, ctx) -> AgentResult:
        return self.result


def _rescued(repo_url: str, fix_sha: str) -> _StubAgent:
    return _StubAgent(
        AgentOutput(
            value=PatchTuple(
                repository_url=repo_url,
                fix_commit=CommitSha(fix_sha),
                introduced=None,
            ),
            rationale="stub",
        )
    )


def test_pipeline_end_to_end_local_repo(tmp_path):
    """Diff body is always fix^..fix; here the introduced commit happens to *be*
    fix^, so commit_before == introduced as a side-effect."""
    origin, introduced, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    pipeline = Pipeline(
        agent=_rescued(f"file://{origin}", fixed),
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(TargetedFetchLayer(), ShallowCloneLayer(depths=(2,)))
        ),
        disk_limit_pct=99.9,
    )
    result = pipeline.run("CVE-2099-12345", work)
    assert result.cve_id == "CVE-2099-12345"
    assert result.bundle.commit_after == fixed
    assert result.bundle.commit_before == introduced  # fix^ == introduced here
    assert result.bundle.files_changed == 1
    assert "-a" in result.bundle.diff_text and "+b" in result.bundle.diff_text


def test_pipeline_derives_introduced_from_fix_parent(tmp_path):
    origin, introduced, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    pipeline = Pipeline(
        agent=_rescued(f"file://{origin}", fixed),
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(ShallowCloneLayer(depths=(5,)),)
        ),
        disk_limit_pct=99.9,
    )
    result = pipeline.run("CVE-X", work)
    assert result.bundle.commit_before == introduced
    assert result.bundle.commit_after == fixed


def test_pipeline_diff_body_is_fix_parent_to_fix(tmp_path):
    """Diff body is always ``fix^..fix``, regardless of the agent's
    knowledge of the introducing commit. Bug #1 defense — older code
    diffed full ``introduced..fix`` spans and produced 20MB blobs."""
    repo = tmp_path / "origin"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    shas = []
    for i in range(6):
        (repo / f"f{i}.txt").write_text(f"v{i}\n")
        _git(repo, "add", f"f{i}.txt")
        _git(repo, "commit", "-q", "-m", f"c{i}")
        shas.append(_git(repo, "rev-parse", "HEAD"))
    fix = shas[-1]
    fix_parent = shas[-2]
    work = tmp_path / "work"
    work.mkdir()
    pipeline = Pipeline(
        agent=_rescued(f"file://{repo}", fix),
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(ShallowCloneLayer(depths=(10,)),)
        ),
        disk_limit_pct=99.9,
    )
    result = pipeline.run("CVE-X", work)
    assert result.bundle.commit_before == fix_parent
    assert result.bundle.files_changed == 1  # only the latest file added


def test_pipeline_raises_discovery_error_on_no_evidence(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    pipeline = Pipeline(
        agent=_StubAgent(AgentSurrender(reason="no_evidence", detail="empty OSV")),
        disk_limit_pct=99.9,
    )
    with pytest.raises(DiscoveryError):
        pipeline.run("CVE-NONE", work)


def test_pipeline_raises_unsupported_source_on_agent_unsupported(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    pipeline = Pipeline(
        agent=_StubAgent(AgentSurrender(reason="UnsupportedSource", detail="firmware")),
        disk_limit_pct=99.9,
    )
    with pytest.raises(UnsupportedSource):
        pipeline.run("CVE-CLOSED", work)


@dataclass
class _QueuedAgent:
    """Stub that returns ``results`` in order, one per ``run`` call."""
    results: list[AgentResult]
    calls: list = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.calls = []

    def run(self, config, ctx) -> AgentResult:
        self.calls.append((config, ctx))
        return self.results.pop(0)


def test_retry_runs_when_budget_surrender_has_candidates(tmp_path):
    """budget_cost surrender + verified candidates → retry runs."""
    origin, introduced, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    surrender = AgentSurrender(
        reason="budget_cost_usd",
        detail="ran out at iter 14",
        verified_candidates=(("acme/widget", fixed),),
    )
    success = AgentOutput(
        value=PatchTuple(
            repository_url=f"file://{origin}",
            fix_commit=CommitSha(fixed),
            introduced=None,
        ),
        rationale="retry succeeded",
    )
    agent = _QueuedAgent(results=[surrender, success])
    pipeline = Pipeline(
        agent=agent,
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(ShallowCloneLayer(depths=(5,)),)
        ),
        disk_limit_pct=99.9,
    )
    pipeline.run("CVE-RETRY", work)
    assert len(agent.calls) == 2, "retry should have run"
    retry_config = agent.calls[1][0]
    assert retry_config.budget_cost_usd == 3.00
    assert retry_config.max_iterations == 44
    assert "acme/widget" in retry_config.user_message
    assert fixed in retry_config.user_message


def test_no_retry_when_surrender_has_no_candidates(tmp_path):
    """budget_cost surrender without candidates → no retry, original error propagates."""
    work = tmp_path / "work"
    work.mkdir()
    surrender = AgentSurrender(
        reason="budget_cost_usd",
        detail="found nothing",
        verified_candidates=(),
    )
    agent = _QueuedAgent(results=[surrender])
    pipeline = Pipeline(agent=agent, disk_limit_pct=99.9)
    with pytest.raises(DiscoveryError):
        pipeline.run("CVE-NOFOUND", work)
    assert len(agent.calls) == 1


def test_no_retry_on_unsupported_source(tmp_path):
    """UnsupportedSource is not retried even with candidates (closed-source is the answer)."""
    work = tmp_path / "work"
    work.mkdir()
    surrender = AgentSurrender(
        reason="UnsupportedSource",
        detail="closed-source",
        verified_candidates=(("noise/repo", "abc1234"),),
    )
    agent = _QueuedAgent(results=[surrender])
    pipeline = Pipeline(agent=agent, disk_limit_pct=99.9)
    with pytest.raises(UnsupportedSource):
        pipeline.run("CVE-CLOSED", work)
    assert len(agent.calls) == 1


def test_retry_runs_on_budget_s_with_candidates(tmp_path):
    """budget_s exhaustion (wall-clock) + candidates → meta-retry kicks in.
    Same recovery shape as budget_cost_usd; the agent's first run
    finished its exploration but ran out of clock before submit_result."""
    origin, introduced, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    surrender = AgentSurrender(
        reason="budget_s",
        detail="elapsed=240s",
        verified_candidates=(("acme/widget", fixed),),
    )
    success = AgentOutput(
        value=PatchTuple(
            repository_url=f"file://{origin}",
            fix_commit=CommitSha(fixed),
            introduced=None,
        ),
        rationale="retry succeeded",
    )
    agent = _QueuedAgent(results=[surrender, success])
    pipeline = Pipeline(
        agent=agent,
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(ShallowCloneLayer(depths=(5,)),)
        ),
        disk_limit_pct=99.9,
    )
    pipeline.run("CVE-BUDGETS", work)
    assert len(agent.calls) == 2


def test_retry_runs_on_llm_error_with_candidates(tmp_path):
    """llm_error after in-loop retries exhaust + candidates → meta-retry kicks in."""
    origin, introduced, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    surrender = AgentSurrender(
        reason="llm_error",
        detail="Anthropic 529",
        verified_candidates=(("acme/widget", fixed),),
    )
    success = AgentOutput(
        value=PatchTuple(
            repository_url=f"file://{origin}",
            fix_commit=CommitSha(fixed),
            introduced=None,
        ),
        rationale="retry succeeded",
    )
    agent = _QueuedAgent(results=[surrender, success])
    pipeline = Pipeline(
        agent=agent,
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(ShallowCloneLayer(depths=(5,)),)
        ),
        disk_limit_pct=99.9,
    )
    pipeline.run("CVE-LLMRETRY", work)
    assert len(agent.calls) == 2


def test_retry_failure_propagates_retry_surrender(tmp_path):
    """If retry also surrenders, the retry surrender is what propagates."""
    work = tmp_path / "work"
    work.mkdir()
    first = AgentSurrender(
        reason="budget_cost_usd",
        detail="first",
        verified_candidates=(("acme/widget", "deadbeef1234567"),),
    )
    second = AgentSurrender(reason="no_evidence", detail="retry gave up")
    agent = _QueuedAgent(results=[first, second])
    pipeline = Pipeline(agent=agent, disk_limit_pct=99.9)
    with pytest.raises(DiscoveryError) as exc_info:
        pipeline.run("CVE-RETRYFAIL", work)
    assert len(agent.calls) == 2
    assert "no_evidence" in str(exc_info.value)


def test_pipeline_raises_analysis_error_on_notes_only_shape(tmp_path, monkeypatch):
    """When the diff shape is notes_only, the pipeline raises AnalysisError
    rather than silently passing a downstream-mirror commit."""
    origin, _, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    # Override the shape classification — the synthetic test repo's diff
    # would normally be classified as "source".
    from cve_diff.diffing import shape_dynamic
    monkeypatch.setattr(shape_dynamic, "classify", lambda *a, **kw: "notes_only")
    pipeline = Pipeline(
        agent=_rescued(f"file://{origin}", fixed),
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(TargetedFetchLayer(), ShallowCloneLayer(depths=(2,)))
        ),
        disk_limit_pct=99.9,
    )
    with pytest.raises(AnalysisError):
        pipeline.run("CVE-X", work)


# ---- API-extract fallback cascade ------------------------------------------

class _FailingAcquirer:
    """Always raises AcquisitionError. `reports` exposed for parity."""
    reports: tuple = ()

    def acquire(self, ref, repo_path):
        raise AcquisitionError("simulated clone failure")


def test_pipeline_falls_back_to_api_when_clone_fails(tmp_path, monkeypatch):
    """Acquire raises AcquisitionError → extract_via_api succeeds → bundle returned."""
    work = tmp_path / "work"
    work.mkdir()

    fix_sha = "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619"
    parent_sha = "feedfacefeedfacefeedfacefeedfacefeedface"
    api_payload = {
        "sha": fix_sha,
        "parents": [{"sha": parent_sha}],
        "files": [
            {"filename": "src/foo.c",
             "patch": "@@ -1,3 +1,3 @@\n-bad\n+good\n"},
        ],
    }
    from cve_diff.diffing import extract_via_api as eva_mod
    monkeypatch.setattr(eva_mod.github_client, "get_commit",
                        lambda slug, sha: api_payload)
    monkeypatch.setattr(eva_mod.github_client, "get_languages",
                        lambda slug: {"C": 1000})

    pipeline = Pipeline(
        agent=_rescued("https://github.com/torvalds/linux", fix_sha),
        acquirer_factory=_FailingAcquirer,
        disk_limit_pct=99.9,
        enable_consensus=False,
    )
    result = pipeline.run("CVE-2016-5195", work)
    assert result.bundle.commit_after == fix_sha
    assert result.bundle.commit_before == parent_sha
    assert result.bundle.files_changed == 1
    assert "+good" in result.bundle.diff_text
    assert result.bundle.shape == "source"


def test_pipeline_propagates_clone_error_when_api_fallback_disabled(tmp_path):
    """`api_extract_fallback=False` → AcquisitionError propagates immediately."""
    work = tmp_path / "work"
    work.mkdir()
    pipeline = Pipeline(
        agent=_rescued(
            "https://github.com/torvalds/linux",
            "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619",
        ),
        acquirer_factory=_FailingAcquirer,
        disk_limit_pct=99.9,
        api_extract_fallback=False,
        enable_consensus=False,
    )
    with pytest.raises(AcquisitionError, match="simulated clone failure"):
        pipeline.run("CVE-X", work)


def test_pipeline_propagates_clone_error_when_api_also_fails(tmp_path, monkeypatch):
    """Both clone and API fail → original AcquisitionError propagates (per plan)."""
    work = tmp_path / "work"
    work.mkdir()
    from cve_diff.diffing import extract_via_api as eva_mod
    # API returns None (simulating 404) → extract_via_api raises AnalysisError.
    monkeypatch.setattr(eva_mod.github_client, "get_commit",
                        lambda slug, sha: None)
    pipeline = Pipeline(
        agent=_rescued(
            "https://github.com/torvalds/linux",
            "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619",
        ),
        acquirer_factory=_FailingAcquirer,
        disk_limit_pct=99.9,
        enable_consensus=False,
    )
    with pytest.raises(AcquisitionError, match="simulated clone failure"):
        pipeline.run("CVE-X", work)


def test_pipeline_clone_path_skips_api_fallback(tmp_path, monkeypatch):
    """When clone succeeds, the API path is not invoked."""
    origin, _, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    api_called = {"n": 0}

    def fake_get_commit(slug, sha):
        api_called["n"] += 1
        return None

    from cve_diff.diffing import extract_via_api as eva_mod
    monkeypatch.setattr(eva_mod.github_client, "get_commit", fake_get_commit)

    pipeline = Pipeline(
        agent=_rescued(f"file://{origin}", fixed),
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(TargetedFetchLayer(), ShallowCloneLayer(depths=(2,)))
        ),
        disk_limit_pct=99.9,
        enable_consensus=False,
    )
    result = pipeline.run("CVE-X", work)
    assert result.bundle.diff_text  # clone path produced the diff
    assert api_called["n"] == 0     # API never invoked


# ---------- post-submit agentic retry ----------
#
# When stages 2-5 fail (acquire / resolve / diff / shape) on the
# agent's submitted (slug, sha), the pipeline now spawns a second
# agent run with the failure as feedback so the agent can pick a
# different verified candidate.  Caps at one retry; preserves the
# original error if both attempts fail.

class _SequencedAgent:
    """Returns canned AgentResults in order of `pipeline.run` calls.

    Used to simulate a primary agent run + a focused post-submit
    retry. The first call returns the candidate that will fail; the
    second call returns the candidate that should succeed.
    """
    def __init__(self, results: list) -> None:
        self._results = list(results)
        self.calls = 0

    def run(self, config, ctx):
        self.calls += 1
        if not self._results:
            raise RuntimeError("ran out of canned agent results")
        return self._results.pop(0)


def _output(repo_url: str, fix_sha: str) -> AgentOutput:
    return AgentOutput(
        value=PatchTuple(
            repository_url=repo_url,
            fix_commit=CommitSha(fix_sha),
            introduced=None,
        ),
        rationale="stub",
    )


def test_post_submit_retry_on_acquisition_error_recovers(tmp_path):
    """Acquirer raises AcquisitionError on the first (slug, sha); after
    the agent re-runs and picks the second candidate, acquire succeeds.
    Pipeline returns a PipelineResult and flags the retry attempt."""
    origin, introduced, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()

    bad_url = f"file://{tmp_path}/does-not-exist"
    good_url = f"file://{origin}"

    agent = _SequencedAgent([
        _output(bad_url, fixed),   # primary: a bogus path
        _output(good_url, fixed),  # retry:   the real one
    ])
    pipeline = Pipeline(
        agent=agent,
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(TargetedFetchLayer(), ShallowCloneLayer(depths=(2,)))
        ),
        disk_limit_pct=99.9,
        enable_consensus=False,
        api_extract_fallback=False,
    )
    result = pipeline.run("CVE-X", work)
    assert result.bundle.commit_after == fixed
    assert agent.calls == 2
    assert getattr(pipeline, "_last_post_submit_retry_attempted", False) is True


def test_post_submit_retry_on_analysis_error_recovers(tmp_path):
    """Diff shape returns notes_only first (rejected by AnalysisError);
    second attempt returns source. Retry path produces the PASS."""
    origin, introduced, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()

    # The same repo will be used for both attempts; we toggle the shape
    # check by patching it to fail-then-succeed.
    from cve_diff import pipeline as pipeline_mod
    shape_calls = {"n": 0}
    real_check = pipeline_mod.check_diff_shape

    def flaky_check(shape: str):
        shape_calls["n"] += 1
        if shape_calls["n"] == 1:
            return "notes_only_diff"  # reject first
        return None  # accept retry

    import unittest.mock as mock
    with mock.patch.object(pipeline_mod, "check_diff_shape", side_effect=flaky_check):
        agent = _SequencedAgent([
            _output(f"file://{origin}", fixed),
            _output(f"file://{origin}", fixed),
        ])
        pipeline = Pipeline(
            agent=agent,
            acquirer_factory=lambda: CascadingRepoAcquirer(
                layers=(ShallowCloneLayer(depths=(5,)),)
            ),
            disk_limit_pct=99.9,
            enable_consensus=False,
            api_extract_fallback=False,
        )
        result = pipeline.run("CVE-X", work)
        assert result.bundle.commit_after == fixed
        assert agent.calls == 2
        assert getattr(pipeline, "_last_post_submit_retry_attempted", False) is True


def test_post_submit_retry_caps_at_max(tmp_path):
    """Two consecutive AcquisitionErrors → original error propagates after
    the retry cap is hit (default _MAX_POST_SUBMIT_RETRIES = 1)."""
    work = tmp_path / "work"
    work.mkdir()

    bad_url = f"file://{tmp_path}/no-repo-here"
    agent = _SequencedAgent([
        _output(bad_url, "deadbeef" * 5),
        _output(bad_url, "deadbeef" * 5),
    ])
    pipeline = Pipeline(
        agent=agent,
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(TargetedFetchLayer(), ShallowCloneLayer(depths=(2,)))
        ),
        disk_limit_pct=99.9,
        enable_consensus=False,
        api_extract_fallback=False,
    )
    with pytest.raises(AcquisitionError):
        pipeline.run("CVE-X", work)
    # The retry was attempted (cap = 1 retry → 2 total acquire attempts);
    # both failed and the original AcquisitionError propagated.
    assert agent.calls == 2
    assert getattr(pipeline, "_last_post_submit_retry_attempted", False) is True


def test_post_submit_retry_does_not_fire_on_unrelated_errors(tmp_path):
    """DiscoveryError raised before stages 2-5 (e.g. agent surrender)
    must NOT trigger the retry. The primary agent call gets one shot."""
    work = tmp_path / "work"
    work.mkdir()
    agent = _SequencedAgent([
        AgentSurrender(reason="no_evidence", detail="empty"),
    ])
    pipeline = Pipeline(
        agent=agent,
        disk_limit_pct=99.9,
        enable_consensus=False,
    )
    with pytest.raises(DiscoveryError):
        pipeline.run("CVE-X", work)
    assert agent.calls == 1  # no retry
    assert getattr(pipeline, "_last_post_submit_retry_attempted", False) is False


def test_post_submit_retry_telemetry_starts_false(tmp_path):
    """Pipeline initialises with the retry-flag at False; PASSes that
    don't need a retry must not flip it."""
    origin, _introduced, fixed = _make_origin(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    pipeline = Pipeline(
        agent=_rescued(f"file://{origin}", fixed),
        acquirer_factory=lambda: CascadingRepoAcquirer(
            layers=(ShallowCloneLayer(depths=(5,)),)
        ),
        disk_limit_pct=99.9,
        enable_consensus=False,
    )
    pipeline.run("CVE-X", work)
    assert getattr(pipeline, "_last_post_submit_retry_attempted", False) is False
