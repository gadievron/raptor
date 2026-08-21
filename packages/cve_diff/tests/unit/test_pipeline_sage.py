"""SAGE fix-pointer wiring through the pipeline (opt-in, agent-source
bookkeeping). The hook pair itself is tested in
``core/sage/tests/test_sage_hooks_cve.py``; here we assert the
pipeline-side contract: recall short-circuits the agent, stores happen
only for agent-discovered picks, and everything stays off by default.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from cve_diff.agent.types import AgentOutput
from cve_diff.core.models import CommitSha, PatchTuple
from cve_diff.pipeline import Pipeline

FIX = "a" * 40
PARENT = "b" * 40
REPO = "https://github.com/example/proj"

POINTER = {
    "cve_id": "CVE-2024-31337",
    "repository_url": REPO,
    "fix_commit": FIX,
    "parent_commit": PARENT,
}


@dataclass
class _CountingAgent:
    runs: int = 0

    def run(self, config, ctx):
        self.runs += 1
        return AgentOutput(
            value=PatchTuple(
                repository_url=REPO,
                fix_commit=CommitSha(FIX),
                introduced=None,
            ),
            rationale="agent stub",
        )


def _patch_hooks(monkeypatch, pointer=None):
    calls = {"recall": 0, "store": []}

    def _recall(cve_id):
        calls["recall"] += 1
        return pointer

    def _store(cve_id, repo, fix, parent="", *, consensus_count=0, shape=""):
        calls["store"].append((cve_id, repo, fix, parent))
        return True

    monkeypatch.setattr("core.sage.hooks.recall_cve_fix_pointer", _recall)
    monkeypatch.setattr("core.sage.hooks.store_cve_fix_pointer", _store)
    return calls


class _FakeBundle:
    def __init__(self):
        from cve_diff.core.models import DiffBundle, RepoRef
        self.bundle = DiffBundle(
            cve_id="CVE-2024-31337",
            repo_ref=RepoRef(
                repository_url=REPO,
                fix_commit=CommitSha(FIX),
                introduced=CommitSha(PARENT),
                canonical_score=100,
            ),
            commit_before=CommitSha(PARENT),
            commit_after=CommitSha(FIX),
            diff_text="d",
            files_changed=1,
            bytes_size=1,
        )


def test_recall_short_circuits_agent_and_skips_store(tmp_path, monkeypatch):
    calls = _patch_hooks(monkeypatch, pointer=POINTER)
    agent = _CountingAgent()
    pipeline = Pipeline(agent=agent, disk_limit_pct=99.9, sage_enabled=True)
    seen_ref = {}

    def _fake_acquire(cve_id, ref, agent_result, work_dir):
        seen_ref["ref"] = ref
        return _FakeBundle()

    monkeypatch.setattr(pipeline, "_acquire_to_render", _fake_acquire)
    pipeline.run("CVE-2024-31337", tmp_path)

    assert calls["recall"] == 1
    assert agent.runs == 0, "agent must not run when a pointer was recalled"
    assert seen_ref["ref"].repository_url == REPO
    assert seen_ref["ref"].fix_commit == FIX
    # SAGE-recalled pick: no re-store (no self-reinforcing loop).
    assert calls["store"] == []


def test_agent_pick_is_stored_after_mechanical_verification(
    tmp_path, monkeypatch,
):
    calls = _patch_hooks(monkeypatch, pointer=None)
    agent = _CountingAgent()
    pipeline = Pipeline(agent=agent, disk_limit_pct=99.9, sage_enabled=True)
    monkeypatch.setattr(
        pipeline, "_acquire_to_render", lambda *a, **k: _FakeBundle(),
    )
    pipeline.run("CVE-2024-31337", tmp_path)

    assert agent.runs == 1
    assert calls["store"] == [("CVE-2024-31337", REPO, FIX, PARENT)]


def test_stale_pointer_falls_back_to_agent(tmp_path, monkeypatch):
    from cve_diff.core.exceptions import AnalysisError

    calls = _patch_hooks(monkeypatch, pointer=POINTER)
    agent = _CountingAgent()
    pipeline = Pipeline(agent=agent, disk_limit_pct=99.9, sage_enabled=True)
    attempts = {"n": 0}

    def _first_refuses(cve_id, ref, agent_result, work_dir):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise AnalysisError("CVE-2024-31337: shape rejected")
        return _FakeBundle()

    monkeypatch.setattr(pipeline, "_acquire_to_render", _first_refuses)
    pipeline.run("CVE-2024-31337", tmp_path)

    assert agent.runs == 1, "post-submit retry must fall back to the agent"
    # The agent's (verified) pick gets stored; the stale recall did not.
    assert calls["store"] == [("CVE-2024-31337", REPO, FIX, PARENT)]


def test_sage_off_by_default(tmp_path, monkeypatch):
    calls = _patch_hooks(monkeypatch, pointer=POINTER)
    agent = _CountingAgent()
    pipeline = Pipeline(agent=agent, disk_limit_pct=99.9)
    monkeypatch.setattr(
        pipeline, "_acquire_to_render", lambda *a, **k: _FakeBundle(),
    )
    pipeline.run("CVE-2024-31337", tmp_path)

    assert calls["recall"] == 0
    assert calls["store"] == []
    assert agent.runs == 1


def test_sage_recalled_pick_never_feeds_scorecard(tmp_path, monkeypatch):
    _patch_hooks(monkeypatch, pointer=POINTER)
    recorded = []
    monkeypatch.setattr(
        "cve_diff.infra.scorecard.record_discovery_outcome",
        lambda *a, **k: recorded.append((a, k)) or True,
    )
    pipeline = Pipeline(
        agent=_CountingAgent(), disk_limit_pct=99.9,
        sage_enabled=True, scorecard_enabled=True,
    )
    monkeypatch.setattr(
        pipeline, "_acquire_to_render", lambda *a, **k: _FakeBundle(),
    )
    pipeline.run("CVE-2024-31337", tmp_path)
    assert recorded == []


def test_hook_import_failure_degrades_silently(tmp_path, monkeypatch):
    """A broken/absent SAGE install must not break the pipeline."""
    import builtins

    real_import = builtins.__import__

    def _no_sage(name, *a, **k):
        if name.startswith("core.sage"):
            raise ImportError("sage not installed")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_sage)
    agent = _CountingAgent()
    pipeline = Pipeline(agent=agent, disk_limit_pct=99.9, sage_enabled=True)
    monkeypatch.setattr(
        pipeline, "_acquire_to_render", lambda *a, **k: _FakeBundle(),
    )
    result = pipeline.run("CVE-2024-31337", tmp_path)
    assert isinstance(result, _FakeBundle)
    assert agent.runs == 1


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
