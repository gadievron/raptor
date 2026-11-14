"""Harvest commit bounds are validated before the Git transport seam."""

import subprocess

import pytest

from core.dataflow import parser_pack_harvest as harvest


@pytest.mark.parametrize("limit", [-1, True, 1.5, "2", None], ids=["negative", "bool", "float", "text", "none"])
def test_invalid_limit_refused_before_git(monkeypatch, limit):
    calls = []
    def recorded_git(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(harvest, "_run_git", recorded_git)
    source = harvest.HarvestSource("owned", ("owned_.*",), repo_dir="owned-inert-clone")
    with pytest.raises(ValueError, match="max_commits"):
        harvest.harvest_git_repo(source, max_commits=limit)
    assert calls == []


def test_zero_limit_skips_git(monkeypatch):
    def forbidden_git(*args, **kwargs):
        pytest.fail("zero budget must not invoke Git")
    monkeypatch.setattr(harvest, "_run_git", forbidden_git)
    source = harvest.HarvestSource("owned", ("owned_.*",), repo_dir="owned-inert-clone")
    result = harvest.harvest_git_repo(source, max_commits=0)
    assert result.library == "owned"
    assert result.commits_walked == 0
    assert result.names == {}
    assert result.errors == []


def test_positive_limit_forwarded_unchanged(monkeypatch):
    calls = []
    def recorded_git(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(harvest, "_run_git", recorded_git)
    source = harvest.HarvestSource("owned", ("owned_.*",), repo_dir="owned-inert-clone")
    result = harvest.harvest_git_repo(source, max_commits=2)
    assert len(calls) == 1
    assert "--max-count=2" in calls[0]
    assert result.commits_walked == 0


def test_cli_negative_limit_refused_before_sources(monkeypatch):
    def forbidden_sources(path):
        pytest.fail("invalid budget must not load sources")
    monkeypatch.setattr(harvest, "load_sources", forbidden_sources)
    with pytest.raises(SystemExit) as exc:
        harvest.main(["--max-commits", "-1"])
    assert exc.value.code == 2
