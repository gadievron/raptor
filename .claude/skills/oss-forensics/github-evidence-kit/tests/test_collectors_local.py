"""
Tests for LocalGitCollector.
"""
from unittest.mock import Mock

import pytest

from src.collectors.local import LocalGitCollector
from src.schema.common import EvidenceSource


@pytest.fixture
def mock_git_client():
    client = Mock()
    client.get_commit.return_value = {
        "sha": "a" * 40,
        "author_name": "Test Author",
        "author_email": "test@example.com",
        "author_date": "2023-01-01T00:00:00Z",
        "committer_name": "Test Committer",
        "committer_email": "committer@example.com",
        "committer_date": "2023-01-01T00:00:00Z",
        "parents": [],
        "message": "Test commit message\n\nBody",
    }
    client.get_commit_files.return_value = [
        {"status": "modified", "filename": "test.py"}
    ]
    return client


def test_collect_commit(mock_git_client):
    collector = LocalGitCollector(client=mock_git_client)
    commit = collector.collect_commit("a" * 40)

    assert commit.sha == "a" * 40
    assert commit.author.name == "Test Author"
    assert commit.message == "Test commit message\n\nBody"
    assert commit.original_what == "Test commit message"
    assert commit.observed_by == EvidenceSource.GIT
    assert len(commit.files) == 1
    assert commit.files[0].filename == "test.py"


def test_collect_log_commits(mock_git_client):
    mock_git_client.get_log.return_value = [
        {"sha": "a" * 40},
        {"sha": "c" * 40},
    ]
    mock_git_client.get_commit.side_effect = lambda sha: {
        "sha": sha,
        "author_name": "Test Author",
        "author_email": "test@example.com",
        "author_date": "2023-01-01T00:00:00Z",
        "committer_name": "Test Committer",
        "committer_email": "committer@example.com",
        "committer_date": "2023-01-01T00:00:00Z",
        "parents": [],
        "message": f"Commit {sha[:8]}",
    }
    mock_git_client.get_commit_files.return_value = []

    collector = LocalGitCollector(client=mock_git_client)
    commits = collector.collect_log_commits(limit=10)

    assert len(commits) == 2
    assert commits[0].sha == "a" * 40
    assert commits[1].sha == "c" * 40
    assert all(c.observed_by == EvidenceSource.GIT for c in commits)
    mock_git_client.get_log.assert_called_once_with(
        ref="HEAD", since=None, until=None, limit=10, all_refs=False,
    )


def test_collect_log_commits_all_refs(mock_git_client):
    mock_git_client.get_log.return_value = [{"sha": "a" * 40}]
    mock_git_client.get_commit.side_effect = lambda sha: {
        "sha": sha,
        "author_name": "A",
        "author_email": "a@a.com",
        "author_date": "2023-01-01T00:00:00Z",
        "committer_name": "A",
        "committer_email": "a@a.com",
        "committer_date": "2023-01-01T00:00:00Z",
        "parents": [],
        "message": "m",
    }
    mock_git_client.get_commit_files.return_value = []

    collector = LocalGitCollector(client=mock_git_client)
    commits = collector.collect_log_commits(all_refs=True, since="2023-01-01")

    assert len(commits) == 1
    mock_git_client.get_log.assert_called_once_with(
        ref="HEAD", since="2023-01-01", until=None, limit=100, all_refs=True,
    )


def test_collect_log_commits_skips_errors(mock_git_client):
    mock_git_client.get_log.return_value = [
        {"sha": "a" * 40},
        {"sha": "b" * 40},
    ]

    def commit_side_effect(sha):
        if sha == "b" * 40:
            raise RuntimeError("bad commit")
        return {
            "sha": sha,
            "author_name": "Test",
            "author_email": "t@t.com",
            "author_date": "2023-01-01T00:00:00Z",
            "committer_name": "Test",
            "committer_email": "t@t.com",
            "committer_date": "2023-01-01T00:00:00Z",
            "parents": [],
            "message": "ok",
        }

    mock_git_client.get_commit.side_effect = commit_side_effect
    mock_git_client.get_commit_files.return_value = []

    collector = LocalGitCollector(client=mock_git_client)
    commits = collector.collect_log_commits()

    assert len(commits) == 1
    assert commits[0].sha == "a" * 40


def test_collect_dangling_commits(mock_git_client):
    mock_git_client.fsck.return_value = f"dangling commit {'b' * 40}\n"
    mock_git_client.get_commit.return_value = {
        "sha": "b" * 40,
        "author_name": "Dangler",
        "author_email": "dangler@example.com",
        "author_date": "2023-01-01T00:00:00Z",
        "committer_name": "Dangler",
        "committer_email": "dangler@example.com",
        "committer_date": "2023-01-01T00:00:00Z",
        "parents": [],
        "message": "Dangling commit",
    }
    
    collector = LocalGitCollector(client=mock_git_client)
    commits = collector.collect_dangling_commits()
    
    assert len(commits) == 1
    assert commits[0].sha == "b" * 40
    assert commits[0].is_dangling is True
