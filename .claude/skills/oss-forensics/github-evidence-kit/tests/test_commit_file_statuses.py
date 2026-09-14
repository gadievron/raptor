"""collect_commit must survive the full GitHub file-status vocabulary.

The commits API also emits "changed", "copied" and "unchanged"; a
single such file used to raise ValidationError and kill evidence
collection for the whole commit.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.collectors.api import GitHubAPICollector


def _commit_data(statuses: list[str | None]) -> dict:
    files = []
    for i, status in enumerate(statuses):
        f = {"filename": f"f{i}.txt", "additions": 1, "deletions": 0}
        if status is not None:
            f["status"] = status
        files.append(f)
    return {
        "sha": "a" * 40,
        "commit": {
            "message": "msg",
            "author": {"name": "a", "email": "a@x", "date": "2024-01-15T10:30:00Z"},
            "committer": {"name": "c", "email": "c@x", "date": "2024-01-15T10:30:00Z"},
        },
        "author": {"login": "a"},
        "files": files,
    }


def _collect(statuses: list[str | None]):
    client = MagicMock()
    client.get_commit.return_value = _commit_data(statuses)
    return GitHubAPICollector(client=client).collect_commit("o", "r", "a" * 40)


def test_changed_and_copied_statuses_do_not_crash():
    obs = _collect(["added", "changed", "copied", "unchanged"])
    assert [f.status for f in obs.files] == [
        "added", "changed", "copied", "unchanged",
    ]


def test_unknown_future_status_degrades_to_modified():
    obs = _collect(["weird_future_status"])
    assert obs.files[0].status == "modified"


def test_missing_status_defaults_to_modified():
    obs = _collect([None])
    assert obs.files[0].status == "modified"
