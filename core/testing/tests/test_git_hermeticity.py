"""Tests for core.testing.git_hermeticity + its root-conftest wiring.

Three layers:

* pure unit tests over the env pin/restore and fingerprint logic;
* live assertions that THIS session is actually pinned (the root
  conftest applied ``pin_git_env`` at import time — these verify the
  wiring end-to-end, not a copy of it);
* source pins (driftguard style) so the conftest wiring and the
  pytest.ini marker registration cannot silently disappear.

The session-fail path of the drift guard (deliberate mutation of the
ambient config -> exitstatus 1 + loud summary) is exercised manually on
a throwaway clone — it cannot run in-tree because the only honest
fixture would be mutating the real checkout's config.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from core.testing import git_hermeticity as gh

REPO_ROOT = Path(__file__).resolve().parents[3]

_HAS_GIT = shutil.which("git") is not None


# ---------------------------------------------------------------------------
# pin_git_env / restore_git_env (pure dict, no os.environ)
# ---------------------------------------------------------------------------

def test_pin_sets_config_pins_and_strips_ambient():
    env = {
        "PATH": "/usr/bin",
        "GIT_CONFIG_GLOBAL": "/home/op/.gitconfig",
        "GIT_AUTHOR_NAME": "Operator",
        "GIT_DIR": "/somewhere/.git",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "user.name",
        "GIT_CONFIG_VALUE_0": "Operator",
        "GIT_TEMPLATE_DIR": "/somewhere/templates",
        "GIT_EXEC_PATH": "/somewhere/git-core",
    }
    saved = gh.pin_git_env(env)
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert env["GIT_CONFIG_SYSTEM"] == "/dev/null"
    for gone in ("GIT_AUTHOR_NAME", "GIT_DIR", "GIT_CONFIG_COUNT",
                 "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
                 "GIT_TEMPLATE_DIR", "GIT_EXEC_PATH"):
        assert gone not in env
    assert env["PATH"] == "/usr/bin"  # untouched
    # displaced originals captured (None = was unset)
    assert saved["GIT_CONFIG_GLOBAL"] == "/home/op/.gitconfig"
    assert saved["GIT_CONFIG_SYSTEM"] is None
    assert saved["GIT_AUTHOR_NAME"] == "Operator"


def test_pin_restore_round_trips_exactly():
    original = {
        "PATH": "/usr/bin",
        "GIT_CONFIG_GLOBAL": "/home/op/.gitconfig",
        "GIT_COMMITTER_EMAIL": "op@example.invalid",
    }
    env = dict(original)
    saved = gh.pin_git_env(env)
    gh.restore_git_env(saved, env)
    assert env == original


def test_restore_removes_pins_that_were_unset():
    env: dict[str, str] = {"PATH": "/usr/bin"}
    saved = gh.pin_git_env(env)
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    gh.restore_git_env(saved, env)
    assert "GIT_CONFIG_GLOBAL" not in env
    assert "GIT_CONFIG_SYSTEM" not in env
    assert env == {"PATH": "/usr/bin"}


# ---------------------------------------------------------------------------
# repo_config_paths / config_fingerprint / describe_drift
# ---------------------------------------------------------------------------

def _init(repo: Path) -> None:
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(repo)],
        check=True, capture_output=True, timeout=15,
    )


@pytest.mark.skipif(not _HAS_GIT, reason="git not installed")
def test_repo_config_paths_plain_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init(repo)
    assert gh.repo_config_paths(repo) == [repo / ".git" / "config"]


@pytest.mark.skipif(not _HAS_GIT, reason="git not installed")
def test_repo_config_paths_linked_worktree_points_at_common_config(tmp_path):
    """Repo-level `git config` writes from a linked worktree land in the
    COMMON dir's config — the guard must watch that file."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init(repo)
    subprocess.run(
        ["git", "-C", str(repo),
         "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "commit", "-q", "--allow-empty", "-m", "seed"],
        check=True, capture_output=True, timeout=15,
    )
    wt = tmp_path / "wt"
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "-q", str(wt)],
        check=True, capture_output=True, timeout=15,
    )
    assert gh.repo_config_paths(wt) == [repo / ".git" / "config"]


def test_repo_config_paths_outside_any_repo(tmp_path):
    assert gh.repo_config_paths(tmp_path) == []


@pytest.mark.skipif(not _HAS_GIT, reason="git not installed")
def test_config_fingerprint_detects_repo_level_config_write(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _init(repo)
    before = gh.config_fingerprint(repo)
    assert before is not None
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test"],
        check=True, capture_output=True, timeout=15,
    )
    after = gh.config_fingerprint(repo)
    assert after is not None
    assert after != before
    drift = gh.describe_drift(before, after)
    assert len(drift) == 1
    assert str(repo / ".git" / "config") in drift[0]


def test_config_fingerprint_none_when_nothing_to_guard(tmp_path):
    assert gh.config_fingerprint(tmp_path) is None


@pytest.mark.skipif(not _HAS_GIT, reason="git not installed")
def test_config_fingerprint_unreadable_is_drift_not_skip(
        tmp_path, monkeypatch):
    """A config file that exists but cannot be read fingerprints as
    "unreadable" — a permission flip mid-session must surface as drift,
    not silently disable the guard."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _init(repo)
    before = gh.config_fingerprint(repo)
    assert before is not None

    def _raise(_self):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_bytes", _raise)
    after = gh.config_fingerprint(repo)
    assert after is not None
    assert after[str(repo / ".git" / "config")] == "unreadable"
    assert gh.describe_drift(before, after)


def test_describe_drift_no_change_is_empty():
    fp = {"/x/.git/config": "ab" * 32}
    assert gh.describe_drift(fp, dict(fp)) == []


def test_describe_drift_marks_absent_files():
    before = {"/x/.git/config": None}
    after = {"/x/.git/config": "ab" * 32}
    (line,) = gh.describe_drift(before, after)
    assert "absent" in line and "abababab" in line


# ---------------------------------------------------------------------------
# Live wiring: THIS session must be pinned (root conftest, import time)
# ---------------------------------------------------------------------------

def test_session_env_is_pinned():
    """These live-wiring tests intentionally FAIL under invocations
    that bypass the root conftest (e.g. ``--confcutdir``): such a
    session is genuinely not hermetic, and the failure is the alarm."""
    assert os.environ.get("GIT_CONFIG_GLOBAL") == "/dev/null"
    assert os.environ.get("GIT_CONFIG_SYSTEM") == "/dev/null"


def test_session_publishes_ambient_handoff():
    """The top-level session records the true displaced env snapshot so
    xdist workers' escape hatch restores operator values, not the
    pinned ones they inherited."""
    import json

    raw = os.environ.get("RAPTOR_GIT_AMBIENT_ENV")
    assert raw, "root conftest must publish the ambient git env snapshot"
    snapshot = json.loads(raw)
    assert "GIT_CONFIG_GLOBAL" in snapshot


@pytest.mark.skipif(not _HAS_GIT, reason="git not installed")
def test_operator_global_config_invisible_to_git(tmp_path):
    """End-to-end: a git subprocess spawned the way tests spawn them
    cannot see any global/system config. returncode 0 distinguishes
    "empty /dev/null config" from "no global config file at all"
    (exit 128) — keeps the test non-vacuous on hosts without a
    ~/.gitconfig."""
    proc = subprocess.run(
        ["git", "config", "--global", "--list"],
        capture_output=True, text=True, timeout=15, cwd=str(tmp_path),
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Source pins (adoption-driftguard style): the wiring cannot silently go
# ---------------------------------------------------------------------------

def test_root_conftest_wires_the_guard():
    src = (REPO_ROOT / "conftest.py").read_text(encoding="utf-8")
    assert "from core.testing import git_hermeticity" in src, (
        "root conftest.py must import the git hermeticity substrate"
    )
    assert "pin_git_env()" in src, (
        "root conftest.py must apply the env pins at import time"
    )
    assert "config_fingerprint" in src, (
        "root conftest.py must fingerprint the ambient repo config "
        "at session start/finish (drift guard)"
    )


def test_marker_registered():
    ini = (REPO_ROOT / "pytest.ini").read_text(encoding="utf-8")
    assert "ambient_git_config:" in ini, (
        "pytest.ini must register the ambient_git_config escape-hatch "
        "marker"
    )
