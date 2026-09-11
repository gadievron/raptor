"""Shared pinned-clone sha verification: match semantics + hardening."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core.recall.pinned_clone import verify_pinned_clone

_HAS_GIT = shutil.which("git") is not None

pytestmark = pytest.mark.skipif(not _HAS_GIT, reason="git not installed")


class _CorpusError(RuntimeError):
    pass


def _make_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "clone"
    repo.mkdir()
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)],
                   check=True)
    env = ["-c", "user.email=t@example.org", "-c", "user.name=t"]
    subprocess.run(["git", "-C", str(repo), *env, "add", "-A"],
                   check=True)
    subprocess.run(["git", "-C", str(repo), *env, "commit", "-qm", "c"],
                   check=True)
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True).stdout.strip()
    return repo, head


class TestMatchSemantics:
    def test_full_pin_exact_match_passes(self, tmp_path):
        repo, head = _make_repo(tmp_path)
        assert verify_pinned_clone(repo, head,
                                   error_cls=_CorpusError) == head

    def test_full_pin_mismatch_refused_with_hint(self, tmp_path):
        repo, _ = _make_repo(tmp_path)
        with pytest.raises(_CorpusError, match="pinned") as exc:
            verify_pinned_clone(repo, "0" * 40, error_cls=_CorpusError,
                                hint="re-acquire per SOURCES")
        assert "re-acquire per SOURCES" in str(exc.value)

    def test_short_pin_prefix_accepted(self, tmp_path):
        repo, head = _make_repo(tmp_path)
        assert verify_pinned_clone(repo, head[:12],
                                   error_cls=_CorpusError) == head

    def test_short_pin_mismatch_refused(self, tmp_path):
        repo, _ = _make_repo(tmp_path)
        with pytest.raises(_CorpusError, match="labels are invalid"):
            verify_pinned_clone(repo, "0" * 12, error_cls=_CorpusError)

    def test_not_a_repo_refused(self, tmp_path):
        with pytest.raises(_CorpusError, match="sha-verify"):
            verify_pinned_clone(tmp_path, "0" * 40,
                                error_cls=_CorpusError)


class TestHostileCloneConfig:
    def test_hostile_config_commands_not_executed(self, tmp_path):
        """The clone is internet-sourced and verified BEFORE the pin
        check, so its ``.git/config`` can name arbitrary programs
        (core.fsmonitor, core.pager, diff.external). The rev-parse
        must neutralise them — the canary fires if git honours a
        repo-configured command."""
        repo, head = _make_repo(tmp_path)
        canary = tmp_path / "canary"
        evil = tmp_path / "evil.sh"
        evil.write_text(f"#!/bin/sh\ntouch '{canary}'\n")
        evil.chmod(0o755)
        for key in ("core.fsmonitor", "core.pager", "diff.external"):
            subprocess.run(
                ["git", "-C", str(repo), "config", key, str(evil)],
                check=True)

        assert verify_pinned_clone(repo, head,
                                   error_cls=_CorpusError) == head
        assert not canary.exists(), (
            "hostile .git/config command executed during sha-verify")


def test_recall_measure_shim_uses_env_repo_root():
    # The shim must take the repo root from the launcher-set env slot
    # (hard lookup), never from a __file__-relative walk — the
    # __file__ form is reserved for libexec/ dispatch scripts.
    src = (Path(__file__).resolve().parents[1] / "scripts"
           / "recall-measure").read_text(encoding="utf-8")
    assert 'sys.path.insert(0, os.environ["RAPTOR_DIR"])' in src
    assert "parents[3]" not in src
