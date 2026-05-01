"""
Acquisition layers — tested against local file:// repos so the suite is
hermetic. Each test builds a tiny throwaway repo with two commits, then
exercises the layer against a `file://` URL pointing at it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cve_diff.acquisition import layers as layers_mod
from cve_diff.acquisition.layers import (
    CascadingRepoAcquirer,
    FullCloneLayer,
    ShallowCloneLayer,
    TargetedFetchLayer,
)
from cve_diff.core.exceptions import AcquisitionError
from cve_diff.core.models import CommitSha, RepoRef


def test_progressive_depths_dropped_2000():
    """The 2000-depth layer was responsible for 64s median and 3/40 bench
    timeouts on the 2026-04-20 OSV-only run: if the SHA is not reachable at
    depth=500 it almost never is at 2000 either (the commit is a cherry-pick
    off a branch we can't resolve). Drop it to cut worst-case acquire time.
    """
    assert 2000 not in layers_mod.PROGRESSIVE_DEPTHS
    assert layers_mod.PROGRESSIVE_DEPTHS == (100, 500)


def test_git_timeout_bounded():
    """Per-subprocess timeout must be shorter than the bench per-CVE 300 s
    watchdog so a single hanging fetch can't eat the whole budget.
    """
    assert layers_mod.GIT_TIMEOUT_S <= 180


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _make_origin(tmp_path: Path, n_commits: int = 3) -> tuple[Path, list[str]]:
    """Build a bare-cloneable origin repo with `n_commits` commits."""
    repo = tmp_path / "origin"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    shas: list[str] = []
    for i in range(n_commits):
        (repo / f"f{i}.txt").write_text(f"content {i}\n")
        _git(repo, "add", f"f{i}.txt")
        _git(repo, "commit", "-q", "-m", f"commit {i}")
        shas.append(_git(repo, "rev-parse", "HEAD"))
    return repo, shas


def _file_url(repo: Path) -> str:
    return f"file://{repo}"


# --- TargetedFetchLayer ----------------------------------------------------

def test_targeted_fetch_acquires_fix_commit(tmp_path):
    origin, shas = _make_origin(tmp_path)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(shas[-1]),
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    layer = TargetedFetchLayer()
    report = layer.acquire(ref, dest)
    assert report.ok, report.detail
    assert report.name == "targeted_fetch"
    out = subprocess.run(
        ["git", "-C", str(dest), "cat-file", "-e", f"{shas[-1]}^{{commit}}"],
        check=False,
    )
    assert out.returncode == 0


def test_targeted_fetch_acquires_both_commits(tmp_path):
    origin, shas = _make_origin(tmp_path, n_commits=4)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(shas[-1]),
        introduced=CommitSha(shas[0]),
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    report = TargetedFetchLayer().acquire(ref, dest)
    assert report.ok, report.detail
    for sha in (shas[0], shas[-1]):
        out = subprocess.run(
            ["git", "-C", str(dest), "cat-file", "-e", f"{sha}^{{commit}}"],
            check=False,
        )
        assert out.returncode == 0, f"missing {sha}"


def test_targeted_fetch_refuses_nonempty_dest(tmp_path):
    origin, shas = _make_origin(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "junk").write_text("x")
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(shas[-1]),
        introduced=None,
        canonical_score=100,
    )
    report = TargetedFetchLayer().acquire(ref, dest)
    assert not report.ok
    assert "not empty" in report.detail


def test_targeted_fetch_fails_on_unknown_sha(tmp_path):
    origin, _ = _make_origin(tmp_path)
    bogus = "0" * 40
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(bogus),
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    report = TargetedFetchLayer().acquire(ref, dest)
    assert not report.ok


# --- ShallowCloneLayer -----------------------------------------------------

def test_shallow_clone_finds_recent_commit(tmp_path):
    origin, shas = _make_origin(tmp_path, n_commits=3)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(shas[-1]),
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    report = ShallowCloneLayer(depths=(2,)).acquire(ref, dest)
    assert report.ok, report.detail
    assert "depth=2" in report.detail


def test_shallow_clone_progressive_deepening(tmp_path):
    """Depth 1 cannot reach the oldest commit; depth 5 can."""
    origin, shas = _make_origin(tmp_path, n_commits=5)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(shas[0]),  # the oldest commit
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    report = ShallowCloneLayer(depths=(1, 5)).acquire(ref, dest)
    assert report.ok, report.detail
    assert "depth=5" in report.detail


def test_shallow_clone_all_depths_fail(tmp_path):
    origin, _ = _make_origin(tmp_path, n_commits=2)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha("0" * 40),
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    report = ShallowCloneLayer(depths=(1, 2)).acquire(ref, dest)
    assert not report.ok


# --- FullCloneLayer --------------------------------------------------------

def test_full_clone_acquires_old_commit(tmp_path):
    """Full clone reaches a commit that depth=1 wouldn't, without depth limit."""
    origin, shas = _make_origin(tmp_path, n_commits=5)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(shas[0]),  # oldest commit
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    report = FullCloneLayer(timeout_s=60).acquire(ref, dest)
    assert report.ok, report.detail
    out = subprocess.run(
        ["git", "-C", str(dest), "cat-file", "-e", f"{shas[0]}^{{commit}}"],
        check=False,
    )
    assert out.returncode == 0


def test_full_clone_aborts_on_oversized_repo(tmp_path, monkeypatch):
    """Disk guardrail: GitHub repos larger than max_size_mb are skipped."""
    origin, shas = _make_origin(tmp_path)
    # Pretend the file:// URL is a huge github.com repo via monkeypatch
    ref = RepoRef(
        repository_url="https://github.com/torvalds/linux",
        fix_commit=CommitSha(shas[-1]),
        introduced=None,
        canonical_score=100,
    )
    monkeypatch.setattr(
        "cve_diff.infra.github_client.get_repo",
        lambda slug: {"size": 4_000_000},  # 4 GB in KB > 2 GB cap
    )
    dest = tmp_path / "dest"
    report = FullCloneLayer(max_size_mb=2048).acquire(ref, dest)
    assert not report.ok
    assert "too large" in report.detail


def test_full_clone_fails_on_unknown_sha(tmp_path):
    origin, _ = _make_origin(tmp_path)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha("0" * 40),
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    report = FullCloneLayer(timeout_s=60).acquire(ref, dest)
    assert not report.ok
    assert "missing" in report.detail


# --- CascadingRepoAcquirer -------------------------------------------------

def test_cascade_uses_first_layer_when_it_succeeds(tmp_path):
    origin, shas = _make_origin(tmp_path)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(shas[-1]),
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    acq = CascadingRepoAcquirer(layers=(TargetedFetchLayer(), ShallowCloneLayer(depths=(2,))))
    acq.acquire(ref, dest)
    assert len(acq.reports) == 1
    assert acq.reports[0].name == "targeted_fetch"
    assert acq.reports[0].ok


def test_cascade_falls_through_to_second_layer(tmp_path):
    """A layer that always fails should not block the next layer."""
    origin, shas = _make_origin(tmp_path)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha(shas[-1]),
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"

    from cve_diff.acquisition.layers import AcquisitionLayer, LayerReport

    class _AlwaysFails(AcquisitionLayer):
        name = "always_fails"

        def acquire(self, ref, dest):
            return LayerReport(self.name, False, "synthetic")

    acq = CascadingRepoAcquirer(
        layers=(_AlwaysFails(), ShallowCloneLayer(depths=(2,)))
    )
    acq.acquire(ref, dest)
    assert len(acq.reports) == 2
    assert acq.reports[0].name == "always_fails"
    assert not acq.reports[0].ok
    assert acq.reports[1].name == "shallow_clone"
    assert acq.reports[1].ok


def test_cascade_raises_when_all_layers_fail(tmp_path):
    origin, _ = _make_origin(tmp_path)
    ref = RepoRef(
        repository_url=_file_url(origin),
        fix_commit=CommitSha("0" * 40),
        introduced=None,
        canonical_score=100,
    )
    dest = tmp_path / "dest"
    acq = CascadingRepoAcquirer(
        layers=(TargetedFetchLayer(), ShallowCloneLayer(depths=(1,)))
    )
    with pytest.raises(AcquisitionError) as excinfo:
        acq.acquire(ref, dest)
    msg = str(excinfo.value)
    assert "targeted_fetch" in msg
    assert "shallow_clone" in msg


# ---------- _clean_dest safety guard ----------
# Defense-in-depth: the helper does ``rm -rf $dest``. Today every caller
# passes a tempdir, but a future caller could pass ``Path("/")`` or a
# similarly short absolute path. Guard refuses anything that's not at
# least 3 path-components and absolute.


def test_clean_dest_refuses_filesystem_root():
    from cve_diff.acquisition.layers import _clean_dest
    with pytest.raises(ValueError, match="dangerous path"):
        _clean_dest(Path("/"))


def test_clean_dest_refuses_short_absolute_path():
    from cve_diff.acquisition.layers import _clean_dest
    with pytest.raises(ValueError, match="dangerous path"):
        _clean_dest(Path("/tmp"))


def test_clean_dest_refuses_relative_path():
    from cve_diff.acquisition.layers import _clean_dest
    with pytest.raises(ValueError, match="dangerous path"):
        _clean_dest(Path("foo/bar"))


def test_clean_dest_accepts_real_tempdir(tmp_path):
    """Sanity: a real ≥3-component absolute path with content gets removed."""
    from cve_diff.acquisition.layers import _clean_dest
    target = tmp_path / "subdir"
    target.mkdir()
    (target / "file.txt").write_text("content")
    assert target.exists()
    _clean_dest(target)
    assert not target.exists()
