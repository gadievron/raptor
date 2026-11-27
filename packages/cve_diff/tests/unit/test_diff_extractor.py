from __future__ import annotations

import subprocess
from pathlib import Path

from cve_diff.core.models import CommitSha, RepoRef
from cve_diff.diffing.extractor import extract_diff


def _init_two_commit_repo(path: Path) -> tuple[str, str]:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True, timeout=15)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.email", "t@t"], check=True
    )
    subprocess.run(["git", "-C", str(path), "config", "user.name", "t"], check=True, timeout=15)
    (path / "a.c").write_text("int a = 1;\n")
    subprocess.run(["git", "-C", str(path), "add", "a.c"], check=True, timeout=15)
    subprocess.run(
        ["git", "-C", str(path), "commit", "-q", "-m", "first"], check=True
    )
    before = subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()
    (path / "a.c").write_text("int a = 2;\n")
    subprocess.run(
        ["git", "-C", str(path), "commit", "-q", "-am", "fix"], check=True
    )
    after = subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()
    return before, after


def test_extract_diff_produces_text(tmp_path: Path) -> None:
    before, after = _init_two_commit_repo(tmp_path)
    ref = RepoRef(
        repository_url="local",
        fix_commit=CommitSha(after),
        introduced=CommitSha(before),
        canonical_score=100,
    )
    bundle = extract_diff(
        repo_path=tmp_path,
        cve_id="CVE-TEST-0001",
        ref=ref,
        commit_before=CommitSha(before),
        commit_after=CommitSha(after),
    )
    assert "int a = 1;" in bundle.diff_text
    assert "int a = 2;" in bundle.diff_text
    assert bundle.files_changed == 1
    assert bundle.bytes_size == len(bundle.diff_text.encode("utf-8"))


def test_run_git_bounded_records_clip_out_of_band(tmp_path: Path) -> None:
    # The clip fact must ride the CompletedProcess OUT OF BAND
    # (core.sandbox.capture_truncated): the in-band marker sits in a
    # repo-controlled stream, so a hostile repo can forge it — any
    # consumer of the fact needs the flag on the result object.
    from core.sandbox import capture_truncated
    from cve_diff.diffing.extractor import _run_git_bounded

    _before, after = _init_two_commit_repo(tmp_path)
    clipped = _run_git_bounded(
        ["git", "-C", str(tmp_path), "show", after],
        timeout_s=15, cap_bytes=16,
    )
    assert clipped.returncode == 0
    assert capture_truncated(clipped) == (True, False)
    whole = _run_git_bounded(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        timeout_s=15, cap_bytes=1 << 20,
    )
    assert whole.returncode == 0
    assert capture_truncated(whole) == (False, False)
