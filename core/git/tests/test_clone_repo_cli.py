"""CLI argument contract for ``libexec/raptor-clone-repo``.

``--depth N`` and ``--full`` are documented as alternatives; the CLI
must refuse the contradictory combination instead of silently letting
the shallow depth override an explicit full-history request.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-clone-repo"


def _run(args: list[str], tmp_home: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    env["HOME"] = str(tmp_home)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


class TestDepthFullExclusivity:
    def test_both_flags_rejected(self, tmp_path: Path) -> None:
        res = _run(
            ["https://github.com/org/repo.git", str(tmp_path / "dst"),
             "--full", "--depth", "1"],
            tmp_path,
        )
        assert res.returncode == 2
        assert "mutually exclusive" in res.stderr

    def test_both_flags_rejected_either_order(self, tmp_path: Path) -> None:
        res = _run(
            ["https://github.com/org/repo.git", str(tmp_path / "dst"),
             "--depth", "1", "--full"],
            tmp_path,
        )
        assert res.returncode == 2
        assert "mutually exclusive" in res.stderr

    def test_full_alone_still_accepted(self, tmp_path: Path) -> None:
        # A non-allowlisted URL fails validation inside
        # clone_repository (no network touched): reaching the
        # "clone failed" path proves --full parsed cleanly and was
        # not swallowed by the exclusivity check.
        res = _run(
            ["https://evil.example/repo.git", str(tmp_path / "dst"),
             "--full"],
            tmp_path,
        )
        assert res.returncode == 1
        assert "clone failed" in res.stderr

    def test_depth_alone_still_accepted(self, tmp_path: Path) -> None:
        res = _run(
            ["https://evil.example/repo.git", str(tmp_path / "dst"),
             "--depth", "1"],
            tmp_path,
        )
        assert res.returncode == 1
        assert "clone failed" in res.stderr

    def test_bad_depth_still_usage_error(self, tmp_path: Path) -> None:
        res = _run(
            ["https://github.com/org/repo.git", str(tmp_path / "dst"),
             "--depth", "abc"],
            tmp_path,
        )
        assert res.returncode == 2
