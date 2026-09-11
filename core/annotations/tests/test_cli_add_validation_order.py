"""``raptor-annotate add`` must reject traversal/absolute source paths
BEFORE any filesystem access on them.

With ``--lines`` given, the function-hash computation opens the
annotated file; the source-path validation therefore has to run first,
or an absolute / ``..`` path is opened (and hashed) before the add is
refused.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-annotate"


def _run(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


class TestAddValidatesPathFirst:
    def test_traversal_path_rejected(self, tmp_path: Path) -> None:
        base = tmp_path / "annotations"
        res = _run([
            "add", "../escape.py", "f",
            "--lines", "1-2", "--base", str(base), "-m", "note",
        ])
        assert res.returncode == 2
        assert ".." in res.stderr
        # Nothing written under the base.
        assert not list(base.rglob("*.md")) if base.exists() else True

    def test_absolute_path_rejected(self, tmp_path: Path) -> None:
        victim = tmp_path / "victim.txt"
        victim.write_text("secret\n", encoding="utf-8")
        base = tmp_path / "annotations"
        res = _run([
            "add", str(victim), "f",
            "--lines", "1-1", "--base", str(base), "-m", "note",
        ])
        assert res.returncode == 2
        assert "relative" in res.stderr

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="mkfifo not available",
    )
    def test_rejected_before_any_read(self, tmp_path: Path) -> None:
        # A FIFO with no writer blocks any reader forever. If the CLI
        # opened the file before rejecting the absolute path, this run
        # would hang and trip the subprocess timeout; a prompt exit 2
        # proves the rejection happens before any filesystem access.
        fifo = tmp_path / "trap.fifo"
        os.mkfifo(fifo)
        res = _run(
            [
                "add", str(fifo), "f",
                "--lines", "1-2",
                "--base", str(tmp_path / "annotations"), "-m", "note",
            ],
            timeout=20,
        )
        assert res.returncode == 2

    def test_valid_relative_path_still_writes(self, tmp_path: Path) -> None:
        target = tmp_path / "src"
        target.mkdir()
        (target / "mod.py").write_text(
            "def f():\n    return 1\n", encoding="utf-8",
        )
        base = tmp_path / "annotations"
        res = _run([
            "add", "mod.py", "f",
            "--lines", "1-2", "--base", str(base),
            "--target", str(target), "-m", "reviewed",
        ])
        assert res.returncode == 0, res.stderr
        written = list(base.rglob("*.md"))
        assert len(written) == 1
        content = written[0].read_text(encoding="utf-8")
        assert "## f" in content
        # --lines was honoured: the source hash stamp landed.
        assert "hash=" in content
