"""_load_suppression_records reads attacker-writable run-dir bytes.

suppressions.jsonl sits inside a run dir whose rw grant sandboxed code
holds. The reader must therefore be swap-proof and bounded: the old
stat-then-``read_text`` pair raced a swap (a FIFO planted after the
stat hung the CLI; a file grown after the stat was slurped unbounded).
It now routes through ``core.json.load_jsonl``, whose open refuses
non-regular files on the OPENED fd (O_NOFOLLOW + O_NONBLOCK + fstat)
and enforces the byte budgets before buffering.
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file-type semantics")


def _load_review_module():
    cli_path = str(REPO_ROOT / "libexec" / "raptor-review")
    loader = SourceFileLoader("raptor_review_cli_suppr", cli_path)
    spec = importlib.util.spec_from_loader("raptor_review_cli_suppr", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def cli():
    return _load_review_module()


def _write_records(path: Path, records: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


class TestLoadSuppressionRecords:

    def test_filters_matching_records(self, cli, tmp_path: Path) -> None:
        _write_records(tmp_path / "suppressions.jsonl", [
            {"file_path": "src/a.c", "function": "f", "verdict": "absent"},
            {"file_path": "src/a.c", "function": "g", "verdict": "absent"},
            {"file_path": "src/b.c", "function": "f", "verdict": "inlined"},
            {"file_path": "src/a.c", "function": "f", "dropped": False},
        ])
        recs = cli._load_suppression_records(tmp_path, "src/a.c", "f")
        assert len(recs) == 2
        assert all(r["file_path"] == "src/a.c" and r["function"] == "f"
                   for r in recs)

    def test_missing_and_no_dir_load_empty(self, cli, tmp_path: Path) -> None:
        assert cli._load_suppression_records(None, "a", "f") == []
        assert cli._load_suppression_records(tmp_path, "a", "f") == []

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
    def test_fifo_at_trail_path_returns_without_hang(
            self, cli, tmp_path: Path) -> None:
        """The defect shape the old reader had: a FIFO swapped in
        after its stat gate hung the CLI on the read. The hardened
        open must refuse and return promptly."""
        os.mkfifo(str(tmp_path / "suppressions.jsonl"))
        # Hard backstop: if the open regresses to a blocking one this
        # raises instead of wedging the whole suite.
        def _boom(signum: int, frame: object) -> None:
            raise AssertionError(
                "reader blocked on a reader-less FIFO — the "
                "non-blocking regularity gate regressed")
        old = signal.signal(signal.SIGALRM, _boom)
        signal.alarm(20)
        try:
            assert cli._load_suppression_records(tmp_path, "a", "f") == []
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)

    def test_symlink_at_trail_path_refused(
            self, cli, tmp_path: Path) -> None:
        run = tmp_path / "run"
        run.mkdir()
        victim = tmp_path / "victim.jsonl"
        _write_records(victim, [{"file_path": "a", "function": "f"}])
        os.symlink(str(victim), str(run / "suppressions.jsonl"))
        assert cli._load_suppression_records(run, "a", "f") == []

    def test_oversize_trail_refused_before_buffering(
            self, cli, tmp_path: Path) -> None:
        """A trail grown past the 64 MiB budget loads as no records —
        the size gate runs on the opened fd BEFORE any read (sparse
        file: the size is real to fstat, no disk cost)."""
        path = tmp_path / "suppressions.jsonl"
        with open(path, "wb") as fh:
            fh.truncate(64 * 1024 * 1024 + 1)
        assert cli._load_suppression_records(tmp_path, "a", "f") == []

    def test_oversize_line_skipped_others_survive(
            self, cli, tmp_path: Path) -> None:
        good = {"file_path": "src/a.c", "function": "f", "ok": 1}
        bomb = json.dumps(
            {"file_path": "src/a.c", "function": "f",
             "pad": "x" * (2 * 1024 * 1024)})
        (tmp_path / "suppressions.jsonl").write_text(
            bomb + "\n" + json.dumps(good) + "\n", encoding="utf-8")
        recs = cli._load_suppression_records(tmp_path, "src/a.c", "f")
        assert recs == [good]
