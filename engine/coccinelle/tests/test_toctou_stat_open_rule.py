"""Fixture tests for the toctou_stat_open rule.

Verification-role rule (fires mint confirmed CWE-367 verdicts): the
positive pins the actual check/use pair on one path, the negatives pin
the shapes that must NOT be confirmed — different paths, a path
reassigned between check and use, and the fstat-on-fd idiom the rule's
own message recommends.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "toctou_stat_open.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(rule), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_stat_then_open_same_path_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int check_then_open(const char *path, void *st)
            {
                if (stat(path, st) < 0)
                    return -1;
                return open(path, 0);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "toctou_stat_open"
        assert results[0]["line"] == 5

    def test_access_then_fopen_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void *check_then_fopen(const char *path)
            {
                if (access(path, 4) != 0)
                    return 0;
                return fopen(path, "r");
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5


class TestNegatives:
    def test_different_paths_do_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int two_paths(const char *a, const char *b, void *st)
            {
                if (stat(a, st) < 0)
                    return -1;
                return open(b, 0);
            }
        """)
        assert results == []

    def test_path_reassigned_between_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int reassigned(const char *path, void *st)
            {
                if (stat(path, st) < 0)
                    return -1;
                path = "/etc/other";
                return open(path, 0);
            }
        """)
        assert results == []

    def test_open_then_fstat_does_not_fire(self, tmp_path):
        # The recommended fix shape: open first, fstat the fd.
        results = _run_rule(tmp_path, """\
            int open_then_fstat(const char *path, void *st)
            {
                int fd = open(path, 0);
                if (fd < 0)
                    return -1;
                if (fstat(fd, st) < 0)
                    return -1;
                return fd;
            }
        """)
        assert results == []
