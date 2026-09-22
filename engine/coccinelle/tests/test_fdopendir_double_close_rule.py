"""Fixture tests for the fdopendir_double_close rule.

Verification-role rule (fires mint confirmed CWE-675 verdicts):
closedir() on an fdopendir() stream already closes the underlying
fd, so an explicit close(fd) afterwards is a double close. The
positive pins that close; the negative pins the correct
closedir-only teardown.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "fdopendir_double_close.cocci"
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
    def test_close_after_closedir_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void list_dir(int fd)
            {
                void *dir = fdopendir(fd);
                walk(dir);
                closedir(dir);
                close(fd);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "fdopendir_double_close"
        assert results[0]["line"] == 6


class TestNegatives:
    def test_closedir_only_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void list_dir(int fd)
            {
                void *dir = fdopendir(fd);
                walk(dir);
                closedir(dir);
            }
        """)
        assert results == []
