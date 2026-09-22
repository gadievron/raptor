"""Fixture tests for the use_after_fclose rule.

Verification-role rule (fires mint confirmed CWE-416 verdicts):
stdio operations on a FILE* after fclose() are use-after-free. The
positive pins fprintf on the closed stream; the negative pins the
documented escape — the pointer reassigned (fopen) before reuse.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "use_after_fclose.cocci"
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
    def test_fprintf_after_fclose_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_and_close(void *fp)
            {
                fclose(fp);
                fprintf(fp, "done\n");
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "use_after_fclose"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_reassigned_stream_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void reopen(void *fp, const char *path)
            {
                fclose(fp);
                fp = fopen(path, "w");
                fprintf(fp, "fresh\n");
            }
        """)
        assert results == []
