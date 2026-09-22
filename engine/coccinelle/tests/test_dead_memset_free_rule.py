"""Fixture tests for the dead_memset_free rule.

Verification-role rule (fires mint confirmed CWE-14 verdicts):
a memset immediately before free is a dead store the compiler may
elide, silently stripping a secret-clearing write. The positive
pins the clear-then-free pair; the negative pins an intervening
read of the buffer, which keeps the store observable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "dead_memset_free.cocci"
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
    def test_clear_then_free_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void discard_key(char *key, unsigned long len)
            {
                memset(key, 0, len);
                free(key);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "dead_memset_free"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_read_between_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void archive_key(char *out, char *key, unsigned long len)
            {
                memset(key, 0, len);
                memcpy(out, key, len);
                free(key);
            }
        """)
        assert results == []
