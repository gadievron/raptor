"""Fixture tests for the inet_ntoa_double_call rule.

Verification-role rule (fires mint confirmed CWE-676 verdicts):
two inet_ntoa() calls in one argument list share the same static
buffer — the first result is clobbered. The positive pins the
two-call printf; the negative pins a single call, which is safe.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "inet_ntoa_double_call.cocci"
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
    def test_two_calls_in_one_arglist_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_route(struct in_addr src, struct in_addr dst)
            {
                printf("%s -> %s\n", inet_ntoa(src), inet_ntoa(dst));
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "inet_ntoa_double_call"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_single_call_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_peer(struct in_addr src)
            {
                printf("peer %s\n", inet_ntoa(src));
            }
        """)
        assert results == []
