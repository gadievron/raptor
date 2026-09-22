"""Fixture tests for the signal_sigkill_sigstop rule.

Verification-role rule (fires mint confirmed CWE-252 verdicts):
signal(SIGKILL, ...) always fails with EINVAL — the handler is
never installed. The positive pins the SIGKILL registration; the
negative pins a catchable signal (SIGTERM).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "signal_sigkill_sigstop.cocci"
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
    def test_signal_sigkill_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void install(void (*handler)(int))
            {
                signal(SIGKILL, handler);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "signal_sigkill_sigstop"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_signal_sigterm_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void install(void (*handler)(int))
            {
                signal(SIGTERM, handler);
            }
        """)
        assert results == []
