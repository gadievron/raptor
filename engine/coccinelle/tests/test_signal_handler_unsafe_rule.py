"""Fixture tests for the signal_handler_unsafe rule.

Verification-role rule (fires mint confirmed CWE-364 verdicts):
async-signal-unsafe functions called from a handler registered via
signal() are undefined behaviour per POSIX. The positive pins a
printf call inside the handler body; the negative pins the safe
sig_atomic_t-flag idiom.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "signal_handler_unsafe.cocci"
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
    def test_printf_in_handler_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void on_term(int sig)
            {
                printf("terminating: %d\n", sig);
            }

            void install(void)
            {
                signal(15, on_term);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "signal_handler_unsafe"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_flag_only_handler_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static volatile int got_signal;

            void on_term(int sig)
            {
                got_signal = sig;
            }

            void install(void)
            {
                signal(15, on_term);
            }
        """)
        assert results == []
