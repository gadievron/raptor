"""Fixture tests for the uninitialized_return rule.

Pattern 2's domination scan must treat an unconditional assignment
BETWEEN the declaration and the switch as initialising: whatever the
default-less switch does, the variable is already set at the return.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "uninitialized_return.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(_RULE), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


def _switch_results(results: list[dict]) -> list[dict]:
    return [r for r in results if "switch without default" in r["message"]]


class TestPositives:
    def test_switch_without_default_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(int mode)
            {
                int err;
                switch (mode) {
                case 1:
                    err = do_one();
                    break;
                case 2:
                    err = do_two();
                    break;
                }
                return err;
            }
        """)
        assert len(_switch_results(results)) == 1

    def test_conditional_init_before_switch_still_fires(self, tmp_path):
        # An init nested inside an if does NOT dominate the return.
        results = _run_rule(tmp_path, """\
            int bug(int mode, int flag)
            {
                int err;
                if (flag) {
                    err = 5;
                }
                switch (mode) {
                case 1:
                    err = do_one();
                    break;
                }
                return err;
            }
        """)
        assert len(_switch_results(results)) == 1


class TestNegatives:
    def test_unconditional_init_before_switch_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(int mode)
            {
                int err;
                err = 0;
                switch (mode) {
                case 1:
                    err = do_one();
                    break;
                case 2:
                    err = do_two();
                    break;
                }
                return err;
            }
        """)
        assert _switch_results(results) == []

    def test_switch_with_default_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int ok(int mode)
            {
                int err;
                switch (mode) {
                case 1:
                    err = do_one();
                    break;
                default:
                    err = -1;
                    break;
                }
                return err;
            }
        """)
        assert _switch_results(results) == []
