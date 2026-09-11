"""Sweep-runner compatibility flags on the SMT check shims.

The sweep runner forwards ``--source`` / ``--function`` context keys
generically to every SMT verb dispatch; each shim must accept (and
ignore) them rather than argparse-exit with "unrecognized arguments".
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

_CASES = [
    ("raptor-smt-check-oob", ["--buffer-size", "size", "--index", "idx"]),
    ("raptor-smt-check-overflow",
     ["--op", "+", "--operand", "a", "--operand", "b"]),
    ("raptor-smt-check-null-deref", ["--ptr", "p"]),
    ("raptor-smt-check-negative-bypass", ["--value", "v", "--limit", "10"]),
]


def _run(script: str, args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "libexec" / script), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


class TestCompatFlags:
    @pytest.mark.parametrize(("script", "args"), _CASES)
    def test_source_function_accepted(self, script: str, args: list[str]):
        res = _run(
            script, [*args, "--source", "src/x.c", "--function", "f"],
        )
        assert res.returncode == 0, res.stderr
        # Result JSON still lands on stdout (feasible may be null
        # when z3 is absent — that is still a successful invocation).
        assert '"feasible"' in res.stdout

    @pytest.mark.parametrize(("script", "args"), _CASES)
    def test_plain_invocation_still_works(self, script: str,
                                          args: list[str]):
        res = _run(script, args)
        assert res.returncode == 0, res.stderr
        assert '"feasible"' in res.stdout

    @pytest.mark.parametrize(("script", "args"), _CASES)
    def test_truly_unknown_flag_still_rejected(self, script: str,
                                               args: list[str]):
        res = _run(script, [*args, "--bogus-flag", "x"])
        assert res.returncode == 2
