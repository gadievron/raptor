"""Regression integration test — subprocesses core/zkpox/test/run-tests.sh.

This wraps the shell harness so CI gets a single `pytest` entry point
covering all targets × all witnesses × execute mode. Prove mode is too
slow for unit runs; CI workflows in Phase 1.8 will gate it on a slower
job tier.

Gated on the Rust binary existing — if `zkpox-prove` hasn't been built
locally the test skips with a clear message rather than masquerading
as a real failure.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
ZKPOX_TEST_DIR = REPO_ROOT / "core" / "zkpox" / "test"
PROVE_BIN = REPO_ROOT / "core" / "zkpox" / "target" / "release" / "zkpox-prove"


@pytest.mark.skipif(
    os.environ.get("RAPTOR_SLOW_TESTS") != "1",
    reason=(
        "slow integration test (~10 min, SP1 SDK spin-up × 25 witnesses); "
        "set RAPTOR_SLOW_TESTS=1 to run"
    ),
)
@pytest.mark.skipif(
    not PROVE_BIN.exists(),
    reason=(
        f"zkpox-prove not built (expected at {PROVE_BIN}). Build with: "
        "cargo build --release --manifest-path core/zkpox/Cargo.toml"
    ),
)
def test_regression_full_corpus():
    """Run the witness corpus through the prover in execute mode and
    assert every assertion in run-tests.sh passes (exit 0)."""
    result = subprocess.run(
        ["bash", "run-tests.sh"],
        cwd=ZKPOX_TEST_DIR,
        capture_output=True,
        text=True,
        timeout=600,
        env={**os.environ, "TERM": "dumb"},  # no ANSI in output
    )
    assert result.returncode == 0, (
        f"run-tests.sh exited {result.returncode}\n"
        f"stdout (tail):\n{_tail(result.stdout, 40)}\n"
        f"stderr (tail):\n{_tail(result.stderr, 20)}"
    )

    # Cheap structural sanity: all target families must appear and
    # each must report PASSes. Otherwise we may have silently regressed
    # to a single-target run.
    assert " t=1 " in result.stdout, "no target-01 verdicts in output"
    assert " t=2 " in result.stdout, "no target-02 verdicts in output"
    assert " t=3 " in result.stdout, "no target-03 verdicts in output"

    # And the summary line must report ≥ 40 passes (current corpus
    # size; tightens automatically if the corpus grows).
    pass_line = next(
        (l for l in result.stdout.splitlines() if l.startswith("passed:")),
        "",
    )
    assert pass_line, f"no `passed:` summary line: {result.stdout[-400:]!r}"
    n = int(pass_line.split(":", 1)[1].strip())
    assert n >= 40, f"only {n} passes (expected ≥40 for current corpus)"


def _tail(text: str, n: int) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n:])
