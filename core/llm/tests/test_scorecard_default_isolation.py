"""Test-session isolation of the shared per-model reliability ledger.

The scorecard sidecar is operator telemetry: real runs grade real
models, and the cells steer routing and merge weights. Two seams keep
test-fabricated cells (test models, synthetic decision classes) out of
the real ledger:

* the root conftest points ``RAPTOR_SCORECARD_PATH`` at a
  session-scoped scratch file, so ANY flush that reaches the default
  resolver during a test session — including one from a suite whose
  own isolation fixture is missing or not yet written — lands in
  scratch, never in ``<RAPTOR_DIR>/out/llm_scorecard.json``;
* ``get_safe_env()`` propagates the override across the subprocess
  boundary, so a child that flushes does not silently re-resolve the
  default ledger and drop the isolation (the same silent-loss class
  as ``RAPTOR_OUT_DIR``), while target-bound envs still strip it.

This suite deliberately has no scorecard-path fixture of its own —
it observes exactly what an unfixtured test would.
"""

from __future__ import annotations

import os
from pathlib import Path


def test_test_sessions_never_resolve_the_production_ledger() -> None:
    override = os.environ.get("RAPTOR_SCORECARD_PATH")
    assert override, (
        "root conftest must pin RAPTOR_SCORECARD_PATH for the whole "
        "test session"
    )
    from core.llm.scorecard.paths import default_scorecard_path

    assert default_scorecard_path() == Path(override)


def test_safe_env_propagates_the_ledger_override(monkeypatch) -> None:
    from core.config import RaptorConfig

    monkeypatch.setenv(
        "RAPTOR_SCORECARD_PATH", "/somewhere/llm_scorecard.json",
    )
    env = RaptorConfig.get_safe_env()
    assert env.get("RAPTOR_SCORECARD_PATH") == "/somewhere/llm_scorecard.json"


def test_target_bound_envs_strip_the_ledger_path() -> None:
    # A ledger path in an executed target's env is a framework
    # fingerprint; the table-driven strip harness enforces the actual
    # stripping, this pins the membership.
    from core.config import RaptorConfig

    assert "RAPTOR_SCORECARD_PATH" in RaptorConfig.TARGET_ENV_STRIP_SET
