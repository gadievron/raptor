"""cve_env test utilities.

SDK-dependent tests must gate with ``pytest.importorskip("claude_agent_sdk")``
at module level or per-function. See test_sdk_retry.py for the pattern.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _output_root_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect ``cve_env.config.OUTPUT_ROOT`` into the test's tmp dir.

    OUTPUT_ROOT defaults to ``REPO_ROOT/output`` when ``CVE_ENV_OUTPUT_ROOT``
    is unset, and ``refusals.default_log_path()`` re-reads the module
    attribute at call time — so any test that drives ``build()`` through a
    refusal path appends ``refusals-log.md`` into the checkout. Point the
    root at ``tmp_path`` so the source tree stays byte-clean no matter which
    code paths a test exercises.
    """
    from cve_env import config

    monkeypatch.setattr(config, "OUTPUT_ROOT", tmp_path / "cve-env-output")
