"""--sandbox none residuals: the disable must shed the branded-TMPDIR
overlay, and the profile's discard warning must name tool_paths.

The operator-disable contract is "rlimits only": a disabled run's
child is a bare subprocess a bisecting operator compares against
exactly that. The branded-TMPDIR anti-fingerprint rewrite survived
the disable as the run's one residual env mutation (child saw
TMPDIR=/tmp while the parent carried the branded session dir).
"""

from __future__ import annotations

import sys

import pytest

from core.sandbox.tests.capability import requires_network_block_backend

pytestmark = pytest.mark.skipif(
    sys.platform == "darwin", reason="linux lane under test",
)


@pytest.mark.parametrize("session_scratch", [False, True])
def test_operator_disable_preserves_trusted_safe_env_tmpdir(tmp_path, monkeypatch, session_scratch):
    from core.config import RaptorConfig
    from core.sandbox import context, state
    from core.security import env_sanitisation

    monkeypatch.setattr(state, "_cli_sandbox_profile", "none")
    monkeypatch.setattr(state, "_cli_sandbox_disabled", True)
    selected = str(tmp_path / "raptor-session-test-shed") if session_scratch else "/tmp"
    if session_scratch:
        (tmp_path / "raptor-session-test-shed").mkdir()
    monkeypatch.setattr(env_sanitisation, "_subprocess_tmpdir", selected)
    monkeypatch.setenv("TMPDIR", "/tmp/raptor-session-injected-later")
    baseline = RaptorConfig.get_safe_env()
    assert baseline["TMPDIR"] == selected

    res = context.run(
        ["/bin/sh", "-c", "echo TMPDIR=${TMPDIR-unset}"],
        capture_output=True, text=True, timeout=30,
    )
    assert res.returncode == 0
    # Disabled execution must preserve the trusted safe-env value, including
    # a legitimate /tmp default. A branded session value must not be rewritten
    # by the anti-fingerprint overlay, nor replaced by the later ambient value.
    assert res.stdout == f"TMPDIR={baseline['TMPDIR']}\n", res.stderr


@requires_network_block_backend
def test_discard_warning_names_tool_paths(tmp_path, caplog):
    import logging

    from core.sandbox import context

    with caplog.at_level(logging.WARNING):
        res = context.run(
            ["/bin/true"],
            profile="network-only",
            target=str(tmp_path),
            tool_paths=[str(tmp_path)],
            capture_output=True, text=True, timeout=30,
        )
    assert res.returncode == 0
    warn = [r.message for r in caplog.records
            if "ignores" in str(r.message)]
    assert warn and "tool_paths" in str(warn[0]), warn
