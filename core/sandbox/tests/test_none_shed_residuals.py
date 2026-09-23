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

pytestmark = pytest.mark.skipif(
    sys.platform == "darwin", reason="linux lane under test",
)


def test_branded_tmpdir_survives_operator_disable(tmp_path, monkeypatch):
    from core.sandbox import context, state

    monkeypatch.setattr(state, "_cli_sandbox_profile", "none")
    monkeypatch.setattr(state, "_cli_sandbox_disabled", True)
    branded = "/tmp/raptor-session-test-shed"
    monkeypatch.setenv("TMPDIR", branded)

    res = context.run(
        ["/bin/sh", "-c", "echo TMPDIR=${TMPDIR-unset}"],
        capture_output=True, text=True, timeout=30,
    )
    assert res.returncode == 0
    # The safe-env allowlist legitimately drops TMPDIR (that IS
    # bare-subprocess-through-get_safe_env behaviour); what must not
    # happen is the anti-fingerprint overlay REINTRODUCING it as
    # TMPDIR=/tmp — the disable's one residual env mutation.
    assert "TMPDIR=/tmp\n" not in res.stdout, (
        f"disabled run carried the branded-TMPDIR overlay (got "
        f"{res.stdout!r}) — --sandbox none must not mutate the child "
        f"env beyond the safe-env allowlist"
    )


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
