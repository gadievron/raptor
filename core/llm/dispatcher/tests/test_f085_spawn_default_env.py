"""Regression test for F085.

`spawn_worker` accepts `env: Optional[Mapping[str, str]] = None`. When
the caller passes `env=None` (either explicitly or by not passing it),
the previous behaviour was:

    base_env = dict(env) if env is not None else {}

i.e. the child got an environment of literally `{}` — no PATH, no
HOME, no LANG, no anything except the two RAPTOR_LLM_* vars added a
few lines below. Most child binaries fail catastrophically without
PATH (`exec` can't locate the binary if it's a wrapper that re-execs),
HOME (process-local config-file resolution explodes), or LANG (Python
text-mode I/O can pick weird encodings).

The fix mirrors `core/sandbox/context.py:890-906` exactly — when env
is None, default to `RaptorConfig.get_safe_env()` (so credentials are
stripped but baseline shell env is preserved).

This test asserts that calling `spawn_worker(..., env=None)` results
in the subprocess receiving a non-empty env containing at least PATH.
We mock the dispatcher and subprocess.Popen so we can introspect what
env was passed to Popen.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def fake_dispatcher():
    d = MagicMock()
    d.allocate_worker.return_value = ("/tmp/fake.sock", 99)
    return d


def test_spawn_worker_env_none_defaults_to_safe_env(fake_dispatcher):
    """When env=None, Popen must receive a non-empty environment that
    inherits PATH (and other baseline shell vars) via
    `RaptorConfig.get_safe_env()`. Mirrors the sandbox context.py
    treatment of env=None.
    """
    from core.llm.dispatcher import spawn as spawn_mod

    captured_env: dict[str, str] = {}

    class FakePopen:
        def __init__(self, *args, **kwargs):
            captured_env.update(kwargs.get("env") or {})

    with patch.object(spawn_mod.subprocess, "Popen", FakePopen), \
            patch("os.close"):
        spawn_mod.spawn_worker(
            fake_dispatcher,
            ["/bin/true"],
            label="test-worker",
            env=None,  # the bug path
        )

    # The RAPTOR_LLM_* vars are always set by spawn_worker. The bug:
    # env=None used to make base_env={} so PATH/HOME/etc were missing.
    # The fix: env=None should fall back to RaptorConfig.get_safe_env()
    # which always contains PATH (it's in SAFE_ENV_VARS).
    assert "PATH" in captured_env, (
        "spawn_worker(env=None) failed to inherit PATH via "
        f"RaptorConfig.get_safe_env(). Captured env keys: "
        f"{sorted(captured_env.keys())}"
    )
    # And the dispatcher vars must still be set.
    assert captured_env.get("RAPTOR_LLM_SOCKET") == "/tmp/fake.sock"
    assert captured_env.get("RAPTOR_LLM_TOKEN_FD") == "99"
