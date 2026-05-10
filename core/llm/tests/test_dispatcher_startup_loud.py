"""Pin that ``raptor._get_or_start_dispatcher`` surfaces failures
loudly on stderr — Phase C activation step 1.

The dispatcher's startup failure used to be a silent
``logger.warning`` that operators would only see if they had
log-level configured. Today (post-step-1) it also writes a
single-line message to stderr at the moment of failure, so
operators see the failure regardless of log config.

Why this matters: once Phase C activation strips API keys from
``RaptorConfig.get_llm_env``, the env-direct fallback that
``_get_or_start_dispatcher → None`` falls through to will
produce workers WITHOUT auth. The symptom shifts from "dispatcher
silently absent, env-direct works fine" to "dispatcher silently
absent, worker fails 30 seconds later on its first LLM call".
Step 1 makes the underlying root cause visible at the moment it
happens.
"""

from __future__ import annotations

import importlib
import io
import os
import sys
from contextlib import redirect_stderr
from unittest import mock

import pytest


# Wire RAPTOR onto sys.path the same way other test modules do.
_RAPTOR_DIR = os.environ["RAPTOR_DIR"]
if _RAPTOR_DIR not in sys.path:
    sys.path.insert(0, _RAPTOR_DIR)


@pytest.fixture
def fresh_raptor_module():
    """Re-import ``raptor`` so the module-level ``_active_dispatcher``
    is None at the start of each test (the prod module is imported
    at most once per process; tests that share the import would
    leak state)."""
    # Clear the cached module if any earlier test imported it.
    sys.modules.pop("raptor", None)
    raptor = importlib.import_module("raptor")
    yield raptor
    # Reset for cleanliness — clear the module-level cache.
    raptor._active_dispatcher = None
    sys.modules.pop("raptor", None)


def test_dispatcher_startup_failure_writes_loud_stderr_line(
    fresh_raptor_module,
):
    """When ``LLMDispatcher`` raises during startup,
    ``_get_or_start_dispatcher`` must emit a clear single-line
    message on stderr. Future Phase C activation depends on this
    failure being visible at the moment it happens, not 30s later
    when a worker dies."""
    raptor = fresh_raptor_module

    err = io.StringIO()
    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        side_effect=RuntimeError("simulated dispatcher crash"),
    ), redirect_stderr(err):
        result = raptor._get_or_start_dispatcher()

    assert result is None, "fallback path: function returns None"
    captured = err.getvalue()
    assert "credential-isolation dispatcher failed to start" in captured, (
        f"expected loud failure message on stderr, got: {captured!r}"
    )
    assert "RuntimeError" in captured
    assert "simulated dispatcher crash" in captured
    # Phase C migration hint must be present so operators understand
    # the consequence of ignoring the failure.
    assert "Phase C" in captured


def test_dispatcher_startup_success_is_quiet(fresh_raptor_module):
    """Success path emits nothing on stderr — the loud message is
    failure-only, not always-on."""
    raptor = fresh_raptor_module

    fake_dispatcher = mock.Mock()
    err = io.StringIO()
    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        return_value=fake_dispatcher,
    ), redirect_stderr(err):
        result = raptor._get_or_start_dispatcher()

    assert result is fake_dispatcher
    assert err.getvalue() == "", (
        f"success path leaked stderr output: {err.getvalue()!r}"
    )


def test_loud_message_includes_phase_c_migration_hint(
    fresh_raptor_module,
):
    """The stderr message must explain WHY this matters now (the
    pre-Phase-C "no worse than today" guarantee) so operators
    don't dismiss it as cosmetic. Pin specific phrasing so a future
    well-meaning edit doesn't drop the migration hint."""
    raptor = fresh_raptor_module

    err = io.StringIO()
    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        side_effect=ImportError("dispatcher module missing"),
    ), redirect_stderr(err):
        raptor._get_or_start_dispatcher()

    captured = err.getvalue()
    # The message must specifically warn that workers will lose
    # LLM auth post-activation — not just a generic "fallback"
    # phrasing that operators could ignore.
    assert "auth" in captured.lower(), (
        f"loud message lacks auth-implication hint: {captured!r}"
    )


def test_dispatcher_failure_is_idempotent_within_one_process(
    fresh_raptor_module,
):
    """Once the dispatcher fails, subsequent calls also fall through
    to None. Pin this so a future "retry on demand" change doesn't
    silently start succeeding mid-process and confuse the
    workflow."""
    raptor = fresh_raptor_module

    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        side_effect=RuntimeError("first attempt"),
    ):
        first = raptor._get_or_start_dispatcher()
    # A subsequent call should also hit the failure path (state
    # isn't cached as "tried-and-failed", which is by design — the
    # global ``_active_dispatcher`` is the cache, and it stays None).
    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        side_effect=RuntimeError("second attempt"),
    ):
        second = raptor._get_or_start_dispatcher()

    assert first is None
    assert second is None
