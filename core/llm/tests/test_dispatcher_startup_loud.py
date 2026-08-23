"""Pin that ``raptor._get_or_start_dispatcher`` surfaces failures
loudly on stderr.

The dispatcher's startup failure used to be a silent
``logger.warning`` that operators would only see if they had
log-level configured. Now it also writes a single-line message to
stderr at the moment of failure, so operators see the failure
regardless of log config.
"""

from __future__ import annotations

import importlib
import io
import sys
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

import pytest


# parents[3] climbs:
#   [0] core/llm/tests/  (this file's directory)
#   [1] core/llm/
#   [2] core/
#   [3] <repo root>
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


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
    assert "env-direct" in captured


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


def test_loud_message_includes_fallback_hint(
    fresh_raptor_module,
):
    """The stderr message must explain the consequence so operators
    don't dismiss it as cosmetic."""
    raptor = fresh_raptor_module

    err = io.StringIO()
    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        side_effect=ImportError("dispatcher module missing"),
    ), redirect_stderr(err):
        raptor._get_or_start_dispatcher()

    captured = err.getvalue()
    assert "credential-isolation" in captured.lower(), (
        f"loud message lacks credential-isolation hint: {captured!r}"
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
