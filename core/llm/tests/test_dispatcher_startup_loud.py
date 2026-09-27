"""Pin that ``raptor._get_or_start_dispatcher`` surfaces failures.

The dispatcher's startup failure used to be a silent
``logger.warning`` that operators would only see if they had
log-level configured. The failure now feeds the env-direct downgrade
announcement: ``_get_or_start_dispatcher`` records WHY it failed in
``raptor._dispatcher_failure_reason``, and the single prominent
operator-facing banner (naming the credential-isolation downgrade +
that reason) prints at the fallback site in ``_run_script`` — pinned
in ``core/run/tests/test_env_direct_downgrade_banner.py``.
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
    and ``_dispatcher_failure_reason`` are None at the start of each
    test (the prod module is imported at most once per process; tests
    that share the import would leak state)."""
    # Clear the cached module if any earlier test imported it.
    sys.modules.pop("raptor", None)
    raptor = importlib.import_module("raptor")
    yield raptor
    # Reset for cleanliness — clear the module-level cache.
    raptor._active_dispatcher = None
    raptor._dispatcher_failure_reason = None
    sys.modules.pop("raptor", None)


def test_dispatcher_startup_failure_records_the_reason(
    fresh_raptor_module,
):
    """When ``LLMDispatcher`` raises during startup,
    ``_get_or_start_dispatcher`` must return None AND record the
    failure shape in ``_dispatcher_failure_reason`` — that string is
    what the downgrade banner and the run's credential-posture.json
    surface to the operator."""
    raptor = fresh_raptor_module

    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        side_effect=RuntimeError("simulated dispatcher crash"),
    ):
        result = raptor._get_or_start_dispatcher()

    assert result is None, "fallback path: function returns None"
    reason = raptor._dispatcher_failure_reason
    assert reason is not None
    assert "RuntimeError" in reason
    assert "simulated dispatcher crash" in reason


def test_dispatcher_startup_success_is_quiet(fresh_raptor_module):
    """Success path emits nothing on stderr and records no failure
    reason — the downgrade machinery is failure-only, not always-on."""
    raptor = fresh_raptor_module

    fake_dispatcher = mock.Mock()
    err = io.StringIO()
    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        return_value=fake_dispatcher,
    ), redirect_stderr(err):
        result = raptor._get_or_start_dispatcher()

    assert result is fake_dispatcher
    assert raptor._dispatcher_failure_reason is None
    assert err.getvalue() == "", (
        f"success path leaked stderr output: {err.getvalue()!r}"
    )


def test_failure_reason_feeds_the_downgrade_banner(
    fresh_raptor_module, capsys,
):
    """The recorded reason must reach the operator through the
    prominent downgrade banner — the consequence (raw keys in the
    child env) is explained so operators don't dismiss it as
    cosmetic."""
    raptor = fresh_raptor_module

    with mock.patch(
        "core.llm.dispatcher.server.LLMDispatcher",
        side_effect=ImportError("dispatcher module missing"),
    ):
        raptor._get_or_start_dispatcher()
    raptor._announce_env_direct_downgrade("scanner.py", None)

    captured = capsys.readouterr().err
    assert "CREDENTIAL-ISOLATION DOWNGRADE" in captured
    assert "dispatcher module missing" in captured


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
