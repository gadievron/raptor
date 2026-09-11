"""Per-directory test infra.

Journal appends stamp rows with an HMAC key under
``$XDG_DATA_HOME/raptor/journal-mac.key`` (``core.coverage.journal_mac``;
the witness/iris/scorecard integrity layers keep sibling keys in the
same directory). Point XDG_DATA_HOME at a per-test tmp dir so the
suite never touches (or depends on) the developer's real key files,
and every test starts from a fresh-key state. Same pattern as
``core/llm/scorecard/tests/conftest.py``. Tests that need a specific
key state set XDG_DATA_HOME themselves inside the test body, which
runs after this autouse fixture and wins.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_mac_keys(tmp_path_factory, monkeypatch):
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")),
    )


@pytest.fixture(autouse=True)
def _reset_llm_egress_state(monkeypatch):
    """Audit tests construct real LLMClients (llm_review, synthesis,
    budget suites), whose enable_llm_egress side effect swaps the
    HTTPS_PROXY family to a loopback in-process proxy. Without this
    reset the dead pointer outlives the suite and later packages in
    the same session (observed: core/sandbox proxy tests tunnelling
    via a long-gone 127.0.0.1 upstream). Same shared body the
    core/llm and core/dataflow conftests wrap."""
    from core.testing import reset_llm_egress_state

    yield from reset_llm_egress_state(monkeypatch)


@pytest.fixture(autouse=True)
def _hermetic_sigterm_disposition():
    """The orchestrator installs a process-wide SIGTERM salvage
    handler (install_sigterm_grace, reached by any test that runs the
    orchestrator in-process) and the CLI never uninstalls it. Leaked
    past the test it poisons every LATER test in the same worker
    process: fork children inherit the disposition, so SIGTERM starts
    a salvage drain in the child instead of killing it — observed as
    pool-teardown tests SIGKILLing provably responsive workers after
    their full grace. Restore the disposition (production
    uninstall first, belt-and-braces direct restore second) around
    every audit test."""
    import signal

    try:
        prev = signal.getsignal(signal.SIGTERM)
    except (ValueError, OSError):  # non-main thread / exotic platform
        yield
        return
    yield
    from core.audit import orchestrator as _orch

    _orch.uninstall_sigterm_grace()
    try:
        if (prev is not None
                and signal.getsignal(signal.SIGTERM) is not prev):
            # prev None = C-installed prior handler (getsignal cannot
            # represent it and signal.signal cannot re-install it) —
            # leave whatever is current rather than raise TypeError.
            signal.signal(signal.SIGTERM, prev)
    except (TypeError, ValueError, OSError):
        pass
