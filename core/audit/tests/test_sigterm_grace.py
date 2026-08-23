"""SIGTERM grace: handler semantics (unit) + stubbed-loop drain (E2E).

Unit tests drive the handler functions directly with module state
reset around each; the E2E half SIGTERMs a child process running the
real orchestrator loop with a stub review_fn and asserts the graceful
drain: prompt exit 130, harvested in-flight completion, flushed
ledgers/journal, salvage exports on disk.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import core.audit.orchestrator as orch
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")


@pytest.fixture(autouse=True)
def _reset_term_state():
    """Never leak TERM/shutdown state into other tests."""
    yield
    orch._sigterm_event.clear()
    orch._shutdown_event.clear()
    orch._sigterm_state["count"] = 0
    orch._sigterm_flush_hooks.clear()


class TestCheckBudgetSigterm:

    def test_sigterm_rides_budget_rails(self, tmp_path):
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        result = OrchestratorResult()
        assert orch._check_budget(config, time.monotonic(), result) is False
        orch._sigterm_event.set()
        assert orch._check_budget(config, time.monotonic(), result) is True
        assert result.terminated_by == "sigterm"


class TestInstallSigtermGrace:

    def test_installs_once_main_thread(self, monkeypatch):
        calls = []
        monkeypatch.setitem(orch._sigterm_state, "installed", False)
        monkeypatch.setattr(
            "signal.signal", lambda sig, h: calls.append((sig, h)),
        )
        assert orch.install_sigterm_grace() is True
        assert calls and calls[0][0] == signal.SIGTERM
        # Second call: already installed, no re-registration.
        assert orch.install_sigterm_grace() is True
        assert len(calls) == 1

    def test_worker_thread_refuses(self, monkeypatch):
        import threading
        monkeypatch.setitem(orch._sigterm_state, "installed", False)
        results = []
        t = threading.Thread(
            target=lambda: results.append(orch.install_sigterm_grace()),
        )
        t.start()
        t.join()
        assert results == [False]

    def test_registration_failure_degrades(self, monkeypatch):
        def _boom(sig, h):
            raise ValueError("not in main thread")
        monkeypatch.setitem(orch._sigterm_state, "installed", False)
        monkeypatch.setattr("signal.signal", _boom)
        assert orch.install_sigterm_grace() is False


class TestHandlerSemantics:

    def test_first_term_requests_shutdown_and_arms_watchdog(self, monkeypatch):
        threads = []

        class _FakeThread:
            def __init__(self, **kw):
                threads.append(kw)

            def start(self):
                pass

        monkeypatch.setattr(orch._threading, "Thread", _FakeThread)
        orch._handle_sigterm(signal.SIGTERM, None)
        assert orch.is_sigterm_requested()
        assert orch.is_shutdown_requested()
        assert len(threads) == 1
        assert threads[0]["daemon"] is True

    def test_second_term_exits_immediately_after_flush(self, monkeypatch):
        exits = []
        flushed = []
        monkeypatch.setattr(orch.os, "_exit", lambda code: exits.append(code))
        monkeypatch.setattr(
            orch._threading, "Thread",
            lambda **kw: type("T", (), {"start": lambda self: None})(),
        )
        orch._sigterm_flush_hooks.append(lambda: flushed.append(True))
        orch._handle_sigterm(signal.SIGTERM, None)
        assert exits == []
        orch._handle_sigterm(signal.SIGTERM, None)
        assert exits == [130]
        assert flushed == [True]

    def test_watchdog_flushes_then_exits_130(self, monkeypatch):
        exits = []
        order = []
        monkeypatch.setattr(orch.os, "_exit", lambda code: exits.append(code))
        orch._sigterm_flush_hooks.append(lambda: order.append("flush"))
        orch._sigterm_watchdog(0.0)
        assert exits == [130]
        assert order == ["flush"]

    def test_flush_hook_failure_never_blocks_exit(self, monkeypatch):
        exits = []
        monkeypatch.setattr(orch.os, "_exit", lambda code: exits.append(code))

        def _bad_hook():
            raise RuntimeError("disk gone")

        orch._sigterm_flush_hooks.append(_bad_hook)
        orch._sigterm_watchdog(0.0)
        assert exits == [130]


# ── E2E: stubbed loop, real SIGTERM ─────────────────────────────────

_FUNC_TEMPLATE = """\
int handle_{name}(const char *input, unsigned len) {{
    char buf[{size}];
    unsigned i;
    if (!input)
        return -1;
    if (len > sizeof(buf))
        len = sizeof(buf);
    for (i = 0; i < len; i++) {{
        buf[i] = input[i];
        if (buf[i] == '\\n')
            break;
    }}
    if (i > 4 && buf[0] == 'H') {{
        memcpy(buf, input + 1, len - 1);
        return (int)i + {size};
    }}
    return (int)i;
}}
"""

_DRIVER = textwrap.dedent("""\
    import sys, time
    sys.path.insert(0, sys.argv[3])
    from pathlib import Path
    from core.audit.orchestrator import (
        OrchestratorConfig, ReviewOutcome, run_orchestrator,
    )

    def review_fn(ctx, config):
        time.sleep(0.6)   # window for the parent's SIGTERM
        return ReviewOutcome(
            file=ctx["file"], function=ctx["function"],
            status="clean", body="stub review", cost_usd=0.25,
        )

    config = OrchestratorConfig(
        target_path=Path(sys.argv[1]),
        out_dir=Path(sys.argv[2]),
        max_cost_usd=10.0,
        max_workers=1,
        prefilter=False,
        batch_sloc_threshold=0,
        sweep_validate_findings=False,
        validate=False,
        deepen_suspicious=False,
        clean_check=False,
        adversarial=False,
        enable_session_context=False,
        propagate_constraints=False,
        include_stale=False,
        on_demand_synthesis=False,
    )
    result = run_orchestrator(config, review_fn)
    print("TERMINATED_BY=" + result.terminated_by, flush=True)
    sys.exit(130 if result.terminated_by == "sigterm" else 0)
""")


@pytest.mark.slow
class TestSigtermE2E:

    def test_sigterm_drains_and_salvages(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
        body = ["#include <string.h>", ""]
        body += [_FUNC_TEMPLATE.format(name=n, size=64) for n in names]
        (target / "proto.c").write_text("\n".join(body))

        out = tmp_path / "audit-run"
        env = dict(os.environ, CLAUDECODE="1", _RAPTOR_TRUSTED="1",
                   PYTHONPATH=str(_RAPTOR_DIR))
        r = subprocess.run(
            [sys.executable, _CHECKLIST_CLI, str(target), str(out)],
            env=env, capture_output=True, text=True, check=False,
        )
        assert r.returncode == 0, f"build-checklist failed: {r.stderr}"

        driver = tmp_path / "driver.py"
        driver.write_text(_DRIVER)
        child = subprocess.Popen(
            [sys.executable, str(driver), str(target), str(out),
             str(_RAPTOR_DIR)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True,
        )

        journal = out / "review-journal.jsonl"

        def _entries() -> int:
            if not journal.is_file():
                return 0
            return sum(
                1 for line in journal.read_text().splitlines() if line
            )

        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if child.poll() is not None:
                pytest.fail("child finished before SIGTERM window")
            if _entries() >= 2:
                break
            time.sleep(0.1)
        else:
            child.kill()
            pytest.fail("no journal entries in time")

        at_term = _entries()
        term_sent = time.monotonic()
        child.send_signal(signal.SIGTERM)
        try:
            stdout, _ = child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            child.kill()
            pytest.fail("child did not drain within 60s of SIGTERM")
        drain_s = time.monotonic() - term_sent

        # Graceful conclusion: exit 130-style, prompt (well under the
        # watchdog's forced-exit bound), stop reason named.
        assert child.returncode == 130
        assert "TERMINATED_BY=sigterm" in stdout
        assert drain_s < 25, f"drain took {drain_s:.1f}s"

        # Harvest-first: the in-flight review completed and journaled;
        # dispatch stopped (not all six functions reviewed).
        final_entries = _entries()
        assert final_entries >= at_term
        assert final_entries < 6, (
            "SIGTERM must stop dispatching remaining reviews"
        )

        # Salvage artifacts: flushed audit log (collector buffer),
        # graded export, tier diagnostics, reconciled ledger.
        assert (out / ".audit-log.jsonl").is_file()
        assert (out / "findings-graded.json").is_file()
        assert (out / "tier-diagnostics.json").is_file()
        ledger = json.loads((out / "cost-breakdown.json").read_text())
        assert ledger["totals"]["cost_usd"] == pytest.approx(
            0.25 * final_entries,
        )
