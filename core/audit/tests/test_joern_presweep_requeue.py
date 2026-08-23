"""Interrupted Joern pre-sweep windows: re-queue, surface, never drop.

Receipt (openssh audit): a stuck verification query forced a server
restart while the pre-sweep window was in flight; the window's results
were silently lost — visible only as a log WARNING — and every
function downstream read as "no flows" instead of "not swept".

All tests are hermetic — no Joern process, no spatch.
"""

from __future__ import annotations

import logging
import types
from pathlib import Path

import core.audit.sweep as sweep_mod
from core.audit.joern_backend import (
    PRESWEEP_STATUS_FILENAME,
    build_joern_evidence,
    load_presweep_status,
)
from core.audit.sweep import (
    _presweep_interrupted,
    run_joern_pre_sweep,
)
from core.json import load_json
from packages.joern.models import JoernResult
from packages.joern.server import _RESTARTING_ERROR


def _flow(file: str = "src/a.c", method: str = "parse_input"):
    step = types.SimpleNamespace(file=file)
    return types.SimpleNamespace(steps=[step], source_method=method)


class _FakeServer:
    """Scripted query_script responses + recovery-probe surface."""

    def __init__(self, results, restarting=False, alive=True,
                 cpg_loaded=True):
        self._results = list(results)
        self.calls = 0
        self.restarting = restarting
        self._alive = alive
        self._cpg_loaded = cpg_loaded

    def query_script(self, *_a, **_kw):
        self.calls += 1
        return self._results.pop(0) if self._results else JoernResult(
            query="", errors=["exhausted"],
        )

    def ensure_alive(self):
        return self._alive


def _fast_recovery(monkeypatch):
    monkeypatch.setattr(sweep_mod, "_PRE_SWEEP_RECOVERY_WAIT_S", 0.2)
    monkeypatch.setattr(sweep_mod, "_PRE_SWEEP_RECOVERY_POLL_S", 0.01)


class TestInterruptionClassifier:
    def test_restart_and_transport_errors_classify_interrupted(self):
        for err in (
            _RESTARTING_ERROR,
            "server process exited",
            "query timed out after 300s",
            "timeout (async poll)",
            "cancelled",
            "connection refused: [Errno 111]",
            "connection failed: peer reset",
            "server did not respond",
            "no CPG loaded (call import_cpg first)",
        ):
            assert _presweep_interrupted([err]), err

    def test_query_failures_do_not_classify_interrupted(self):
        assert not _presweep_interrupted(["query failed: -- [E006] ..."])
        assert not _presweep_interrupted([])
        assert not _presweep_interrupted(None)


class TestRequeue:
    def test_interrupted_window_requeued_and_recovered(
        self, tmp_path: Path, monkeypatch,
    ):
        _fast_recovery(monkeypatch)
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.c").write_text("int main(void){}\n")
        srv = _FakeServer([
            JoernResult(query="", errors=[_RESTARTING_ERROR]),
            JoernResult(query="", flows=[_flow()]),
        ])
        status: dict = {}
        flows = run_joern_pre_sweep(
            tmp_path, {}, server=srv, status_out=status,
        )
        assert srv.calls == 2
        assert status["interrupted"] == 1
        assert status["requeued"] == 1
        assert status["recovered"] is True
        assert "src/a.c:parse_input" in flows

    def test_unrecovered_window_bounded_and_reported(
        self, tmp_path: Path, monkeypatch, caplog,
    ):
        _fast_recovery(monkeypatch)
        srv = _FakeServer([
            JoernResult(query="", errors=["server process exited"]),
            JoernResult(query="", errors=["server process exited"]),
            JoernResult(query="", errors=["server process exited"]),
        ])
        status: dict = {}
        with caplog.at_level(logging.WARNING, "core.audit.sweep"):
            flows = run_joern_pre_sweep(
                tmp_path, {}, server=srv, status_out=status,
            )
        assert flows == {}
        assert srv.calls == 3  # initial + 2 bounded re-queues
        assert status["requeued"] == 2
        assert status["recovered"] is False
        assert "LOST" in caplog.text

    def test_query_failure_not_requeued(self, tmp_path: Path, monkeypatch):
        _fast_recovery(monkeypatch)
        srv = _FakeServer([
            JoernResult(query="", errors=["query failed: -- [E006]"]),
        ])
        status: dict = {}
        run_joern_pre_sweep(tmp_path, {}, server=srv, status_out=status)
        assert srv.calls == 1
        assert status["interrupted"] == 0
        assert status["requeued"] == 0

    def test_requeue_abandoned_when_server_never_recovers(
        self, tmp_path: Path, monkeypatch,
    ):
        _fast_recovery(monkeypatch)
        srv = _FakeServer(
            [JoernResult(query="", errors=[_RESTARTING_ERROR])],
            restarting=True,  # never comes back
        )
        status: dict = {}
        run_joern_pre_sweep(tmp_path, {}, server=srv, status_out=status)
        assert srv.calls == 1
        assert status["interrupted"] == 1
        assert status["requeued"] == 0
        assert status["recovered"] is False

    def test_recovery_wait_feeds_progress(self, tmp_path: Path, monkeypatch):
        _fast_recovery(monkeypatch)
        srv = _FakeServer(
            [JoernResult(query="", errors=[_RESTARTING_ERROR])],
            restarting=True,
        )
        seen: list[str] = []
        run_joern_pre_sweep(
            tmp_path, {}, server=srv, on_progress=seen.append,
        )
        assert any("waiting for server recovery" in m for m in seen)


class TestStatusArtifact:
    def _tunables(self):
        return types.SimpleNamespace(
            cpg_timeout_s=600, query_timeout_s=300, heap_mb=None,
        )

    def test_interrupted_presweep_writes_run_dir_artifact(
        self, tmp_path: Path, monkeypatch,
    ):
        def fake_presweep(*_a, status_out=None, **_kw):
            status_out.update(
                interrupted=1, requeued=1, recovered=True, errors=[],
            )
            return {"src/a.c:f": [1, 2]}

        monkeypatch.setattr(
            "core.audit.sweep.run_joern_pre_sweep", fake_presweep,
        )
        monkeypatch.setattr(
            "core.audit.joern_backend.joern_tunables",
            lambda overrides=None: self._tunables(),
        )
        flows = build_joern_evidence(tmp_path, tmp_path)
        assert flows
        record = load_json(tmp_path / PRESWEEP_STATUS_FILENAME)
        assert record["interrupted"] == 1
        assert record["recovered"] is True
        assert record["flows_recovered"] == 2
        assert record["ts"]
        assert load_presweep_status(tmp_path) is not None

    def test_clean_presweep_writes_no_artifact(
        self, tmp_path: Path, monkeypatch,
    ):
        monkeypatch.setattr(
            "core.audit.sweep.run_joern_pre_sweep",
            lambda *_a, status_out=None, **_kw: {},
        )
        monkeypatch.setattr(
            "core.audit.joern_backend.joern_tunables",
            lambda overrides=None: self._tunables(),
        )
        build_joern_evidence(tmp_path, tmp_path)
        assert not (tmp_path / PRESWEEP_STATUS_FILENAME).exists()
        assert load_presweep_status(tmp_path) is None


class TestReportAndCritiqueSurfacing:
    def test_report_summary_surfaces_lost_window(self, tmp_path: Path):
        from core.json import save_json
        save_json(tmp_path / PRESWEEP_STATUS_FILENAME, {
            "interrupted": 3, "requeued": 2, "recovered": False,
            "errors": ["server process exited"],
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert report["joern_presweep"]["recovered"] is False
        assert "pre-sweep window lost" in report["summary"]

    def test_report_summary_surfaces_recovered_window(
        self, tmp_path: Path,
    ):
        from core.json import save_json
        save_json(tmp_path / PRESWEEP_STATUS_FILENAME, {
            "interrupted": 1, "requeued": 1, "recovered": True,
            "errors": [], "flows_recovered": 7,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert "re-queued and recovered" in report["summary"]

    def test_critique_warns_once_on_lost_window(
        self, tmp_path: Path, caplog,
    ):
        from core.json import save_json
        save_json(tmp_path / PRESWEEP_STATUS_FILENAME, {
            "interrupted": 1, "requeued": 2, "recovered": False,
            "errors": ["server process exited"],
        })
        from core.audit.orchestrator import _run_critique
        config = types.SimpleNamespace(
            critique_interval=10, out_dir=tmp_path,
            target_path=tmp_path, project_sinks=None,
        )
        result = types.SimpleNamespace(outcomes=[], tier_counters={})
        with caplog.at_level(logging.WARNING, "core.audit.orchestrator"):
            _run_critique(result, config)
            _run_critique(result, config)
        hits = [
            r for r in caplog.records
            if "pre-sweep window was LOST" in r.getMessage()
        ]
        assert len(hits) == 1  # once per run, not per critique tick
