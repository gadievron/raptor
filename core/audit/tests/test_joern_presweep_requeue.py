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

    def test_errored_presweep_writes_run_dir_artifact(
        self, tmp_path: Path, monkeypatch,
    ):
        # An errored query (either execution path) leaves the same
        # incomplete flow set as a lost window; without the artifact
        # the report and critique read its missing flows as "no
        # flows" instead of "not swept".
        def fake_presweep(*_a, status_out=None, **_kw):
            status_out.update(
                errors=["query failed: parse error"],
                errors_fatal=True, completed=False,
            )
            return {"src/a.c:f": [1]}

        monkeypatch.setattr(
            "core.audit.sweep.run_joern_pre_sweep", fake_presweep,
        )
        monkeypatch.setattr(
            "core.audit.joern_backend.joern_tunables",
            lambda overrides=None: self._tunables(),
        )
        build_joern_evidence(tmp_path, tmp_path)
        record = load_json(tmp_path / PRESWEEP_STATUS_FILENAME)
        assert record["errors"] == ["query failed: parse error"]
        assert record["completed"] is False
        assert record["flows_partial"] == 1
        assert not record.get("interrupted")

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

    def test_report_summary_surfaces_errored_sweep(
        self, tmp_path: Path,
    ):
        # Errored, never interrupted: the summary must state the
        # incomplete evidence WITHOUT misattributing it to a server
        # restart.
        from core.json import save_json
        save_json(tmp_path / PRESWEEP_STATUS_FILENAME, {
            "errors": ["query failed: parse error"],
            "errors_fatal": True, "completed": False,
            "flows_partial": 0,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert "pre-sweep errored" in report["summary"]
        assert "server restart" not in report["summary"]

    def test_critique_warns_on_errored_sweep(
        self, tmp_path: Path, caplog,
    ):
        from core.json import save_json
        save_json(tmp_path / PRESWEEP_STATUS_FILENAME, {
            "errors": ["query failed: parse error"],
            "errors_fatal": True, "completed": False,
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
            if "pre-sweep query ERRORED" in r.getMessage()
        ]
        assert len(hits) == 1  # once per run, not per critique tick
        assert not [
            r for r in caplog.records
            if "server restart" in r.getMessage()
        ]

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


class _TimeoutServer:
    """Every window times out at its own budget; server stays healthy."""

    restarting = False
    _cpg_loaded = True

    def __init__(self):
        self.windows: list[int] = []

    def cpg_size_bytes(self):
        return None

    def ensure_alive(self):
        return True

    def query_script(self, script, timeout=300, substitutions=None):
        self.windows.append(int(timeout))
        return JoernResult(
            query="", errors=[f"query timed out after {timeout}s"],
        )


class TestFailureHonesty:
    """A degraded sweep's status must say WHY (which ceiling bound,
    what operation died) — the before-shape was a fatal status with
    zero flows and no recorded reason at all."""

    def test_timeout_lost_window_names_the_ceiling(
        self, tmp_path: Path, monkeypatch,
    ):
        _fast_recovery(monkeypatch)
        server = _TimeoutServer()
        status: dict = {}
        flows = run_joern_pre_sweep(
            tmp_path, {}, server=server, query_timeout=300,
            status_out=status,
        )
        assert flows == {}
        assert status["completed"] is False
        # The exact before-shape gap: fatal, zero flows — now WITH a
        # machine-readable reason naming the binding ceiling.
        assert status["reason"] == "query_timeout"
        # The LAST attempt's budget is recorded (raised, never the
        # same wall re-bought: 300 -> 600 -> 1200).
        assert server.windows == [300, 600, 1200]
        assert status["query_timeout_s"] == 1200
        assert status["cpg_bytes"] is None

    def test_timeout_requeue_fails_fast_at_ceiling(
        self, tmp_path: Path, monkeypatch,
    ):
        from core.tuning import derived_max_joern_presweep_timeout_s
        cap = derived_max_joern_presweep_timeout_s(4000)
        _fast_recovery(monkeypatch)
        server = _TimeoutServer()
        status: dict = {}
        run_joern_pre_sweep(
            tmp_path, {}, server=server, query_timeout=4000,
            status_out=status,
        )
        # 4000 raises to the cap; a window that timed out AT the cap
        # has no larger budget to retry with — abandon, do not burn
        # the remaining re-queue at the same wall.
        assert server.windows == [4000, cap]
        assert status["reason"] == "query_timeout"
        assert status["query_timeout_s"] == cap

    def test_external_interruption_keeps_budget_and_class(
        self, tmp_path: Path, monkeypatch,
    ):
        # Restart-under-someone-else's-query says nothing about THIS
        # window's wall: the budget stays, and the reason stays the
        # interruption class rather than a fabricated ceiling claim.
        _fast_recovery(monkeypatch)

        class _RestartedServer(_TimeoutServer):
            def query_script(self, script, timeout=300,
                             substitutions=None):
                self.windows.append(int(timeout))
                return JoernResult(query="", errors=[_RESTARTING_ERROR])

        server = _RestartedServer()
        status: dict = {}
        run_joern_pre_sweep(
            tmp_path, {}, server=server, query_timeout=300,
            status_out=status,
        )
        assert server.windows == [300, 300, 300]
        assert status["reason"] == "window_interrupted"

    def test_plain_query_error_reason(self, tmp_path: Path, monkeypatch):
        server = _FakeServer(
            [JoernResult(query="", errors=["parse error in script"])],
        )
        status: dict = {}
        run_joern_pre_sweep(
            tmp_path, {}, server=server, query_timeout=300,
            status_out=status,
        )
        assert server.calls == 1  # not interruption class: no re-queue
        assert status["reason"] == "query_error"

    def test_clean_sweep_records_no_reason(
        self, tmp_path: Path, monkeypatch,
    ):
        server = _FakeServer([JoernResult(query="", errors=[])])
        status: dict = {}
        run_joern_pre_sweep(
            tmp_path, {}, server=server, query_timeout=300,
            status_out=status,
        )
        assert status["completed"] is True
        assert "reason" not in status
        assert status["query_timeout_s"] == 300


class TestNonServerPathBudget:
    """The subprocess path's single wall covers importCpg + the solve:
    it must scale with the built CPG's size, and a degraded end must
    carry the reason fields (the reference before-shape —
    errors_fatal beside zero flows — came from this path)."""

    def _patch_runner(self, monkeypatch, tmp_path: Path, *,
                      cpg_bytes: int, errors: list[str]):
        import packages.joern.prereqs as prereqs
        import packages.joern.runner as runner
        monkeypatch.setattr(prereqs, "is_available", lambda: True)
        p = tmp_path / "cpg.bin"
        with p.open("wb") as f:
            f.truncate(cpg_bytes)  # sparse: size without the bytes
        cpg = types.SimpleNamespace(path=p, exists=lambda: True)
        monkeypatch.setattr(
            runner, "build_cpg", lambda target, **kw: cpg,
        )
        monkeypatch.setattr(
            runner, "build_cpg_cached", lambda target, cache, **kw: cpg,
        )
        monkeypatch.setattr(runner, "cleanup_cpg", lambda c: None)
        captured: dict = {}

        def fake_run_query(c, script, timeout=300, substitutions=None):
            captured["timeout"] = timeout
            return JoernResult(query="", errors=list(errors))

        monkeypatch.setattr(runner, "run_query", fake_run_query)
        return captured

    def test_window_scales_with_cpg_size_including_import(
        self, tmp_path: Path, monkeypatch,
    ):
        captured = self._patch_runner(
            monkeypatch, tmp_path,
            cpg_bytes=190 * 1024 * 1024, errors=[],
        )
        status: dict = {}
        target = tmp_path / "src"
        target.mkdir()
        run_joern_pre_sweep(
            target, {}, query_timeout=300, status_out=status,
        )
        # The kernel-scale shape: the wall clears the flat 300 s that
        # recorded zero flows, and covers import + solve.
        assert captured["timeout"] > 1200
        assert status["query_timeout_s"] == captured["timeout"]
        assert status["cpg_bytes"] == 190 * 1024 * 1024
        assert status["completed"] is True
        assert "reason" not in status

    def test_fatal_zero_flow_status_says_why(
        self, tmp_path: Path, monkeypatch,
    ):
        # The reference before-shape: errors_fatal: true beside
        # flows_partial: 0 with no recorded reason. After the change
        # the same end names the ceiling that bound.
        self._patch_runner(
            monkeypatch, tmp_path, cpg_bytes=1,
            errors=["query timed out after 300s"],
        )
        status: dict = {}
        target = tmp_path / "src"
        target.mkdir()
        flows = run_joern_pre_sweep(
            target, {}, query_timeout=300, status_out=status,
        )
        assert flows == {}
        assert status["errors_fatal"] is True
        assert status["completed"] is False
        assert status["reason"] == "query_timeout"
        assert status["query_timeout_s"] == 300  # tiny CPG: floor
        assert status["cpg_bytes"] == 1


class TestReasonSurfacing:
    """Commit-6 surface: the recorded reason must reach the report
    renderer and the critique warning — and records WITHOUT the
    additive fields (pre-change runs) must render the original
    wording (the sparse-record grace requirement; pinned above by
    TestReportAndCritiqueSurfacing)."""

    def test_report_errored_names_ceiling_and_remedy(
        self, tmp_path: Path,
    ):
        from core.json import save_json
        save_json(tmp_path / PRESWEEP_STATUS_FILENAME, {
            "errors": ["query timed out after 1200s"],
            "errors_fatal": True, "completed": False,
            "flows_partial": 0, "reason": "query_timeout",
            "query_timeout_s": 1200, "cpg_bytes": 1,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert "pre-sweep errored" in report["summary"]
        assert "timed out after 1200s" in report["summary"]
        assert "joern_query_timeout_s" in report["summary"]
        assert "server restart" not in report["summary"]

    def test_report_lost_window_names_ceiling_on_timeout_reason(
        self, tmp_path: Path,
    ):
        from core.json import save_json
        save_json(tmp_path / PRESWEEP_STATUS_FILENAME, {
            "interrupted": 3, "requeued": 2, "recovered": False,
            "errors": ["query timed out after 1200s"],
            "reason": "query_timeout", "query_timeout_s": 1200,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert "pre-sweep window lost" in report["summary"]
        assert "(1200s)" in report["summary"]
        assert "joern_query_timeout_s" in report["summary"]
        # The timeout reason must not be misattributed to a restart.
        assert "server restart" not in report["summary"]

    def test_critique_warning_carries_reason(
        self, tmp_path: Path, caplog,
    ):
        from core.json import save_json
        save_json(tmp_path / PRESWEEP_STATUS_FILENAME, {
            "errors": ["query timed out after 1200s"],
            "errors_fatal": True, "completed": False,
            "reason": "query_timeout", "query_timeout_s": 1200,
        })
        from core.audit.orchestrator import _run_critique
        config = types.SimpleNamespace(
            critique_interval=10, out_dir=tmp_path,
            target_path=tmp_path, project_sinks=None,
        )
        result = types.SimpleNamespace(outcomes=[], tier_counters={})
        with caplog.at_level(logging.WARNING, "core.audit.orchestrator"):
            _run_critique(result, config)
        hits = [
            r for r in caplog.records
            if "pre-sweep query ERRORED" in r.getMessage()
        ]
        assert len(hits) == 1
        assert "[reason: query_timeout, window 1200s]" in hits[0].getMessage()


class TestJoernWallComposition:
    """Every joern_timeout_s producer composes through
    _compose_joern_wall_s — the wall must cover the widest window the
    pre-sweep is allowed to run (derived cap incl. import slope), and
    an operator query-timeout override above the cap must widen it
    further (never narrower than cpg + query, in either direction)."""

    def test_wall_covers_derived_presweep_maximum(self):
        from core.audit.orchestrator import _compose_joern_wall_s
        from core.tuning import derived_max_joern_presweep_timeout_s
        wall = _compose_joern_wall_s(1800, 300)
        assert wall == 1800 + derived_max_joern_presweep_timeout_s(
            300, include_import=True,
        )
        # Direction 1: never the pre-change bare sum — that wall
        # cancelled legitimate kernel-scale windows as "stalled".
        assert wall > 1800 + 300

    def test_operator_override_above_cap_still_widens(self):
        from core.audit.orchestrator import _compose_joern_wall_s
        # Direction 2: a query timeout above the derived cap passes
        # through — the wall never clamps below cpg + query.
        assert _compose_joern_wall_s(1800, 90_000) == 1800 + 90_000
