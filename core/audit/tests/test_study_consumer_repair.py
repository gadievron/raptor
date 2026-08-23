"""Study-consumer repair: call-class-sized prep timeout, no
retry-from-scratch, loud degradation, low-priority throttle slot."""

from __future__ import annotations

import subprocess
import time
import types
from contextlib import contextmanager

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    StudyQueue,
    StudyRequest,
    _LockedOutcomes,
    _study_consumer_loop,
    _study_prep_timeout_s,
)


class TestStudyPrepTimeout:
    def _mock_primary(self, monkeypatch, timeout):
        mc = types.SimpleNamespace(timeout=timeout)
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: mc,
        )

    def test_covers_primary_model_call_timeout(self, monkeypatch):
        self._mock_primary(monkeypatch, 600)
        assert _study_prep_timeout_s() == 900

    def test_larger_model_timeout_raises_ceiling(self, monkeypatch):
        self._mock_primary(monkeypatch, 1200)
        assert _study_prep_timeout_s() == 1500

    def test_tiny_model_timeout_floored(self, monkeypatch):
        self._mock_primary(monkeypatch, 30)
        assert _study_prep_timeout_s() == 120 + 300

    def test_no_primary_model_uses_cc_default(self, monkeypatch):
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: None,
        )
        assert _study_prep_timeout_s() == 900

    def test_config_probe_failure_tolerated(self, monkeypatch):
        def _boom(prefer=None):
            raise RuntimeError("config exploded")

        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model", _boom,
        )
        assert _study_prep_timeout_s() == 900

    def test_never_the_old_120s(self, monkeypatch):
        self._mock_primary(monkeypatch, None)
        assert _study_prep_timeout_s() > 120

    @staticmethod
    def _checklist(total_lines, *, per_fn=500):
        items = []
        line = 1
        remaining = total_lines
        while remaining > 0:
            span = min(per_fn, remaining)
            items.append(
                {"name": f"f{line}", "line_start": line,
                 "line_end": line + span - 1},
            )
            line += span
            remaining -= span
        return {"files": [{"path": "big.c", "items": items}]}

    def test_cap_scales_with_target_size(self, monkeypatch):
        # A size-blind 900s cap timed out on a large target and
        # disabled domain models for the whole run. 100 KLoC at
        # 3 s/KLoC buys 300 extra seconds.
        self._mock_primary(monkeypatch, 600)
        checklist = self._checklist(100_000)
        assert _study_prep_timeout_s(checklist) == 900 + 300

    def test_scaling_is_bounded(self, monkeypatch):
        # A monorepo can't stretch the cap indefinitely.
        self._mock_primary(monkeypatch, 600)
        checklist = self._checklist(1_000_000)   # would be +3000s raw
        assert _study_prep_timeout_s(checklist) == 900 + 900

    def test_small_target_keeps_base_cap(self, monkeypatch):
        self._mock_primary(monkeypatch, 600)
        checklist = self._checklist(200)   # 0.2 KLoC → +0s
        assert _study_prep_timeout_s(checklist) == 900

    def test_unusable_checklist_falls_back(self, monkeypatch):
        self._mock_primary(monkeypatch, 600)
        assert _study_prep_timeout_s(None) == 900
        assert _study_prep_timeout_s({}) == 900
        assert _study_prep_timeout_s(
            {"files": [{"items": [{"line_start": None, "line_end": "x"}]}]},
        ) == 900


def _capture_warnings(monkeypatch):
    """Capture rendered logger.warning lines from the orchestrator."""
    import core.audit.orchestrator as _orch

    lines = []

    def _sink(msg, *args, **kwargs):
        try:
            lines.append(str(msg) % args if args else str(msg))
        except (TypeError, ValueError):
            lines.append(str(msg))

    monkeypatch.setattr(_orch.logger, "warning", _sink)
    return lines


def _queue_with_batches(n_items: int) -> StudyQueue:
    q = StudyQueue()
    for i in range(n_items):
        q.enqueue(StudyRequest(
            question=f"what is concept{i}?",
            source_file="a.c",
            source_function=f"fn{i}",
        ))
    q.signal_producer_done()
    return q


def _run_loop(config, queue, throttle=None):
    shared = types.SimpleNamespace(domain_model=None)
    _study_consumer_loop(
        queue, config, shared, lambda ctx, cfg: None,
        _LockedOutcomes(), OrchestratorResult(),
        checklist={"files": []},
        context_map=None,
        evidence_index={},
        sarif_cache=None,
        entry_points=set(),
        start_time=time.monotonic(),
        on_progress=None,
        throttle=throttle,
    )


class TestPrepFailureDisablesLoudly:
    """Prep runs AT MOST once; failure disables the subsystem with one
    operator-visible line and stops the consumer instead of retrying
    the whole prep from scratch on every subsequent batch."""

    def _config(self, tmp_path):
        return OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)

    def test_timeout_disables_once_and_stops(self, monkeypatch, tmp_path):
        import core.audit.orchestrator as _orch

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

        monkeypatch.setattr(_orch, "_run_study_prep", fake_run)
        warnings = _capture_warnings(monkeypatch)

        # 20 items → 2 batches of 15/5: pre-fix the second batch
        # would re-run prep from scratch.
        _run_loop(self._config(tmp_path), _queue_with_batches(20))

        assert len(calls) == 1, (
            f"prep must run at most once, ran {len(calls)} times"
        )
        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1, (
            f"expected exactly one loud disable line, got: {warnings}"
        )
        assert "timed out" in disabled[0]

    def test_nonzero_exit_disables_once_and_stops(
        self, monkeypatch, tmp_path,
    ):
        import core.audit.orchestrator as _orch

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return types.SimpleNamespace(returncode=1, stderr="boom")

        monkeypatch.setattr(_orch, "_run_study_prep", fake_run)
        warnings = _capture_warnings(monkeypatch)

        _run_loop(self._config(tmp_path), _queue_with_batches(20))

        assert len(calls) == 1
        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1
        assert "exit 1" in disabled[0]

    def test_missing_study_list_disables_once(self, monkeypatch, tmp_path):
        import core.audit.orchestrator as _orch

        def fake_run(cmd, **kwargs):
            return types.SimpleNamespace(returncode=0, stderr="")

        monkeypatch.setattr(_orch, "_run_study_prep", fake_run)
        warnings = _capture_warnings(monkeypatch)

        _run_loop(self._config(tmp_path), _queue_with_batches(20))

        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1
        assert "no study-list.json" in disabled[0]

    def test_timeout_warning_surfaces_size_and_budget(
        self, monkeypatch, tmp_path,
    ):
        # The size-scaled cap is used for the subprocess AND the
        # disable warning states what the cap was sized for plus the
        # remaining-vs-needed picture against the run's time budget.
        import core.audit.orchestrator as _orch

        seen = {}

        def fake_run(cmd, **kwargs):
            seen["timeout"] = kwargs.get("timeout")
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

        monkeypatch.setattr(_orch, "_run_study_prep", fake_run)
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: types.SimpleNamespace(timeout=600),
        )
        warnings = _capture_warnings(monkeypatch)

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path, max_seconds=3600,
        )
        checklist = {"files": [{"path": "big.c", "items": [
            {"name": "f", "line_start": 1, "line_end": 100_000},
        ]}]}
        shared = types.SimpleNamespace(domain_model=None)
        _study_consumer_loop(
            _queue_with_batches(2), config, shared,
            lambda ctx, cfg: None,
            _LockedOutcomes(), OrchestratorResult(),
            checklist=checklist,
            context_map=None,
            evidence_index={},
            sarif_cache=None,
            entry_points=set(),
            start_time=time.monotonic(),
            on_progress=None,
        )

        assert seen["timeout"] == 1200   # 900 base + 100 KLoC × 3 s
        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1
        assert "timed out after 1200s" in disabled[0]
        assert "~100 KLoC" in disabled[0]
        assert "needed >1200s" in disabled[0]
        assert "left of the run's 3600s budget" in disabled[0]

    def test_prep_uses_call_class_timeout(self, monkeypatch, tmp_path):
        import core.audit.orchestrator as _orch

        seen = {}

        def fake_run(cmd, **kwargs):
            seen["timeout"] = kwargs.get("timeout")
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 0))

        monkeypatch.setattr(_orch, "_run_study_prep", fake_run)
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: types.SimpleNamespace(timeout=600),
        )
        _capture_warnings(monkeypatch)

        _run_loop(self._config(tmp_path), _queue_with_batches(2))

        assert seen["timeout"] == 900


class _RecordingThrottle:
    def __init__(self):
        self.priorities = []

    @contextmanager
    def acquire_sync(self, *, low_priority=False):
        self.priorities.append(low_priority)
        yield


class TestStudyRunUsesLowPriorityThrottle:
    def test_run_study_acquires_low_priority_slot(
        self, monkeypatch, tmp_path,
    ):
        import core.audit.orchestrator as _orch

        def fake_run(cmd, **kwargs):
            # Prep "succeeds" and produces the study list.
            (tmp_path / "study-list.json").write_text("[]")
            return types.SimpleNamespace(returncode=0, stderr="")

        monkeypatch.setattr(_orch, "_run_study_prep", fake_run)

        studied = []
        import core.concepts.study as _study_mod
        monkeypatch.setattr(
            _study_mod, "run_study",
            lambda *a, **kw: studied.append(1),
        )

        import core.llm.client as _client_mod
        monkeypatch.setattr(
            _client_mod, "LLMClient",
            lambda *a, **kw: types.SimpleNamespace(total_cost=0.0),
        )

        throttle = _RecordingThrottle()
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
        )
        _run_loop(config, _queue_with_batches(2), throttle=throttle)

        assert studied, "run_study was never reached"
        assert throttle.priorities, "throttle slot never acquired"
        assert all(p is True for p in throttle.priorities), (
            "study batches must acquire the throttle slot at low "
            f"priority; got {throttle.priorities}"
        )
