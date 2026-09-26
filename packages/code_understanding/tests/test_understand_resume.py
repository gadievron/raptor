"""End-to-end resume tests for ``libexec/raptor-understand``.

The acceptance shape: a multi-model run interrupted after N of M
models must NOT re-spend from zero — ``--resume <run-dir>`` carries
the checkpointed models' results and costs forward and dispatches
only the remainder. Driven through the shim's ``main()`` with a fake
dispatch (no LLM, no network), the same in-process pattern as
test_libexec_trajectory_e2e.py.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from core.json import load_json
from core.run import RUN_METADATA_FILE, start_run

REPO_ROOT = Path(__file__).resolve().parents[3]
LIBEXEC = REPO_ROOT / "libexec" / "raptor-understand"

MODELS = ("model-a", "model-b", "model-c")
RUN1_COSTS = {"model-a": 1.0, "model-b": 2.0, "model-c": 0.75}


def _load_shim():
    loader = SourceFileLoader("raptor_understand_resume_e2e", str(LIBEXEC))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def repo(tmp_path):
    src = tmp_path / "repo" / "src"
    src.mkdir(parents=True)
    (src / "x.c").write_text("void f(char *p) { strcpy(buf, p); }\n")
    return tmp_path / "repo"


@pytest.fixture
def run_dir(tmp_path, repo):
    """A lifecycle-started /understand run directory (the skill does
    this before invoking the shim)."""
    out = tmp_path / "run"
    start_run(out, "understand", target=str(repo))
    return out


def _patch_models(mod, monkeypatch):
    from core.llm.config import ModelConfig
    configs = {
        name: ModelConfig(
            provider="anthropic", model_name=name,
            api_key="fake-key-for-test",
        )
        for name in MODELS
    }

    def _resolve(names):
        return [configs[n] for n in names if n in configs], []

    monkeypatch.setattr(mod, "_resolve_models", _resolve)


def _patch_hunt_dispatch(monkeypatch, calls, *, interrupt_on=None):
    """Fake default_hunt_dispatch: records calls, books a per-model
    cost, returns one variant per model. ``interrupt_on`` simulates
    the external kill arriving while that model runs."""

    def fake(model, pattern, repo_path, *, max_cost_usd=None,
             cost_collector=None, verbose_logger=None):
        name = model.model_name
        calls.append((name, max_cost_usd))
        if name == interrupt_on:
            raise KeyboardInterrupt
        if cost_collector is not None:
            cost_collector(RUN1_COSTS[name])
        return [{
            "file": "src/x.c", "line": 1, "function": f"f_{name}",
            "confidence": "high", "snippet": "strcpy(buf, p)",
        }]

    monkeypatch.setattr(
        "packages.code_understanding.dispatch.default_hunt_dispatch",
        fake,
    )


def _run_shim(mod, monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["raptor-understand", *argv])
    return mod.main()


def _interrupted_hunt_run(mod, monkeypatch, repo, run_dir):
    """Segment 1: 3 models, sequential, killed while model-c runs."""
    calls: list = []
    _patch_models(mod, monkeypatch)
    _patch_hunt_dispatch(monkeypatch, calls, interrupt_on="model-c")
    rc = _run_shim(mod, monkeypatch, [
        "--hunt", "strcpy misuse", "--hunt-tool", "llm",
        "--target", str(repo), "--out", str(run_dir),
        "--model", "model-a", "--model", "model-b", "--model", "model-c",
        "--max-cost", "6.0", "--max-parallel", "1",
    ])
    assert rc == 130, "interruption must exit 130"
    return calls


class TestInterruptThenResume:
    def test_resume_runs_only_the_remainder(
        self, repo, run_dir, monkeypatch,
    ):
        mod = _load_shim()
        run1_calls = _interrupted_hunt_run(mod, monkeypatch, repo, run_dir)
        assert [c[0] for c in run1_calls] == list(MODELS)

        # Interruption is visible: not stuck 'running', and no result.
        meta = load_json(run_dir / RUN_METADATA_FILE)
        assert meta["status"] == "interrupted"
        assert not (run_dir / "hunt-result.json").exists()
        # The completed models' work survived as checkpoints.
        ckpts = sorted(
            p.name for p in
            (run_dir / "understand-checkpoints").glob("*.json")
        )
        assert len(ckpts) == 2

        # Segment 2: only the remainder dispatches.
        run2_calls: list = []
        _patch_hunt_dispatch(monkeypatch, run2_calls)
        rc = _run_shim(mod, monkeypatch, ["--resume", str(run_dir)])
        assert rc == 0

        assert [c[0] for c in run2_calls] == ["model-c"], (
            "checkpointed models must not re-dispatch"
        )
        # Remaining-budget cap: $6 cap - $3 booked = $3 for the one
        # remaining model.
        assert run2_calls[0][1] == pytest.approx(3.0)

        result = json.loads((run_dir / "hunt-result.json").read_text())
        functions = {i.get("function") for i in result["items"]}
        assert functions == {"f_model-a", "f_model-b", "f_model-c"}
        # Continuous accounting: carried costs + segment-2 spend.
        assert result["model_costs_usd"] == pytest.approx(RUN1_COSTS)
        assert result["total_cost_usd"] == pytest.approx(3.75)
        assert result["resumed_segment"] == 2
        assert result["carried_models"] == ["model-a", "model-b"]

        meta = load_json(run_dir / RUN_METADATA_FILE)
        assert meta["status"] == "completed"
        assert meta["extra"]["resumes"][0]["segment"] == 2

    def test_resume_refuses_fresh_steering_flags(
        self, repo, run_dir, monkeypatch, capsys,
    ):
        mod = _load_shim()
        monkeypatch.setattr(sys, "argv", [
            "raptor-understand", "--resume", str(run_dir),
            "--target", str(repo),
        ])
        with pytest.raises(SystemExit) as exc:
            mod.main()
        assert exc.value.code == 2

    def test_completed_run_never_resumed(
        self, repo, run_dir, monkeypatch, capsys,
    ):
        mod = _load_shim()
        _interrupted_hunt_run(mod, monkeypatch, repo, run_dir)
        run2_calls: list = []
        _patch_hunt_dispatch(monkeypatch, run2_calls)
        assert _run_shim(mod, monkeypatch, ["--resume", str(run_dir)]) == 0
        # Third invocation: the run is completed — final.
        rc = _run_shim(mod, monkeypatch, ["--resume", str(run_dir)])
        assert rc == 1
        assert "never resumed" in capsys.readouterr().err

    def test_run_without_pinned_config_refused(
        self, repo, tmp_path, monkeypatch, capsys,
    ):
        out = tmp_path / "legacy-run"
        start_run(out, "understand", target=str(repo))
        from core.run import interrupt_run
        interrupt_run(out, "kill")
        mod = _load_shim()
        rc = _run_shim(mod, monkeypatch, ["--resume", str(out)])
        assert rc == 1
        assert "understand-run-config.json" in capsys.readouterr().err


class TestDriftGate:
    def _interrupt_then_edit(self, mod, monkeypatch, repo, run_dir):
        _interrupted_hunt_run(mod, monkeypatch, repo, run_dir)
        (repo / "src" / "x.c").write_text(
            "void f(char *p) { strncpy(buf, p, 8); }\n",
        )

    def test_drift_refuses_resume(
        self, repo, run_dir, monkeypatch, capsys,
    ):
        mod = _load_shim()
        self._interrupt_then_edit(mod, monkeypatch, repo, run_dir)
        run2_calls: list = []
        _patch_hunt_dispatch(monkeypatch, run2_calls)
        rc = _run_shim(mod, monkeypatch, ["--resume", str(run_dir)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "drifted" in err
        assert "src/x.c" in err
        assert run2_calls == [], "no spend behind a drift refusal"
        # Refusal happens before the lifecycle flip — still resumable.
        meta = load_json(run_dir / RUN_METADATA_FILE)
        assert meta["status"] == "interrupted"

    def test_allow_drift_carries_and_stamps(
        self, repo, run_dir, monkeypatch,
    ):
        mod = _load_shim()
        self._interrupt_then_edit(mod, monkeypatch, repo, run_dir)
        run2_calls: list = []
        _patch_hunt_dispatch(monkeypatch, run2_calls)
        rc = _run_shim(
            mod, monkeypatch,
            ["--resume", str(run_dir), "--allow-drift"],
        )
        assert rc == 0
        assert [c[0] for c in run2_calls] == ["model-c"]
        result = json.loads((run_dir / "hunt-result.json").read_text())
        assert result["resumed_with_drift"] == 1
        assert result["carried_models"] == ["model-a", "model-b"]


class TestTraceResume:
    def test_trace_resume_uses_pinned_traces(
        self, repo, run_dir, tmp_path, monkeypatch,
    ):
        """The pinned traces snapshot — not the operator's file —
        feeds the resumed segment: deleting the original between
        segments changes nothing."""
        mod = _load_shim()
        _patch_models(mod, monkeypatch)
        traces_file = tmp_path / "traces.json"
        traces = [
            {"trace_id": "t1", "entry": "main"},
            {"trace_id": "t2", "entry": "handler"},
        ]
        traces_file.write_text(json.dumps(traces))

        calls: list = []

        def fake_trace(model, traces_arg, repo_path, *, max_cost_usd=None,
                       cost_collector=None, verbose_logger=None):
            name = model.model_name
            calls.append(name)
            if name == "model-b" and not (run_dir / "segment2").exists():
                raise KeyboardInterrupt
            if cost_collector is not None:
                cost_collector(0.5)
            return [
                {"trace_id": t["trace_id"], "verdict": "reachable",
                 "model": name}
                for t in traces_arg
            ]

        monkeypatch.setattr(
            "packages.code_understanding.dispatch.default_trace_dispatch",
            fake_trace,
        )
        rc = _run_shim(mod, monkeypatch, [
            "--trace", str(traces_file), "--target", str(repo),
            "--out", str(run_dir),
            "--model", "model-a", "--model", "model-b",
            "--max-parallel", "1",
        ])
        assert rc == 130
        assert calls == ["model-a", "model-b"]
        assert (run_dir / "understand-traces-pin.json").exists()

        traces_file.unlink()  # the original is gone; the pin remains
        (run_dir / "segment2").mkdir()
        calls.clear()
        rc = _run_shim(mod, monkeypatch, ["--resume", str(run_dir)])
        assert rc == 0
        assert calls == ["model-b"]
        result = json.loads((run_dir / "trace-result.json").read_text())
        assert result["trace_count"] == 2
        assert {i.get("trace_id") for i in result["items"]} == {"t1", "t2"}
        assert result["resumed_segment"] == 2
        assert result["carried_models"] == ["model-a"]


class TestSpendFloorBooksFailedDispatch:
    def test_failed_model_spend_still_raises_the_floor(
            self, tmp_path, repo, run_dir):
        # The floor is the resume machinery's "money already left the
        # building" record. A dispatch whose result is failure-shaped
        # (all-error list) spent real money via the cost collector,
        # and the floor is monotonic — so the bump must not be gated
        # on success (a failed final model once left its whole cost
        # off the floor, and a resumed run under-booked the spend).
        from core.run.resume import spend_floor_usd

        mod = _load_shim()
        cost_by_model: dict[str, float] = {}

        class _Args:
            pass

        class _Model:
            model_name = "model-a"

        def dispatch(model, task_arg, repo_path):
            cost_by_model["model-a"] = 1.5  # collector booked pre-failure
            return [{"error": "provider 500"}]

        wrapped = mod._checkpoint_wrap(
            dispatch, _Args(), run_dir, mode="hunt", task_key="k",
            target=repo, cost_by_model=cost_by_model)
        results = wrapped(_Model(), "pattern", str(repo))

        assert results == [{"error": "provider 500"}]
        assert spend_floor_usd(run_dir) >= 1.5
        # The failed result itself is still NOT checkpointed — it must
        # re-run on resume, not replay.
        from packages.code_understanding.checkpoint import (
            CheckpointStore,
            task_fingerprint,
        )
        store = CheckpointStore(
            run_dir, mode="hunt",
            fingerprint=task_fingerprint("hunt", "k", repo),
            target=repo)
        assert store.load("model-a") is None
