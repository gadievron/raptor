"""Run-lifecycle wiring tests for ``libexec/raptor-cve-diff``.

The shim participates in RAPTOR's shared run lifecycle
(``core.run.metadata``): ``start_run`` before any pipeline work (with
the ``OUTPUT_DIR=`` sentinel printed for downstream lifecycle steps),
``complete_run`` on success, ``fail_run`` on both mapped pipeline
errors and unexpected exceptions, ``interrupt_run`` on SIGINT.

All lifecycle functions are patched at their import site so the tests
never touch ``~/.raptor`` or the real ``out/`` tree — these are
contract tests for the wiring and ordering, not for
``core.run.metadata`` itself (which has its own suite).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[5]
LIBEXEC = REPO_ROOT / "libexec" / "raptor-cve-diff"


def _load_shim():
    """Import libexec/raptor-cve-diff as a module. The session-wide
    ``_RAPTOR_TRUSTED=1`` env var lets the trust-marker check pass."""
    loader = SourceFileLoader("raptor_cve_diff_lifecycle", str(LIBEXEC))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _lifecycle_recorder(calls, create_dir=True):
    """Patched stand-ins for the four lifecycle entry points, recording
    call order. ``start_run`` optionally creates the directory — the
    real one does (via ``safe_run_mkdir``), and the shim's success path
    writes artifacts into it."""

    def start_run(output_dir, command, extra=None, **kw):
        calls.append(("start", command, dict(extra or {})))
        if create_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        return Path(output_dir)

    def complete_run(output_dir, extra=None, **kw):
        calls.append(("complete", str(output_dir)))

    def fail_run(output_dir, error=None, **kw):
        calls.append(("fail", str(error)))

    def interrupt_run(output_dir, reason=None, **kw):
        calls.append(("interrupt", str(reason)))

    return start_run, complete_run, fail_run, interrupt_run


def _run_shim(argv, fake_pipeline, calls, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["raptor-cve-diff", *argv])
    mod = _load_shim()
    start, complete, fail, interrupt = _lifecycle_recorder(calls)
    with (
        patch("core.run.metadata.start_run", start),
        patch("core.run.metadata.complete_run", complete),
        patch("core.run.metadata.fail_run", fail),
        patch("core.run.metadata.interrupt_run", interrupt),
        patch("cve_diff.pipeline.Pipeline", fake_pipeline),
    ):
        return mod.main()


class _FailingPipeline:
    """Raises the mapped UnsupportedSource error, recording the moment."""

    calls: list | None = None  # class attr injected per test

    def __init__(self, **_kw):
        self.agent = type("A", (), {"last_telemetry": None})()

    def run(self, cve_id, work_dir):
        type(self).calls.append(("pipeline", cve_id))
        from cve_diff.core.exceptions import UnsupportedSource
        raise UnsupportedSource("test stub: closed-source vendor")


def test_start_before_pipeline_fail_on_mapped_error_and_sentinel(
    tmp_path, monkeypatch, capsys,
):
    out_dir = tmp_path / "run"
    calls: list = []
    _FailingPipeline.calls = calls

    rc = _run_shim(
        ["run", "CVE-2024-11111", "--output-dir", str(out_dir)],
        _FailingPipeline, calls, monkeypatch,
    )

    assert rc == 4
    kinds = [c[0] for c in calls]
    assert kinds == ["start", "pipeline", "fail"], (
        f"lifecycle order wrong: {calls}"
    )
    # start_run carries the command name + CVE id extra.
    assert calls[0][1] == "cve-diff"
    assert calls[0][2] == {"cve_id": "CVE-2024-11111"}
    # fail_run carries the mapped error class.
    assert calls[2][1].startswith("UnsupportedSource:")

    # The OUTPUT_DIR sentinel is on stdout, before the JSON summary.
    stdout = capsys.readouterr().out
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    sentinel = [ln for ln in lines if ln.startswith("OUTPUT_DIR=")]
    assert sentinel, f"no OUTPUT_DIR sentinel in stdout: {stdout!r}"
    assert sentinel[0] == f"OUTPUT_DIR={out_dir.resolve()}"
    assert stdout.index("OUTPUT_DIR=") < stdout.index('"ok"')


def test_complete_run_fires_on_success(tmp_path, monkeypatch, capsys):
    out_dir = tmp_path / "run"
    calls: list = []

    from cve_diff.core.models import CommitSha, DiffBundle, RepoRef

    ref = RepoRef(
        repository_url="https://github.com/example/proj",
        fix_commit=CommitSha("a" * 40),
        introduced=CommitSha("b" * 40),
        canonical_score=100,
    )
    bundle = DiffBundle(
        cve_id="CVE-2024-22222",
        repo_ref=ref,
        commit_before=CommitSha("b" * 40),
        commit_after=CommitSha("a" * 40),
        diff_text="--- a\n+++ b\n",
        files_changed=1,
        bytes_size=12,
    )
    report = type("R", (), {"name": "shallow_clone", "ok": True})()
    acquirer = type("Acq", (), {"reports": [report]})()

    class _OkPipeline:
        def __init__(self, **_kw):
            self.agent = type("A", (), {"last_telemetry": {
                "cost_usd": 0.01, "tokens": 10, "elapsed_s": 1.0,
                "tool_calls": [], "tool_calls_with_args": [],
            }})()
            self._stage_status = {"render": {"status": "ok"}}
            self._last_extra_bundles = []

        def run(self, cve_id, work_dir):
            calls.append(("pipeline", cve_id))
            from cve_diff.pipeline import PipelineResult
            return PipelineResult(
                cve_id=cve_id, bundle=bundle,
                agent_result=None, acquirer=acquirer,
            )

    rc = _run_shim(
        ["run", "CVE-2024-22222", "--output-dir", str(out_dir)],
        _OkPipeline, calls, monkeypatch,
    )

    assert rc == 0
    kinds = [c[0] for c in calls]
    assert kinds == ["start", "pipeline", "complete"], (
        f"lifecycle order wrong: {calls}"
    )

    # complete_run fired BEFORE the JSON summary print (the summary is
    # documented as the last thing on stdout) and the summary is valid
    # JSON with ok=true.
    stdout = capsys.readouterr().out
    json_start = stdout.index("{")
    summary = json.loads(stdout[json_start:])
    assert summary["ok"] is True
    assert summary["cve_id"] == "CVE-2024-22222"


def test_unexpected_exception_marks_run_failed(tmp_path, monkeypatch):
    out_dir = tmp_path / "run"
    calls: list = []

    class _CrashingPipeline:
        def __init__(self, **_kw):
            self.agent = type("A", (), {"last_telemetry": None})()

        def run(self, cve_id, work_dir):
            calls.append(("pipeline", cve_id))
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        _run_shim(
            ["run", "CVE-2024-33333", "--output-dir", str(out_dir)],
            _CrashingPipeline, calls, monkeypatch,
        )

    kinds = [c[0] for c in calls]
    assert kinds == ["start", "pipeline", "fail"], (
        f"lifecycle order wrong: {calls}"
    )
    assert calls[2][1] == "RuntimeError: boom"


def test_keyboard_interrupt_marks_run_interrupted(tmp_path, monkeypatch):
    out_dir = tmp_path / "run"
    calls: list = []

    class _InterruptedPipeline:
        def __init__(self, **_kw):
            self.agent = type("A", (), {"last_telemetry": None})()

        def run(self, cve_id, work_dir):
            calls.append(("pipeline", cve_id))
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _run_shim(
            ["run", "CVE-2024-44444", "--output-dir", str(out_dir)],
            _InterruptedPipeline, calls, monkeypatch,
        )

    kinds = [c[0] for c in calls]
    assert kinds == ["start", "pipeline", "interrupt"], (
        f"lifecycle order wrong: {calls}"
    )


def test_output_dir_resolution_goes_through_shared_resolver(
    tmp_path, monkeypatch,
):
    """Without --output-dir the shim must delegate to
    ``core.run.output.get_output_dir`` (project attachment, standalone
    naming) instead of rolling its own timestamped directory."""
    calls: list = []
    _FailingPipeline.calls = calls
    resolved = tmp_path / "resolved-run"
    seen = {}

    def fake_get_output_dir(command, target_name="", explicit_out=None,
                            target_path=None):
        seen["command"] = command
        seen["target_name"] = target_name
        seen["explicit_out"] = explicit_out
        return resolved

    monkeypatch.setattr(sys, "argv",
                        ["raptor-cve-diff", "run", "CVE-2024-55555"])
    mod = _load_shim()
    start, complete, fail, interrupt = _lifecycle_recorder(calls)
    with (
        patch("core.run.output.get_output_dir", fake_get_output_dir),
        patch("core.run.output.resolve_default_target", lambda: None),
        patch("core.run.metadata.start_run", start),
        patch("core.run.metadata.complete_run", complete),
        patch("core.run.metadata.fail_run", fail),
        patch("core.run.metadata.interrupt_run", interrupt),
        patch("cve_diff.pipeline.Pipeline", _FailingPipeline),
    ):
        rc = mod.main()

    assert rc == 4
    assert seen == {
        "command": "cve-diff",
        "target_name": "CVE-2024-55555",
        "explicit_out": None,
    }


def test_telemetry_sink_installed_during_pipeline(tmp_path, monkeypatch):
    """The shim installs a run-local TelemetrySink (llm-telemetry.jsonl
    in the output dir) before the pipeline runs and uninstalls it on
    the way out, so agent-turn and root-cause records land next to the
    run's other artifacts."""
    out_dir = tmp_path / "run"
    calls: list = []
    seen = {}

    class _SinkProbePipeline:
        def __init__(self, **_kw):
            self.agent = type("A", (), {"last_telemetry": None})()

        def run(self, cve_id, work_dir):
            calls.append(("pipeline", cve_id))
            from core.llm.telemetry import current_sink
            sink = current_sink()
            seen["sink_path"] = str(sink.path) if sink is not None else None
            from cve_diff.core.exceptions import UnsupportedSource
            raise UnsupportedSource("test stub")

    rc = _run_shim(
        ["run", "CVE-2024-66666", "--output-dir", str(out_dir)],
        _SinkProbePipeline, calls, monkeypatch,
    )

    assert rc == 4
    expected = str(out_dir.resolve() / "llm-telemetry.jsonl")
    assert seen["sink_path"] == expected, (
        f"sink not installed for the run: {seen}"
    )
    # Uninstalled after the run — no leak into the next command.
    from core.llm.telemetry import current_sink
    assert current_sink() is None


def test_model_flag_reaches_pipeline_and_default_resolves(
    tmp_path, monkeypatch,
):
    """--model passes through to Pipeline(model_id=...); without the
    flag the shim resolves the operator's configured primary via
    cve_diff.llm.auth.default_model_id."""
    out_dir = tmp_path / "run"
    calls: list = []
    seen_kw = {}

    class _KwProbePipeline:
        def __init__(self, **kw):
            seen_kw.update(kw)
            self.agent = type("A", (), {"last_telemetry": None})()

        def run(self, cve_id, work_dir):
            calls.append(("pipeline", cve_id))
            from cve_diff.core.exceptions import UnsupportedSource
            raise UnsupportedSource("test stub")

    rc = _run_shim(
        ["run", "CVE-2024-77777", "--output-dir", str(out_dir),
         "--model", "gemini-2.5-pro"],
        _KwProbePipeline, calls, monkeypatch,
    )
    assert rc == 4
    assert seen_kw["model_id"] == "gemini-2.5-pro"

    # No flag → registry default.
    seen_kw.clear()
    calls.clear()
    monkeypatch.setattr(
        "cve_diff.llm.auth.default_model_id", lambda: "registry-default-model",
    )
    rc = _run_shim(
        ["run", "CVE-2024-88888", "--output-dir", str(out_dir / "b")],
        _KwProbePipeline, calls, monkeypatch,
    )
    assert rc == 4
    assert seen_kw["model_id"] == "registry-default-model"
