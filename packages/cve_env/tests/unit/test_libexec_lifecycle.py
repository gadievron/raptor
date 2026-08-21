"""Run-lifecycle wiring tests for ``libexec/raptor-cve-env``.

The shim (the RAPTOR-facing entry point — NOT ``bin/cve-env``, which
stays lifecycle-free per the facade contract) opens a run before the
build, prints the ``OUTPUT_DIR=`` sentinel, redirects the audit root
into the run dir unless the caller chose one, installs the run-local
LLM telemetry sink, and closes the run on every exit path. Lifecycle
functions are patched at their import site so nothing touches
``~/.raptor`` or the real ``out/`` tree.
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
LIBEXEC = REPO_ROOT / "libexec" / "raptor-cve-env"


def _load_shim():
    loader = SourceFileLoader("raptor_cve_env_lifecycle", str(LIBEXEC))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _recorder(calls, run_dir):
    def get_output_dir(command, target_name="", explicit_out=None,
                       target_path=None):
        calls.append(("resolve", command, target_name))
        return run_dir

    def start_run(output_dir, command, extra=None, **kw):
        calls.append(("start", command, dict(extra or {})))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return Path(output_dir)

    def complete_run(output_dir, extra=None, **kw):
        calls.append(("complete", str(output_dir)))

    def fail_run(output_dir, error=None, **kw):
        calls.append(("fail", str(error)))

    def interrupt_run(output_dir, reason=None, **kw):
        calls.append(("interrupt", str(reason)))

    return get_output_dir, start_run, complete_run, fail_run, interrupt_run


def _run(argv, cli_main, tmp_path, capsys):
    run_dir = tmp_path / "run"
    calls: list = []
    god, start, complete, fail, interrupt = _recorder(calls, run_dir)
    mod = _load_shim()
    with (
        patch("core.run.output.get_output_dir", god),
        patch("core.run.output.resolve_default_target", lambda: None),
        patch("core.run.metadata.start_run", start),
        patch("core.run.metadata.complete_run", complete),
        patch("core.run.metadata.fail_run", fail),
        patch("core.run.metadata.interrupt_run", interrupt),
        patch("cve_env.cli.main", cli_main),
    ):
        rc = mod.main(argv)
    return rc, calls, run_dir, capsys.readouterr()


CVE = "CVE-2018-7600"


def test_success_run_lifecycle_and_sentinel(tmp_path, capsys):
    seen_argv = {}

    def cli_main(argv):
        seen_argv["argv"] = list(argv)
        from core.llm.telemetry import current_sink
        seen_argv["sink"] = str(current_sink().path) if current_sink() else None
        return 0

    rc, calls, run_dir, out = _run(["build", CVE], cli_main, tmp_path, capsys)
    assert rc == 0
    kinds = [c[0] for c in calls]
    assert kinds == ["resolve", "start", "complete"]
    assert calls[0][1:] == ("cve-env", CVE)
    assert calls[1][2] == {"cve_id": CVE}
    # Sentinel on stdout before anything else.
    assert out.out.splitlines()[0] == f"OUTPUT_DIR={run_dir}"
    # Audit root redirected into the run dir when the caller passed none.
    assert seen_argv["argv"][-2:] == ["--audit-root", str(run_dir)]
    # Telemetry sink installed at the run dir during the build.
    assert seen_argv["sink"] == str(run_dir / "llm-telemetry.jsonl")
    from core.llm.telemetry import current_sink
    assert current_sink() is None, "sink must be uninstalled after the run"


def test_non_success_outcome_is_a_completed_run(tmp_path, capsys):
    rc, calls, _run_dir, _ = _run(["build", CVE], lambda argv: 1,
                                  tmp_path, capsys)
    assert rc == 1
    assert [c[0] for c in calls] == ["resolve", "start", "complete"], (
        "exit 1 is a completed run with a non-success OUTCOME, not a "
        "failed run"
    )


def test_caller_audit_root_is_respected(tmp_path, capsys):
    seen_argv = {}

    def cli_main(argv):
        seen_argv["argv"] = list(argv)
        return 0

    _rc, _calls, run_dir, _ = _run(
        ["build", CVE, "--audit-root", str(tmp_path / "mine")],
        cli_main, tmp_path, capsys,
    )
    assert seen_argv["argv"].count("--audit-root") == 1
    assert str(run_dir) not in seen_argv["argv"], (
        "explicit --audit-root must not be overridden"
    )


def test_exception_marks_run_failed(tmp_path, capsys):
    def cli_main(argv):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        _run(["build", CVE], cli_main, tmp_path, capsys)
    # calls captured inside _run are lost on raise; re-drive precisely:
    run_dir = tmp_path / "run2"
    calls: list = []
    god, start, complete, fail, interrupt = _recorder(calls, run_dir)
    mod = _load_shim()
    with (
        patch("core.run.output.get_output_dir", god),
        patch("core.run.output.resolve_default_target", lambda: None),
        patch("core.run.metadata.start_run", start),
        patch("core.run.metadata.complete_run", complete),
        patch("core.run.metadata.fail_run", fail),
        patch("core.run.metadata.interrupt_run", interrupt),
        patch("cve_env.cli.main", cli_main),
        pytest.raises(RuntimeError),
    ):
        mod.main(["build", CVE])
    assert [c[0] for c in calls] == ["resolve", "start", "fail"]
    assert calls[2][1] == "RuntimeError: boom"


def test_keyboard_interrupt_marks_run_interrupted(tmp_path, capsys):
    def cli_main(argv):
        raise KeyboardInterrupt

    run_dir = tmp_path / "run"
    calls: list = []
    god, start, complete, fail, interrupt = _recorder(calls, run_dir)
    mod = _load_shim()
    with (
        patch("core.run.output.get_output_dir", god),
        patch("core.run.output.resolve_default_target", lambda: None),
        patch("core.run.metadata.start_run", start),
        patch("core.run.metadata.complete_run", complete),
        patch("core.run.metadata.fail_run", fail),
        patch("core.run.metadata.interrupt_run", interrupt),
        patch("cve_env.cli.main", cli_main),
        pytest.raises(KeyboardInterrupt),
    ):
        mod.main(["build", CVE])
    assert [c[0] for c in calls] == ["resolve", "start", "interrupt"]


def test_usage_error_exits_before_any_lifecycle(tmp_path, capsys):
    calls: list = []
    god, start, complete, fail, interrupt = _recorder(calls, tmp_path / "r")
    mod = _load_shim()
    with (
        patch("core.run.output.get_output_dir", god),
        patch("core.run.metadata.start_run", start),
        pytest.raises(SystemExit),
    ):
        mod.main(["build", "not-a-cve-id"])
    assert calls == [], "argparse rejection must precede run creation"


def test_doctor_takes_no_lifecycle(tmp_path, capsys):
    calls: list = []
    god, start, *_ = _recorder(calls, tmp_path / "r")
    mod = _load_shim()
    with (
        patch("core.run.output.get_output_dir", god),
        patch("core.run.metadata.start_run", start),
        patch("cve_env.cli.main", lambda argv: 0),
    ):
        rc = mod.main(["doctor"])
    assert rc == 0
    assert calls == []
