"""CLI target assertion reaches configuration and persists for resume."""

import json

import pytest

from core.audit.tests.test_audit_forecast_cli import cli_env as _forecast_cli_env

cli_env = _forecast_cli_env


def test_cli_choice_reaches_pipeline_and_persisted_resume(cli_env, monkeypatch, request):
    from core.audit import pipeline, run_lock
    from core.audit.orchestrator import OrchestratorResult

    owned_acquire = run_lock.acquire_run_lock
    handles = []

    def acquire(*args, **kwargs):
        handle = owned_acquire(*args, **kwargs)
        request.addfinalizer(handle.release)
        handles.append(handle)
        return handle

    monkeypatch.setattr(run_lock, "acquire_run_lock", acquire)
    captured = []

    def run(opts):
        captured.append(opts)
        return OrchestratorResult()

    monkeypatch.setattr(pipeline, "run_audit_pipeline", run)
    monkeypatch.setattr(cli_env.mod, "_finalize_run", lambda *a, **kw: 0)
    assert cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
        "--integer-abi", "lp64", "--max-cost", "1", "--no-binary-oracle",
        "--no-supervisor-bound", "--no-study-lib", "--codeql-db", str(cli_env.out_dir / "unused-db"),
    ]) == 0
    assert len(captured) == 1 and captured[0].integer_abi == "lp64"
    saved = json.loads((cli_env.out_dir / "audit-run-config.json").read_text())
    assert saved["integer_abi"] == "lp64"
    config = pipeline._build_orchestrator_config(captured[0], client=None, models=["test-model"], mode=pipeline.ReviewMode.SECURITY)
    assert config.integer_abi == "lp64"

    # Exercise resume's actual options construction; lifecycle eligibility is
    # incidental to this option-plumbing test and is already tested separately.
    for handle in handles:
        handle.release()
        assert not handle.held
        # This test's pipeline has returned. Remove only its owned stamp
        # after releasing the owned fd to model the segment process exit.
        handle.lock_path.unlink(missing_ok=True)
    from core.audit import resume
    from core.run import metadata
    monkeypatch.setattr(resume, "resume_ineligibility", lambda *a, **kw: None)
    monkeypatch.setattr(metadata, "resume_run", lambda *a, **kw: 2)
    (cli_env.out_dir / "review-journal.jsonl").write_text("")
    assert cli_env.run_cli(["resume", str(cli_env.out_dir)]) == 0
    assert len(captured) == 2 and captured[1].integer_abi == "lp64"


def test_parser_rejects_host_default_and_unknown_profiles(cli_env):
    for name in ["native", "host", "auto", "not-an-abi"]:
        with pytest.raises(SystemExit) as error:
            cli_env.run_cli(["run", str(cli_env.target), "--integer-abi", name])
        assert error.value.code == 2
    assert not cli_env.lifecycle_calls


def test_unconfigured_pipeline_keeps_unknown_abi(tmp_path):
    from core.audit.pipeline import AuditPipelineOpts, ReviewMode, _build_orchestrator_config

    config = _build_orchestrator_config(AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path),
                                        client=None, models=["test-model"], mode=ReviewMode.SECURITY)
    assert config.integer_abi is None


def test_invalid_programmatic_configuration_is_not_silently_accepted(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig

    with pytest.raises(ValueError, match="integer ABI"):
        OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path, integer_abi="native")


def test_cli_help_describes_target_not_host_assertion(cli_env, capsys):
    with pytest.raises(SystemExit) as result:
        cli_env.run_cli(["run", "--help"])
    assert result.value.code == 0
    text = capsys.readouterr().out
    assert "--integer-abi" in text
    assert "operator assertion" in text
    assert "default: unknown" in text
