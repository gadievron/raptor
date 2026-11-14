"""An explicit shared-study allowance survives pipeline and resume options."""

import json

import pytest

from core.audit.tests.test_audit_forecast_cli import cli_env as _forecast_cli_env

cli_env = _forecast_cli_env


@pytest.mark.parametrize("selection", [None, 1, 3, "legacy", "invalid-saved"])
def test_explicit_job_cap_reaches_pipeline_saved_config_and_resume(
    cli_env, monkeypatch, request, selection,
):
    from core.audit import pipeline, run_lock
    from core.audit.orchestrator import OrchestratorResult

    acquire_run_lock = run_lock.acquire_run_lock
    handles = []

    def acquire(*args, **kwargs):
        handle = acquire_run_lock(*args, **kwargs)
        request.addfinalizer(handle.release)
        handles.append(handle)
        return handle

    monkeypatch.setattr(run_lock, "acquire_run_lock", acquire)
    captured = []

    def capture_options(opts):
        captured.append(opts)
        return OrchestratorResult()

    monkeypatch.setattr(pipeline, "run_audit_pipeline", capture_options)
    monkeypatch.setattr(cli_env.mod, "_finalize_run", lambda *args, **kwargs: 0)
    expected = None if selection == "legacy" else 1 if selection == "invalid-saved" else selection
    policy_args = [] if expected is None else ["--study-job-call-limit", str(expected)]
    assert cli_env.run_cli([
        "run", str(cli_env.target), "--out", str(cli_env.out_dir),
        *policy_args, "--integer-abi", "unknown", "--max-cost", "1",
        "--no-binary-oracle", "--no-supervisor-bound", "--no-study-lib",
        "--codeql-db", str(cli_env.out_dir / "unused-db"),
    ]) == 0
    assert len(captured) == 1 and captured[0].study_job_call_limit == expected
    path = cli_env.out_dir / "audit-run-config.json"
    saved = json.loads(path.read_text())
    assert saved["study_job_call_limit"] == expected
    config = pipeline._build_orchestrator_config(
        captured[0], client=None, models=["test-model"], mode=pipeline.ReviewMode.SECURITY,
    )
    assert config.study_job_call_limit == expected

    # The captured pipeline has returned; retire only its owned segment stamp
    # before exercising resume's actual options construction.
    for handle in handles:
        handle.release()
        assert not handle.held
        handle.lock_path.unlink(missing_ok=True)
    from core.audit import resume
    from core.run import metadata

    monkeypatch.setattr(resume, "resume_ineligibility", lambda *args, **kwargs: None)
    monkeypatch.setattr(metadata, "resume_run", lambda *args, **kwargs: 2)
    (cli_env.out_dir / "review-journal.jsonl").write_text("")
    if selection == "legacy":
        saved.pop("study_job_call_limit")
        path.write_text(json.dumps(saved))
    if selection == "invalid-saved":
        saved["study_job_call_limit"] = True
        path.write_text(json.dumps(saved))
        try:
            status = cli_env.run_cli(["resume", str(cli_env.out_dir)])
        except ValueError as error:
            assert "study" in str(error).lower()
        except SystemExit as error:
            assert error.code != 0
        else:
            assert status != 0
        assert len(captured) == 1
        return
    assert cli_env.run_cli(["resume", str(cli_env.out_dir)]) == 0
    assert len(captured) == 2 and captured[1].study_job_call_limit == expected
    resumed_config = pipeline._build_orchestrator_config(
        captured[1], client=None, models=["test-model"], mode=pipeline.ReviewMode.SECURITY,
    )
    assert resumed_config.study_job_call_limit == expected


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "not-a-number"])
def test_parser_refuses_invalid_job_cap_before_lifecycle(cli_env, value):
    with pytest.raises(SystemExit) as caught:
        cli_env.run_cli(["run", str(cli_env.target), "--study-job-call-limit", value])
    assert caught.value.code == 2
    assert not cli_env.lifecycle_calls


@pytest.mark.parametrize("kind", ["pipeline", "orchestrator"])
@pytest.mark.parametrize("value", [None, 1, 3])
def test_programmatic_policy_accepts_only_explicit_positive_or_none(tmp_path, kind, value):
    from core.audit.orchestrator import OrchestratorConfig
    from core.audit.pipeline import AuditPipelineOpts

    constructor = AuditPipelineOpts if kind == "pipeline" else OrchestratorConfig
    config = constructor(target_path=tmp_path, out_dir=tmp_path, study_job_call_limit=value)
    assert config.study_job_call_limit == value


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, "3"])
def test_pipeline_policy_refuses_invalid_explicit_values(tmp_path, value):
    from core.audit.pipeline import AuditPipelineOpts

    with pytest.raises(ValueError, match="study.job|study job"):
        AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path, study_job_call_limit=value)


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, "3"])
def test_legacy_low_level_invalid_policy_remains_inactive(tmp_path, value):
    from core.audit.orchestrator import OrchestratorConfig
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime

    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path, study_job_call_limit=value)
    runtime = AuditKnowledgeRuntime(tmp_path, None, deadline=float("inf"),
                                    study_job_call_limit=config.study_job_call_limit)
    try:
        assert runtime.study_jobs_enabled is False
    finally:
        runtime.close()


def test_config_builder_revalidates_a_mutated_policy(tmp_path):
    from core.audit.pipeline import AuditPipelineOpts, ReviewMode, _build_orchestrator_config

    opts = AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path, integer_abi="lp64")
    opts.study_job_call_limit = True
    with pytest.raises(ValueError, match="study.job|study job"):
        _build_orchestrator_config(opts, client=None, models=["test-model"], mode=ReviewMode.SECURITY)
