"""CLI target assertion reaches configuration and persists for resume."""

import json

import pytest

from core.audit.tests.test_audit_forecast_cli import cli_env as _forecast_cli_env

cli_env = _forecast_cli_env


@pytest.mark.parametrize("selection", ["lp64", None, "unknown", "legacy"])
@pytest.mark.parametrize("binary_target", [False, True], ids=["source", "binary"])
def test_cli_choice_reaches_pipeline_and_persisted_resume(cli_env, monkeypatch, request, selection, binary_target):
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
    from core.audit import integer_abi
    host = integer_abi.IntegerABI("host-lp64", 8, 16, 32, 64, 64,
                                  "twos-complement-no-padding", source="host-assumption")
    audit_target = cli_env.target
    default_abi = host
    if binary_target:
        from core.binary.tests.test_pe_facts import build_pe
        audit_target = cli_env.target / "program.exe"
        audit_target.write_bytes(build_pe())
        checklist_path = cli_env.out_dir / "checklist.json"
        checklist = json.loads(checklist_path.read_text())
        checklist["target_path"] = str(audit_target)
        checklist_path.write_text(json.dumps(checklist))
        default_abi = integer_abi.binary_integer_abi(audit_target)
        assert default_abi.source == "binary-platform"
    monkeypatch.setattr(integer_abi, "host_integer_abi", lambda: host)
    expected = default_abi.record() if selection is None else ("unknown" if selection == "legacy" else selection)
    captured = []

    def run(opts):
        captured.append(opts)
        return OrchestratorResult()

    monkeypatch.setattr(pipeline, "run_audit_pipeline", run)
    monkeypatch.setattr(cli_env.mod, "_finalize_run", lambda *a, **kw: 0)
    abi_args = [] if selection is None else ["--integer-abi", expected]
    assert cli_env.run_cli([
        "run", str(audit_target), "--out", str(cli_env.out_dir),
        *abi_args, "--max-cost", "1", "--no-binary-oracle",
        "--no-supervisor-bound", "--no-study-lib", "--codeql-db", str(cli_env.out_dir / "unused-db"),
    ]) == 0
    assert len(captured) == 1 and captured[0].integer_abi == expected
    saved = json.loads((cli_env.out_dir / "audit-run-config.json").read_text())
    assert saved["integer_abi"] == expected
    config = pipeline._build_orchestrator_config(captured[0], client=None, models=["test-model"], mode=pipeline.ReviewMode.SECURITY)
    assert config.integer_abi == (None if expected == "unknown" else expected)

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
    if selection == "legacy":
        saved.pop("integer_abi")
        (cli_env.out_dir / "audit-run-config.json").write_text(json.dumps(saved))
    monkeypatch.setattr(integer_abi, "host_integer_abi",
                        lambda: pytest.fail("resume must not remeasure the host"))
    monkeypatch.setattr(integer_abi, "binary_integer_abi",
                        lambda *args: pytest.fail("resume must not rederive the binary ABI"))
    assert cli_env.run_cli(["resume", str(cli_env.out_dir)]) == 0
    assert len(captured) == 2 and captured[1].integer_abi == expected


def test_parser_rejects_unsupported_profiles(cli_env):
    for name in ["native", "host", "auto", "not-an-abi"]:
        with pytest.raises(SystemExit) as error:
            cli_env.run_cli(["run", str(cli_env.target), "--integer-abi", name])
        assert error.value.code == 2
    assert not cli_env.lifecycle_calls


def test_unconfigured_pipeline_uses_labelled_host_abi(tmp_path, monkeypatch, caplog):
    from core.audit.pipeline import AuditPipelineOpts, ReviewMode, _build_orchestrator_config

    from core.audit.integer_abi import host_integer_abi
    host = host_integer_abi()
    assert host is not None
    config = _build_orchestrator_config(AuditPipelineOpts(target_path=tmp_path, out_dir=tmp_path),
                                        client=None, models=["test-model"], mode=ReviewMode.SECURITY)
    assert config.integer_abi == host.record()
    assert "assuming host" in caplog.text
    assert "Integer results apply under this assumption" in caplog.text


def test_invalid_programmatic_configuration_is_not_silently_accepted(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig

    with pytest.raises(ValueError, match="integer ABI"):
        OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path, integer_abi="native")


def test_cli_help_describes_host_assumption_and_override(cli_env, capsys):
    with pytest.raises(SystemExit) as result:
        cli_env.run_cli(["run", "--help"])
    assert result.value.code == 0
    text = capsys.readouterr().out
    assert "--integer-abi" in text
    assert "operator assertion" in text
    assert "binary platform layout" in text
    assert "measured host C layout" in text
    assert "analysis assumption" in text
