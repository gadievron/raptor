"""Lifecycle admission refuses unsupported primary routes before audit dispatch."""
from threading import RLock
from types import SimpleNamespace

import pytest

from core.audit import pipeline
from core.llm.budget_errors import LLMCallAdmissionRefused
from core.llm.client import LLMClient
from core.run.metadata import RUN_METADATA_FILE


@pytest.fixture
def factory(monkeypatch, tmp_path):
    from core.audit import attempt_reservations
    from core.llm import transcript

    calls = []
    client = object.__new__(LLMClient)
    client._stats_lock = RLock()
    client._pending_usage_reservations = {}
    client.config = SimpleNamespace(primary_model=SimpleNamespace(model_name="captured"))
    provider = SimpleNamespace()

    def get_provider(model):
        assert model is client.config.primary_model
        calls.append("provider")
        return provider

    client._get_provider = get_provider
    client.bind_attempt_reservations = lambda store, **kwargs: calls.append("bind")
    monkeypatch.setattr(transcript, "build_llm_client", lambda **kwargs: client)
    monkeypatch.setattr(attempt_reservations, "AttemptReservations",
                        lambda *args, **kwargs: calls.append("store") or object())
    monkeypatch.setattr(pipeline, "_ensure_dispatcher_route",
                        lambda *args, **kwargs: calls.append("route"))
    opts = pipeline.AuditPipelineOpts(out_dir=tmp_path, models=["captured"])
    return opts, client, provider, calls


@pytest.mark.parametrize("protocol", [None, True, "1", 0, 2])
@pytest.mark.parametrize("resume", [False, True])
def test_lifecycle_refuses_unsupported_before_store_or_dispatch(factory, protocol, resume):
    opts, client, provider, calls = factory
    provider._prepared_wire_admission_protocol = protocol
    if resume:
        opts.same_run_reuse = True
    else:
        (opts.out_dir / RUN_METADATA_FILE).write_text("{}")
    with pytest.raises(LLMCallAdmissionRefused, match="unsupported/not_run"):
        pipeline._make_llm_client(opts)
    assert calls == ["provider"]
    assert not getattr(client, "_prepared_admission_enabled", False)
    assert not (opts.out_dir / "audit-report.json").exists()


def test_supported_lifecycle_keeps_actual_prepared_enable(factory):
    opts, client, provider, calls = factory
    provider._prepared_wire_admission_protocol = 1
    (opts.out_dir / RUN_METADATA_FILE).write_text("{}")
    result, models, primary = pipeline._make_llm_client(opts)
    assert result is client and models == ["captured"] and primary == "captured"
    assert calls == ["provider", "store", "bind", "route"]
    assert client._prepared_admission_enabled is True


def test_metadata_free_library_keeps_legacy_without_provider_probe(factory):
    opts, client, provider, calls = factory
    provider._prepared_wire_admission_protocol = None
    result, _, _ = pipeline._make_llm_client(opts)
    assert result is client and calls == ["route"]
    assert not getattr(client, "_prepared_admission_enabled", False)


def test_pipeline_refusal_precedes_review_and_orchestrator(factory, monkeypatch):
    opts, _, _, calls = factory
    from core.audit import llm_review, orchestrator

    (opts.out_dir / RUN_METADATA_FILE).write_text("{}")
    monkeypatch.setattr(pipeline, "_maybe_auto_siblings", lambda opts: None)

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported startup must not create reviews or run the audit")

    monkeypatch.setattr(llm_review, "make_review_fn", forbidden)
    monkeypatch.setattr(orchestrator, "run_orchestrator", forbidden)
    with pytest.raises(LLMCallAdmissionRefused, match="no audit model request was sent"):
        pipeline.run_audit_pipeline(opts)
    assert calls == ["provider"]


@pytest.mark.parametrize("entry_index", [0, 1])
def test_actual_cli_pipeline_failure_guard_marks_failed_and_returns_one(
    factory, capsys, entry_index,
):
    """Exercise the existing run/resume guard without CLI/native setup."""
    import ast
    from pathlib import Path
    import sys

    opts, _, _, _ = factory
    (opts.out_dir / RUN_METADATA_FILE).write_text("{}")
    script = Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit"
    tree = ast.parse(script.read_text())
    guards = [node for node in ast.walk(tree) if isinstance(node, ast.Try)
              and node.body and isinstance(node.body[0], ast.Assign)
              and isinstance(node.body[0].value, ast.Call)
              and isinstance(node.body[0].value.func, ast.Name)
              and node.body[0].value.func.id == "run_audit_pipeline"]
    assert len(guards) == 2
    guard = sorted(guards, key=lambda node: node.lineno)[entry_index]
    wrapper = ast.parse("def captured_cli_guard():\n    pass\n")
    wrapper.body[0].body = [guard, ast.Return(ast.Constant(77))]
    ast.fix_missing_locations(wrapper)
    failures = []
    namespace = {
        "run_audit_pipeline": lambda unused: pipeline._make_llm_client(opts),
        "opts": opts, "out_dir": opts.out_dir, "sys": sys,
        "sanitise_for_terminal": lambda text, **kwargs: text,
        "_lifecycle_fail": lambda path, reason: failures.append((path, reason)),
    }
    exec(compile(wrapper, str(script), "exec"), namespace)
    assert namespace["captured_cli_guard"]() == 1
    assert len(failures) == 1 and failures[0][0] == opts.out_dir
    assert "unsupported/not_run" in failures[0][1]
    assert "unsupported/not_run" in capsys.readouterr().err
    assert not (opts.out_dir / "audit-report.json").exists()
