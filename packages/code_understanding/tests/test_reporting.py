"""Captured understand receipts, source protection and public CLI controls."""
from __future__ import annotations

import argparse
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from core.reporting.options import ReportOptions
from core.testing.state_isolation import pin_user_state_dirs
from packages.code_understanding.reporting import complete_understand_report, prepare_understand_report


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path)


def _args(tmp_path, **overrides):
    target = tmp_path / "source"
    target.mkdir(exist_ok=True)
    args = argparse.Namespace(target=str(target), report_format=["json"], report_output=None,
                              no_report=False, trace=None)
    vars(args).update(overrides)
    return args


def _payload():
    return {"mode": "hunt", "models": ["a", "b"], "items": [{"secret_detail": "not copied"}],
            "failed_models": ["b"], "model_errors": {"b": "failed"}, "model_costs_usd": {"a": 2.0},
            "total_cost_usd": 2.0, "carried_models": ["a"], "resumed_segment": 2,
            "resumed_with_drift": 1, "correlation": {"summary": {"variants": 1}}}


def test_receipt_retains_resume_accounting_without_copying_items(tmp_path):
    args = _args(tmp_path)
    native = tmp_path / "run" / "hunt-result.json"
    native.parent.mkdir()
    payload = _payload()
    native.write_text(json.dumps(payload))
    before = native.read_bytes()
    prepare_understand_report(args, native.parent, Path(args.target))
    result = complete_understand_report(args, payload, native)
    assert not result.errors
    context = json.loads((native.parent / "portable-reports" / "report-context.json").read_text())
    data = context["extensions"]["raptor.result"]
    assert set(data) == {"mode", "backend", "items_recorded", "models", "failed_models", "model_errors",
                         "model_costs_usd", "total_cost_usd", "correlation_summary", "resumed_segment",
                         "carried_models", "resumed_with_drift"}
    assert data["total_cost_usd"] == 2.0
    assert data["resumed_segment"] == 2
    assert data["resumed_with_drift"] == 1
    assert data["carried_models"]["names"] == ["a"]
    assert data["items_recorded"] == 1
    assert context["state"] == "partial"
    assert context["run_id"] == "unknown"
    assert "secret_detail" not in json.dumps(context)
    assert native.read_bytes() == before


def test_metadata_bounds_disclose_omissions(tmp_path):
    args = _args(tmp_path)
    native = tmp_path / "run" / "hunt-result.json"
    payload = _payload()
    payload["models"] = ["model" + str(i) for i in range(102)]
    payload["model_errors"] = {str(i): "x" * 10000 for i in range(102)}
    result = complete_understand_report(args, payload, native)
    assert not result.errors
    context = json.loads((native.parent / "portable-reports" / "report-context.json").read_text())
    data = context["extensions"]["raptor.result"]
    assert data["models"]["total"] == 102
    assert len(data["models"]["names"]) == 100
    assert data["models"]["names_omitted"] == 2
    assert data["model_errors"]["entries_omitted"] == 2
    assert len(data["model_errors"]["entries"][0][1]) < 2100


def test_source_destination_refused_before_report_write(tmp_path):
    args = _args(tmp_path)
    args.report_output = Path(args.target) / "report.json"
    with pytest.raises(ValueError, match="outside the analysed source tree"):
        prepare_understand_report(args, tmp_path / "run", Path(args.target))
    assert not args.report_output.exists()


def test_native_checkpoint_destination_is_reserved(tmp_path):
    out = tmp_path / "run"
    checkpoint = out / "understand-checkpoints" / "model.json"
    checkpoint.parent.mkdir(parents=True)
    checkpoint.write_text("checkpoint")
    args = _args(tmp_path, report_output=checkpoint)
    with pytest.raises(ValueError, match="checkpoints are reserved"):
        prepare_understand_report(args, out, Path(args.target))
    assert checkpoint.read_text() == "checkpoint"


def test_disabled_report_does_not_build_or_refresh(tmp_path, monkeypatch):
    args = _args(tmp_path, report_format=None, no_report=True)
    args._report_options = ReportOptions(enabled=False)
    from packages.code_understanding import reporting
    def forbidden(*args, **kwargs):
        pytest.fail("disabled report must not build a result")
    monkeypatch.setattr(reporting, "NativeResult", forbidden)
    assert complete_understand_report(args, _payload(), tmp_path / "hunt-result.json") is None


def _load_shim(monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    path = Path(__file__).resolve().parents[3] / "libexec" / "raptor-understand"
    loader = SourceFileLoader("understand_reporting_cli", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(module)
    return module


@pytest.mark.parametrize("flags,exported", [(["--report-format", "json"], True), ([], False), (["--no-report"], False)])
def test_public_cli_captures_once_and_keeps_native_summary(tmp_path, monkeypatch, capsys, flags, exported):
    mod = _load_shim(monkeypatch)
    args = _args(tmp_path)
    out = tmp_path / "run"
    calls = []
    monkeypatch.setattr(mod, "_do_hunt", lambda args: calls.append(args.target) or _payload())
    monkeypatch.setattr(mod, "_pin_run_config", lambda *args: None)
    import core.understand_graph as graph
    import core.sage.hooks as sage
    from core.testing.module_views import scoped_function_imports
    with scoped_function_imports(mod, ("_run_modes",), {
        "core.understand_graph": graph, "core.sage.hooks": sage,
    }) as imports:
        getattr(imports, "core.understand_graph").ingest_run = lambda *args: None
        getattr(imports, "core.sage.hooks").store_hunt_results = lambda *args: None
        monkeypatch.setattr(sys, "argv", [str(mod.__file__), "--hunt", "pattern", "--target", args.target,
                                         "--out", str(out), "--model", "a", *flags])
        assert mod.main() == 0
    assert calls == [args.target]
    assert json.loads((out / "hunt-result.json").read_text()) == _payload()
    assert (out / "portable-reports" / "understand-report.json").exists() is exported
    assert "Items: 1" in capsys.readouterr().out


def test_public_cli_source_refusal_precedes_dispatch(tmp_path, monkeypatch):
    mod = _load_shim(monkeypatch)
    args = _args(tmp_path)
    monkeypatch.setattr(mod, "_do_hunt", lambda args: pytest.fail("source refusal must precede dispatch"))
    monkeypatch.setattr(sys, "argv", [str(mod.__file__), "--hunt", "pattern", "--target", args.target,
                                     "--out", str(Path(args.target) / "run"), "--model", "a", "--report-format", "json"])
    assert mod.main() == 1
    assert not (Path(args.target) / "run").exists()


def test_public_cli_refuses_invalid_flags_without_analysis(tmp_path, monkeypatch):
    mod = _load_shim(monkeypatch)
    monkeypatch.setattr(mod, "_main_body", lambda args: pytest.fail("must reject before dispatch"))
    monkeypatch.setattr(sys, "argv", [str(mod.__file__), "--map", "--target", "binary", "--out", str(tmp_path),
                                     "--no-report", "--report-format", "json"])
    with pytest.raises(SystemExit) as exc:
        mod.main()
    assert exc.value.code == 2
