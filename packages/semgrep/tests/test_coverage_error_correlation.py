"""Correlate native JSON diagnostics without merging unrelated failures."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from core.testing.module_bindings import patch_module_attribute
from packages.semgrep import runner, runtime
from packages.semgrep.coverage import to_coverage_record
from packages.semgrep.models import SemgrepResult, parse_json_output


def _payload(errors):
    return json.dumps({"version": "1.2.3", "paths": {"scanned": ["a.py"]},
                       "errors": errors})


def _error(message, path=None):
    entry = {"type": "SemgrepError", "level": "error", "message": message}
    if path is not None:
        entry["path"] = path
    return entry


@pytest.mark.parametrize("message", ["x" * 500, "broken\nsource"],
                         ids=["truncated", "escaped"])
def test_path_diagnostic_is_not_duplicated(message):
    result = SemgrepResult(name="pack", **parse_json_output(
        _payload([_error(message, "a.py")])
    ))
    record = to_coverage_record([result])
    assert [entry["path"] for entry in record["files_failed"]] == ["a.py"]
    assert result.errors and not result.ok
    assert result.files_failed[0]["reason"] == message
    assert "_path_error_renderings" not in result.to_dict()


def test_identical_unassociated_error_retains_its_multiplicity():
    result = SemgrepResult(name="pack", **parse_json_output(
        _payload([_error("same", "a.py"), _error("same")])
    ))
    record = to_coverage_record([result])
    assert [entry["path"] for entry in record["files_failed"]] == ["a.py", "pack"]
    assert len(result.errors) == 2


def test_runner_transports_error_correlation(tmp_path, monkeypatch):
    monkeypatch.setattr(RaptorConfig, "SEMGREP_OFFLINE", False)
    monkeypatch.setattr(runner, "is_available", lambda *args: True)
    monkeypatch.setattr(runner, "scope_isolation_available", lambda *args: True)
    monkeypatch.setattr(runner, "resolve_snap_runtime", lambda *args: None)
    patch_module_attribute(monkeypatch, runner, "shutil", "which",
                           lambda *args: "/owned/semgrep")
    calls = []
    payload = _payload([_error("x" * 500, "a.py")])

    def execute(command, **kwargs):
        calls.append(command)
        Path(command[command.index("--json-output") + 1]).write_text(payload)
        return SimpleNamespace(returncode=2, stderr="", stdout=json.dumps({
            "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}},
                                          "results": []}],
        }))

    result = runner.run_rule(tmp_path, "owned.yaml", name="pack",
                             json_output_path=tmp_path / "metadata.json",
                             subprocess_runner=execute)
    assert len(calls) == 1
    record = to_coverage_record([result])
    assert [entry["path"] for entry in record["files_failed"]] == ["a.py"]
    assert result.errors and not result.ok


def test_rejected_snap_payload_keeps_uncorrelated_errors(tmp_path, monkeypatch):
    class OwnedRuntime(runtime.SnapRuntime):
        def validate(self):
            return None  # Runtime installation trust has separate controls.

    spec = OwnedRuntime(
        "/owned/semgrep", tmp_path / "app", tmp_path / "base",
        tmp_path / "base/python", tmp_path / "app/pysemgrep",
        tmp_path / "app/site-packages", tmp_path / "base/stdlib", "1.56.0", (),
    )
    monkeypatch.setattr(RaptorConfig, "SEMGREP_OFFLINE", False)
    monkeypatch.setattr(runner, "is_available", lambda *args: True)
    monkeypatch.setattr(runner, "scope_isolation_available", lambda *args: True)
    monkeypatch.setattr(runner, "resolve_snap_runtime", lambda *args: spec)
    patch_module_attribute(monkeypatch, runner, "shutil", "which",
                           lambda *args: "/owned/semgrep")
    payload = _payload([_error("x" * 500, "a.py")])
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=2, stderr="", stdout=payload)

    execute.with_semgrep_runtime = lambda selected: execute
    result = runner.run_rule(tmp_path, "owned.yaml", name="pack",
                             json_output_path=tmp_path / "metadata.json",
                             subprocess_runner=execute)
    assert len(calls) == 1
    assert result.json_output == payload
    assert not result.files_failed and not result.files_examined
    assert any("version does not match" in error for error in result.errors)
    assert any(error.startswith("SemgrepError:") for error in result.errors)
    record = to_coverage_record([result])
    assert len(record["files_failed"]) == len(result.errors)
    assert all(entry["path"] == "pack" for entry in record["files_failed"])
