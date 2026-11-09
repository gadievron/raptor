"""Trace report controls delegate once without changing execution policy."""
import json

import pytest

from core.hash import sha256_file
from core.testing.logging_state import isolated_cli_logging
from core.testing.module_bindings import patch_module_attribute
from packages.binary_analysis import cli
from packages.binary_analysis.manifest import BinaryManifest


@pytest.mark.parametrize("flags,expected", [([], []), (["--no-report"], ["--no-report"])])
@isolated_cli_logging()
def test_runtime_defaults_and_disable_keep_one_child_and_status(monkeypatch, flags, expected):
    calls = []
    patch_module_attribute(monkeypatch, cli, "subprocess", "call", lambda command, **kwargs: calls.append(command) or 3)
    assert cli.main(["runtime", "1234", *flags]) == 3
    assert len(calls) == 1
    command = calls[0]
    assert command[1:7] == ["--target", "1234", "--template", "binary-flow-trace", "--duration", "30"]
    assert command[7:] == expected
    assert "--unsafe-attach" not in command and "--spawn" not in command


@isolated_cli_logging()
def test_runtime_forwards_formats_and_resolves_report_output_before_child_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    calls = []
    patch_module_attribute(monkeypatch, cli, "subprocess", "call", lambda command, **kwargs: calls.append(command) or 0)
    assert cli.main(["runtime", "1234", "--report-format", "json", "--report-format", "xml",
                     "--report-output", "receipts"]) == 0
    assert calls[0][-6:] == ["--report-format", "json", "--report-format", "xml", "--report-output", str(tmp_path / "receipts")]
    assert len(calls) == 1


@isolated_cli_logging()
def test_runtime_report_preflight_precedes_child(monkeypatch, tmp_path):
    patch_module_attribute(monkeypatch, cli, "subprocess", "call", lambda *args, **kwargs: pytest.fail("must preflight"))
    with pytest.raises(SystemExit) as error:
        cli.main(["runtime", "1234", "--report-format", "json", "--report-output", str(tmp_path / "bad.xml")])
    assert error.value.code == 2


def _mapped(tmp_path, *, valid):
    binary = tmp_path / "sample"
    binary.write_bytes(b"owned fixture")
    run = tmp_path / "run"
    run.mkdir()
    manifest = BinaryManifest(schema_version=1, binary_path=str(binary), binary_sha256=sha256_file(binary) if valid else "0" * 64,
                              size_bytes=binary.stat().st_size, executable=True, target_kind="elf", arch="x86", bits=64, binary_format="elf")
    (run / "binary-manifest.json").write_text(json.dumps(manifest.to_dict()))
    return run


@isolated_cli_logging()
def test_trace_parser_still_refuses_changed_binary_before_any_child(tmp_path, monkeypatch, capsys):
    run = _mapped(tmp_path, valid=False)
    monkeypatch.setattr(cli, "_run_active_phase", lambda **kwargs: pytest.fail("identity gate must run first"))
    assert cli.main(["trace-parser", str(run), "--report-format", "json"]) == 2
    assert "mapped binary has changed" in capsys.readouterr().err


@isolated_cli_logging()
def test_trace_parser_forwards_report_controls_once_and_preserves_phase_failure(tmp_path, monkeypatch):
    run = _mapped(tmp_path, valid=True)
    phases = []
    monkeypatch.setattr(cli, "_run_active_phase", lambda **kwargs: phases.append(kwargs) or {
        "status": "failed", "stderr": str(run / "parser-runtime" / "stderr.log")})
    monkeypatch.setattr(cli, "append_runtime_evidence_to_run", lambda *args, **kwargs: pytest.fail("failed phase must not refresh"))
    assert cli.main(["trace-parser", str(run), "--report-format", "json"]) == 1
    assert len(phases) == 1
    command = phases[0]["cmd"]
    assert command[-2:] == ["--report-format", "json"]
    assert "--unsafe-attach" not in command
    assert command[command.index("--out") + 1] == str(run / "parser-runtime")
