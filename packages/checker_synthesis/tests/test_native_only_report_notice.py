"""Checker refusal paths identify retained portable reports without synthesis."""
import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from core.testing.state_isolation import pin_user_state_dirs
from packages.checker_synthesis import cve_bridge as bridge, reporting


@pytest.fixture(autouse=True)
def no_synthesis(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("repository refusal must precede model construction and synthesis")

    monkeypatch.setattr(bridge, "_build_llm", forbidden)
    monkeypatch.setattr(bridge, "synthesise_checker_from_cve", forbidden)


def _args(tmp_path):
    source = tmp_path / "captured-run"
    source.mkdir()
    return [str(source), "--repo", str(tmp_path / "unavailable-repository"),
            "--library-dir", str(tmp_path / "owned-rule-library")], source / "checkers-bridge"


@pytest.mark.parametrize("disabled", [False, True])
@isolated_cli_logging()
def test_native_only_refusal_preserves_prior_receipt_and_warns_once(tmp_path, monkeypatch, capsys, disabled):
    argv, root = _args(tmp_path)
    assert bridge.cli_main([*argv, "--report-format", "json"]) == 2
    context, _, _ = load_committed_report(root)
    assert context.state == "failed"
    assert context.extensions["raptor.metrics"]["Native exit status"] == 2
    assert context.extensions["raptor.metrics"]["Derived seeds"] is None
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}

    def forbidden(*args, **kwargs):
        pytest.fail("native-only refusal must not construct another portable receipt")

    monkeypatch.setattr(reporting, "complete_bridge_report", forbidden)
    capsys.readouterr()
    flags = ["--no-report"] if disabled else []
    assert bridge.cli_main([*argv, *flags]) == 2
    streams = capsys.readouterr()
    assert streams.out == "" and "repo not found" in streams.err
    assert streams.err.count("prior report artifacts were not refreshed") == 1
    assert "Summary" not in streams.err
    assert {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("disabled", [False, True])
@isolated_cli_logging()
def test_fresh_native_only_refusal_keeps_native_error_without_portable_output(tmp_path, capsys, disabled):
    argv, root = _args(tmp_path)
    flags = ["--no-report"] if disabled else []
    assert bridge.cli_main([*argv, *flags]) == 2
    streams = capsys.readouterr()
    assert streams.out == "" and "repo not found" in streams.err
    assert "prior report artifacts" not in streams.err and "Summary" not in streams.err
    assert not root.exists()
