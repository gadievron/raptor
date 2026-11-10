"""Reject reserved report destinations before a consumer starts capture/work."""
import pytest

from core.reporting.options import ReportOptions


def test_options_refuse_reserved_persistence_file_before_capture(tmp_path):
    source = tmp_path / "report-context.json"
    source.write_text('{"native": "evidence"}')
    original = source.read_bytes()
    with pytest.raises(ValueError, match="reserved persistence filename"):
        ReportOptions(("json",), source).validate()
    assert source.read_bytes() == original


def test_reserved_destination_stops_cli_before_capture(tmp_path, monkeypatch):
    from core.reporting import __main__ as cli

    source = tmp_path / "captured.sarif"
    source.write_text('{"version":"2.1.0","runs":[]}')
    output = tmp_path / "reports"
    calls = []

    def capture(*args, **kwargs):
        calls.append(args)
        raise AssertionError("capture must not start")

    monkeypatch.setattr(cli, "context_from_sarif", capture)
    with pytest.raises(SystemExit) as error:
        cli.main(["sarif", str(source), "--out", str(output),
                  "--report-format", "json", "--report-output",
                  str(tmp_path / "report-context.json")])
    assert error.value.code == 2
    assert calls == []
    assert not output.exists()
    assert source.read_text() == '{"version":"2.1.0","runs":[]}'


@pytest.mark.parametrize("relative", [".reporting", ".reporting/generation/result.json"])
def test_generation_destinations_refused(tmp_path, relative):
    with pytest.raises(ValueError, match="immutable reporting generation"):
        ReportOptions(("json",), tmp_path / relative).validate()


def test_alias_to_reserved_source_refused(tmp_path):
    source = tmp_path / "report-context.json"
    source.write_text("captured")
    alias = tmp_path / "export.json"
    alias.symlink_to(source)
    with pytest.raises(ValueError, match="reserved persistence filename"):
        ReportOptions(("json",), alias).validate()
    assert source.read_text() == "captured"


def test_reserved_override_refused_without_output_directory():
    with pytest.raises(ValueError, match="reserved persistence filename"):
        ReportOptions(("json",), filenames=(("json", "summary.json"),)).validate()


def test_override_alias_checked_at_actual_directory(tmp_path):
    source = tmp_path / "report-context.json"
    source.write_text("captured")
    (tmp_path / "custom.json").symlink_to(source)
    with pytest.raises(ValueError, match="reserved persistence filename"):
        ReportOptions(("json",), tmp_path,
                      filenames=(("json", "custom.json"),)).validate()
    assert source.read_text() == "captured"


@pytest.mark.parametrize("name", ["exports", "summary.json", "report-context.json"])
def test_existing_directories_keep_directory_semantics(tmp_path, name):
    directory = tmp_path / name
    directory.mkdir()
    options = ReportOptions(("json",), directory)
    assert options.validate() == options
    assert list(directory.iterdir()) == []


def test_valid_file_and_disabled_export_preserved(tmp_path):
    normal = ReportOptions(("json",), tmp_path / "results.json")
    assert normal.validate() == normal
    disabled = ReportOptions(("json",), tmp_path / "report-context.json", enabled=False)
    assert disabled.validate() == disabled
    assert list(tmp_path.iterdir()) == []
