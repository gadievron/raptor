"""Health report wiring retains native reachability and offline semantics."""
import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.sca import health
from packages.sca.health_reporting import health_result


@isolated_cli_logging()
def test_health_report_reuses_completed_probes_and_preserves_gate(tmp_path, monkeypatch, capsys):
    calls = []

    class Registry:
        def __init__(self, *args, **kwargs):
            pass

        def list_versions(self, package):
            calls.append(package)
            return ["1.0"] if package == "reachable" else []

    monkeypatch.setattr(health, "_PROBES", [("owned-a", Registry, "reachable"), ("owned-b", Registry, "unreachable")])
    output = tmp_path / "health.json"
    assert health.main(["--report-format", "json", "--report-output", str(output)]) == 1
    assert sorted(calls) == ["reachable", "unreachable"]
    streams = capsys.readouterr()
    assert "1/2 registries healthy" in streams.out and "Summary" in streams.err
    context, _, _ = load_committed_report(tmp_path / ".health-report")
    assert context.state == "partial"
    assert context.extensions["raptor.metrics"]["Failed registry probes"] == 1
    assert len(context.extensions["raptor.result"]["probes"]) == 2
    assert context.extensions["raptor.findings_available"] is False


@isolated_cli_logging()
def test_offline_receipt_is_unavailable_not_failed_registry_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(health, "default_client", lambda: pytest.fail("offline must not build transport"))
    assert health.main(["--offline", "--report-format", "json", "--report-output", str(tmp_path / "offline.json")]) == 2
    context, _, _ = load_committed_report(tmp_path / ".offline-report")
    assert context.state == "failed" and context.extensions["raptor.result"]["probes"] == []
    assert any("No live" in note for note in context.diagnostics)


def test_health_capture_redacts_proxy_credentials_without_mutating_probe():
    probe = health._ProbeResult("owned", "package", False, 12, 0,
                               "proxy https://user:owned-password@example.invalid refused\x1b[31m")
    context, _ = health_result([probe]).build()
    error = context.extensions["raptor.result"]["probes"][0]["error"]
    assert "owned-password" not in error and "\x1b" not in error
    assert "owned-password" in probe.error


def test_health_report_format_requires_destination_before_probes(monkeypatch):
    monkeypatch.setattr(health, "default_client", lambda: pytest.fail("invalid reporting must not probe"))
    with pytest.raises(SystemExit) as error:
        health.main(["--report-format", "json"])
    assert error.value.code == 2
