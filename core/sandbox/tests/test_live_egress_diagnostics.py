"""Live-canary failures retain evidence without becoming successful results."""

from subprocess import CompletedProcess

import pytest

from core.sandbox.tests import test_e2e_sandbox as e2e
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize("returncode,events", [
    pytest.param(28, [{"result": "allowed", "host": "github.com"}], id="transfer-timeout"),
    pytest.param(56, [], id="proxy-receive-failure"),
    pytest.param(0, [], id="missing-allow-event"),
])
def test_live_egress_failure_reports_transfer_and_proxy_evidence(monkeypatch, returncode, events):
    result = CompletedProcess([], returncode, "HTTP/1.1 200 Connection established\r\n",
                              "curl timings: tls=0 first_byte=0 total=15 http=000")
    result.sandbox_info = {"proxy_events": events}

    def run(command, **options):
        assert "-sSI" in command
        assert command[command.index("--max-time") + 1] == "15"
        assert "%{time_appconnect}" in command[command.index("--write-out") + 1]
        assert options["use_egress_proxy"]
        assert options["proxy_hosts"] == ["github.com"]
        assert options["timeout"] == 20
        return result

    patch_module_attribute(monkeypatch, e2e, "shutil", "which", lambda _: "/owned/curl")
    monkeypatch.setattr(e2e, "sandbox_run", run)
    case = e2e.TestE2EEgressProxy("test_allowed_host_succeeds")
    # Call only the assertion path; the native suite owns real namespace and
    # network execution. This test must not start a listener or contact GitHub.
    with pytest.raises(AssertionError) as raised:
        case.test_allowed_host_succeeds()
    diagnostic = str(raised.value)
    assert f"curl exit={returncode}" in diagnostic
    assert "HTTP/1.1 200 Connection established" in diagnostic
    assert result.stderr in diagnostic
    assert f"proxy_events={events!r}" in diagnostic
