"""Proxy policy verdicts, rather than client errors, establish network denials."""
from unittest.mock import Mock

import pytest

from core.sandbox import observe


@pytest.fixture
def evidence(monkeypatch):
    record = Mock()
    log = Mock()
    monkeypatch.setattr(observe, "record_denial", record)
    monkeypatch.setattr(observe, "logger", log)
    return record, log


@pytest.mark.parametrize("events", [
    [], [{"result": "allowed"}], [{"result": "upstream_failed"}],
    [{"result": "dns_failed"}], [{"result": "bad_request"}],
    [{"result": "refused_capacity"}], [{"result": "parser_unavailable"}],
    [{"result": "timed_out"}], [{"result": "would_deny_host"}],
    [{"result": "would_deny_resolved_ip"}],
])
def test_connection_failure_is_not_a_proxy_policy_denial(events, evidence):
    record, log = evidence
    info = {}
    observe._check_blocked(
        "requests.exceptions.ConnectionError: RemoteDisconnected; Connection refused",
        "semgrep scan --config", 2, info, network_engaged=True, proxy_events=events,
    )
    assert "blocked" not in info
    record.assert_not_called()
    log.info.assert_not_called()


@pytest.mark.parametrize("verdict", [
    "denied_host", "denied_resolved_ip", "denied_port", "denied_sni",
])
@pytest.mark.parametrize("stderr,returncode", [("", 0), ("ConnectionError", 2)])
def test_recorded_proxy_denial_survives_empty_stderr_and_success(
    verdict, stderr, returncode, evidence,
):
    record, log = evidence
    events = [{"result": "allowed"}, {"result": verdict}, {"result": verdict}]
    info = {}
    observe._check_blocked(
        stderr, "tool", returncode, info, network_engaged=True, proxy_events=events,
    )
    assert info["blocked"] == ["Outbound connection denied by egress proxy policy"]
    record.assert_called_once_with("tool", returncode, "network")
    log.info.assert_called_once()


def test_nonproxy_network_attribution_is_unchanged(evidence):
    record, _log = evidence
    info = {}
    observe._check_blocked(
        "Network is unreachable", "tool", 1, info, network_engaged=True,
    )
    assert len(info["blocked"]) == 1
    record.assert_called_once_with("tool", 1, "network")


def test_proxy_mode_keeps_other_enforcement_evidence(evidence):
    record, _log = evidence
    info = {}
    observe._check_blocked(
        "ConnectionError; cannot create '/outside': Permission denied",
        "tool", 1, info, network_engaged=True, landlock_engaged=True, proxy_events=[],
    )
    assert len(info["blocked"]) == 1
    assert "write" in info["blocked"][0].lower()
    assert record.call_args.args[2] == "write"


def test_real_proxy_denial_is_attributed_without_child_stderr(tmp_path, monkeypatch, evidence):
    import sys
    from core.sandbox import sandbox
    from core.testing.proxy_scope import isolated_proxy_scope

    record, _log = evidence
    code = """
import urllib.request, urllib.error
try:
    urllib.request.urlopen('https://denied.invalid/', timeout=5)
except urllib.error.URLError as error:
    print(str(error.reason))
    if '403' not in str(error.reason):
        raise SystemExit(2)
else:
    raise SystemExit(3)
"""
    with isolated_proxy_scope():
        with sandbox(profile="none", use_egress_proxy=True,
                     proxy_hosts=["allowed.invalid"], output=str(tmp_path)) as run:
            result = run([sys.executable, "-S", "-c", code],
                         text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr + result.stdout
    assert result.stderr == ""
    assert any(event["result"] == "denied_host"
               for event in result.sandbox_info["proxy_events"])
    assert result.sandbox_info["blocked"] == ["Outbound connection denied by egress proxy policy"]
    record.assert_called_once()
    assert record.call_args.args[1:] == (0, "network")
