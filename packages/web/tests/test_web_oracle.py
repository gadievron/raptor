from types import SimpleNamespace

from packages.web.client import WebClient
from packages.web.fuzzer import WebFuzzer
from packages.web.models import WebFinding
from packages.web.verified_outcomes import from_web_finding


def _response(status, text):
    return SimpleNamespace(
        status_code=status,
        text=text,
        content=text.encode(),
    )


def test_fuzzer_requires_attack_diff_for_confirmation():
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)
    responses = iter([
        _response(200, "normal search page"),
        _response(500, "You have an error in your SQL syntax near q"),
    ])
    client.get = lambda url, params=None: next(responses)

    finding = fuzzer._test_payload(
        "https://example.test/search",
        "q",
        "' OR 1=1--",
        "sqli",
    )

    assert finding is not None
    assert finding["baseline_evidence"].startswith("HTTP 200")
    assert "attack HTTP 500" in finding["diff_summary"]
    assert finding["attack_evidence"] == finding["response_evidence"]


def test_fuzzer_rejects_signal_already_present_in_baseline():
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)
    responses = iter([
        _response(200, "You have an error in your SQL syntax near docs"),
        _response(200, "You have an error in your SQL syntax near docs"),
    ])
    client.get = lambda url, params=None: next(responses)

    finding = fuzzer._test_payload(
        "https://example.test/search",
        "q",
        "' OR 1=1--",
        "sqli",
    )

    assert finding is None


def test_fuzzer_replaces_existing_query_param_instead_of_appending():
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)

    replaced = fuzzer._url_with_param(
        "https://example.test/xss/reflect?q=test&lang=en",
        "q",
        "<script>alert(1)</script>",
    )

    assert replaced == (
        "https://example.test/xss/reflect?"
        "lang=en&q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    )


def test_command_oracle_accepts_non_root_id_output():
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)

    response = _response(200, "<pre>uid=999(appuser) gid=999(appuser)</pre>")
    confirmation = fuzzer._analyze_response(
        response,
        "127.0.0.1; id",
        "command_injection",
    )

    assert confirmation is not None
    assert confirmation["signal"] == "command_output:uid=999(appuser)"


def test_host_like_command_payloads_include_prefix_value():
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)

    payloads = fuzzer._get_basic_payloads("command_injection", param_name="host")

    assert payloads[0] == "127.0.0.1; id"
    assert any(payload.startswith("127.0.0.1") for payload in payloads)


def test_command_like_payloads_try_direct_id_with_inert_baseline():
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)

    payloads = fuzzer._get_basic_payloads("command_injection", param_name="cmd")

    assert payloads[0] == "id"
    assert fuzzer._baseline_value("cmd") == "raptor-baseline"


def test_web_finding_maps_to_verified_outcome():
    finding = WebFinding(
        id="WEB-0001",
        title="SQL Injection",
        severity="high",
        confidence="medium",
        status="needs_review",
        url="https://example.test/search",
        evidence="confirmed",
        description="SQLi",
        recommendation="Use parameterised queries",
        vuln_type="injection",
        asvs_category="V5",
        check_id="V5.2.1",
        cwe_id="CWE-89",
        confirmed=True,
        target_url="https://example.test/search",
        confirmation_payload="' OR 1=1--",
        response_evidence="SQL syntax",
        baseline_evidence="HTTP 200, 10 bytes",
        attack_evidence="SQL syntax",
        diff_summary="baseline HTTP 200/10 bytes; attack HTTP 500/50 bytes",
        attack_vector="query_param",
        method="GET",
    )

    outcome = from_web_finding(finding)

    assert outcome is not None
    data = outcome.to_dict()
    assert data["oracle"] == "web"
    assert data["status"] == "verified"
    assert data["reproducible"] is False
    assert data["evidence"]["payload"] == "' OR 1=1--"
    assert data["evidence"]["diff_summary"].startswith("baseline HTTP")
