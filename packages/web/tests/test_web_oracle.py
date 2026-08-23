"""Three-gate web oracle behavior of the fuzzer (no network)."""

from __future__ import annotations

from types import SimpleNamespace

from packages.web.client import WebClient
from packages.web.fuzzer import WebFuzzer
from packages.web.markers import find_marker, marker_present


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
    assert finding["confirmed"] is True
    assert finding["baseline_evidence"].startswith("HTTP 200")
    assert "attack HTTP 500" in finding["diff_summary"]
    assert finding["attack_evidence"] == finding["response_evidence"]
    assert finding["oracle_signal"].startswith("sqli_error:")


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


def test_xss_requires_unescaped_reflection():
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)
    payload = "<script>alert(1)</script>"

    escaped_only = _response(
        200, "you searched for &lt;script&gt;alert(1)&lt;/script&gt;"
    )
    assert fuzzer._analyze_response(escaped_only, payload, "xss") is None

    both = _response(
        200,
        f"raw {payload} and escaped &lt;script&gt;alert(1)&lt;/script&gt;",
    )
    assert fuzzer._analyze_response(both, payload, "xss") is None

    raw_only = _response(200, f"hello {payload} world")
    confirmation = fuzzer._analyze_response(raw_only, payload, "xss")
    assert confirmation is not None
    assert confirmation["signal"] == "xss_reflected_unescaped"


def test_ssti_marker_requires_baseline_diff():
    """'49' in a response means nothing on its own — the three-gate
    baseline veto is what makes the ssti marker usable."""
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)

    # Page that always contains 49: vetoed.
    responses = iter([
        _response(200, "products found: 49"),
        _response(200, "products found: 49"),
    ])
    client.get = lambda url, params=None: next(responses)
    assert (
        fuzzer._test_payload("https://example.test/s", "q", "{{7*7}}", "ssti")
        is None
    )

    # Evaluated template only in the attack leg: confirmed.
    responses = iter([
        _response(200, "you searched for raptor-baseline"),
        _response(200, "you searched for 49"),
    ])
    client.get = lambda url, params=None: next(responses)
    finding = fuzzer._test_payload("https://example.test/s", "q", "{{7*7}}", "ssti")
    assert finding is not None
    assert finding["oracle_signal"] == "ssti_evaluated:49"


def test_no_llm_fuzzer_uses_static_payloads():
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)  # no LLM

    payloads = fuzzer._generate_payloads("q", "text", "sqli")

    assert payloads == fuzzer._get_basic_payloads("sqli", param_name="q")
    assert fuzzer.payload_cache_stats == (0, 0)


def test_fuzz_parameter_stops_after_first_confirmed_hit_per_class(monkeypatch):
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client)
    tested: list[str] = []

    def fake_test(url, param, payload, vuln_type, method="GET"):
        tested.append(payload)
        return {"payload": payload, "vulnerability_type": vuln_type}

    monkeypatch.setattr(fuzzer, "_test_payload", fake_test)

    findings = fuzzer.fuzz_parameter(
        "https://example.test/s", "q", vulnerability_types=["sqli"]
    )

    assert len(findings) == 1
    assert len(tested) == 1  # first confirmed hit ends the class


def test_markers_shared_between_fuzzer_and_oracle_tiers():
    """find_marker feeds the fuzzer's signals; marker_present drives the
    verification oracle's replay legs — same patterns by construction."""
    body = "boom: uid=1000(web) gid=1000(web)"
    assert marker_present("command_injection", body)
    assert find_marker("command_injection", body) == "uid=1000(web)"

    assert marker_present("ssti", "result 49 here")
    assert not marker_present("ssti", "result 50 here")
    assert not marker_present("nosuchclass", body)
