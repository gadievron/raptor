from types import SimpleNamespace

from packages.web.client import WebClient
from packages.web.fuzzer import WebFuzzer


class DummyLLM:
    pass


def _response():
    return SimpleNamespace(status_code=200, content=b"ok", text="sql syntax error")


def test_web_client_redacts_secret_urls_in_history_by_default():
    secret_value = "api-" + "a" * 24
    client = WebClient("https://example.test")

    client._log_request(
        "GET",
        f"https://example.test/path?api_key={secret_value}&debug=true",
        _response(),
        0.01,
    )

    logged_url = client.request_history[0]["url"]
    assert secret_value not in logged_url
    assert "api_key=[REDACTED]" in logged_url
    assert "debug=true" in logged_url


def test_web_client_ignores_legacy_reveal_environment(monkeypatch):
    secret_value = "api-" + "b" * 24
    legacy_env_name = "RAPTOR_REVEAL" + "_TARGET_SECRETS"
    monkeypatch.setenv(legacy_env_name, "true")
    client = WebClient("https://example.test")

    client._log_request(
        "GET",
        f"https://example.test/path?api_key={secret_value}&debug=true",
        _response(),
        0.01,
    )

    logged_url = client.request_history[0]["url"]
    assert secret_value not in logged_url
    assert "api_key=[REDACTED]" in logged_url


def test_web_client_can_preserve_secret_urls_for_debugging():
    secret_value = "api-" + "d" * 24
    client = WebClient("https://example.test", reveal_secrets=True)

    client._log_request(
        "GET",
        f"https://example.test/path?api_key={secret_value}&debug=true",
        _response(),
        0.01,
    )

    assert client.request_history[0]["url"].endswith(f"api_key={secret_value}&debug=true")



def test_web_fuzzer_redacts_finding_urls_by_default():
    secret_value = "access-" + "e" * 24
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client, DummyLLM())
    client.get = lambda url, params=None: _response()

    finding = fuzzer._test_payload(
        f"https://example.test/search?access_token={secret_value}",
        "q",
        "' OR '1'='1",
        "sqli",
    )

    assert finding is not None
    assert secret_value not in finding["url"]
    assert "access_token=[REDACTED]" in finding["url"]


def test_web_fuzzer_can_preserve_finding_urls_for_debugging():
    secret_value = "access-" + "f" * 24
    client = WebClient("https://example.test", reveal_secrets=True)
    fuzzer = WebFuzzer(client, DummyLLM())
    client.get = lambda url, params=None: _response()

    finding = fuzzer._test_payload(
        f"https://example.test/search?access_token={secret_value}",
        "q",
        "' OR '1'='1",
        "sqli",
    )

    assert finding is not None
    assert finding["url"].endswith(f"access_token={secret_value}")
