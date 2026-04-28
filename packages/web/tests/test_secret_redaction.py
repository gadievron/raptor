from types import SimpleNamespace

from packages.web.client import WebClient
from packages.web.fuzzer import WebFuzzer


class DummyLLM:
    pass


def _response():
    return SimpleNamespace(status_code=200, content=b"ok", text="sql syntax error")


def test_web_client_redacts_secret_urls_in_history_by_default():
    redaction_probe = "api-" + "a" * 24
    client = WebClient("https://example.test")

    client._log_request(
        "GET",
        f"https://example.test/path?api_key={redaction_probe}&debug=true",
        _response(),
        0.01,
    )

    logged_url = client.request_history[0]["url"]
    assert redaction_probe not in logged_url
    assert "api_key=[REDACTED]" in logged_url
    assert "debug=true" in logged_url


def test_web_client_ignores_legacy_reveal_environment(monkeypatch):
    redaction_probe = "api-" + "b" * 24
    legacy_env_name = "RAPTOR_REVEAL" + "_TARGET_SECRETS"
    monkeypatch.setenv(legacy_env_name, "true")
    client = WebClient("https://example.test")

    client._log_request(
        "GET",
        f"https://example.test/path?api_key={redaction_probe}&debug=true",
        _response(),
        0.01,
    )

    logged_url = client.request_history[0]["url"]
    assert redaction_probe not in logged_url
    assert "api_key=[REDACTED]" in logged_url


def test_web_client_can_preserve_secret_urls_for_debugging():
    redaction_probe = "api-" + "d" * 24
    client = WebClient("https://example.test", reveal_secrets=True)

    client._log_request(
        "GET",
        f"https://example.test/path?api_key={redaction_probe}&debug=true",
        _response(),
        0.01,
    )

    assert client.request_history[0]["url"].endswith(f"api_key={redaction_probe}&debug=true")



def test_web_fuzzer_redacts_finding_urls_by_default():
    redaction_probe = "access-" + "e" * 24
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client, DummyLLM())
    client.get = lambda url, params=None: _response()

    finding = fuzzer._test_payload(
        f"https://example.test/search?access_token={redaction_probe}",
        "q",
        "' OR '1'='1",
        "sqli",
    )

    assert finding is not None
    assert redaction_probe not in finding["url"]
    assert "access_token=[REDACTED]" in finding["url"]


def test_web_fuzzer_can_preserve_finding_urls_for_debugging():
    redaction_probe = "access-" + "f" * 24
    client = WebClient("https://example.test", reveal_secrets=True)
    fuzzer = WebFuzzer(client, DummyLLM())
    client.get = lambda url, params=None: _response()

    finding = fuzzer._test_payload(
        f"https://example.test/search?access_token={redaction_probe}",
        "q",
        "' OR '1'='1",
        "sqli",
    )

    assert finding is not None
    assert finding["url"].endswith(f"access_token={redaction_probe}")


class RecordingLogger:
    def __init__(self):
        self.messages = []

    def info(self, message, **kwargs):
        self.messages.append(message)

    def warning(self, message, **kwargs):
        self.messages.append(message)

    def error(self, message, **kwargs):
        self.messages.append(message)

    def debug(self, message, **kwargs):
        self.messages.append(message)


def test_web_client_redacts_timeout_urls_in_logs(monkeypatch):
    import packages.web.client as client_module
    import requests

    redaction_probe = "api-" + "g" * 24
    recorder = RecordingLogger()
    client = WebClient("https://example.test")
    monkeypatch.setattr(client_module, "logger", recorder)

    def raise_timeout(*args, **kwargs):
        raise requests.exceptions.Timeout("boom")

    monkeypatch.setattr(client.session, "request", raise_timeout)

    try:
        client.get(f"/slow?api_key={redaction_probe}")
    except requests.exceptions.Timeout:
        pass

    joined = "\n".join(recorder.messages)
    assert redaction_probe not in joined
    assert "api_key=[REDACTED]" in joined


def test_web_client_redacts_request_exception_urls_in_logs(monkeypatch):
    import packages.web.client as client_module
    import requests

    redaction_probe = "access-" + "h" * 24
    recorder = RecordingLogger()
    client = WebClient("https://example.test")
    monkeypatch.setattr(client_module, "logger", recorder)

    def raise_error(*args, **kwargs):
        raise requests.exceptions.RequestException(
            f"failed for https://example.test/path?access_token={redaction_probe}"
        )

    monkeypatch.setattr(client.session, "request", raise_error)

    try:
        client.post("/path")
    except requests.exceptions.RequestException:
        pass

    joined = "\n".join(recorder.messages)
    assert redaction_probe not in joined
    assert "access_token=[REDACTED]" in joined


def test_web_fuzzer_redacts_secret_urls_in_start_log(monkeypatch):
    import packages.web.fuzzer as fuzzer_module

    redaction_probe = "client-" + "i" * 24
    recorder = RecordingLogger()
    client = WebClient("https://example.test")
    fuzzer = WebFuzzer(client, DummyLLM())
    monkeypatch.setattr(fuzzer_module, "logger", recorder)
    monkeypatch.setattr(fuzzer, "_generate_payloads", lambda *args, **kwargs: [])

    fuzzer.fuzz_parameter(
        f"https://example.test/search?client_secret={redaction_probe}&q=term",
        "q",
    )

    joined = "\n".join(recorder.messages)
    assert redaction_probe not in joined
    assert "client_secret=[REDACTED]" in joined
    assert "q=term" in joined
