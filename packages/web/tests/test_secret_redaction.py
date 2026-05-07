from types import SimpleNamespace

from packages.web.client import WebClient
from packages.web.crawler import WebCrawler
from packages.web.fuzzer import WebFuzzer


class DummyLLM:
    pass


def _response():
    return SimpleNamespace(status_code=200, content=b"ok", text="sql syntax error")


def test_web_crawler_redacts_secret_url_artifacts_by_default():
    api_key = "api-" + "j" * 24
    access_probe = "access-" + "k" * 24
    client_probe = "client-" + "l" * 24
    refresh_probe = "refresh-" + "m" * 24
    crawler = WebCrawler(WebClient("https://example.test"))
    crawler.visited_urls.add(f"https://example.test/start?api_key={api_key}&debug=true")
    crawler.discovered_urls.add(
        f"https://example.test/callback#access_token={access_probe}&state=ok"
    )
    crawler.discovered_forms.append(
        {
            "action": f"https://example.test/login?client_secret={client_probe}",
            "method": "POST",
            "inputs": {"username": {"type": "text", "value": ""}},
            "page_url": f"https://example.test/form?refresh_token={refresh_probe}",
        }
    )
    crawler.discovered_apis.append(
        {
            "url": f"https://example.test/api?access_token={access_probe}",
            "method": "GET",
            "response_keys": ["ok"],
        }
    )

    results = crawler.get_results()
    rendered = str(results)

    assert api_key not in rendered
    assert access_probe not in rendered
    assert client_probe not in rendered
    assert refresh_probe not in rendered
    assert "api_key=[REDACTED]" in rendered
    assert "access_token=[REDACTED]" in rendered
    assert "client_secret=[REDACTED]" in rendered
    assert "refresh_token=[REDACTED]" in rendered
    assert "debug=true" in rendered
    assert "state=ok" in rendered


def test_web_crawler_can_preserve_secret_url_artifacts_for_debugging():
    api_key = "api-" + "n" * 24
    access_probe = "access-" + "o" * 24
    client_probe = "client-" + "p" * 24
    client = WebClient("https://example.test", reveal_secrets=True)
    crawler = WebCrawler(client)
    crawler.visited_urls.add(f"https://example.test/start?api_key={api_key}")
    crawler.discovered_urls.add(
        f"https://example.test/callback?access_token={access_probe}"
    )
    crawler.discovered_forms.append(
        {
            "action": f"https://example.test/login?client_secret={client_probe}",
            "method": "POST",
            "inputs": {},
            "page_url": "https://example.test/form",
        }
    )

    rendered = str(crawler.get_results())

    assert api_key in rendered
    assert access_probe in rendered
    assert client_probe in rendered


def test_web_crawler_redacts_secret_urls_in_logs(monkeypatch):
    import packages.web.crawler as crawler_module

    api_key = "api-" + "q" * 24
    recorder = RecordingLogger()
    crawler = WebCrawler(WebClient("https://example.test"), max_depth=0)
    monkeypatch.setattr(crawler_module, "logger", recorder)
    monkeypatch.setattr(
        crawler.client, "get", lambda path: SimpleNamespace(status_code=404)
    )

    url = "https://example.test/start?" + "api_key=" + api_key
    crawler.crawl(url)

    joined = "\n".join(recorder.messages)
    assert api_key not in joined
    assert "api_key" not in joined
    assert "/start" not in joined
    assert "page_id=page-0001" in joined
    assert "Starting crawl from https://example.test page_id=" in joined
    assert "Crawling: https://example.test page_id=" in joined
    assert "Non-200 response for https://example.test page_id=" in joined


def test_web_crawler_redacts_secret_urls_inside_exception_messages(monkeypatch):
    import packages.web.crawler as crawler_module

    request_probe = "api-" + "r" * 24
    recorder = RecordingLogger()
    crawler = WebCrawler(WebClient("https://example.test"), max_depth=0)
    monkeypatch.setattr(crawler_module, "logger", recorder)

    def raise_error(path):
        raise RuntimeError(f"failed for https://example.test{path}&trace=1")

    monkeypatch.setattr(crawler.client, "get", raise_error)

    url = "https://example.test/start?" + "api_key=" + request_probe
    crawler.crawl(url)

    joined = "\n".join(recorder.messages)
    assert request_probe not in joined
    assert "api_key" not in joined
    assert "trace=1" not in joined
    assert "failed for" not in joined
    assert "page_id=page-0001" in joined
    assert "Error crawling https://example.test page_id=" in joined
    assert "RuntimeError" in joined


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

    assert client.request_history[0]["url"].endswith(
        f"api_key={redaction_probe}&debug=true"
    )


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


def test_web_crawler_redacts_sensitive_prefilled_form_input_values_by_default():
    csrf_probe = "csrf-" + "s" * 24
    api_probe = "api-" + "t" * 24
    oauth_state_probe = "state-" + "u" * 24
    normal_probe = "visible-" + "v" * 8
    crawler = WebCrawler(WebClient("https://example.test"))
    crawler.discovered_forms.append(
        {
            "action": "https://example.test/login",
            "method": "POST",
            "inputs": {
                "csrf_token": {"type": "hidden", "value": csrf_probe},
                "api_key": {"type": "hidden", "value": api_probe},
                "state": {"type": "hidden", "value": oauth_state_probe},
                "username": {"type": "text", "value": normal_probe},
            },
            "page_url": "https://example.test/form",
        }
    )

    results = crawler.get_results()
    rendered = str(results)

    assert csrf_probe not in rendered
    assert api_probe not in rendered
    assert oauth_state_probe not in rendered
    assert rendered.count("[REDACTED]") >= 3
    assert normal_probe in rendered


def test_web_crawler_can_preserve_prefilled_form_input_values_for_debugging():
    csrf_probe = "csrf-" + "w" * 24
    api_probe = "api-" + "x" * 24
    crawler = WebCrawler(WebClient("https://example.test", reveal_secrets=True))
    crawler.discovered_forms.append(
        {
            "action": "https://example.test/login",
            "method": "POST",
            "inputs": {
                "csrf_token": {"type": "hidden", "value": csrf_probe},
                "api_key": {"type": "hidden", "value": api_probe},
            },
            "page_url": "https://example.test/form",
        }
    )

    rendered = str(crawler.get_results())

    assert csrf_probe in rendered
    assert api_probe in rendered


def test_web_crawler_redacts_secret_urls_inside_non_sensitive_form_values():
    refresh_probe = "refresh-" + "y" * 24
    crawler = WebCrawler(WebClient("https://example.test"))
    crawler.discovered_forms.append(
        {
            "action": "https://example.test/continue",
            "method": "POST",
            "inputs": {
                "next_url": {
                    "type": "text",
                    "value": f"https://example.test/callback?refresh_token={refresh_probe}&ok=1",
                }
            },
            "page_url": "https://example.test/form",
        }
    )

    rendered = str(crawler.get_results())

    assert refresh_probe not in rendered
    assert "refresh_token=[REDACTED]" in rendered
    assert "ok=1" in rendered


def test_web_crawler_redacts_concatenated_secret_form_input_names():
    access_probe = "access-" + "z" * 24
    client_probe = "client-" + "a" * 24
    refresh_probe = "refresh-" + "b" * 24
    crawler = WebCrawler(WebClient("https://example.test"))
    crawler.discovered_forms.append(
        {
            "action": "https://example.test/login",
            "method": "POST",
            "inputs": {
                "accessToken": {"type": "hidden", "value": access_probe},
                "clientSecret": {"type": "hidden", "value": client_probe},
                "refreshToken": {"type": "hidden", "value": refresh_probe},
            },
            "page_url": "https://example.test/form",
        }
    )

    rendered = str(crawler.get_results())

    assert access_probe not in rendered
    assert client_probe not in rendered
    assert refresh_probe not in rendered
    assert rendered.count("[REDACTED]") >= 3


def test_web_crawler_preserves_page_context_in_parser_logs_without_url_text(
    monkeypatch,
):
    import packages.web.crawler as crawler_module

    access_probe = "access-" + "c" * 24
    recorder = RecordingLogger()
    crawler = WebCrawler(WebClient("https://example.test"))
    monkeypatch.setattr(crawler_module, "logger", recorder)

    class BadJsonResponse:
        def json(self):
            raise RuntimeError(
                f"failed for https://example.test/api?access_token={access_probe}&trace=1"
            )

    url = f"https://example.test/api?access_token={access_probe}&debug=1"
    crawler._process_json_response(
        url,
        BadJsonResponse(),
    )

    joined = "\n".join(recorder.messages)
    assert access_probe not in joined
    assert "access_token" not in joined
    assert "debug=1" not in joined
    assert "trace=1" not in joined
    assert "page_id=page-0001" in joined
    assert "Error parsing JSON from https://example.test page_id=" in joined
    assert "RuntimeError" in joined


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
