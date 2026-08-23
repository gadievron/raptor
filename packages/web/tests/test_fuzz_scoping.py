"""Fuzzing scope + payload memoisation.

Pre-fix the scanner fuzzed every discovered parameter against every
discovered URL, and the fuzzer paid one LLM payload-generation call per
(URL, param, vuln) cell. Post-fix parameters are fuzzed only where the
crawler discovered them, and payload generation is memoised on the full
prompt context (param_name, param_type, vuln_type).
"""

from __future__ import annotations

import http.server
import threading
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock

import pytest


class _RecordingFuzzer:
    """Stands in for WebFuzzer; records fuzz cells, finds nothing."""

    payload_cache_stats = (0, 0)

    def __init__(self):
        self.calls = []

    def fuzz_parameter(self, url, param, param_type="text",
                       vulnerability_types=None, method="GET"):
        self.calls.append((url, param, method))
        return []


def _make_fuzzer():
    from packages.web.fuzzer import WebFuzzer

    mock_llm = MagicMock()
    mock_llm.generate_structured.return_value = (
        {"payloads": ["' OR 1=1--"]},
        "raw",
    )
    mock_client = MagicMock()
    mock_client.reveal_secrets = False
    return WebFuzzer(client=mock_client, llm=mock_llm), mock_llm


class TestPayloadMemoisation:
    def test_same_key_generates_once(self):
        fuzzer, mock_llm = _make_fuzzer()
        first = fuzzer._generate_payloads("q", "text", "sqli")
        second = fuzzer._generate_payloads("q", "text", "sqli")
        assert first == second == ["' OR 1=1--"]
        assert mock_llm.generate_structured.call_count == 1
        assert fuzzer.payload_cache_stats == (1, 1)

    def test_distinct_keys_generate_separately(self):
        fuzzer, mock_llm = _make_fuzzer()
        fuzzer._generate_payloads("q", "text", "sqli")
        fuzzer._generate_payloads("q", "text", "xss")
        fuzzer._generate_payloads("user", "text", "sqli")
        assert mock_llm.generate_structured.call_count == 3
        assert fuzzer.payload_cache_stats == (0, 3)

    def test_cached_list_is_a_copy(self):
        fuzzer, _ = _make_fuzzer()
        first = fuzzer._generate_payloads("q", "text", "sqli")
        first.append("mutated")
        second = fuzzer._generate_payloads("q", "text", "sqli")
        assert "mutated" not in second

    def test_llm_failure_is_not_cached(self):
        fuzzer, mock_llm = _make_fuzzer()
        mock_llm.generate_structured.side_effect = RuntimeError("boom")
        fallback = fuzzer._generate_payloads("q", "text", "sqli")
        assert fallback  # basic payloads
        # A second call retries the LLM rather than pinning the fallback.
        fuzzer._generate_payloads("q", "text", "sqli")
        assert mock_llm.generate_structured.call_count == 2
        assert fuzzer.payload_cache_stats == (0, 0)


class _ParamTargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        if self.path == "/":
            self.wfile.write(
                b'<a href="/page-1?first=1">one</a>'
                b'<a href="/page-2?second=2">two</a>'
            )
        else:
            self.wfile.write(b"ok")

    def log_message(self, format, *args):  # pragma: no cover
        pass


@contextmanager
def _fake_target():
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), _ParamTargetHandler,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class TestParamScopedFuzzing:

    def test_parameters_fuzzed_only_where_discovered(self, tmp_path: Path):
        pytest.importorskip("requests")
        pytest.importorskip("bs4")
        from packages.web.scanner import WebScanner

        with _fake_target() as base_url:
            scanner = WebScanner(
                base_url, llm=None, out_dir=tmp_path,
                max_depth=2, max_pages=10,
                block_private_ips=False,
                rate_limit=0,  # loopback fixture; politeness is real-target manners
            )
            recording = _RecordingFuzzer()
            scanner.fuzzer = recording
            scanner.scan()
            crawler = scanner.crawler
            scanner.close()

        # The crawler recorded each param at its discovery URL.
        assert set(crawler.parameter_urls) == {"first", "second"}

        by_param = {}
        for url, param, method in recording.calls:
            assert method == "GET"
            by_param.setdefault(param, set()).add(url)

        assert set(by_param) == {"first", "second"}
        # Each param probed only at the single URL that carried it —
        # not the full URL x parameter cross-product.
        assert by_param["first"] == {f"{base_url}/page-1?first=1"}
        assert by_param["second"] == {f"{base_url}/page-2?second=2"}

    def test_crawl_artifact_exposes_parameter_urls(self, tmp_path: Path):
        pytest.importorskip("requests")
        pytest.importorskip("bs4")
        from packages.web.client import WebClient
        from packages.web.crawler import WebCrawler

        with _fake_target() as base_url:
            client = WebClient(base_url, block_private_ips=False, rate_limit=0)
            crawler = WebCrawler(client, max_depth=2, max_pages=10)
            results = crawler.crawl(base_url)
            client.close()

        assert set(results["parameter_urls"]) == {"first", "second"}
        assert results["parameter_urls"]["first"] == [
            f"{base_url}/page-1?first=1",
        ]
