"""Per-process caching of the Ollama availability probe.

``_get_available_ollama_models`` promises "Cached per-process to avoid
repeated HTTP checks", but only the successful (HTTP 200) path set the
cache flag — when Ollama was absent or unreachable, every
``LLMConfig()`` construction re-ran the probe and paid up to the 2s
connect timeout on filtered/proxied hosts. Negative results (probe
exception, non-200) must be cached too.

The probe's connect-failure debug log must also never leak a remote
OLLAMA_HOST through interpolated exception text —
``_redact_remote_host`` masks the host before logging, while loopback
hosts stay verbatim.
"""

from __future__ import annotations

import pytest

from core.llm import detection


@pytest.fixture(autouse=True)
def _reset_probe_cache(monkeypatch):
    """Isolate each test (and the rest of the suite) from the module-
    level probe cache."""
    monkeypatch.setattr(detection, "_ollama_checked", False)
    monkeypatch.setattr(detection, "_cached_ollama_models", None)
    monkeypatch.setattr(detection, "_cached_ollama_capabilities", {})
    monkeypatch.setattr(detection, "_ollama_capability_probing_disabled", set())


def _patch_http(monkeypatch, side_effect=None, response=None, handler=None):
    """Replace requests at the transport boundary for the Ollama probe."""
    calls = []

    def request(method, url, timeout=None, **kwargs):
        call = {"method": method, "url": url, "timeout": timeout, **kwargs}
        calls.append(call)
        if side_effect is not None:
            raise side_effect
        if handler is not None:
            return handler(call)
        return response

    class _Session:
        def __init__(self):
            self.trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, url, timeout=None, **kwargs):
            return request("GET", url, timeout, **kwargs)

        def post(self, url, timeout=None, **kwargs):
            return request("POST", url, timeout, **kwargs)

    import requests
    monkeypatch.setattr(requests, "Session", _Session)
    monkeypatch.setattr(
        requests, "get",
        lambda url, timeout=None, **kwargs: request(
            "GET", url, timeout, **kwargs,
        ),
    )
    monkeypatch.setattr(
        requests, "post",
        lambda url, timeout=None, **kwargs: request(
            "POST", url, timeout, **kwargs,
        ),
    )
    return calls


class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_unreachable_probe_is_cached(monkeypatch):
    calls = _patch_http(monkeypatch, side_effect=ConnectionError("refused"))
    assert detection._get_available_ollama_models() == []
    assert detection._get_available_ollama_models() == []
    assert len(calls) == 1, (
        "negative probe result was not cached — every call re-pays the "
        "connect timeout"
    )


def test_non_200_probe_is_cached(monkeypatch):
    calls = _patch_http(monkeypatch, response=_Resp(503))
    assert detection._get_available_ollama_models() == []
    assert detection._get_available_ollama_models() == []
    assert len(calls) == 1


def test_successful_probe_still_cached(monkeypatch):
    tags = {"models": [{"name": "llama3:8b"}]}

    def handler(call):
        if call["method"] == "GET":
            return _Resp(200, tags)
        return _Resp(200, {"capabilities": ["completion"]})

    calls = _patch_http(monkeypatch, handler=handler)
    assert detection._get_available_ollama_models() == ["llama3:8b"]
    assert detection._get_available_ollama_models() == ["llama3:8b"]
    assert [call["method"] for call in calls] == ["GET", "POST"]


# ---------------------------------------------------------------------------
# Remote-host redaction in the probe's failure log
# ---------------------------------------------------------------------------

# Documentation-only test host (TEST-NET-3, RFC 5737).
_REMOTE_HOST = "203.0.113.7"
_REMOTE_HOSTPORT = f"{_REMOTE_HOST}:11434"


class _RecordingLogger:
    """Minimal logger stand-in capturing fully-formatted messages."""

    def __init__(self):
        self.messages: list[str] = []

    def _record(self, msg, *args):
        self.messages.append(msg % args if args else str(msg))

    debug = info = warning = error = _record


def test_redact_remote_host_replaces_hostport_and_host():
    text = (
        f"HTTPConnectionPool(host='{_REMOTE_HOST}', port=11434): "
        f"retries exceeded for http://{_REMOTE_HOSTPORT}/api/tags"
    )
    out = detection._redact_remote_host(text, f"http://{_REMOTE_HOSTPORT}")
    assert _REMOTE_HOST not in out
    assert "[REMOTE-OLLAMA]" in out


def test_redact_remote_host_schemeless_url():
    out = detection._redact_remote_host(
        f"connect to {_REMOTE_HOSTPORT} failed", _REMOTE_HOSTPORT,
    )
    assert _REMOTE_HOST not in out


def test_ollama_probe_failure_log_has_no_remote_host(monkeypatch):
    from core.config import RaptorConfig

    recorder = _RecordingLogger()
    monkeypatch.setattr(detection, "logger", recorder)
    monkeypatch.setattr(RaptorConfig, "OLLAMA_HOST", _REMOTE_HOSTPORT)
    _patch_http(monkeypatch, side_effect=ConnectionError(
        f"HTTPConnectionPool(host='{_REMOTE_HOST}', port=11434): "
        f"Max retries exceeded with url: /api/tags"
    ))
    assert detection._get_available_ollama_models() == []
    joined = "\n".join(recorder.messages)
    assert _REMOTE_HOST not in joined
    assert "[REMOTE-OLLAMA]" in joined


def test_local_host_probe_failure_log_stays_verbatim(monkeypatch):
    from core.config import RaptorConfig

    recorder = _RecordingLogger()
    monkeypatch.setattr(detection, "logger", recorder)
    monkeypatch.setattr(RaptorConfig, "OLLAMA_HOST", "127.0.0.1:11434")
    _patch_http(monkeypatch, side_effect=ConnectionError("connection refused"))
    assert detection._get_available_ollama_models() == []
    assert any("127.0.0.1:11434" in m for m in recorder.messages)


def test_tags_capabilities_are_authoritative(monkeypatch):
    payload = {"models": [
        {"name": "vectors:latest", "capabilities": ["embedding"]},
        {"name": "embedded-coder:latest", "capabilities": ["completion"]},
        {"name": "unknown:latest", "capabilities": []},
    ]}
    calls = _patch_http(monkeypatch, response=_Resp(200, payload))
    assert detection._get_available_ollama_models() == [
        "embedded-coder:latest",
    ]
    assert [call["method"] for call in calls] == ["GET"]


def test_unreachable_show_stops_further_probes(monkeypatch):
    tags = {"models": [
        {"name": "broken-embed:latest"},
        {"name": "llama3.1:8b"},
        {"name": "qwen2.5-coder:7b"},
    ]}

    def handler(call):
        if call["method"] == "GET":
            return _Resp(200, tags)
        raise ConnectionError("show unavailable")

    calls = _patch_http(monkeypatch, handler=handler)
    assert detection._get_available_ollama_models() == [
        "llama3.1:8b", "qwen2.5-coder:7b",
    ]
    assert [call["method"] for call in calls] == ["GET", "POST"]


def test_model_specific_show_failure_keeps_probing(monkeypatch):
    tags = {"models": [
        {"name": "missing-embed:latest"},
        {"name": "vectors:latest"},
        {"name": "embedded-coder:latest"},
    ]}
    shown = {
        "vectors:latest": {"capabilities": ["embedding"]},
        "embedded-coder:latest": {"capabilities": ["completion"]},
    }

    def handler(call):
        if call["method"] == "GET":
            return _Resp(200, tags)
        model = call["json"]["model"]
        if model == "missing-embed:latest":
            return _Resp(404)
        return _Resp(200, shown[model])

    calls = _patch_http(monkeypatch, handler=handler)
    assert detection._get_available_ollama_models() == [
        "embedded-coder:latest",
    ]
    assert [call["method"] for call in calls] == [
        "GET", "POST", "POST", "POST",
    ]


def test_show_capabilities_filter_models_when_tags_omit_them(monkeypatch):
    tags = {"models": [
        {"name": "vectors:latest", "details": {"family": "qwen3"}},
        {"name": "embedded-coder:latest", "details": {"family": "qwen2"}},
    ]}
    shown = {
        "vectors:latest": {"capabilities": ["embedding"]},
        "embedded-coder:latest": {"capabilities": ["completion"]},
    }

    def handler(call):
        if call["method"] == "GET":
            return _Resp(200, tags)
        return _Resp(200, shown[call["json"]["model"]])

    calls = _patch_http(monkeypatch, handler=handler)
    assert detection._get_available_ollama_models() == [
        "embedded-coder:latest",
    ]
    assert [call["method"] for call in calls] == ["GET", "POST", "POST"]


def test_old_server_uses_embedding_heuristic_as_fallback(monkeypatch):
    tags = {"models": [
        {"name": "qwen3-embedding:0.6b", "details": {"family": "qwen3"}},
        {"name": "bge-m3:latest", "details": {"family": "bert"}},
        {"name": "llama3.1:8b", "details": {"family": "llama"}},
    ]}

    def handler(call):
        if call["method"] == "GET":
            return _Resp(200, tags)
        return _Resp(200, {"details": {"family": "unknown"}})

    calls = _patch_http(monkeypatch, handler=handler)
    assert detection._get_available_ollama_models() == ["llama3.1:8b"]
    assert [call["method"] for call in calls] == ["GET", "POST"]


def test_show_probes_share_one_time_budget(monkeypatch):
    tags = {"models": [
        {"name": "chat-one:latest"},
        {"name": "vectors:latest"},
        {"name": "llama3.1:8b"},
    ]}
    shown = {
        "chat-one:latest": {"capabilities": ["completion"]},
        "vectors:latest": {"capabilities": ["embedding"]},
    }
    clock = iter([10.0, 10.25, 11.5, 12.0])
    monkeypatch.setattr(detection, "monotonic", lambda: next(clock))

    def handler(call):
        if call["method"] == "GET":
            return _Resp(200, tags)
        return _Resp(200, shown[call["json"]["model"]])

    calls = _patch_http(monkeypatch, handler=handler)
    assert detection._get_available_ollama_models() == [
        "chat-one:latest", "llama3.1:8b",
    ]
    assert [call["timeout"] for call in calls if call["method"] == "POST"] == [
        1.75, 0.5,
    ]
