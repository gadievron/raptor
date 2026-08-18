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


def _patch_probe(monkeypatch, side_effect=None, response=None):
    calls = []

    def fake_get(url, timeout=None, **kwargs):
        calls.append(url)
        if side_effect is not None:
            raise side_effect
        return response

    from core.llm import egress
    monkeypatch.setattr(egress, "loopback_safe_get", fake_get)
    return calls


class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_unreachable_probe_is_cached(monkeypatch):
    calls = _patch_probe(monkeypatch, side_effect=ConnectionError("refused"))
    assert detection._get_available_ollama_models() == []
    assert detection._get_available_ollama_models() == []
    assert len(calls) == 1, (
        "negative probe result was not cached — every call re-pays the "
        "connect timeout"
    )


def test_non_200_probe_is_cached(monkeypatch):
    calls = _patch_probe(monkeypatch, response=_Resp(503))
    assert detection._get_available_ollama_models() == []
    assert detection._get_available_ollama_models() == []
    assert len(calls) == 1


def test_successful_probe_still_cached(monkeypatch):
    payload = {"models": [{"name": "llama3:8b"}]}
    calls = _patch_probe(monkeypatch, response=_Resp(200, payload))
    assert detection._get_available_ollama_models() == ["llama3:8b"]
    assert detection._get_available_ollama_models() == ["llama3:8b"]
    assert len(calls) == 1


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
    _patch_probe(monkeypatch, side_effect=ConnectionError(
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
    _patch_probe(monkeypatch, side_effect=ConnectionError("connection refused"))
    assert detection._get_available_ollama_models() == []
    assert any("127.0.0.1:11434" in m for m in recorder.messages)
