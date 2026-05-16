"""Tests for packages.nvd.client — NvdClient with mocked HTTP."""
from __future__ import annotations

import json as _json
from typing import Any

import pytest

from core.http import HttpError, Response
from packages.nvd import client as nvd_client_mod
from packages.nvd.client import NvdClient


class _NvdStubHttp:
    """FIFO response queue mocking ``UrllibClient.request()``."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self._queue: list[dict[str, Any]] = []

    def add(self, *, json: Any = None, status: int = 200) -> None:
        self._queue.append({"json": json, "status": status})

    def request(
        self, method: str, url: str, *, headers: dict | None = None,
        timeout: int | None = None, retries: int = 0, **kw: Any,
    ) -> Response:
        self.calls.append({"method": method, "url": url, "headers": dict(headers or {}), "timeout": timeout})
        if not self._queue:
            raise HttpError("no mock response queued")
        spec = self._queue.pop(0) if len(self._queue) > 1 else self._queue[0]
        if spec["status"] >= 400:
            raise HttpError(
                f"HTTP {spec['status']}", status=spec["status"],
                retry_after=0 if spec["status"] == 429 else None,
            )
        body = _json.dumps(spec["json"]).encode() if spec["json"] is not None else b""
        return Response(status=spec["status"], headers={}, body=body, url=url)


def _cve_payload(refs: list[dict] | None = None) -> dict:
    return {"vulnerabilities": [{"cve": {"id": "CVE-2024-1234", "references": refs or []}}]}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(nvd_client_mod, "_RETRY_BASE_S", 0.0)


@pytest.fixture
def stub(monkeypatch) -> _NvdStubHttp:
    s = _NvdStubHttp()
    monkeypatch.setattr(nvd_client_mod, "_default_http", lambda: s)
    return s


class TestGetPayload:
    def test_returns_payload_on_200(self, stub) -> None:
        stub.add(json=_cve_payload())
        payload = NvdClient(cache_enabled=False).get_payload("CVE-2024-1234")
        assert payload is not None
        assert payload["vulnerabilities"]

    def test_returns_none_on_404(self, stub) -> None:
        stub.add(status=404)
        assert NvdClient(cache_enabled=False).get_payload("CVE-2024-1234") is None

    def test_returns_none_on_500(self, stub) -> None:
        stub.add(status=500)
        assert NvdClient(cache_enabled=False).get_payload("CVE-2024-1234") is None


class TestMemoryCache:
    def test_second_call_from_memory(self, stub) -> None:
        stub.add(json=_cve_payload())
        client = NvdClient(disk_cache_dir=None)
        first = client.get_payload("CVE-2099-9999")
        assert first is not None
        second = client.get_payload("CVE-2099-9999")
        assert second is not None
        assert len(stub.calls) == 1


class TestDiskCache:
    def test_disk_cache_roundtrip(self, stub, tmp_path) -> None:
        stub.add(json=_cve_payload())
        c1 = NvdClient(disk_cache_dir=tmp_path / "nvd")
        assert c1.get_payload("CVE-2024-1234") is not None

        c2 = NvdClient(disk_cache_dir=tmp_path / "nvd")
        result = c2.get_payload("CVE-2024-1234")
        assert result is not None
        assert len(stub.calls) == 1


class TestRateLimitRetry:
    def test_retries_on_429(self, stub) -> None:
        stub.add(status=429)
        stub.add(json=_cve_payload())
        payload = NvdClient(cache_enabled=False).get_payload("CVE-2024-1234")
        assert payload is not None

    def test_gives_up_after_max_retries(self, stub) -> None:
        for _ in range(6):
            stub.add(status=429)
        assert NvdClient(cache_enabled=False).get_payload("CVE-2024-1234") is None

    def test_rate_limit_callback_called(self, stub) -> None:
        stub.add(status=429)
        stub.add(json=_cve_payload())
        calls: list[bool] = []
        client = NvdClient(cache_enabled=False, on_rate_limit=lambda: calls.append(True))
        client.get_payload("CVE-2024-1234")
        assert len(calls) == 1


class TestApiKey:
    def test_api_key_env_sends_header(self, stub, monkeypatch) -> None:
        # batch 550 — NVD API keys must be UUID-format. The
        # pre-fix test used `"test-key-123"` which is not a
        # valid NVD key shape; client now rejects it (treats
        # as no-key). Use a real UUID for the positive case.
        monkeypatch.setenv(
            "NVD_API_KEY", "12345678-1234-1234-1234-1234567890ab",
        )
        stub.add(json=_cve_payload())
        NvdClient(cache_enabled=False).get_payload("CVE-2024-9999")
        assert (
            stub.calls[0]["headers"].get("apiKey")
            == "12345678-1234-1234-1234-1234567890ab"
        )

    def test_invalid_api_key_format_treated_as_no_key(self, stub, monkeypatch) -> None:
        # batch 550 — placeholder / wrong-format keys
        # (operator copy-paste error, "YOUR_KEY_HERE", non-
        # UUID strings) are silently dropped rather than sent.
        # Better than triggering 401/403 retry storms.
        monkeypatch.setenv("NVD_API_KEY", "YOUR_KEY_HERE")
        stub.add(json=_cve_payload())
        NvdClient(cache_enabled=False).get_payload("CVE-2024-9997")
        assert "apiKey" not in stub.calls[0]["headers"]

    def test_no_api_key_sends_no_header(self, stub) -> None:
        stub.add(json=_cve_payload())
        NvdClient(cache_enabled=False).get_payload("CVE-2024-9998")
        assert "apiKey" not in stub.calls[0]["headers"]
