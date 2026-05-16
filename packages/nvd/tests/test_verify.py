"""Tests for packages.nvd.verify — NVD oracle verification."""
from __future__ import annotations

import json as _json
from typing import Any

import pytest

from core.http import HttpError, Response
from packages.nvd import client as nvd_client_mod
from packages.nvd.client import NvdClient
from packages.nvd.verify import verify
from packages.osv.verdicts import Verdict


class _NvdStubHttp:
    def __init__(self) -> None:
        self._queue: list[dict[str, Any]] = []

    def add(self, *, json: Any = None, status: int = 200) -> None:
        self._queue.append({"json": json, "status": status})

    def request(self, method, url, *, headers=None, timeout=None, retries=0, **kw):
        if not self._queue:
            raise HttpError("no mock response queued")
        spec = self._queue.pop(0) if len(self._queue) > 1 else self._queue[0]
        if spec["status"] >= 400:
            raise HttpError(f"HTTP {spec['status']}", status=spec["status"])
        body = _json.dumps(spec["json"]).encode() if spec["json"] is not None else b""
        return Response(status=spec["status"], headers={}, body=body, url=url)


def _nvd_payload(refs: list[dict]) -> dict:
    return {"vulnerabilities": [{"cve": {"id": "CVE-TEST", "references": refs}}]}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(nvd_client_mod, "_RETRY_BASE_S", 0.0)


@pytest.fixture
def stub(monkeypatch) -> _NvdStubHttp:
    s = _NvdStubHttp()
    monkeypatch.setattr(nvd_client_mod, "_default_http", lambda: s)
    return s


def _client() -> NvdClient:
    return NvdClient(cache_enabled=False)


def test_match_exact(stub) -> None:
    stub.add(json=_nvd_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Patch"]},
    ]))
    v = verify("CVE-TEST", "curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", _client())
    assert v.verdict == Verdict.MATCH_EXACT
    assert v.source == "nvd"


def test_orphan_no_patch_refs(stub) -> None:
    stub.add(json=_nvd_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Third Party Advisory"]},
    ]))
    v = verify("CVE-TEST", "curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", _client())
    assert v.verdict == Verdict.ORPHAN


def test_hallucination(stub) -> None:
    stub.add(json=_nvd_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Patch"]},
    ]))
    v = verify("CVE-TEST", "other/repo", "deadbeefcafebabe1234567890abcdef12345678", _client())
    assert v.verdict == Verdict.LIKELY_HALLUCINATION


def test_dispute_bench_refused(stub) -> None:
    stub.add(json=_nvd_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Patch"]},
    ]))
    v = verify("CVE-TEST", "", "", _client())
    assert v.verdict == Verdict.DISPUTE


def test_orphan_on_fetch_error(stub) -> None:
    for _ in range(6):
        stub.add(status=500)
    v = verify("CVE-TEST", "curl/curl", "abc1234", _client())
    assert v.verdict == Verdict.ORPHAN
