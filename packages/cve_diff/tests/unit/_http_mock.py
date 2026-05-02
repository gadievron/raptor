"""Minimal HTTP mocker for cve-diff unit tests.

Pre-2026-05-02 the discovery / oracle test files used the ``responses``
library to intercept ``requests.get`` / ``requests.post``. ``responses``
patches ``requests.adapters.HTTPAdapter.send``, so it captures every call
regardless of which module dereferenced ``requests``.

This helper does the same job at a smaller surface: it monkey-patches
``requests.get`` and ``requests.post`` at the ``requests`` module level
(every consumer in cve-diff uses ``import requests; requests.get(...)``,
which dereferences at call time, so module-level patches are picked up).

API is intentionally close to the slice of ``responses`` we used:

  http = HttpMock(monkeypatch)
  http.add(GET, "https://api.example.com/foo",
           json={"ok": True}, status=200)
  http.add(POST, "https://api.example.com/bar", json={...}, status=200)
  http.add(GET, "https://api.example.com/baz",
           body=requests.ConnectionError("boom"))   # network-error path
  ...
  assert http.calls[0].url == "https://..."
  assert http.calls[0].headers.get("Authorization") == "Bearer xyz"

Multiple ``add()`` calls for the same ``(method, url)`` are FIFO-replayed
to simulate retry sequences.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any, Callable
from unittest.mock import MagicMock

GET = "GET"
POST = "POST"


@dataclass
class _Call:
    method: str
    url: str
    headers: dict
    json: Any = None
    data: Any = None
    timeout: float | None = None


class HttpMock:
    """Records ``requests.get`` / ``requests.post`` calls and returns
    canned responses keyed by ``(method, url)``."""

    def __init__(self, monkeypatch) -> None:
        self.calls: list[_Call] = []
        self._registry: dict[tuple[str, str], list[dict]] = {}
        self._matchers: list[
            tuple[str, Callable[[str], bool], dict]
        ] = []
        monkeypatch.setattr("requests.get", self._fake_get)
        monkeypatch.setattr("requests.post", self._fake_post)

    def add(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        status: int = 200,
        headers: dict | None = None,
        body: Any = None,
    ) -> None:
        """Register a canned response.

        ``body`` may be an ``Exception`` instance — raised by
        ``requests.get/post`` to simulate a transport-level failure.
        Otherwise the response object's ``.json()`` returns ``json``
        and ``.status_code`` is ``status``.
        """
        self._registry.setdefault((method.upper(), url), []).append({
            "status": status, "json": json,
            "headers": headers or {}, "body": body,
        })

    # Convenience shortcuts matching the ``responses`` library's
    # call shape so test bodies don't have to thread the method
    # through every registration.

    def get(self, url: str, **kwargs) -> None:
        self.add(GET, url, **kwargs)

    def post(self, url: str, **kwargs) -> None:
        self.add(POST, url, **kwargs)

    def add_match(
        self,
        method: str,
        predicate: Callable[[str], bool],
        *,
        json: Any = None,
        status: int = 200,
        headers: dict | None = None,
    ) -> None:
        """Register a response keyed by a predicate over the URL.
        Used when test fixtures hit URLs that vary per-call (e.g.
        per-CVE NVD lookups in batch tests)."""
        self._matchers.append((method.upper(), predicate, {
            "status": status, "json": json,
            "headers": headers or {}, "body": None,
        }))

    def _build_response(self, spec: dict) -> MagicMock:
        resp = MagicMock()
        resp.status_code = spec["status"]
        resp.headers = spec["headers"]
        if spec["json"] is not None:
            resp.json.return_value = spec["json"]
            resp.text = _json.dumps(spec["json"])
        else:
            resp.json.side_effect = ValueError("no JSON body")
            resp.text = ""
        return resp

    def _handle(self, method: str, url: str, **kwargs) -> MagicMock:
        self.calls.append(_Call(
            method=method, url=url,
            headers=dict(kwargs.get("headers") or {}),
            json=kwargs.get("json"),
            data=kwargs.get("data"),
            timeout=kwargs.get("timeout"),
        ))
        queue = self._registry.get((method, url))
        if queue:
            spec = queue.pop(0) if len(queue) > 1 else queue[0]
            if isinstance(spec.get("body"), Exception):
                raise spec["body"]
            return self._build_response(spec)
        for m_method, predicate, spec in self._matchers:
            if m_method == method and predicate(url):
                return self._build_response(spec)
        raise RuntimeError(f"no mock registered for {method} {url}")

    def _fake_get(self, url, **kwargs):
        return self._handle(GET, url, **kwargs)

    def _fake_post(self, url, **kwargs):
        return self._handle(POST, url, **kwargs)
