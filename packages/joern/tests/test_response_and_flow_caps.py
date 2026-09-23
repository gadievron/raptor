"""Materialisation caps: query emitters and transport reads.

The taint emitters carry per-traversal ``.take`` caps (the in-tree
flow-cap doctrine standard_sinks.sc / tiered_taint.sc established);
three emitters shipped without one, and the client-side response
reads were unbounded against the very output those emitters size —
while the SAME class is capped at 1 MiB in health_check.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.joern import server as server_mod
from packages.joern.server import _MAX_RESPONSE_BYTES, JoernServer

_QUERIES = Path(__file__).resolve().parents[1] / "queries"


class TestEmitterFlowCaps:
    def test_sink_arg_index_flow_traversal_is_capped(self):
        src = (_QUERIES / "sink_arg_index.sc").read_text()
        assert "reachableByFlows(source).take(500).l" in src
        assert "reachableByFlows(source).l" not in src

    def test_summary_taint_rules_flow_traversal_is_capped(self):
        src = (_QUERIES / "summary_taint_rules.sc").read_text()
        assert "reachableByFlows(param).take(500).l" in src
        assert "reachableByFlows(param).l" not in src

    def test_callers_materialisation_is_capped(self):
        src = (_QUERIES / "callers.sc").read_text()
        assert "}.take(500).l" in src


class _OversizeResp:
    """Response double: read(n) hands back n bytes — always over."""

    def read(self, n: int = -1) -> bytes:
        return b"x" * (n if n and n > 0 else _MAX_RESPONSE_BYTES + 1)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestTransportResponseCeiling:
    def _server(self) -> JoernServer:
        srv = JoernServer()
        srv._base_url = "http://joern-local"
        return srv

    def test_urllib_refuses_oversize_response(self):
        srv = self._server()
        with patch.object(server_mod._NO_PROXY_OPENER, "open",
                          return_value=_OversizeResp()):
            out = srv._post_urllib("http://joern-local/query-sync",
                                   {"query": "1+1"}, 5)
        assert out is None
        assert "exceeds" in srv._last_post_error

    def test_urllib_accepts_bounded_response(self):
        srv = self._server()

        class _SmallResp(_OversizeResp):
            def read(self, n: int = -1) -> bytes:
                return b'{"success": true, "stdout": "ok"}'

        with patch.object(server_mod._NO_PROXY_OPENER, "open",
                          return_value=_SmallResp()):
            out = srv._post_urllib("http://joern-local/query-sync",
                                   {"query": "1+1"}, 5)
        assert out == {"success": True, "stdout": "ok"}

    def test_uds_refuses_oversize_response(self):
        srv = self._server()
        srv._uds_path = "/nonexistent.sock"
        conn = MagicMock()
        conn.getresponse.return_value = _OversizeResp()
        with patch.object(server_mod, "_UnixHTTPConnection",
                          return_value=conn):
            out = srv._uds_request("POST", "/query-sync",
                                   {"query": "1+1"}, 5)
        assert out is None
        assert "exceeds" in srv._last_post_error

    def test_httpx_refuses_oversize_stream(self):
        srv = self._server()

        class _StreamCtx:
            def __enter__(self):
                resp = MagicMock()
                resp.iter_bytes.return_value = iter(
                    [b"x" * (_MAX_RESPONSE_BYTES // 2 + 1)] * 2,
                )
                return resp

            def __exit__(self, *exc):
                return False

        fake_httpx = MagicMock()
        fake_httpx.Client.return_value.stream.return_value = _StreamCtx()
        with patch.object(server_mod, "_httpx", fake_httpx):
            out = srv._post_httpx("http://joern-local/query-sync",
                                  {"query": "1+1"}, 5)
        assert out is None
        assert "exceeds" in srv._last_post_error
