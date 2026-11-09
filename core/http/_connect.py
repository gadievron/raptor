"""HTTP/1.1 CONNECT transport for the local enforcement proxy.

Unlike a general forward proxy, the enforcement proxy accepts CONNECT only.
Keep a pool per destination and send origin-form requests inside each tunnel.
"""
from collections.abc import Mapping
from typing import Any

from urllib3 import PoolManager, ProxyManager
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import ProxyError
from urllib3.response import BaseHTTPResponse
from urllib3.util import Url


class _ConnectHTTPConnection(HTTPConnection):
    def connect(self) -> None:
        try:
            super().connect()
        except OSError as exc:
            self.close()
            raise ProxyError("Unable to establish CONNECT tunnel", exc) from exc


class _ConnectHTTPPool(HTTPConnectionPool):
    connect_proxy: Url
    connect_headers: Mapping[str, str]

    def _new_conn(self) -> HTTPConnection:
        self.num_connections += 1
        assert self.connect_proxy.host is not None
        conn = _ConnectHTTPConnection(
            host=self.connect_proxy.host,
            port=self.connect_proxy.port,
            timeout=self.timeout.connect_timeout,
            **self.conn_kw,
        )
        conn.set_tunnel(self.host, port=self.port, headers=self.connect_headers)
        return conn


class ConnectProxyManager(ProxyManager):
    """Tunnel both HTTP and HTTPS through an HTTP enforcement proxy.

    Proxy credentials belong to CONNECT only. HTTP pools deliberately have
    no urllib3 forward-proxy configuration, so origin requests cannot inherit
    proxy authentication or absolute-form URLs.
    """

    def __init__(self, proxy_url: str, **kwargs: Any) -> None:
        super().__init__(proxy_url, **kwargs)
        if self.proxy is None or self.proxy.scheme != "http":
            raise ValueError("CONNECT enforcement requires an HTTP proxy")
        self.pool_classes_by_scheme = self.pool_classes_by_scheme.copy()
        self.pool_classes_by_scheme["http"] = _ConnectHTTPPool

    def connection_from_host(
        self, host: str | None, port: int | None = None, scheme: str | None = "http",
        pool_kwargs: dict[str, Any] | None = None,
    ) -> HTTPConnectionPool:
        return PoolManager.connection_from_host(
            self, host, port=port, scheme=scheme, pool_kwargs=pool_kwargs,
        )

    def _new_pool(
        self, scheme: str, host: str, port: int,
        request_context: dict[str, Any] | None = None,
    ) -> HTTPConnectionPool:
        context = (self.connection_pool_kw if request_context is None else request_context).copy()
        if scheme == "http":
            for key in ("_proxy", "_proxy_headers", "_proxy_config"):
                context.pop(key, None)
        pool = super()._new_pool(scheme, host, port, context)
        if scheme == "http":
            assert isinstance(pool, _ConnectHTTPPool)
            assert self.proxy is not None
            pool.connect_proxy = self.proxy
            pool.connect_headers = dict(self.proxy_headers)
        return pool

    def _proxy_requires_url_absolute_form(self, parsed_url: Url) -> bool:
        return False

    def urlopen(  # type: ignore[override]  # Match ProxyManager's redirect signature.
        self, method: str, url: str, redirect: bool = True, **kwargs: Any,
    ) -> BaseHTTPResponse:
        return PoolManager.urlopen(self, method, url, redirect=redirect, **kwargs)
