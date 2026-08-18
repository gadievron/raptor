"""Narrowed best-effort handlers in WebClient close paths.

Representative fails-before coverage for the suppress(Exception)
narrowing sweep in packages/web: session/response close used to eat
*any* exception; after narrowing only the legitimate teardown errors
(OSError, requests/urllib3 error trees) are suppressed, so a miswired
call surfaces.
"""

from __future__ import annotations

import pytest
import requests

from packages.web.client import WebClient


def _client() -> WebClient:
    return WebClient("http://127.0.0.1:1", block_private_ips=False)


class TestCloseNarrowing:
    def test_miswiring_class_exception_propagates(self):
        client = _client()

        def _bad_close():
            raise TypeError("close() takes no arguments")

        client.session.close = _bad_close
        with pytest.raises(TypeError):
            client.close()

    @pytest.mark.parametrize(
        "exc",
        [
            OSError("socket already torn down"),
            requests.RequestException("pool teardown failed"),
        ],
    )
    def test_legitimate_close_failures_still_suppressed(self, exc):
        client = _client()

        def _flaky_close():
            raise exc

        client.session.close = _flaky_close
        client.close()
