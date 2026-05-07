"""Worker-side helpers for using the credential-isolation dispatcher.

A worker spawned via :func:`spawn_worker` inherits two pieces of state:

  * ``RAPTOR_LLM_SOCKET`` env var — UDS path of the dispatcher.
  * ``RAPTOR_LLM_TOKEN_FD`` env var — read-end of a pipe with the
    32-byte capability token. Worker must read it before doing any
    other work and close the FD.

This module provides:

  * :func:`read_token` — one-shot read of the token from the inherited
    FD. Worker code calls this exactly once at startup.
  * :func:`make_anthropic_client` — stock ``anthropic.Anthropic``
    client wired to talk HTTP-over-UDS to the dispatcher, with the
    token automatically attached as a header on every request.

Workers don't need a custom SDK shim — the LLM SDKs sit on top of
``httpx`` and accept a custom HTTP client, which is what we provide.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx


_TOKEN_HEADER = "X-Raptor-Token"


def read_token(fd: Optional[int] = None) -> str:
    """Read the worker's capability token from the inherited FD.

    Pass ``fd`` explicitly for tests; production code reads
    ``RAPTOR_LLM_TOKEN_FD`` from the environment. The FD is closed
    after a successful read so the token doesn't survive the call.
    """
    if fd is None:
        env = os.environ.get("RAPTOR_LLM_TOKEN_FD")
        if env is None:
            raise RuntimeError(
                "RAPTOR_LLM_TOKEN_FD not set — worker must be spawned via "
                "core.llm.dispatcher.spawn_worker"
            )
        fd = int(env)
    try:
        # 64 bytes is plenty for a 32-byte url-safe token.
        token = os.read(fd, 64).decode("ascii").strip()
    finally:
        os.close(fd)
    if not token:
        raise RuntimeError("RAPTOR_LLM_TOKEN_FD pipe was empty")
    return token


def _make_httpx_client(socket_path: str, token: str) -> httpx.Client:
    """Build the underlying ``httpx`` client.

    UDS transport directs all traffic to the dispatcher; the
    ``X-Raptor-Token`` header is attached to every request via the
    client's default headers.
    """
    transport = httpx.HTTPTransport(uds=socket_path)
    return httpx.Client(
        transport=transport,
        headers={_TOKEN_HEADER: token},
        timeout=httpx.Timeout(60.0, connect=5.0),
    )


def make_anthropic_client(
    *,
    socket_path: Optional[str] = None,
    token: Optional[str] = None,
):
    """Return a stock ``anthropic.Anthropic`` client routed through
    the dispatcher.

    Defaults read socket path from ``RAPTOR_LLM_SOCKET`` and the
    token from ``RAPTOR_LLM_TOKEN_FD``. Pass arguments explicitly
    only in tests.

    The returned client behaves exactly like a normal Anthropic SDK
    client — workers call ``client.messages.create(...)`` etc. and
    receive responses (including streamed ones). The credential
    isolation is invisible at the call site.
    """
    import anthropic   # imported lazily so the module loads without the SDK

    if socket_path is None:
        env = os.environ.get("RAPTOR_LLM_SOCKET")
        if env is None:
            raise RuntimeError(
                "RAPTOR_LLM_SOCKET not set — worker must be spawned via "
                "core.llm.dispatcher.spawn_worker"
            )
        socket_path = env
    if token is None:
        token = read_token()

    http = _make_httpx_client(socket_path, token)
    # ``api_key='dummy'`` because the SDK validates that *something*
    # was passed; the dispatcher strips it and injects the real key.
    # ``base_url`` directs requests to ``/anthropic/v1/...`` so the
    # dispatcher can route by path prefix.
    return anthropic.Anthropic(
        api_key="dummy-not-used",
        base_url="http://_/anthropic/v1",
        http_client=http,
    )
