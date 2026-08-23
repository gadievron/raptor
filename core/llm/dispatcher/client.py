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

import logging
import os
import threading
import time

import httpx

_logger = logging.getLogger(__name__)

_TOKEN_HEADER = "X-Raptor-Token"

# Worker-token renewal (mirrors server._TOKEN_RENEW_PATH). The
# dispatcher's worker-token TTL bounds time-since-last-renewal, not
# total run length: a still-valid token may re-arm its window via
# POST /_token/renew on the UDS plane. The client below renews
# proactively so runs longer than the TTL (the observed failure:
# 8 h TTL, >12 h audit segment, 690 straight 401s) keep a live token
# for as long as they keep dispatching. A worker that goes silent
# for longer than the TTL still expires — that is the L4 security
# property, unchanged.
_RENEW_PATH = "/_token/renew"
_RENEW_MARGIN_MIN_S = 30.0
_RENEW_MARGIN_MAX_S = 3600.0
_RENEW_RETRY_BACKOFF_S = 30.0
# Consecutive renewal failures before ONE WARNING is emitted.
# Individual failures stay at DEBUG (renewal is best-effort and a
# transient blip self-heals), but a permanently broken renewal plane
# means the worker token hard-401s at TTL — hours later — and the
# operator deserves the heads-up when the pattern sets in, not at the
# expiry. Latched: one WARNING per broken streak; a successful
# renewal resets both the counter and the latch.
_RENEW_FAILURE_WARN_THRESHOLD = 3


class _TokenRenewalAuth(httpx.Auth):
    """httpx auth hook that proactively renews the worker token.

    The token header itself rides the client's default headers (set
    in :func:`_make_httpx_client`); this hook's only job is the
    renewal side-channel. Before a request whose token is past its
    renewal threshold (unknown expiry counts — the first request
    always renews to learn ``expires_at``), the hook sends
    ``POST /_token/renew`` OUT OF BAND on a dedicated short-timeout
    client over the same UDS, then lets the real request proceed.

    Out-of-band (rather than a yielded auth-flow request) is what
    makes "renewal failures never fail the caller's request" true at
    the TRANSPORT level too: an exception raised while sending a
    yielded auth-flow request propagates out of ``Client.send`` before
    the main request is ever attempted, so a slow-to-accept dispatcher
    inside the renewal margin would have converted healthy requests
    into failures. Here every renewal exception is swallowed (logged
    at debug, retried after a backoff; one WARNING once a streak of
    ``_RENEW_FAILURE_WARN_THRESHOLD`` consecutive failures suggests
    the renewal plane is broken rather than blipping); HTTP-status
    failures behave as before — a genuinely dead token still 401s on
    the main request, and a dispatcher without the endpoint
    (403/404/405) disables further attempts.

    Thread-safe: one renewal in flight at a time; concurrent requests
    skip the renewal leg rather than stampede or block.
    """

    def __init__(
        self,
        token: str,
        socket_path: str | None = None,
        renew_client: httpx.Client | None = None,
    ) -> None:
        self._token = token
        self._socket_path = socket_path
        self._renew_http = renew_client   # injectable for tests
        self._renew_http_lock = threading.Lock()
        self._expires_at: float | None = None   # unknown until first renew
        self._margin_s = _RENEW_MARGIN_MIN_S
        self._lock = threading.Lock()
        self._renew_inflight = False
        # Broken-renewal-plane visibility (see the threshold constant).
        self._consecutive_failures = 0
        self._failure_warned = False
        self._disabled = (
            socket_path is None and renew_client is None
        ) or os.environ.get(
            "RAPTOR_LLM_TOKEN_RENEW", "",
        ).lower() in ("0", "false", "no")

    # -- scheduling ----------------------------------------------------

    def _claim_renewal(self) -> bool:
        """True when THIS call should perform the renewal leg (and has
        claimed the in-flight slot). Callers must release via
        :meth:`_release_renewal`."""
        if self._disabled:
            return False
        with self._lock:
            if self._renew_inflight:
                return False
            due = (
                self._expires_at is None
                or time.time() >= self._expires_at - self._margin_s
            )
            if due:
                self._renew_inflight = True
            return due

    def _release_renewal(self) -> None:
        with self._lock:
            self._renew_inflight = False

    def _renew_transport(self) -> httpx.Client | None:
        """The dedicated renewal-leg client (lazily built over the
        UDS). Separate from the caller's client so a renewal-leg
        transport failure can never surface as the caller's."""
        if self._renew_http is not None:
            return self._renew_http
        with self._renew_http_lock:
            if self._renew_http is None:
                if not self._socket_path:
                    self._disabled = True
                    return None
                self._renew_http = httpx.Client(
                    transport=httpx.HTTPTransport(uds=self._socket_path),
                    timeout=httpx.Timeout(10.0, connect=5.0),
                )
            return self._renew_http

    def _maybe_renew(self) -> None:
        """Best-effort proactive renewal. Never raises."""
        if not self._claim_renewal():
            return
        try:
            http = self._renew_transport()
            if http is None:
                return
            response = http.post(
                "http://_" + _RENEW_PATH,
                headers={_TOKEN_HEADER: self._token},
            )
            self._note_renew_response(response)
        except Exception:  # noqa: BLE001 — renewal must never fail the caller
            _logger.debug(
                "llm-dispatcher client: token renewal attempt failed "
                "(will retry after backoff)", exc_info=True,
            )
            with self._lock:
                self._expires_at = (
                    time.time() + _RENEW_RETRY_BACKOFF_S + self._margin_s
                )
            self._note_renew_failure("transport error")
        finally:
            self._release_renewal()

    def _note_renew_failure(self, why: str) -> None:
        """Count a failed renewal attempt; escalate to ONE WARNING
        when the streak reaches the threshold (a permanently broken
        renewal plane otherwise surfaces only at token TTL, hours
        later, as a hard 401)."""
        with self._lock:
            self._consecutive_failures += 1
            should_warn = (
                self._consecutive_failures >= _RENEW_FAILURE_WARN_THRESHOLD
                and not self._failure_warned
            )
            if should_warn:
                self._failure_warned = True
            count = self._consecutive_failures
        if should_warn:
            _logger.warning(
                "llm-dispatcher client: token renewal has failed %d "
                "consecutive times (last: %s) — if this persists the "
                "worker token expires at its TTL and requests will "
                "start failing with 401",
                count, why,
            )

    def _note_renew_success(self) -> None:
        """Reset the failure streak; log recovery once if we warned."""
        with self._lock:
            recovered = self._failure_warned
            self._consecutive_failures = 0
            self._failure_warned = False
        if recovered:
            _logger.info(
                "llm-dispatcher client: token renewal recovered",
            )

    def _note_renew_response(self, response: httpx.Response) -> None:
        if response.status_code == 200:
            try:
                data = response.json()
                expires_at = float(data.get("expires_at") or 0.0)
                ttl_s = float(data.get("ttl_s") or 0.0)
            except (ValueError, TypeError):
                expires_at, ttl_s = 0.0, 0.0
            with self._lock:
                if expires_at > 0:
                    self._expires_at = expires_at
                if ttl_s > 0:
                    # Renew when less than the margin remains. Half
                    # the TTL for short windows; capped at an hour so
                    # an 8 h token renews roughly once an hour under
                    # steady traffic, and floored so one long LLM call
                    # can't straddle the threshold un-renewed.
                    self._margin_s = min(
                        _RENEW_MARGIN_MAX_S,
                        max(_RENEW_MARGIN_MIN_S, ttl_s * 0.5),
                    )
            self._note_renew_success()
            return
        if response.status_code in (403, 404, 405):
            # Endpoint absent (older dispatcher) or this token kind is
            # not renewable — stop paying the extra round trip.
            self._disabled = True
            _logger.debug(
                "llm-dispatcher client: token renewal unavailable "
                "(%d) — proactive renewal disabled", response.status_code,
            )
            return
        # 401 = token already dead (the main request will surface the
        # same 401 to the SDK); 5xx = transient. Back off so a dead
        # token doesn't double every request with a futile renew leg.
        with self._lock:
            self._expires_at = time.time() + _RENEW_RETRY_BACKOFF_S + self._margin_s
        self._note_renew_failure(f"HTTP {response.status_code}")

    # -- httpx auth flows -----------------------------------------------

    def sync_auth_flow(self, request):
        request.headers[_TOKEN_HEADER] = self._token
        self._maybe_renew()
        yield request

    async def async_auth_flow(self, request):
        # No renewal on the async flow: the out-of-band renewal client
        # is synchronous and must not block an event loop. No RAPTOR
        # worker uses an async client against the dispatcher today; if
        # one appears, its token simply behaves like a non-refreshing
        # client's (hard 401 at TTL).
        request.headers[_TOKEN_HEADER] = self._token
        yield request


def read_token(fd: int | None = None) -> str:
    """Read the worker's capability token from the inherited FD.

    Pass ``fd`` explicitly for tests; production code reads
    ``RAPTOR_LLM_TOKEN_FD`` from the environment. The FD is closed
    after a successful read so the token doesn't survive the call.
    """
    if fd is None:
        env = os.environ.get("RAPTOR_LLM_TOKEN_FD")
        if env is None:
            msg = (
                "RAPTOR_LLM_TOKEN_FD not set — worker must be spawned via "
                "core.llm.dispatcher.spawn_worker"
            )
            raise RuntimeError(msg)
        try:
            fd = int(env)
        except (ValueError, TypeError):
            msg = f"RAPTOR_LLM_TOKEN_FD is not a valid fd number: {env!r}"
            raise RuntimeError(msg) from None
    try:
        # 64 bytes is plenty for a 32-byte url-safe token.
        raw = os.read(fd, 64)
        try:
            token = raw.decode("ascii").strip()
        except UnicodeDecodeError as e:
            # Scrub the raw bytes from any propagated error message:
            # ``UnicodeDecodeError.__str__`` embeds the input bytes
            # which IS the token. Re-raise with a generic message
            # so a traceback in operator logs never leaks the
            # credential. Reason ("encoding" / "position") is safe.
            msg = (
                f"RAPTOR_LLM_TOKEN_FD payload was not ASCII "
                f"({e.reason} at position {e.start})"
            )
            raise RuntimeError(msg) from None
        finally:
            # Drop the buffer reference before propagating any error
            # so a `pdb` post-mortem doesn't surface the raw bytes
            # from a local. (Best-effort; CPython may keep it alive
            # in the frame's f_locals until GC.)
            del raw
    finally:
        os.close(fd)
    if not token:
        msg = "RAPTOR_LLM_TOKEN_FD pipe was empty"
        raise RuntimeError(msg)
    return token


# Token cache: ``read_token()`` consumes the FD on first read. When
# multiple ``Provider`` instances share the same worker process — every
# RAPTOR analysis script does this when the operator has multiple
# providers configured — the second instance's call to ``read_token``
# would fail because the FD is already closed. Cache the value at
# process scope so all Provider constructors in the same worker share
# one resolved token.
_cached_token: str | None = None
_cache_lock = threading.Lock()


def _get_or_read_token() -> str:
    """Return the worker's token, reading once and caching for the
    rest of the process lifetime."""
    global _cached_token
    if _cached_token is not None:
        return _cached_token
    with _cache_lock:
        if _cached_token is not None:
            return _cached_token
        _cached_token = read_token()
        return _cached_token


def _make_httpx_client(
    socket_path: str, token: str, *, timeout: float | None = None,
) -> httpx.Client:
    """Build the underlying ``httpx`` client.

    UDS transport directs all traffic to the dispatcher; the
    ``X-Raptor-Token`` header is attached to every request via the
    client's default headers.

    ``timeout`` (seconds) sets the request timeout the SDK ends up
    using; setting it on the SDK client AFTER construction is a
    no-op for the underlying httpx, so it has to flow in through
    here.

    The client also carries :class:`_TokenRenewalAuth`, which
    proactively re-arms the worker token's TTL window before expiry
    (out-of-band POST ``/_token/renew`` over the same UDS) so runs
    longer than the dispatcher's token TTL keep dispatching instead
    of 401-ing mid-run. Set ``RAPTOR_LLM_TOKEN_RENEW=0`` to opt out.
    """
    transport = httpx.HTTPTransport(uds=socket_path)
    request_timeout = timeout if timeout is not None else 60.0
    return httpx.Client(
        transport=transport,
        headers={_TOKEN_HEADER: token},
        auth=_TokenRenewalAuth(token, socket_path),
        timeout=httpx.Timeout(request_timeout, connect=5.0),
    )


def _resolve_socket_and_token(
    socket_path: str | None, token: str | None,
) -> tuple[str, str]:
    """Shared default-resolution for the per-provider client factories.

    Lifted out of ``make_anthropic_client`` so OpenAI and Gemini
    factories don't repeat the same env-var fallback logic and stay
    in sync if the env var names ever change.
    """
    if socket_path is None:
        env = os.environ.get("RAPTOR_LLM_SOCKET")
        if env is None:
            msg = (
                "RAPTOR_LLM_SOCKET not set — worker must be spawned via "
                "core.llm.dispatcher.spawn_worker"
            )
            raise RuntimeError(msg)
        socket_path = env
    if token is None:
        token = _get_or_read_token()
    return socket_path, token


def make_anthropic_client(
    *,
    socket_path: str | None = None,
    token: str | None = None,
    timeout: float | None = None,
):
    """Return a stock ``anthropic.Anthropic`` client routed through
    the dispatcher.

    Defaults read socket path from ``RAPTOR_LLM_SOCKET`` and the
    token from ``RAPTOR_LLM_TOKEN_FD``. Pass arguments explicitly
    only in tests.

    ``timeout`` (seconds) flows through to the underlying httpx; the
    SDK clients on the dispatcher path don't accept post-construction
    timeout changes since their httpx instance is fixed at build time.

    The returned client behaves exactly like a normal Anthropic SDK
    client — workers call ``client.messages.create(...)`` etc. and
    receive responses (including streamed ones). The credential
    isolation is invisible at the call site.

    ``max_retries=0``: the callers' own retry loops (the provider
    turn() loops, ``LLMClient``'s generate loops) are the single
    retry authority — the SDK default (max_retries=2) stacks
    multiplicatively under them, and each stacked attempt rides the
    dispatcher's full upstream read timeout.
    """
    import anthropic  # imported lazily so the module loads without the SDK

    socket_path, token = _resolve_socket_and_token(socket_path, token)
    http = _make_httpx_client(socket_path, token, timeout=timeout)
    # ``api_key='dummy'`` because the SDK validates that *something*
    # was passed; the dispatcher strips it and injects the real key.
    # ``base_url`` directs requests to ``/anthropic/...`` so the
    # dispatcher can route by path prefix. The Anthropic SDK appends
    # ``/v1/messages`` itself, so the base URL stops at the provider
    # prefix — adding ``/v1`` here would double it and produce
    # ``/v1/v1/messages`` upstream.
    return anthropic.Anthropic(
        api_key="dummy-not-used",
        base_url="http://_/anthropic",
        max_retries=0,
        http_client=http,
    )


def make_bedrock_client(
    *,
    api: str = "mantle",
    socket_path: str | None = None,
    token: str | None = None,
    timeout: float | None = None,
):
    """Return a stock ``anthropic.Anthropic`` client whose requests are
    AWS-auth-attached for a Bedrock surface by the dispatcher.

    ``api`` selects which Bedrock surface the dispatcher forwards to:

    * ``"mantle"`` (default) — ``bedrock-mantle.<region>.api.aws/
      anthropic/v1/messages``, native Anthropic Messages API with bare
      model IDs (``anthropic.claude-opus-4-8``), native SSE streaming,
      tool use, prompt caching, computer use.
    * ``"runtime"`` — ``bedrock-runtime.<region>.amazonaws.com/model/
      <id>/invoke``, legacy InvokeModel surface.  Required for models
      not yet on Mantle, for cross-region inference profile IDs
      (``us.``/``eu.``/``global.``), and for compliance-pinned
      ARN-versioned IDs.  Non-streaming only.

    Identical shape to :func:`make_anthropic_client` except the base URL
    points at the ``/bedrock/<api>`` prefix.  The worker speaks plain
    Anthropic Messages and holds no AWS credentials — boto3/botocore
    never load in the worker's address space.  The dispatcher's bedrock
    rule attaches the parent's bearer token (``AWS_BEARER_TOKEN_BEDROCK``)
    or SigV4-signs with the parent's AWS credentials, and forwards to
    the selected Bedrock surface.  The response is standard Anthropic
    Messages JSON regardless of which API was used.  Same
    ``max_retries=0`` contract as :func:`make_anthropic_client`."""
    import anthropic

    if api not in ("mantle", "runtime"):
        msg = (
            f"make_bedrock_client: api must be 'mantle' or 'runtime', "
            f"got {api!r}"
        )
        raise ValueError(msg)
    socket_path, token = _resolve_socket_and_token(socket_path, token)
    http = _make_httpx_client(socket_path, token, timeout=timeout)
    return anthropic.Anthropic(
        api_key="dummy-not-used",
        base_url=f"http://_/bedrock/{api}",
        max_retries=0,
        http_client=http,
    )


def make_openai_client(
    *,
    socket_path: str | None = None,
    token: str | None = None,
    timeout: float | None = None,
):
    """Return a stock ``openai.OpenAI`` client routed through the
    dispatcher. Same shape (and ``max_retries=0`` contract) as
    :func:`make_anthropic_client`."""
    import openai

    socket_path, token = _resolve_socket_and_token(socket_path, token)
    http = _make_httpx_client(socket_path, token, timeout=timeout)
    return openai.OpenAI(
        api_key="dummy-not-used",
        base_url="http://_/openai/v1",
        max_retries=0,
        http_client=http,
    )


def relay_for_grandchild() -> tuple[str, int]:
    """Return ``(socket_path, token_fd)`` for a grandchild ``Popen``.

    Use case: a worker script that's already authenticated to a
    dispatcher (env has ``RAPTOR_LLM_SOCKET`` + ``RAPTOR_LLM_TOKEN_FD``)
    needs to spawn its own subprocess that should share the same
    LLM session — typical example is ``raptor_agentic.py`` spawning
    ``packages/llm_analysis/agent.py`` in ``--sequential`` mode.

    The grandchild gets:
      - the same UDS path (same dispatcher) via env var
      - the same token value, but in a fresh inheritable FD

    Sharing the token value within a parent → child trust boundary
    is fine: both processes are part of the same RAPTOR run, both
    are equally trusted. The FD wrapper (rather than env-var token
    passing) keeps the same property as the original ``spawn_worker``
    chain — no other same-UID process can scrape the token via
    ``/proc/N/environ``.

    Caller is responsible for ``os.close(token_fd)`` after passing
    it via ``Popen(pass_fds=...)``, mirroring the spawn_worker
    contract.
    """
    socket_path, token = _resolve_socket_and_token(None, None)
    read_fd, write_fd = os.pipe()
    # Pre-fix: a failure in ``os.write`` (e.g. EPIPE / EBADF) or
    # ``os.set_inheritable`` left ``read_fd`` open, leaking an
    # inheritable FD that pointed at a half-written token pipe.
    # Wrap the setup so any failure closes BOTH ends before the
    # exception propagates.
    try:
        try:
            os.write(write_fd, token.encode())
        finally:
            os.close(write_fd)
        os.set_inheritable(read_fd, True)
    except OSError:
        try:
            os.close(read_fd)
        except OSError:
            pass
        raise
    return socket_path, read_fd


def _child_admin_request(
    op: str,
    payload: dict,
    *,
    socket_path: str | None = None,
    token: str | None = None,
    timeout: float = 10.0,
) -> dict:
    """POST one /_child/<op> management request over the dispatcher UDS.

    The worker's own capability token authenticates the call — child-
    token management is delegation/attenuation of authority the worker
    already holds (it can spend the budget itself; minting a scoped
    child token only narrows it). Raises ``RuntimeError`` with a clear
    message when the dispatcher is unreachable or refuses, so callers
    fail fast instead of hanging or silently downgrading.
    """
    socket_path, token = _resolve_socket_and_token(socket_path, token)
    http = _make_httpx_client(socket_path, token, timeout=timeout)
    try:
        resp = http.post(f"http://_/_child/{op}", json=payload)
    except httpx.HTTPError as exc:
        msg = (
            f"LLM dispatcher unreachable for child-token {op} "
            f"({type(exc).__name__}) — is the dispatcher running?"
        )
        raise RuntimeError(msg) from exc
    finally:
        http.close()
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code != 200:
        msg = (
            f"child-token {op} refused ({resp.status_code}): "
            f"{data.get('error', 'unknown error')}"
        )
        raise RuntimeError(msg)
    if not isinstance(data, dict):
        msg = f"child-token {op}: malformed response"
        raise RuntimeError(msg)
    return data


def mint_child_token(
    *,
    budget_usd: float,
    models: list | None = None,
    ttl_s: int | None = None,
    label: str = "cc-child",
    socket_path: str | None = None,
    token: str | None = None,
) -> dict:
    """Mint a scoped child token via the dispatcher's UDS plane.

    Returns ``{"token", "token_id", "expires_at", "budget_usd",
    "request_budget"}``. The ``token`` value is the child's bearer
    credential — hand it ONLY to the spawned child's env, never log it
    (``token_id`` is the loggable correlation id).
    """
    payload: dict = {"budget_usd": budget_usd, "label": label}
    if models:
        payload["models"] = list(models)
    if ttl_s:
        payload["ttl_s"] = int(ttl_s)
    return _child_admin_request(
        "mint", payload, socket_path=socket_path, token=token,
    )


def revoke_child_token(
    token_id: str,
    *,
    socket_path: str | None = None,
    token: str | None = None,
) -> dict:
    """Revoke a child token by its public id."""
    return _child_admin_request(
        "revoke", {"token_id": token_id},
        socket_path=socket_path, token=token,
    )


def child_token_spend(
    token_id: str,
    *,
    socket_path: str | None = None,
    token: str | None = None,
) -> dict:
    """Read a child token's spend/limits snapshot by its public id."""
    return _child_admin_request(
        "spend", {"token_id": token_id},
        socket_path=socket_path, token=token,
    )


def reconcile_child_spend(
    dispatcher_spent_usd: float,
    child_reported_usd: float = 0.0,
) -> float:
    """Reconcile the two ledgers for one CC child: the dispatcher's
    booked token spend and the child's own exit-report cost.

    Max-of-ledgers, never sum: the two ledgers measure the SAME calls
    from opposite ends of the wire, so adding them double-books; the
    max guarantees nothing vanishes when either side under-reports
    (a killed child reports nothing; an unpriced model books $0 on
    the dispatcher). Matches the failed-call booking contract on the
    provider ledger (``max(total_cost, provider_spend)``).
    """
    try:
        a = max(float(dispatcher_spent_usd), 0.0)
    except (TypeError, ValueError):
        a = 0.0
    try:
        b = max(float(child_reported_usd), 0.0)
    except (TypeError, ValueError):
        b = 0.0
    return max(a, b)


def make_gemini_base_url(*, socket_path: str | None = None,
                          token: str | None = None,
                          timeout: float | None = None,
                          ) -> tuple[str, httpx.Client]:
    """Gemini's Python SDK (``google-genai``) doesn't take a custom
    httpx client through its top-level ``Client`` constructor in all
    versions, so callers wire the base URL + httpx client themselves.

    Returns a tuple ``(base_url, http_client)`` the caller passes to
    whichever Gemini client wrapper they use. Same socket/token
    resolution as the other factories, and ``timeout`` (seconds)
    flows through to the underlying httpx exactly like the
    Anthropic/OpenAI/Bedrock factories — without it, dispatcher-routed
    Gemini calls were pinned to the 60s httpx default regardless of
    the model's configured timeout (thinking calls routinely exceed
    60s).
    """
    socket_path, token = _resolve_socket_and_token(socket_path, token)
    http = _make_httpx_client(socket_path, token, timeout=timeout)
    return "http://_/gemini", http
