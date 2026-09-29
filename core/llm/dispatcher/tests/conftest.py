"""Shared fixtures for dispatcher tests.

Proxy-env hermeticity: these tests spin up loopback fake upstreams
(Bedrock runtime doubles, provider echo servers) and forward to them
through the dispatcher's httpx client, which honours proxy env
(trust_env). On a mandatory-egress-proxy host the live HTTPS_PROXY in
the test process routed every "upstream" call to the corporate proxy
— which cannot reach this machine's loopback — so 30 tests failed
with 403s / missing captures while passing on unproxied machines.

Scrub the whole conventional proxy family for every test in this
directory. Tests that exercise proxy propagation explicitly (e.g.
test_f085_spawn_default_env) re-set the vars with monkeypatch inside
the test body, which runs after this autouse fixture — unaffected.

Same class of fix as the hermetic-proxy-host-tests patch (see
core/orchestration/tests/test_agentic_passes.py).

AWS-env hermeticity, same reasoning: CredentialStore reads the
ambient env at construction and deliberately prefers a profile chain
(AWS_PROFILE — refresh-capable) over explicit keys. On a
Bedrock-configured host that made the SigV4 signing tests resolve the
host's REAL credentials through a network-touching botocore chain
instead of the seeded fakes — signature assertions failed (or hung
once the proxy env was scrubbed). Tests seed exactly the credentials
they mean to test; the ambient family is noise here.
"""

import os
import shutil
import socketserver
import tempfile
from collections.abc import Iterator

import pytest

_PROXY_ENV_FAMILY = (
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
)

_AWS_ENV_FAMILY = (
    "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK", "AWS_ENDPOINT_URL_BEDROCK",
    "CLAUDE_CODE_USE_BEDROCK",
)

# Snapshot at import time (before any scrubbing) so tests that
# genuinely need the operator's real egress route can opt back in.
_OPERATOR_PROXY_ENV = {
    k: v for k in _PROXY_ENV_FAMILY if (v := os.environ.get(k)) is not None
}


@pytest.fixture(autouse=True)
def _scrub_ambient_env(monkeypatch):
    for var in (*_PROXY_ENV_FAMILY, *_AWS_ENV_FAMILY):
        monkeypatch.delenv(var, raising=False)


# serve_forever() shutdown-notice poll, for every socketserver these
# tests spin up (the dispatcher's worker/child/TCP planes AND the
# captive upstream doubles): socketserver's serve_forever only checks
# for shutdown() every ``poll_interval``, so each server thread pays
# up to one interval of pure wall-clock wait at teardown. At the
# stdlib default (0.5s) with three-plus servers per test, that wait
# was the single largest cost of this battery (~0.7s of nearly every
# dispatcher test). The knob bounds ONLY shutdown-notice latency —
# request handling is selector-driven and wakes immediately — so
# shrinking it weakens nothing the tests assert.
#
# 0.02s, both directions: TOO LOW (sub-millisecond) has every idle
# server thread busy-spinning its selector for the length of each
# test, which under ``-n auto`` is real contention; TOO HIGH
# re-inserts per-server teardown latency (0.1s would already put
# ~0.3s back on every dispatcher-constructing test). Production code
# is untouched: it keeps the stdlib default, and this wrapper lives
# only in the test harness.
_SERVE_POLL_INTERVAL_S = 0.02

# Bound once at import so repeated fixture applications can never
# stack wrappers.
_REAL_SERVE_FOREVER = socketserver.BaseServer.serve_forever


@pytest.fixture(autouse=True)
def _fast_serve_shutdown_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    def _serve_forever_fast_poll(
        self: socketserver.BaseServer,
        poll_interval: float = _SERVE_POLL_INTERVAL_S,
    ) -> None:
        # Explicit callers keep their own interval — only the stdlib
        # default is replaced.
        _REAL_SERVE_FOREVER(self, poll_interval=poll_interval)

    monkeypatch.setattr(
        socketserver.BaseServer, "serve_forever", _serve_forever_fast_poll,
    )


# AF_UNIX hermeticity: every real-dispatcher test binds two Unix
# sockets under a ``tempfile.mkdtemp(prefix="raptor-llm-<run_id>-")``
# dir, and Linux caps a socket path at 108 bytes (sun_path, incl. NUL).
# The session-wide TMPDIR containment (root conftest) nests scratch
# one level deeper, and on hosts whose ambient TMPDIR is itself a
# nested per-session dir the combined prefix pushes
# ``.../raptor-llm-<run_id>-XXXXXXXX/llm-child.sock`` past the cap —
# every dispatcher construction then dies with "AF_UNIX path too
# long" while short-/tmp hosts (CI) pass. Budget below the cap for
# the dispatcher's own suffix: "/raptor-llm-" + run_id (headroom 40;
# longest in this dir is 31) + "-XXXXXXXX" + "/llm-child.sock".
# Every quantity here is BYTES of the fsencoded path — the unit the
# kernel compares sun_path in — so the TMPDIR side of the check must
# measure ``len(os.fsencode(...))``, never ``len(str)`` (a multibyte
# root is longer in bytes than in chars, and an undecodable root
# reaches Python as surrogate-escaped str that bare ``.encode()``
# rejects). The suffix terms below are ASCII literals: chars == bytes.
_AF_UNIX_PATH_MAX = 107  # usable bytes (108 incl. the trailing NUL)
_SOCKET_SUFFIX_BUDGET = len("/raptor-llm-") + 40 + len("-XXXXXXXX") + len(
    "/llm-child.sock")
_SAFE_TMP_LEN = _AF_UNIX_PATH_MAX - _SOCKET_SUFFIX_BUDGET


@pytest.fixture(autouse=True)
def _af_unix_safe_tmp(monkeypatch) -> Iterator[None]:
    """Re-root scratch at a short ``/tmp`` dir when the contained
    TMPDIR would blow the AF_UNIX path cap.

    No-op on short-tmp hosts, so the session containment (and its
    kill-leak story) is preserved there; on long-tmp hosts this is
    the root conftest's documented AF_UNIX exception (sites that must
    not be contained anchor at ``dir="/tmp"``). Cleanup is the
    ``finally`` rmtree below; a SIGKILLed session leaks the dir, and
    on exactly these deep-TMPDIR hosts core/run/tmp_reaper.py does
    NOT reclaim it — the sweep covers only ``tempfile.gettempdir()``,
    which here is the deep dir, not ``/tmp``. The ``raptor-llm-``
    prefix listing only helps when some later session runs with
    ``gettempdir() == /tmp`` (CI, short-tmp hosts) and sweeps it up.
    """
    if len(os.fsencode(tempfile.gettempdir())) <= _SAFE_TMP_LEN:
        yield
        return
    short_tmp = tempfile.mkdtemp(prefix="raptor-llm-sock-", dir="/tmp")
    monkeypatch.setenv("TMPDIR", short_tmp)
    monkeypatch.setattr(tempfile, "tempdir", short_tmp)
    try:
        yield
    finally:
        shutil.rmtree(short_tmp, ignore_errors=True)


# Optional-dep (h2) hermeticity: tests marked ``upstream_forward``
# drive a real relayed request through the dispatcher's
# upstream-forwarding leg. That leg builds its httpx clients with
# ``http2=http2_enabled()``, and when the operator has opted into
# HTTP/2 (RAPTOR_HTTP2) the h2 probe behind that flag runs INSIDE
# the relay thread on first forward: on a runner where the ``h2``
# package is unavailable (hidden by a lean-environment meta_path
# blocker, or present-but-broken so ``find_spec``/``import h2``
# raises) the relay thread dies mid-request and the client side of
# the test fails with a RemoteProtocolError — an error, where a
# missing OPTIONAL dependency must produce a skip.
#
# The gate is CONDITIONAL on the opt-in, in both directions:
#
# * opted in + h2 unavailable → skip (reason names h2). Running
#   would error inside the server thread, never a clean failure.
# * no opt-in → run, even with h2 absent. ``http2_enabled()``
#   returns False before ever touching h2, the leg speaks HTTP/1.1,
#   and CI runners — which deliberately do not install h2
#   (requirements.txt ships the pin commented out) — must keep
#   their full relay coverage. An unconditional importorskip here
#   would silently drop all marked tests from every CI lane.
#
# The truthy set below mirrors core.llm.http_pool.http2_enabled()'s
# env parse (the operator contract documented in docs/llm.md); we
# cannot call http2_enabled() itself because it deliberately
# reports False for exactly the opted-in-but-h2-missing case this
# gate exists to intercept. If http2_enabled() grows a new truthy
# spelling, add it here; if a value is retired, drop it here.
_HTTP2_OPT_IN_VALUES = ("1", "true", "yes", "on")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "upstream_forward: the test relays a real request through the "
        "dispatcher's upstream-forwarding leg (whose client "
        "construction probes/imports the optional 'h2' package when "
        "HTTP/2 is opted in via RAPTOR_HTTP2) — skipped when the "
        "opt-in is set but h2 is unavailable",
    )


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("upstream_forward") is None:
        return
    opted_in = os.environ.get(
        "RAPTOR_HTTP2", "",
    ).strip().lower() in _HTTP2_OPT_IN_VALUES
    if not opted_in:
        return
    pytest.importorskip(
        "h2",
        reason="HTTP/2 opted in (RAPTOR_HTTP2) but the optional 'h2' "
               "package is unavailable — the dispatcher "
               "upstream-forwarding leg this test relays through "
               "cannot be built",
    )


@pytest.fixture
def operator_proxy_env(monkeypatch):
    """Opt-back-in for tests that reach REAL external upstreams
    (e.g. the valid-token gate test that forwards to anthropic.com):
    restores the operator's launch-time proxy route that the autouse
    scrub removed. On unproxied hosts this is a no-op."""
    for k, v in _OPERATOR_PROXY_ENV.items():
        monkeypatch.setenv(k, v)
    return dict(_OPERATOR_PROXY_ENV)
