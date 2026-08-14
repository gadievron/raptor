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


@pytest.fixture
def operator_proxy_env(monkeypatch):
    """Opt-back-in for tests that reach REAL external upstreams
    (e.g. the valid-token gate test that forwards to anthropic.com):
    restores the operator's launch-time proxy route that the autouse
    scrub removed. On unproxied hosts this is a no-op."""
    for k, v in _OPERATOR_PROXY_ENV.items():
        monkeypatch.setenv(k, v)
    return dict(_OPERATOR_PROXY_ENV)
