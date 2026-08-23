"""Tests for ``core.oci.auth``.

Auth is security-critical: a wrong answer is either a credentials
leak (env var picked up unexpectedly) or a fetch failure (anonymous
attempted on a registry that requires login). Tests pin both
positive paths AND the refusal of credsStore / credHelpers.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path


from core.oci.auth import (
    BasicCredentials,
    lookup_credentials,
    parse_www_authenticate,
)
from core.oci.client import OciRegistryClient
from core.oci.image_ref import parse_image_ref


# ---------------------------------------------------------------------------
# Env vars
# ---------------------------------------------------------------------------


def test_env_vars_picked_up(monkeypatch):
    monkeypatch.setenv("RAPTOR_OCI_GHCR_IO_USER", "alice")
    monkeypatch.setenv("RAPTOR_OCI_GHCR_IO_PASSWORD", "secret")
    creds = lookup_credentials("ghcr.io")
    assert creds == BasicCredentials("alice", "secret")


def test_env_vars_with_hyphen_in_host(monkeypatch):
    """Hosts with hyphens (``registry-1.docker.io``) need the hyphen
    replaced with ``_`` to fit env-var naming rules — and, because
    that encoding is ambiguous ('.' also maps to '_'), an exact-match
    ``RAPTOR_OCI_<KEY>_HOST`` pin."""
    monkeypatch.setenv("RAPTOR_OCI_REGISTRY_1_DOCKER_IO_USER", "u")
    monkeypatch.setenv("RAPTOR_OCI_REGISTRY_1_DOCKER_IO_PASSWORD", "p")
    monkeypatch.setenv(
        "RAPTOR_OCI_REGISTRY_1_DOCKER_IO_HOST", "registry-1.docker.io",
    )
    creds = lookup_credentials("registry-1.docker.io")
    assert creds == BasicCredentials("u", "p")


def test_env_key_collision_does_not_leak_credentials(monkeypatch):
    """`evil-registry.com` and `evil.registry.com` share the derived
    env key EVIL_REGISTRY_COM. Credentials configured for one must
    never be released to the other: a hostile image reference naming
    the colliding host would otherwise capture them via the Basic /
    token-exchange path."""
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)
    monkeypatch.setattr(
        "pathlib.Path.home", lambda: Path("/nonexistent-home"),
    )
    monkeypatch.setenv("RAPTOR_OCI_EVIL_REGISTRY_COM_USER", "operator")
    monkeypatch.setenv("RAPTOR_OCI_EVIL_REGISTRY_COM_PASSWORD", "hunter2")
    # Un-pinned creds: released only to the dash-free hostname (the
    # encoding's unique dash-free preimage) ...
    assert lookup_credentials("evil.registry.com") \
        == BasicCredentials("operator", "hunter2")
    # ... and never to a colliding dashed hostname.
    assert lookup_credentials("evil-registry.com") is None


def test_env_host_pin_releases_only_to_pinned_host(monkeypatch):
    """When the operator's registry hostname itself contains a dash,
    the RAPTOR_OCI_<KEY>_HOST pin routes credentials to exactly that
    host — and blocks the dotted collider."""
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)
    monkeypatch.setattr(
        "pathlib.Path.home", lambda: Path("/nonexistent-home"),
    )
    monkeypatch.setenv("RAPTOR_OCI_MY_REGISTRY_CORP_USER", "operator")
    monkeypatch.setenv("RAPTOR_OCI_MY_REGISTRY_CORP_PASSWORD", "pw")
    monkeypatch.setenv("RAPTOR_OCI_MY_REGISTRY_CORP_HOST", "my-registry.corp")
    assert lookup_credentials("my-registry.corp") \
        == BasicCredentials("operator", "pw")
    assert lookup_credentials("my.registry.corp") is None


def test_env_underscore_host_refused_without_pin(monkeypatch):
    """Underscores are invalid in DNS hostnames but survive parsing;
    they collide with '.' and '-' in the encoding, so they get the
    same ambiguity treatment."""
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)
    monkeypatch.setattr(
        "pathlib.Path.home", lambda: Path("/nonexistent-home"),
    )
    monkeypatch.setenv("RAPTOR_OCI_EVIL_REGISTRY_COM_USER", "operator")
    monkeypatch.setenv("RAPTOR_OCI_EVIL_REGISTRY_COM_PASSWORD", "pw")
    assert lookup_credentials("evil_registry.com") is None


def test_env_vars_partial_returns_none(monkeypatch):
    """User without password (or vice versa) doesn't half-create a
    credential — both fields are required."""
    monkeypatch.setenv("RAPTOR_OCI_GHCR_IO_USER", "alice")
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_PASSWORD", raising=False)
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)
    monkeypatch.setattr(
        "pathlib.Path.home", lambda: Path("/nonexistent-home"),
    )
    assert lookup_credentials("ghcr.io") is None


# ---------------------------------------------------------------------------
# docker config.json — inline auths
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, body: dict) -> Path:
    cfg_dir = tmp_path / "docker"
    cfg_dir.mkdir()
    (cfg_dir / "config.json").write_text(
        json.dumps(body), encoding="utf-8",
    )
    return cfg_dir


def test_docker_config_inline_auth_picked_up(tmp_path, monkeypatch):
    """The standard ``docker login`` artefact: ``auth: <base64
    user:password>``."""
    encoded = base64.b64encode(b"alice:secret").decode("ascii")
    cfg_dir = _write_config(tmp_path, {
        "auths": {"ghcr.io": {"auth": encoded}},
    })
    monkeypatch.setenv("DOCKER_CONFIG", str(cfg_dir))
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_USER", raising=False)
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_PASSWORD", raising=False)
    creds = lookup_credentials("ghcr.io")
    assert creds == BasicCredentials("alice", "secret")


def test_docker_config_explicit_user_password_fields(tmp_path, monkeypatch):
    """Some tools write ``username``/``password`` fields directly
    instead of base64'd ``auth``. Both shapes should work."""
    cfg_dir = _write_config(tmp_path, {
        "auths": {"ghcr.io": {"username": "alice", "password": "secret"}},
    })
    monkeypatch.setenv("DOCKER_CONFIG", str(cfg_dir))
    creds = lookup_credentials("ghcr.io")
    assert creds == BasicCredentials("alice", "secret")


def test_docker_config_https_prefixed_key(tmp_path, monkeypatch):
    """Older Docker config files use ``https://<host>`` as the
    ``auths`` key. Both with and without the prefix should match."""
    encoded = base64.b64encode(b"alice:secret").decode("ascii")
    cfg_dir = _write_config(tmp_path, {
        "auths": {"https://ghcr.io": {"auth": encoded}},
    })
    monkeypatch.setenv("DOCKER_CONFIG", str(cfg_dir))
    creds = lookup_credentials("ghcr.io")
    assert creds == BasicCredentials("alice", "secret")


def test_docker_config_credsstore_refused(tmp_path, monkeypatch, caplog):
    """``credsStore: osxkeychain`` would require shelling out to a
    credential helper. We refuse and fall through (which yields
    None for callers without env vars)."""
    cfg_dir = _write_config(tmp_path, {
        "credsStore": "osxkeychain",
        "auths": {"ghcr.io": {}},          # empty entry — no inline auth
    })
    monkeypatch.setenv("DOCKER_CONFIG", str(cfg_dir))
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_USER", raising=False)
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_PASSWORD", raising=False)
    assert lookup_credentials("ghcr.io") is None


def test_docker_config_credhelpers_refused(tmp_path, monkeypatch):
    """Per-host credential helpers same story — refused."""
    cfg_dir = _write_config(tmp_path, {
        "credHelpers": {"ghcr.io": "ecr-login"},
        "auths": {"ghcr.io": {}},
    })
    monkeypatch.setenv("DOCKER_CONFIG", str(cfg_dir))
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_USER", raising=False)
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_PASSWORD", raising=False)
    assert lookup_credentials("ghcr.io") is None


def test_docker_config_missing_returns_none(tmp_path, monkeypatch):
    """Common case for new operators / CI: no ``docker login`` ever
    run. Returns None so the caller can fall back to anonymous."""
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "nonexistent"))
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_USER", raising=False)
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_PASSWORD", raising=False)
    assert lookup_credentials("ghcr.io") is None


def test_docker_config_malformed_auth_field(tmp_path, monkeypatch):
    """Malformed base64 / no colon → return None rather than
    crashing. Operators with corrupt configs get graceful
    fallthrough; the failure mode is "no creds found" not "raptor
    crashed"."""
    cfg_dir = _write_config(tmp_path, {
        "auths": {"ghcr.io": {"auth": "!!!notbase64!!!"}},
    })
    monkeypatch.setenv("DOCKER_CONFIG", str(cfg_dir))
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_USER", raising=False)
    monkeypatch.delenv("RAPTOR_OCI_GHCR_IO_PASSWORD", raising=False)
    assert lookup_credentials("ghcr.io") is None


# ---------------------------------------------------------------------------
# Env var beats docker config (closer-to-CLI source wins)
# ---------------------------------------------------------------------------


def test_env_vars_beat_docker_config(tmp_path, monkeypatch):
    """When both an env var AND a docker config entry exist, the
    env var wins. Operators in CI explicitly setting env vars are
    overriding the underlying config; that's the correct
    precedence."""
    encoded = base64.b64encode(b"docker:fromconfig").decode("ascii")
    cfg_dir = _write_config(tmp_path, {
        "auths": {"ghcr.io": {"auth": encoded}},
    })
    monkeypatch.setenv("DOCKER_CONFIG", str(cfg_dir))
    monkeypatch.setenv("RAPTOR_OCI_GHCR_IO_USER", "envuser")
    monkeypatch.setenv("RAPTOR_OCI_GHCR_IO_PASSWORD", "envpw")
    creds = lookup_credentials("ghcr.io")
    assert creds == BasicCredentials("envuser", "envpw")


# ---------------------------------------------------------------------------
# BasicCredentials.to_basic_header
# ---------------------------------------------------------------------------


def test_basic_header_round_trips():
    creds = BasicCredentials("alice", "secret")
    encoded = creds.to_basic_header()
    decoded = base64.b64decode(encoded).decode("utf-8")
    assert decoded == "alice:secret"


# ---------------------------------------------------------------------------
# parse_www_authenticate
# ---------------------------------------------------------------------------


def test_parse_bearer_with_realm_service_scope():
    """Docker Hub's standard challenge."""
    scheme, params = parse_www_authenticate(
        'Bearer realm="https://auth.docker.io/token",'
        'service="registry.docker.io",'
        'scope="repository:library/python:pull"'
    )
    assert scheme == "Bearer"
    assert params["realm"] == "https://auth.docker.io/token"
    assert params["service"] == "registry.docker.io"
    assert params["scope"] == "repository:library/python:pull"


def test_parse_basic_scheme_no_params():
    scheme, params = parse_www_authenticate("Basic")
    assert scheme == "Basic"
    assert params == {}


def test_parse_empty_input():
    scheme, params = parse_www_authenticate("")
    assert scheme == ""
    assert params == {}


def test_parse_extra_whitespace():
    """Some servers emit awkward whitespace; tolerate it."""
    scheme, params = parse_www_authenticate(
        '  Bearer    realm="https://x"  ,  service="y"  '
    )
    assert scheme == "Bearer"
    assert params == {"realm": "https://x", "service": "y"}


# ---------------------------------------------------------------------------
# Client bearer-token cache — the cache must actually serve hits: repeat
# calls for the same image attach the cached token on their FIRST attempt
# (no 401 round-trip, no repeat exchange), and only a 401 received while
# presenting a cached token evicts that token.
# ---------------------------------------------------------------------------


_FAKE_DIGEST = "sha256:" + "0" * 64
_CHALLENGE = (
    'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
    'scope="repository:acme/app:pull"'
)


class _Resp:
    def __init__(self, status: int, body: bytes = b"{}",
                 headers: dict[str, str] | None = None):
        self.status_code = status
        self.content = body
        self.text = body.decode("utf-8", errors="replace")
        self.headers = headers or {}

    def close(self):
        pass


class _TokenDanceHttp:
    """Registry stub: /v2/ paths demand a bearer token from ``valid``
    via a WWW-Authenticate challenge; the token endpoint mints tokens
    from ``minted`` in order."""

    def __init__(self, valid: set[str], minted: list[str]):
        self.valid = valid
        self._minted = list(minted)
        self.exchanges = 0
        # (method, url, Authorization-header-or-None) per request.
        self.requests: list[tuple[str, str, str | None]] = []

    def request(self, method: str, url: str, headers=None, **kwargs):
        auth = (headers or {}).get("Authorization")
        self.requests.append((method, url, auth))
        if url.startswith("https://ghcr.io/token"):
            self.exchanges += 1
            token = self._minted.pop(0)
            return _Resp(200, json.dumps({"token": token}).encode())
        if (auth and auth.startswith("Bearer ")
                and auth[len("Bearer "):] in self.valid):
            return _Resp(
                200, b"{}",
                headers={"Docker-Content-Digest": _FAKE_DIGEST},
            )
        return _Resp(401, b"{}", headers={"WWW-Authenticate": _CHALLENGE})

    def api_calls(self) -> list[tuple[str, str, str | None]]:
        return [r for r in self.requests if "/v2/" in r[1]]


def test_bearer_token_cache_serves_hit_on_second_call():
    http = _TokenDanceHttp(valid={"tok-1"}, minted=["tok-1"])
    client = OciRegistryClient(http, credentials_lookup=lambda r: None)
    ref = parse_image_ref("ghcr.io/acme/app:latest")

    assert client.resolve_digest(ref) == _FAKE_DIGEST
    assert client.resolve_digest(ref) == _FAKE_DIGEST

    # One exchange total — the second call reused the cached token.
    assert http.exchanges == 1
    calls = http.api_calls()
    # First call: anonymous attempt (challenge discovery) + retry.
    # Second call: single request with the cached bearer attached.
    assert len(calls) == 3
    assert calls[0][2] is None
    assert calls[1][2] == "Bearer tok-1"
    assert calls[2][2] == "Bearer tok-1"


def test_stale_cached_token_evicted_and_reexchanged():
    http = _TokenDanceHttp(valid={"tok-1", "tok-2"}, minted=["tok-1", "tok-2"])
    client = OciRegistryClient(http, credentials_lookup=lambda r: None)
    ref = parse_image_ref("ghcr.io/acme/app:latest")

    client.resolve_digest(ref)      # dance → caches tok-1
    http.valid.discard("tok-1")     # token expires server-side
    assert client.resolve_digest(ref) == _FAKE_DIGEST

    # 401-with-cached-token evicted tok-1 and re-exchanged.
    assert http.exchanges == 2
    assert list(client._tokens.values()) == ["tok-2"]
    assert http.api_calls()[-1][2] == "Bearer tok-2"


def test_first_contact_401_does_not_evict_unrelated_entries():
    http = _TokenDanceHttp(valid={"tok-1"}, minted=["tok-1"])
    client = OciRegistryClient(http, credentials_lookup=lambda r: None)
    # A token cached under a DIFFERENT triple must survive the dance.
    other_key = ("https://other.example/token", "svc", "scope")
    client._tokens[other_key] = "other-token"
    ref = parse_image_ref("ghcr.io/acme/app:latest")

    client.resolve_digest(ref)
    assert client._tokens[other_key] == "other-token"
