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

import pytest

from core.oci.auth import (
    BasicCredentials,
    lookup_credentials,
    parse_www_authenticate,
)


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
    replaced with ``_`` to fit env-var naming rules."""
    monkeypatch.setenv("RAPTOR_OCI_REGISTRY_1_DOCKER_IO_USER", "u")
    monkeypatch.setenv("RAPTOR_OCI_REGISTRY_1_DOCKER_IO_PASSWORD", "p")
    creds = lookup_credentials("registry-1.docker.io")
    assert creds == BasicCredentials("u", "p")


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
