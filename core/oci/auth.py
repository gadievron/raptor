"""Auth chain for OCI / Docker registries.

Three sources, tried in order:

  1. **Anonymous bearer token** — for public images. The registry's
     ``WWW-Authenticate`` header on a 401 response carries a
     ``realm`` / ``service`` / ``scope`` triple; we request a token
     from that realm without credentials. Works for everything on
     ``docker.io/library/*``, public ``ghcr.io``, ``public.ecr.aws``,
     ``quay.io`` (mostly).

  2. **``~/.docker/config.json`` inline ``auths``** — the standard
     artefact ``docker login`` produces. We read ONLY the inline
     ``auth`` field (base64'd ``user:password``); we **deliberately
     ignore** ``credsStore`` / ``credHelpers`` because honouring
     those means shelling out to a credential helper binary, which
     is a much larger trust surface than reading a file. Operators
     using credential helpers fall back to the env-var path.

  3. **Per-registry env vars** — ``RAPTOR_OCI_<HOST_UPPER>_USER`` and
     ``RAPTOR_OCI_<HOST_UPPER>_PASSWORD``, with ``.`` replaced by
     ``_`` in the host. So ``ghcr.io`` → ``RAPTOR_OCI_GHCR_IO_USER`` /
     ``RAPTOR_OCI_GHCR_IO_PASSWORD``. Catches CI / ad-hoc cases
     where ``docker login`` hasn't been run.

The chain is consulted lazily: anonymous gets tried first because
it's free (no credential lookup); registry credentials are looked
up only when the anonymous token attempt fails or when the auth
challenge specifies a non-anonymous service.
"""

from __future__ import annotations

import base64
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from core.json import load_json

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BasicCredentials:
    """Username + password for HTTP Basic auth.

    The token-exchange flow takes these and posts them to the
    registry's auth realm, getting back a short-lived bearer token.
    Storing them as a separate dataclass (rather than a tuple) keeps
    the ``__repr__`` from accidentally leaking the password into
    logs — the default dataclass repr includes both fields, but
    callers are reminded by the type name to be careful.
    """
    username: str
    password: str

    def to_basic_header(self) -> str:
        """Render as the ``Authorization: Basic ...`` header value
        (without the ``Basic`` prefix)."""
        token = base64.b64encode(
            f"{self.username}:{self.password}".encode("utf-8"),
        ).decode("ascii")
        return token


def lookup_credentials(registry: str) -> Optional[BasicCredentials]:
    """Find credentials for ``registry`` via the documented chain.

    Returns ``None`` when no credentials are configured — the caller
    falls back to an anonymous token request, which is correct for
    public images. Logs at INFO when credentials are found so
    operators can confirm the right auth source is being used.
    """
    creds = _from_env(registry)
    if creds is not None:
        logger.info(
            "core.oci.auth: using env-var credentials for %s "
            "(RAPTOR_OCI_<HOST>_USER / _PASSWORD)", registry,
        )
        return creds
    creds = _from_docker_config(registry)
    if creds is not None:
        logger.info(
            "core.oci.auth: using ~/.docker/config.json inline auth "
            "for %s", registry,
        )
        return creds
    return None


def _from_env(registry: str) -> Optional[BasicCredentials]:
    """Per-registry env var lookup. Host is uppercased and ``.`` is
    replaced with ``_`` so ``ghcr.io`` → ``RAPTOR_OCI_GHCR_IO_*``,
    ``registry-1.docker.io`` → ``RAPTOR_OCI_REGISTRY_1_DOCKER_IO_*``.
    The ``-`` → ``_`` substitution covers hosts with hyphens
    (``registry-1`` etc.)."""
    safe = registry.upper().replace(".", "_").replace("-", "_")
    user = os.environ.get(f"RAPTOR_OCI_{safe}_USER")
    password = os.environ.get(f"RAPTOR_OCI_{safe}_PASSWORD")
    if user and password:
        return BasicCredentials(username=user, password=password)
    return None


def _from_docker_config(registry: str) -> Optional[BasicCredentials]:
    """Read ``~/.docker/config.json`` inline ``auths`` only.

    Honoured fields:
      * ``auths.<registry>.auth`` — base64'd ``user:password``
      * ``auths.<registry>.username`` + ``auths.<registry>.password``
        (less common, but some tooling writes this shape)

    Refused fields:
      * ``credsStore`` — would require ``docker-credential-<name>``
        subprocess call, which expands the trust surface beyond
        reading a file. Operators using credsStore fall back to the
        env-var path; we surface a debug-level note so they know
        why.
      * ``credHelpers`` — same reasoning.

    The ``DOCKER_CONFIG`` env var, if set, points at an alternate
    config directory (operators often use this for non-default
    locations); honoured per the Docker convention.

    Returns ``None`` when the config file doesn't exist, when no
    credentials match the registry, or when the registry's only
    credentials are stored via a credential helper.
    """
    cfg_dir = os.environ.get("DOCKER_CONFIG") or str(Path.home() / ".docker")
    cfg_path = Path(cfg_dir) / "config.json"
    if not cfg_path.exists():
        return None
    try:
        data = load_json(cfg_path)
    except Exception as e:                          # noqa: BLE001
        logger.debug(
            "core.oci.auth: failed to read %s: %s", cfg_path, e,
        )
        return None
    if not isinstance(data, dict):
        return None

    # ``credsStore`` / ``credHelpers`` are surfaced as a debug note
    # but otherwise ignored. Operators using them must fall back to
    # the env-var path.
    if data.get("credsStore"):
        logger.debug(
            "core.oci.auth: %s declares credsStore=%r — refusing to "
            "shell out; fall back to RAPTOR_OCI_<HOST>_USER/_PASSWORD",
            cfg_path, data["credsStore"],
        )
    if isinstance(data.get("credHelpers"), dict):
        if registry in data["credHelpers"]:
            logger.debug(
                "core.oci.auth: %s registers a credHelper for %s — "
                "refusing to shell out; fall back to env-var path",
                cfg_path, registry,
            )

    auths = data.get("auths") or {}
    if not isinstance(auths, dict):
        return None
    # Try a few common matches: exact host, ``https://<host>``,
    # ``https://<host>/v1/`` (legacy Docker Hub form).
    for key in (registry,
                f"https://{registry}",
                f"https://{registry}/v1/",
                f"https://{registry}/"):
        entry = auths.get(key)
        if isinstance(entry, dict):
            return _entry_to_credentials(entry)
    return None


def _entry_to_credentials(entry: dict) -> Optional[BasicCredentials]:
    """Convert a single ``auths.<host>`` entry to credentials.
    Tries the inline ``auth`` (base64 ``user:password``) first, then
    falls back to explicit ``username``/``password`` fields."""
    auth = entry.get("auth")
    if isinstance(auth, str) and auth.strip():
        try:
            decoded = base64.b64decode(auth, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        if ":" not in decoded:
            return None
        user, _, password = decoded.partition(":")
        if user and password:
            return BasicCredentials(user, password)
    user = entry.get("username")
    password = entry.get("password")
    if isinstance(user, str) and isinstance(password, str) \
            and user and password:
        return BasicCredentials(user, password)
    return None


# ---------------------------------------------------------------------------
# WWW-Authenticate parsing
# ---------------------------------------------------------------------------


_WWW_AUTH_PARAM_RE = re.compile(
    r'(?P<key>[a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*"(?P<value>[^"]*)"'
)


def parse_www_authenticate(header: str) -> Tuple[str, dict]:
    """Parse a ``WWW-Authenticate`` header value into
    ``(scheme, params)``.

    Examples::

        Bearer realm="https://auth.docker.io/token",
               service="registry.docker.io",
               scope="repository:library/python:pull"

    → ``("Bearer", {"realm": "...", "service": "...", "scope": "..."})``

    Tolerates extra whitespace, comma-vs-semicolon separators, and
    parameters in any order. Returns ``("", {})`` for unparseable
    input — the caller falls back to anonymous-no-realm-known
    behaviour, which surfaces clearly later.
    """
    if not header:
        return "", {}
    # Split scheme from params on first space.
    parts = header.strip().split(None, 1)
    scheme = parts[0]
    params_str = parts[1] if len(parts) > 1 else ""
    params: dict = {}
    for m in _WWW_AUTH_PARAM_RE.finditer(params_str):
        params[m.group("key").lower()] = m.group("value")
    return scheme, params


__all__ = [
    "BasicCredentials",
    "lookup_credentials",
    "parse_www_authenticate",
]
