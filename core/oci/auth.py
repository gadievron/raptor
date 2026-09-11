"""Auth chain for OCI / Docker registries.

Three sources, tried in order:

  1. **Anonymous bearer token** — for public images when NO
     credentials are configured. The registry's ``WWW-Authenticate``
     header on a 401 response carries a ``realm`` / ``service`` /
     ``scope`` triple; we request a token from that realm without
     credentials. Works for everything on ``docker.io/library/*``,
     public ``ghcr.io``, ``public.ecr.aws``, ``quay.io`` (mostly).
     When credentials ARE configured for the registry, the token
     exchange sends them from the first attempt (they are needed for
     private scopes and harmless for public ones); the realm has
     already passed the HTTPS + allowlist gate at that point.

  2. **``~/.docker/config.json`` inline ``auths``** — the standard
     artefact ``docker login`` produces. We read ONLY the inline
     ``auth`` field (base64'd ``user:password``); we **deliberately
     ignore** ``credsStore`` / ``credHelpers`` because honouring
     those means shelling out to a credential helper binary, which
     is a much larger trust surface than reading a file. Operators
     using credential helpers fall back to the env-var path.

  3. **Per-registry env vars** — ``RAPTOR_OCI_<HOST_UPPER>_USER`` and
     ``RAPTOR_OCI_<HOST_UPPER>_PASSWORD``, with ``.`` and ``-``
     replaced by ``_`` in the host. So ``ghcr.io`` →
     ``RAPTOR_OCI_GHCR_IO_USER`` / ``RAPTOR_OCI_GHCR_IO_PASSWORD``.
     Catches CI / ad-hoc cases where ``docker login`` hasn't been
     run. Because that encoding collapses ``.`` and ``-`` to the
     same character, hostnames containing a dash (or underscore)
     additionally require ``RAPTOR_OCI_<HOST_UPPER>_HOST`` set to
     the exact hostname — see :func:`_from_env`.

The chain is consulted lazily: the first REQUEST goes out without
auth (the challenge triple is only discoverable from the 401);
credentials are looked up when the challenge arrives, and used on
the token exchange whenever they are configured.
"""

from __future__ import annotations

import base64
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from core.json import load_json

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BasicCredentials:
    """Username + password for HTTP Basic auth.

    The token-exchange flow takes these and posts them to the
    registry's auth realm, getting back a short-lived bearer token.
    ``password`` is excluded from the dataclass ``repr`` so an
    accidental ``repr()`` / f-string / exception interpolation of a
    credentials object never lands the secret in logs.
    """
    username: str
    password: str = field(repr=False)

    def to_basic_header(self) -> str:
        """Render as the ``Authorization: Basic ...`` header value
        (without the ``Basic`` prefix)."""
        return base64.b64encode(
            f"{self.username}:{self.password}".encode(),
        ).decode("ascii")


def lookup_credentials(registry: str) -> BasicCredentials | None:
    """Find credentials for ``registry`` via the documented chain.

    Returns ``None`` when no credentials are configured — the caller
    falls back to an anonymous token request, which is correct for
    public images. Logs at INFO when credentials are found so
    operators can confirm the right auth source is being used.
    """
    creds = _from_env(registry)
    if creds is not None:
        # Only the registry hostname is interpolated; the env-var
        # NAMES (``RAPTOR_OCI_<HOST>_USER`` / ``_PASSWORD``) are
        # documentation strings, not their values. No credentials
        # disclosed.
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
        logger.info(
            "core.oci.auth: using env-var credentials for %s "
            "(RAPTOR_OCI_<HOST>_USER / _PASSWORD)", registry,
        )
        return creds
    creds = _from_docker_config(registry)
    if creds is not None:
        logger.debug(
            "core.oci.auth: using ~/.docker/config.json inline auth "
            "for %s", registry,
        )
        return creds
    return None


def _from_env(registry: str) -> BasicCredentials | None:
    """Per-registry env var lookup. Host is uppercased and ``.`` is
    replaced with ``_`` so ``ghcr.io`` → ``RAPTOR_OCI_GHCR_IO_*``,
    ``registry-1.docker.io`` → ``RAPTOR_OCI_REGISTRY_1_DOCKER_IO_*``.
    The ``-`` → ``_`` substitution covers hosts with hyphens
    (``registry-1`` etc.).

    The host → env-name encoding is NOT injective: ``.`` and ``-``
    both map to ``_``, so an attacker-registrable hostname can
    collide with the operator's configured registry
    (``evil-registry.com`` and ``evil.registry.com`` share the key
    ``EVIL_REGISTRY_COM``) and — via a hostile image reference in a
    scanned repo — receive that registry's credentials. Two gates
    close this:

      * ``RAPTOR_OCI_<KEY>_HOST`` — optional exact-match pin. When
        set, credentials go ONLY to that hostname.
      * Without the pin, credentials are released only to hostnames
        containing no ``-`` (or ``_``). On dash-free hostnames the
        encoding is injective (every ``_`` in the key is
        unambiguously a ``.``), so no distinct colliding hostname
        exists. Operators whose registry hostname contains a dash
        must set the pin; the refusal below says exactly that.
    """
    safe = registry.upper().replace(".", "_").replace("-", "_")
    user = os.environ.get(f"RAPTOR_OCI_{safe}_USER")
    password = os.environ.get(f"RAPTOR_OCI_{safe}_PASSWORD")
    if not (user and password):
        return None
    pinned_host = os.environ.get(f"RAPTOR_OCI_{safe}_HOST")
    if pinned_host is not None:
        if pinned_host.strip().lower() == registry.lower():
            return BasicCredentials(username=user, password=password)
        logger.warning(
            "core.oci.auth: refusing RAPTOR_OCI_%s_* credentials for "
            "%s — RAPTOR_OCI_%s_HOST pins them to %r",
            safe, registry, safe, pinned_host,
        )
        return None
    if "-" in registry or "_" in registry:
        logger.warning(
            "core.oci.auth: refusing RAPTOR_OCI_%s_* credentials for "
            "%s — the hostname is ambiguous under the env-var "
            "encoding ('.' and '-' both map to '_'), so a colliding "
            "hostname could capture these credentials. Set "
            "RAPTOR_OCI_%s_HOST=%s to pin them to this host.",
            safe, registry, safe, registry,
        )
        return None
    return BasicCredentials(username=user, password=password)


def _from_docker_config(registry: str) -> BasicCredentials | None:
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
    probe_keys = [
        registry,
        f"https://{registry}",
        f"https://{registry}/v1/",
        f"https://{registry}/",
    ]
    if registry == "docker.io":
        probe_keys.extend([
            "https://index.docker.io/v1/",
            "index.docker.io",
        ])
    for key in probe_keys:
        entry = auths.get(key)
        if isinstance(entry, dict):
            return _entry_to_credentials(entry)
    return None


def _entry_to_credentials(entry: dict) -> BasicCredentials | None:
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
        if user:
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


# RFC 7235 permits ``auth-param = token "=" ( token / quoted-string )``.
# Pre-fix regex only matched quoted values; a registry sending
# unquoted ``scope=push,pull`` silently dropped the parameter,
# which then caused the token-exchange request to ask for a
# different (often narrower) permission than the operator
# expected. Now both shapes match.
#
# token = 1*<any CHAR except CTL or "()<>@,;:\\\"/[]?={} \t">
# quoted-string = literal "" with optional backslash escapes.
_WWW_AUTH_PARAM_RE = re.compile(
    r'(?P<key>[a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*'
    r'(?:"(?P<qval>[^"]*)"|(?P<tval>[^\s",]+))'
)


# Challenge boundaries within a (possibly folded) WWW-Authenticate
# value. Registries that offer BOTH Bearer and Basic (Nexus,
# Artifactory) either send two headers — which core.http folds into
# one newline-joined value — or one comma-joined value (RFC 7235
# permits multiple challenges per header). The scheme names are the
# ones registries actually emit; a scheme token inside a QUOTED param
# value would falsely split, which no real realm URL contains.
_CHALLENGE_BOUNDARY_RE = re.compile(
    r"(?:^|[\n,]\s*)(?P<scheme>Bearer|Basic|Digest|Negotiate)(?=\s|$)",
    re.IGNORECASE,
)


def split_www_authenticate_challenges(header: str) -> list[tuple[str, str]]:
    """Split a ``WWW-Authenticate`` value into ``(scheme,
    params_str)`` pairs — one per challenge. Handles newline-folded
    duplicate headers (core.http joins them) and comma-joined
    multi-challenge values."""
    matches = list(_CHALLENGE_BOUNDARY_RE.finditer(header))
    out: list[tuple[str, str]] = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(header)
        params_str = header[m.end():end].strip().strip(",").strip()
        out.append((m.group("scheme"), params_str))
    return out


def parse_www_authenticate(header: str) -> tuple[str, dict]:
    """Parse a ``WWW-Authenticate`` header value into
    ``(scheme, params)``.

    Examples::

        Bearer realm="https://auth.docker.io/token",
               service="registry.docker.io",
               scope="repository:library/python:pull"

    → ``("Bearer", {"realm": "...", "service": "...", "scope": "..."})``

    Tolerates extra whitespace, comma-vs-semicolon separators, and
    parameters in any order. Accepts both quoted-string and bare
    token shapes per RFC 7235. Returns ``("", {})`` for unparseable
    input — the caller falls back to anonymous-no-realm-known
    behaviour, which surfaces clearly later.

    Multi-challenge values (dual ``Bearer`` + ``Basic``, sent by
    Nexus / Artifactory as two headers that core.http newline-joins,
    or comma-joined in one header) parse to the BEARER challenge's
    params only — merging both challenges' params corrupted the
    realm/service triple in either order. When no Bearer challenge
    is present the first challenge wins.
    """
    if not header:
        return "", {}
    challenges = split_www_authenticate_challenges(header)
    if not challenges:
        # No recognised scheme name — fall back to first-token-as-
        # scheme so unknown schemes still surface to the caller.
        parts = header.strip().split(None, 1)
        challenges = [(parts[0], parts[1] if len(parts) > 1 else "")]
    scheme, params_str = next(
        (c for c in challenges if c[0].lower() == "bearer"),
        challenges[0],
    )
    params: dict = {}
    for m in _WWW_AUTH_PARAM_RE.finditer(params_str):
        value = m.group("qval")
        if value is None:
            value = m.group("tval")
        params[m.group("key").lower()] = value or ""
    return scheme, params


__all__ = [
    "BasicCredentials",
    "lookup_credentials",
    "parse_www_authenticate",
    "split_www_authenticate_challenges",
]
