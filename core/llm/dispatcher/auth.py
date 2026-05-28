"""Per-provider auth-header injection rules.

Each provider's authentication scheme is a small fact: which headers
to strip from the worker's request, which to inject from the parent's
secret store, which upstream URL to forward to. Encoded as data so
adding a provider is a single dict entry plus a credentials-source.

Only providers RAPTOR actively dispatches to are supported here. If
``api_key`` is None at request time, the dispatcher rejects with
``503 Service Unavailable: provider not configured`` so the worker's
SDK surfaces a clear error rather than a mysterious 401 from upstream.

Most providers are bearer-auth on a known upstream URL: the rule strips
the worker's (dummy) auth header and injects the real one. **AWS
Bedrock** is the exception — it uses sigv4 request signing (a per-request
signature over method/path/headers/body/timestamp), which can't be
relayed as a static header. Bedrock is handled by a ``prepare_request``
hook on its rule: the dispatcher rewrites the worker's stock-Anthropic
``/v1/messages`` request into Bedrock's ``/model/<id>/invoke`` shape, then
attaches auth in one of two modes —

  * **Bedrock API key** (``AWS_BEARER_TOKEN_BEDROCK``) — a static
    ``Authorization: Bearer <token>`` header. No botocore, no signing;
    same shape as every other bearer provider. Takes precedence over
    SigV4 when present (matching the AWS SDKs). Needs a region only for
    the regional host.
  * **SigV4** — sign the rewritten request with the parent's AWS
    credentials via botocore's ``SigV4Auth`` (access key / secret /
    session token, or the resolved profile/SSO/IMDS chain).

The worker keeps using the plain Anthropic SDK with no boto3 in its
address space, and the parent's ``AWS_*`` secrets (keys and bearer token)
are read-and-erased at ``CredentialStore`` construction like every other
provider key — so they never flow to spawned workers. ``botocore`` is an
optional, parent-only dependency needed **only for the SigV4 mode**; the
bearer-token mode works without it. When no usable auth (or region)
resolves, the bedrock rule reports ``503 provider not configured`` like
any unconfigured provider. Non-streaming ``InvokeModel`` only — Bedrock's
streaming endpoint uses a different response framing and is out of scope.

Out of scope for the proxy-based dispatcher:

  * **GCP Vertex AI** — uses OAuth refresh from a service-account
    JSON file (``GOOGLE_APPLICATION_CREDENTIALS``). The dispatcher
    would need ``google-auth`` integration to refresh the bearer
    token at request time. Deferred to a focused follow-up; until
    then ``GOOGLE_APPLICATION_CREDENTIALS`` flows through env to
    workers and the SDK does its own OAuth exchange.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Mapping, Optional
from pathlib import Path


@dataclass(frozen=True)
class PreparedRequest:
    """A fully-prepared upstream request returned by a rule's
    ``prepare_request`` hook.

    Unlike the static strip/inject path, a prepared request carries the
    *absolute* upstream ``url`` plus the exact headers and body to
    forward verbatim — the dispatcher does no further header rewriting.
    Used by the Bedrock rule, whose SigV4 signature is computed over the
    rewritten URL + headers + body and would break if anything else
    touched them afterwards. ``headers`` intentionally omits ``Host`` and
    ``Content-Length`` so the HTTP client derives them from ``url`` /
    ``body`` (matching what was signed).
    """

    method: str
    url: str
    headers: dict[str, str]
    body: bytes


class BedrockTransformError(Exception):
    """Raised by the Bedrock ``prepare_request`` hook when a worker
    request can't be turned into a signed Bedrock call. Carries the HTTP
    ``status`` + ``message`` the dispatcher should return to the worker
    (e.g. 400 for a malformed/streaming request, 503 when Bedrock isn't
    configured)."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class ProviderRule:
    """One provider's auth-injection rule.

    ``upstream_base_url`` is the real upstream the dispatcher forwards
    to (e.g. ``https://api.anthropic.com``). ``inject_headers`` is a
    callable so the secret value is read at request time, not at
    rule-construction time — lets the parent rotate keys without
    rebuilding the dispatcher.

    ``strip_request_headers`` removes any auth-shaped header the worker
    might have added (the SDK is given a dummy key but might still echo
    it back). Defence-in-depth — without this, a worker that overrode
    ``api_key`` with a real-looking value would have its value forwarded
    upstream alongside the real one.

    ``prepare_request`` is an optional hook for providers whose auth
    can't be expressed as static header injection (AWS Bedrock's SigV4
    signing). When set, the dispatcher hands it the worker's
    ``(method, path, headers, body)`` and forwards the returned
    :class:`PreparedRequest` verbatim — the ``upstream_base_url`` /
    ``inject_headers`` / ``strip_request_headers`` fields are unused for
    such a rule. It may raise :class:`BedrockTransformError`.

    ``is_configured`` overrides the default "configured?" predicate
    (``bool(inject_headers())``) for rules whose readiness isn't a single
    injected header — Bedrock checks that botocore + AWS creds + a region
    all resolved.
    """

    name: str
    upstream_base_url: str
    inject_headers: Callable[[], dict[str, str]]
    strip_request_headers: tuple[str, ...] = (
        "authorization", "x-api-key", "x-goog-api-key",
        "api-key", "openai-organization",
    )
    prepare_request: Optional[
        Callable[[str, str, Mapping[str, str], bytes], PreparedRequest]
    ] = None
    is_configured: Optional[Callable[[], bool]] = None


# Sentinel for "AWS signer not yet resolved" — distinct from a resolved
# value of ``None`` (botocore/creds absent), which is cached so we don't
# re-attempt botocore resolution on every request.
_UNRESOLVED = object()


def _read_env(var: str) -> str | None:
    """Read an env var and immediately erase it from the process env.

    The dispatcher reads each provider's key once at startup; after
    that the parent process's environ no longer contains the key.
    Reduces blast radius if the parent is later compromised.
    """
    val = os.environ.get(var)
    if val is not None:
        os.environ.pop(var, None)
    return val


class CredentialStore:
    """In-memory store of provider API keys.

    Loaded once from the parent's environ at dispatcher startup,
    keys then erased from environ. The store is the single point
    that holds plaintext credentials for the lifetime of the run.

    The launcher may also call :func:`seed_from_config` after
    constructing the store to fill any provider slots that env
    didn't supply, from ``~/.config/raptor/models.json``. Env-set
    keys are preserved (the seed only fills ``None`` slots).
    """

    def __init__(self) -> None:
        # Read each provider's key into private state. Store is
        # mutable so tests can inject fakes without touching env.
        self._keys: dict[str, str | None] = {
            "anthropic":  _read_env("ANTHROPIC_API_KEY"),
            "openai":     _read_env("OPENAI_API_KEY"),
            "gemini":     _read_env("GEMINI_API_KEY") or _read_env("GOOGLE_API_KEY"),
            # OpenAI-compatible aggregators + ecosystem providers.
            # Same Bearer-auth shape; different upstream URLs.
            "mistral":    _read_env("MISTRAL_API_KEY"),
            "groq":       _read_env("GROQ_API_KEY"),
            "together":   _read_env("TOGETHER_API_KEY"),
            "openrouter": _read_env("OPENROUTER_API_KEY"),
            "fireworks":  _read_env("FIREWORKS_API_KEY"),
            "deepinfra":  _read_env("DEEPINFRA_API_KEY"),
            "perplexity": _read_env("PERPLEXITY_API_KEY"),
            "cohere":     _read_env("COHERE_API_KEY"),
            # Replicate — uses ``Token <key>`` prefix, not ``Bearer``.
            "replicate":  _read_env("REPLICATE_API_TOKEN"),
            # Azure OpenAI — operator-configured endpoint URL +
            # api-key header. Endpoint read once at startup; if
            # absent the rule's upstream is a sentinel that produces
            # 503 at request time (consistent with other unconfigured
            # providers).
            "azure_openai":           _read_env("AZURE_OPENAI_API_KEY"),
            "azure_openai_endpoint":  _read_env("AZURE_OPENAI_ENDPOINT"),
            # AWS Bedrock — the *secret* parts are read-and-erased like
            # every other provider key so they never reach a spawned
            # worker's env. Static creds set this way; SSO/IMDS/profile
            # creds (no env keys) are resolved by botocore at signing
            # time. Region + endpoint are NOT secrets, so they're read
            # without popping (workers may legitimately need the region).
            "aws_access_key_id":      _read_env("AWS_ACCESS_KEY_ID"),
            "aws_secret_access_key":  _read_env("AWS_SECRET_ACCESS_KEY"),
            "aws_session_token":      _read_env("AWS_SESSION_TOKEN"),
            # Bedrock API key (newer bearer-token auth). When present it
            # takes precedence over SigV4 (matching the AWS SDKs) and the
            # request is authed with a static ``Authorization: Bearer``
            # header — no botocore, no signing. Secret → read-and-erased.
            "aws_bearer_token":       _read_env("AWS_BEARER_TOKEN_BEDROCK"),
        }
        self._aws_region: str | None = (
            os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        )
        self._aws_endpoint: str | None = os.environ.get("AWS_ENDPOINT_URL_BEDROCK")
        # Resolved (credentials, region, endpoint) tuple, or None once we
        # know Bedrock isn't usable. ``_UNRESOLVED`` until first lookup.
        # The lock serialises first-resolution across the threading
        # dispatcher's concurrent request handlers — the resolution is
        # idempotent, but the botocore credential-chain probe (which may
        # hit IMDS) should run once, not once per concurrent first call.
        self._aws_signer_cache: object = _UNRESOLVED
        self._aws_signer_lock = threading.Lock()

    def get(self, provider: str) -> str | None:
        return self._keys.get(provider)

    def set(self, provider: str, key: str | None) -> None:
        """Set or clear one provider's key.

        Used by tests, and by :func:`seed_from_config` to fill slots
        from ``models.json``. No other production caller touches this.
        """
        self._keys[provider] = key

    def set_aws(
        self,
        *,
        access_key: str | None = None,
        secret_key: str | None = None,
        session_token: str | None = None,
        bearer_token: str | None = None,
        region: str | None = None,
        endpoint: str | None = None,
    ) -> None:
        """Inject static AWS credentials/region/endpoint and reset the
        resolved-signer cache. Used by tests to drive the Bedrock path
        deterministically (and to point it at a local stub endpoint)
        without relying on the ambient botocore credential chain."""
        if access_key is not None:
            self._keys["aws_access_key_id"] = access_key
        if secret_key is not None:
            self._keys["aws_secret_access_key"] = secret_key
        if session_token is not None:
            self._keys["aws_session_token"] = session_token
        if bearer_token is not None:
            self._keys["aws_bearer_token"] = bearer_token
        if region is not None:
            self._aws_region = region
        if endpoint is not None:
            self._aws_endpoint = endpoint
        self._aws_signer_cache = _UNRESOLVED

    def aws_bedrock_endpoint(self) -> str | None:
        """Return the Bedrock-runtime base URL, or ``None`` if no region
        is known. Region comes from ``AWS_REGION`` / ``AWS_DEFAULT_REGION``
        (or :meth:`set_aws`); it isn't a secret. Used by the bearer-token
        path, which needs the regional host but does no botocore work."""
        if not self._aws_region:
            return None
        return (
            self._aws_endpoint
            or f"https://bedrock-runtime.{self._aws_region}.amazonaws.com"
        )

    def aws_signer(self):
        """Return ``(credentials, region, endpoint_base)`` for SigV4
        signing, or ``None`` when Bedrock isn't usable (botocore missing,
        no resolvable credentials, or no region). Resolved once and
        cached — including a cached ``None`` so we don't re-probe the
        botocore credential chain on every request."""
        if self._aws_signer_cache is _UNRESOLVED:
            with self._aws_signer_lock:
                # Double-checked: another thread may have resolved it
                # while we waited on the lock.
                if self._aws_signer_cache is _UNRESOLVED:
                    self._aws_signer_cache = self._resolve_aws_signer()
        return self._aws_signer_cache

    def _resolve_aws_signer(self):
        try:
            import botocore.credentials
            import botocore.session
        except ImportError:
            return None

        ak = self._keys.get("aws_access_key_id")
        sk = self._keys.get("aws_secret_access_key")
        st = self._keys.get("aws_session_token")
        region = self._aws_region

        credentials = None
        if ak and sk:
            # Static creds the parent supplied via env (already erased
            # from os.environ) or via set_aws().
            credentials = botocore.credentials.Credentials(ak, sk, st)
        else:
            # No static keys: fall back to botocore's natural credential
            # chain (shared config/profile, SSO cache, container creds,
            # IMDS instance role). The parent is the trust boundary, so
            # the full chain is appropriate here. RefreshableCredentials
            # transparently re-fetch on access, so SSO/IMDS rotation is
            # handled per request.
            try:
                session = botocore.session.Session()
                credentials = session.get_credentials()
                if not region:
                    region = session.get_config_variable("region")
            except Exception:
                credentials = None

        if credentials is None or not region:
            return None
        endpoint = (
            self._aws_endpoint
            or f"https://bedrock-runtime.{region}.amazonaws.com"
        )
        return (credentials, region, endpoint)


_BEDROCK_ANTHROPIC_VERSION = "bedrock-2023-05-31"


def _transform_bedrock_request(endpoint: str, body: bytes) -> tuple[str, bytes]:
    """Rewrite a stock-Anthropic ``/v1/messages`` body into the Bedrock
    ``InvokeModel`` shape, returning ``(url, new_body)``.

    Pops ``model`` (it becomes the ``/model/<id>/invoke`` URL path), adds
    ``anthropic_version`` to the body, and targets the regional
    bedrock-runtime endpoint. Auth-agnostic — shared by both the SigV4
    and bearer-token request builders. Raises :class:`BedrockTransformError`
    on a malformed/streaming/model-less request.
    """
    try:
        payload = json.loads(body) if body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise BedrockTransformError(400, "bedrock: request body is not valid JSON")
    if not isinstance(payload, dict):
        raise BedrockTransformError(400, "bedrock: request body must be a JSON object")
    # v1 is non-streaming only. The Anthropic SDK sets ``stream`` in the
    # body for ``messages.stream``/``create(stream=True)``; Bedrock's
    # streaming endpoint uses different response framing (out of scope).
    if payload.get("stream"):
        raise BedrockTransformError(
            400, "bedrock: streaming is not supported (non-streaming InvokeModel only)"
        )
    payload.pop("stream", None)
    model = payload.pop("model", None)
    if not isinstance(model, str) or not model:
        raise BedrockTransformError(400, "bedrock: request body missing 'model'")
    payload.setdefault("anthropic_version", _BEDROCK_ANTHROPIC_VERSION)
    new_body = json.dumps(payload).encode("utf-8")
    url = endpoint.rstrip("/") + f"/model/{urllib.parse.quote(model, safe='')}/invoke"
    return url, new_body


def _build_signed_bedrock_request(
    credentials, region: str, endpoint: str, body: bytes,
) -> PreparedRequest:
    """Transform + SigV4-sign with the parent's AWS credentials. The
    signed ``Authorization`` / ``X-Amz-Date`` / ``X-Amz-Security-Token``
    headers are returned for verbatim forwarding; ``Host`` and
    ``Content-Length`` are dropped so the HTTP client reproduces exactly
    what SigV4 signed (host from the URL, length from the body).
    """
    # Imported here, not at module top, so ``auth.py`` loads without
    # botocore — the dependency is parent-only and only needed for SigV4
    # (the bearer-token path below needs no botocore at all).
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    url, new_body = _transform_bedrock_request(endpoint, body)
    # Sign Content-Type AND Accept (both go into SignedHeaders) to match
    # boto3's bedrock-runtime InvokeModel request byte-for-byte:
    # ``SignedHeaders=accept;content-type;host;x-amz-date``. AWS would
    # accept the three-header form too (it only verifies what we declare
    # in SignedHeaders), but matching the official client removes any
    # edge where Bedrock treats an unsigned Accept differently.
    aws_req = AWSRequest(
        method="POST", url=url, data=new_body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    SigV4Auth(credentials, "bedrock", region).add_auth(aws_req)

    forwarded = dict(aws_req.headers.items())
    for drop in ("Host", "host", "Content-Length", "content-length"):
        forwarded.pop(drop, None)
    return PreparedRequest(method="POST", url=url, headers=forwarded, body=new_body)


def _build_bearer_bedrock_request(
    bearer_token: str, endpoint: str, body: bytes,
) -> PreparedRequest:
    """Transform + attach a static ``Authorization: Bearer <token>``
    header (Bedrock API-key auth). No botocore, no signing — matches what
    the AWS SDKs send when ``AWS_BEARER_TOKEN_BEDROCK`` is set."""
    url, new_body = _transform_bedrock_request(endpoint, body)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {bearer_token}",
    }
    return PreparedRequest(method="POST", url=url, headers=headers, body=new_body)


def build_rules(creds: CredentialStore) -> dict[str, ProviderRule]:
    """Return the rules table.

    Each provider is a single :class:`ProviderRule` entry. Adding a
    new provider is a closure that returns the right header shape
    plus a ``ProviderRule`` row — no other code changes required.
    Providers whose key is unset at build time are still in the
    table; the dispatcher rejects requests to them with
    ``503 provider not configured`` so worker SDK calls surface a
    clear error.
    """

    def _anthropic_headers() -> dict[str, str]:
        key = creds.get("anthropic")
        if not key:
            return {}
        return {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        }

    def _openai_headers() -> dict[str, str]:
        key = creds.get("openai")
        if not key:
            return {}
        return {"Authorization": f"Bearer {key}"}

    def _gemini_headers() -> dict[str, str]:
        key = creds.get("gemini")
        if not key:
            return {}
        # Gemini's REST API accepts the key either as ``?key=...`` query
        # param or as the ``x-goog-api-key`` header; SDKs default to
        # the header so the dispatcher injects it that way.
        return {"x-goog-api-key": key}

    # Bearer-auth aggregators — closure factory keeps each header
    # injector tight (just reads the matching credential). All use
    # the OpenAI-style ``Authorization: Bearer <key>`` shape.
    def _bearer_headers(provider_key: str):
        def _impl() -> dict[str, str]:
            key = creds.get(provider_key)
            if not key:
                return {}
            return {"Authorization": f"Bearer {key}"}
        return _impl

    def _replicate_headers() -> dict[str, str]:
        # Replicate uses ``Token <key>`` (not Bearer). One-off rather
        # than parameterising the factory above for clarity.
        key = creds.get("replicate")
        if not key:
            return {}
        return {"Authorization": f"Token {key}"}

    def _azure_openai_headers() -> dict[str, str]:
        # Azure OpenAI uses ``api-key`` header (not Bearer). Endpoint
        # is operator-configured per Azure deployment; the
        # ``upstream_base_url`` for this rule is filled from
        # ``AZURE_OPENAI_ENDPOINT`` at build time. When the operator
        # didn't set the endpoint, the rule's upstream is the
        # sentinel below and the dispatcher rejects with 503
        # ``provider not configured`` — same UX as missing key.
        key = creds.get("azure_openai")
        if not key:
            return {}
        return {"api-key": key}

    azure_endpoint = (
        creds.get("azure_openai_endpoint")
        or "https://azure-openai-not-configured.invalid"
    )

    def _bedrock_prepare(
        method: str, path: str, headers: Mapping[str, str], body: bytes,
    ) -> PreparedRequest:
        # ``method`` / ``path`` / ``headers`` from the worker's stock
        # Anthropic request are intentionally discarded: Bedrock always
        # POSTs to a body-derived path with freshly-attached auth.
        # Bearer-token (Bedrock API key) wins over SigV4 when present,
        # matching the AWS SDKs — and needs no botocore.
        bearer = creds.get("aws_bearer_token")
        if bearer:
            endpoint = creds.aws_bedrock_endpoint()
            if endpoint is None:
                raise BedrockTransformError(
                    503, "provider not configured: bedrock (no AWS region)"
                )
            return _build_bearer_bedrock_request(bearer, endpoint, body)
        signer = creds.aws_signer()
        if signer is None:
            raise BedrockTransformError(503, "provider not configured: bedrock")
        credentials, region, endpoint = signer
        return _build_signed_bedrock_request(credentials, region, endpoint, body)

    def _bedrock_configured() -> bool:
        # Bearer token (+ a region for the host) OR a resolvable SigV4
        # signer. Bearer is checked first and cheaply (no botocore probe).
        if creds.get("aws_bearer_token") and creds.aws_bedrock_endpoint():
            return True
        return creds.aws_signer() is not None

    return {
        "anthropic": ProviderRule(
            name="anthropic",
            upstream_base_url="https://api.anthropic.com",
            inject_headers=_anthropic_headers,
        ),
        "openai": ProviderRule(
            name="openai",
            upstream_base_url="https://api.openai.com",
            inject_headers=_openai_headers,
        ),
        "gemini": ProviderRule(
            name="gemini",
            upstream_base_url="https://generativelanguage.googleapis.com",
            inject_headers=_gemini_headers,
        ),
        "mistral": ProviderRule(
            name="mistral",
            upstream_base_url="https://api.mistral.ai",
            inject_headers=_bearer_headers("mistral"),
        ),
        "groq": ProviderRule(
            name="groq",
            upstream_base_url="https://api.groq.com",
            inject_headers=_bearer_headers("groq"),
        ),
        "together": ProviderRule(
            name="together",
            upstream_base_url="https://api.together.xyz",
            inject_headers=_bearer_headers("together"),
        ),
        "openrouter": ProviderRule(
            name="openrouter",
            # OpenRouter's API is rooted at ``/api/v1`` rather than the
            # bare host; SDKs typically configure ``base_url=https://
            # openrouter.ai/api/v1``. Forward to the bare host — the
            # SDK's path component (``/api/v1/chat/completions`` etc.)
            # is preserved end-to-end through the dispatcher.
            upstream_base_url="https://openrouter.ai",
            inject_headers=_bearer_headers("openrouter"),
        ),
        "fireworks": ProviderRule(
            name="fireworks",
            upstream_base_url="https://api.fireworks.ai",
            inject_headers=_bearer_headers("fireworks"),
        ),
        "deepinfra": ProviderRule(
            name="deepinfra",
            upstream_base_url="https://api.deepinfra.com",
            inject_headers=_bearer_headers("deepinfra"),
        ),
        "perplexity": ProviderRule(
            name="perplexity",
            upstream_base_url="https://api.perplexity.ai",
            inject_headers=_bearer_headers("perplexity"),
        ),
        "cohere": ProviderRule(
            name="cohere",
            upstream_base_url="https://api.cohere.ai",
            inject_headers=_bearer_headers("cohere"),
        ),
        "replicate": ProviderRule(
            name="replicate",
            upstream_base_url="https://api.replicate.com",
            inject_headers=_replicate_headers,
        ),
        "azure_openai": ProviderRule(
            name="azure_openai",
            upstream_base_url=azure_endpoint,
            inject_headers=_azure_openai_headers,
            # Azure echoes the api-key in some error responses;
            # strip ``api-key`` from worker requests on top of the
            # default Bearer/x-api-key set so the dispatcher's
            # injected value isn't shadowed.
            strip_request_headers=(
                "authorization", "x-api-key", "x-goog-api-key",
                "api-key", "openai-organization",
            ),
        ),
        "bedrock": ProviderRule(
            name="bedrock",
            # Unused for a prepare_request rule — the hook returns an
            # absolute, region-derived URL. Sentinel keeps the dataclass
            # field populated and makes a stray non-hook forward fail
            # loudly rather than hitting a real endpoint.
            upstream_base_url="https://bedrock-runtime-not-configured.invalid",
            inject_headers=lambda: {},
            prepare_request=_bedrock_prepare,
            is_configured=_bedrock_configured,
        ),
    }


def seed_from_config(store: CredentialStore) -> None:
    """Fill empty slots in *store* from ``~/.config/raptor/models.json``.

    The ``CredentialStore`` reads API keys from env at construction.
    Operators who instead keep their keys in ``models.json`` (the
    documented UX that the startup banner advertises with
    ``via models.json``) would otherwise see a configured-looking
    system that still 503s every request — the proxy has no creds to
    inject.

    The launcher calls this after constructing the store, before
    handing it to ``LLMDispatcher(..., creds=...)``. Env-supplied keys
    always win: only slots where ``store.get(provider) is None`` are
    filled, so an explicit env override of a ``models.json`` entry is
    preserved.

    Path resolution matches ``core/llm/detection.py:_read_config_models``:
    ``$RAPTOR_CONFIG`` if set, else ``~/.config/raptor/models.json``.

    Silent on file-missing, parse-error, or schema-error — same posture
    as the rest of the config-reading path. A misconfigured file looks
    the same as no file at all and surfaces later as the dispatcher's
    own ``503 provider not configured``.
    """
    try:
        from core.json import load_json_with_comments
    except ImportError:
        return

    config_path_str = os.environ.get("RAPTOR_CONFIG")
    if config_path_str:
        config_path = Path(config_path_str).expanduser().resolve()
    else:
        config_path = Path.home() / ".config" / "raptor" / "models.json"

    # Permission posture warning: models.json carries API keys when the
    # operator uses the inline ``api_key`` field. World-readable mode
    # (any of ``0o004`` / ``0o040`` / group-readable on a multi-user
    # box) means another local UID can grep the file. We don't *refuse*
    # to load — that would be a footgun on systems where umask sets
    # 0o644 and the operator didn't notice — but log once at WARNING so
    # the operator can ``chmod 600`` it. Skip on Windows where POSIX
    # bits don't have the same meaning.
    if sys.platform != "win32":
        try:
            st = config_path.stat()
            if st.st_mode & 0o077:
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "models.json at %s is mode %04o — contains API keys "
                    "when populated inline. Consider `chmod 600 %s`.",
                    config_path, st.st_mode & 0o777, config_path,
                )
        except OSError:
            # Missing file / unreadable: load_json_with_comments below
            # will handle the "missing" case (returns None) and the
            # operator hits the "no key configured" path naturally.
            pass

    data = load_json_with_comments(config_path)
    if data is None:
        return

    if isinstance(data, dict):
        entries = data.get("models") or []
    elif isinstance(data, list):
        entries = data
    else:
        return
    if not isinstance(entries, list):
        return

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        provider = entry.get("provider")
        api_key = entry.get("api_key")
        if not isinstance(provider, str) or not isinstance(api_key, str):
            continue
        # Env wins: only fill empty slots. Also handles the duplicate-
        # provider case (operator lists two gemini entries for different
        # roles, same key) — first match seeds, rest are no-ops.
        if store.get(provider) is None:
            store.set(provider, api_key)
