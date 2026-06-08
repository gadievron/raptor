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
hook on its rule.

The hook supports two Bedrock surfaces, selected by URL prefix the
worker addresses:

  * **Mantle** (default) — ``bedrock-mantle.<region>.api.aws/
    anthropic/v1/messages``.  Native Anthropic Messages API with bare
    model IDs (``anthropic.claude-opus-4-8``), native SSE streaming,
    tool use, prompt caching.  Workers point at
    ``http://_/bedrock/mantle`` (or the unprefixed ``http://_/bedrock``
    for backward compatibility).  The worker's ``/v1/messages`` path
    is rewritten to Mantle's ``/anthropic/v1/messages``; the body's
    ``anthropic_version`` is filled in when missing.

  * **Runtime** (legacy InvokeModel) — ``bedrock-runtime.<region>.
    amazonaws.com/model/<id>/invoke``.  Required for models not yet
    on Mantle, for cross-region inference profile IDs
    (``us.``/``eu.``/``global.``), and for compliance-pinned
    ARN-versioned IDs.  Workers point at ``http://_/bedrock/runtime``.
    The body's ``model`` field is moved into the URL path and
    ``anthropic_version`` filled in.  Non-streaming only — operators
    wanting streaming should use Mantle.

For both surfaces, the hook attaches auth in one of two modes:

  * **Bedrock API key** (``AWS_BEARER_TOKEN_BEDROCK``) — a static
    ``Authorization: Bearer <token>`` header. No botocore, no signing;
    same shape as every other bearer provider. Takes precedence over
    SigV4 when present (matching the AWS SDKs). Needs a region only for
    the regional host.
  * **SigV4** — sign the request with the parent's AWS credentials
    via botocore's ``SigV4Auth`` (access key / secret / session token,
    or the resolved profile/SSO/IMDS chain).

The worker keeps using the plain Anthropic SDK with no boto3 in its
address space, and the parent's ``AWS_*`` secrets (keys and bearer token)
are read-and-erased at ``CredentialStore`` construction like every other
provider key — so they never flow to spawned workers. ``botocore`` is an
optional, parent-only dependency needed **only for the SigV4 mode**; the
bearer-token mode works without it. When no usable auth (or region)
resolves, the bedrock rule reports ``503 provider not configured`` like
any unconfigured provider.

Out of scope for the proxy-based dispatcher:

  * **GCP Vertex AI** — uses OAuth refresh from a service-account
    JSON file (``GOOGLE_APPLICATION_CREDENTIALS``). The dispatcher
    would need ``google-auth`` integration to refresh the bearer
    token at request time. Deferred to a focused follow-up; until
    then ``GOOGLE_APPLICATION_CREDENTIALS`` flows through env to
    workers and the SDK does its own OAuth exchange.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Mapping, Optional
from pathlib import Path

_log = logging.getLogger(__name__)


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


def _decode_bedrock_bearer_exp(token: str) -> int | None:
    """Best-effort ``exp`` claim extraction from an AWS Bedrock bearer
    token.  Bedrock short-term API keys are JWT-shaped (three dot-
    separated base64url segments, middle segment is the payload).
    Long-term API keys are opaque strings without an exp claim — we
    return ``None`` for those and the caller treats it as "no expiry
    signal, assume long-lived".

    Signature is NOT verified — that's AWS's job at the request layer.
    We read the exp purely so we can pre-flight check at the parent
    process (warn at startup if the run is likely to outlast the
    token; reject at request time if the token has already expired,
    so we don't burn a network round trip and surface an opaque
    AWS 401 to the worker)."""
    if not isinstance(token, str) or not token:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        pad = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except (ValueError, TypeError, binascii.Error, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    exp = payload.get("exp")
    if isinstance(exp, bool):  # bool is a subtype of int, exclude it
        return None
    if isinstance(exp, (int, float)):
        return int(exp)
    return None


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
        # Operator-pinned profile name (botocore picks up
        # ``AWS_PROFILE`` automatically inside Session(), but reading it
        # explicitly lets us prefer-chain-over-env when the operator
        # set it deliberately — a profile is always refresh-capable).
        self._aws_profile: str | None = os.environ.get("AWS_PROFILE")
        # Resolved (credentials, region, endpoint) tuple, or None once we
        # know Bedrock isn't usable. ``_UNRESOLVED`` until first lookup.
        # The lock serialises first-resolution across the threading
        # dispatcher's concurrent request handlers — the resolution is
        # idempotent, but the botocore credential-chain probe (which may
        # hit IMDS) should run once, not once per concurrent first call.
        self._aws_signer_cache: object = _UNRESOLVED
        self._aws_signer_lock = threading.Lock()
        # Bedrock bearer-token expiry timestamp (unix seconds) if the
        # token is a JWT with an ``exp`` claim; ``None`` for opaque
        # long-term API keys (no expiry signal — assume long-lived).
        # Decoded once at startup so the hot path can pre-flight check
        # without re-parsing on every request.
        self._aws_bearer_exp: int | None = _decode_bedrock_bearer_exp(
            self._keys.get("aws_bearer_token") or ""
        )

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
            self._aws_bearer_exp = _decode_bedrock_bearer_exp(bearer_token)
        if region is not None:
            self._aws_region = region
        if endpoint is not None:
            self._aws_endpoint = endpoint
        self._aws_signer_cache = _UNRESOLVED

    def bedrock_bearer_exp(self) -> int | None:
        """Return the bearer token's ``exp`` claim (unix seconds) if it
        was JWT-shaped, else ``None``.  Decoded once at construction;
        no parsing on the hot path."""
        return self._aws_bearer_exp

    def bedrock_session_warnings(
        self, *, expected_run_seconds: int = 1800,
    ) -> list[str]:
        """Inspect the Bedrock credential state and return a list of
        operator-actionable warning strings.  Empty when there's
        nothing to flag.

        Detects two cases that cause "scan dies mid-run with an opaque
        AWS error":

        * The bearer token is a JWT with an ``exp`` claim that falls
          inside ``expected_run_seconds`` from now.  Operator gets a
          token-specific countdown + the long-term-API-key escape
          hatch.
        * ``AWS_SESSION_TOKEN`` is set OR the access key looks
          short-lived (``ASIA…``) and there's NO ``AWS_PROFILE`` /
          ``AWS_CONFIG_FILE`` / ``~/.aws/credentials`` for the chain
          to refresh from.  Operator gets the
          "configure aws sso / profile" guidance.

        ``expected_run_seconds`` is a hint from the launcher — e.g.
        30 min for ``/scan``, 4 hr for ``/agentic``.  Default is 30 min
        so commands that don't yet pass a hint still warn on really
        short tokens (< 30 min)."""
        warnings: list[str] = []
        exp = self._aws_bearer_exp
        if exp is not None:
            remaining = int(exp - time.time())
            if remaining <= 0:
                warnings.append(
                    "AWS_BEARER_TOKEN_BEDROCK has already expired "
                    "(exp was %d seconds ago).  Regenerate the token "
                    "in the Bedrock console, or switch to a long-term "
                    "API key (Bedrock → API Keys → Long-term)."
                    % (-remaining)
                )
            elif remaining < expected_run_seconds:
                warnings.append(
                    "AWS_BEARER_TOKEN_BEDROCK expires in %d minutes "
                    "but this run may take up to %d minutes.  Long "
                    "scans will fail when the token expires.  Use a "
                    "long-term API key (Bedrock → API Keys → Long-term)"
                    " or switch to SigV4 with a profile / SSO "
                    "(auto-refreshes)." % (
                        remaining // 60, expected_run_seconds // 60,
                    )
                )
        # SigV4-without-botocore case — operator signalled SigV4
        # intent (any of: env access keys, AWS_PROFILE, shared
        # credentials file) but botocore isn't importable in the
        # parent process.  The dispatcher will 503 every Bedrock
        # request; warn upfront so the operator doesn't burn a run
        # to discover it.  Bearer mode doesn't trigger this — bearer
        # auth needs no botocore.
        has_bearer = bool(self._keys.get("aws_bearer_token"))
        if not has_bearer:
            sigv4_intent = bool(
                self._keys.get("aws_access_key_id")
                or self._aws_profile
                or (Path.home() / ".aws" / "credentials").is_file()
                or os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
            )
            if sigv4_intent:
                try:
                    import botocore  # noqa: F401
                except ImportError:
                    warnings.append(
                        "AWS Bedrock SigV4 credentials are configured "
                        "but ``botocore`` is not installed in the parent "
                        "process.  Install it: ``pip install botocore`` "
                        "(or ``pip install boto3`` which pulls it in).  "
                        "Bearer mode (``AWS_BEARER_TOKEN_BEDROCK``) does "
                        "NOT require botocore."
                    )
        looks_short_lived = bool(
            self._keys.get("aws_session_token")
            or (
                isinstance(self._keys.get("aws_access_key_id"), str)
                and (self._keys.get("aws_access_key_id") or "").startswith("ASIA")
            )
        )
        if looks_short_lived and not self._aws_profile:
            # Is there a credentials file botocore can refresh from?
            home_creds = Path.home() / ".aws" / "credentials"
            has_creds_file = home_creds.is_file() or bool(
                os.environ.get("AWS_SHARED_CREDENTIALS_FILE"),
            )
            if not has_creds_file:
                warnings.append(
                    "AWS env credentials look short-lived "
                    "(AWS_SESSION_TOKEN set or ASIA-style access key) "
                    "but no AWS_PROFILE / ~/.aws/credentials configured.  "
                    "These will NOT auto-refresh; long scans will fail "
                    "mid-run when the STS session ends.  Configure "
                    "'aws configure sso' (recommended) or set "
                    "~/.aws/credentials with a refresh-capable profile "
                    "and unset the env vars."
                )
        return warnings

    def bedrock_bearer_expired(self, *, skew_seconds: int = 30) -> bool:
        """True iff the bearer is a JWT whose ``exp`` has passed.  A
        small clock-skew window (default 30s) errs on the side of
        rejecting borderline tokens at the dispatcher — better a
        clear "token expired" than a network round trip that surfaces
        an opaque AWS 401.  Opaque (non-JWT) bearer tokens always
        return ``False`` — they have no expiry signal."""
        exp = self._aws_bearer_exp
        if exp is None:
            return False
        return time.time() + skew_seconds >= exp

    def aws_bedrock_endpoint(self, api: str = "mantle") -> str | None:
        """Return the Bedrock base URL for the chosen ``api``, or
        ``None`` if no region is known.  Region comes from
        ``AWS_REGION`` / ``AWS_DEFAULT_REGION`` (or :meth:`set_aws`);
        it isn't a secret. Used by the bearer-token path, which needs
        the regional host but does no botocore work.

        ``api`` selects between the two Bedrock surfaces:

        * ``"mantle"`` (default) — Bedrock Mantle's Anthropic-Messages
          endpoint at ``bedrock-mantle.<region>.api.aws``, serving
          ``/anthropic/v1/messages``.  Bare model IDs
          (``anthropic.claude-opus-4-8`` — no date/version/region
          prefix).  Native streaming, tool use, prompt caching.

        * ``"runtime"`` — Legacy bedrock-runtime ``InvokeModel`` at
          ``bedrock-runtime.<region>.amazonaws.com``, serving
          ``/model/<id>/invoke``.  Accepts both bare model IDs and
          cross-region inference profile IDs
          (``us.anthropic.claude-x``, ``global.anthropic.claude-x``).
          Required for models not yet on Mantle.

        ``AWS_ENDPOINT_URL_BEDROCK`` overrides the host for both APIs
        — for local-stub testing.  Operators running stubs for both
        APIs simultaneously should run two dispatchers (one per
        API), each with its own ``AWS_ENDPOINT_URL_BEDROCK``."""
        if not self._aws_region:
            return None
        if self._aws_endpoint:
            return self._aws_endpoint
        if api == "runtime":
            return f"https://bedrock-runtime.{self._aws_region}.amazonaws.com"
        return f"https://bedrock-mantle.{self._aws_region}.api.aws"

    def aws_signer(self, api: str = "mantle"):
        """Return ``(credentials, region, endpoint)`` for SigV4 signing
        against the chosen ``api``, or ``None`` when Bedrock isn't
        usable (botocore missing, no resolvable credentials, no region).
        Credentials + region are resolved once and cached; the endpoint
        is built per-call so the same dispatcher can route requests to
        either API surface without a second botocore probe."""
        if self._aws_signer_cache is _UNRESOLVED:
            with self._aws_signer_lock:
                # Double-checked: another thread may have resolved it
                # while we waited on the lock.
                if self._aws_signer_cache is _UNRESOLVED:
                    self._aws_signer_cache = self._resolve_aws_credentials()
        if self._aws_signer_cache is None:
            return None
        credentials, region = self._aws_signer_cache
        endpoint = self.aws_bedrock_endpoint(api)
        if endpoint is None:
            return None
        return (credentials, region, endpoint)

    def _resolve_aws_credentials(self):
        """Resolve ``(credentials, region)`` from botocore.

        Lookup order is tuned so long RAPTOR scans "just work" regardless
        of how the operator configured AWS:

        1. If ``AWS_PROFILE`` is set → use botocore's chain with that
           profile.  Profiles backed by SSO, role-assumption, or shared-
           config return ``RefreshableCredentials`` that auto-refresh on
           every access, so mid-scan session expiry is handled.

        2. If env carries a session token (``AWS_SESSION_TOKEN`` set, or
           an ``ASIA…`` access key shape) → try the chain FIRST so SSO/
           IMDS/profile-derived credentials win over an env snapshot the
           operator might have set hours ago.  Fall back to the static
           env creds only if the chain doesn't resolve.  This is the
           "operator pasted temp creds into env" case — they typically
           also have a profile or SSO cache that refreshes; we should
           prefer that without making them unset env.

        3. Static env creds otherwise (``AKIA…`` long-lived keys).
           These don't expire; no refresh story needed.

        4. Bare chain fallback if env doesn't have credentials at all.

        Endpoint URL is built per-request (see :meth:`aws_signer`) since
        the same creds + region serve both Mantle and runtime."""
        try:
            import botocore.credentials
            import botocore.session
        except ImportError:
            return None

        ak = self._keys.get("aws_access_key_id")
        sk = self._keys.get("aws_secret_access_key")
        st = self._keys.get("aws_session_token")
        region = self._aws_region

        def _from_chain() -> tuple[object, str | None]:
            try:
                session = botocore.session.Session(
                    profile=self._aws_profile,
                )
                creds = session.get_credentials()
            except Exception:
                return None, None
            chain_region = None
            try:
                chain_region = session.get_config_variable("region")
            except Exception:
                pass
            return creds, chain_region

        credentials = None
        looks_short_lived = bool(
            st or (isinstance(ak, str) and ak.startswith("ASIA"))
        )

        if self._aws_profile or (looks_short_lived and not (ak and sk)):
            # Case 1 — profile pinned.
            credentials, chain_region = _from_chain()
            if region is None:
                region = chain_region
        elif looks_short_lived and ak and sk:
            # Case 2 — env has temp creds but chain (SSO/profile) is
            # likely fresher; prefer chain, fall back to env snapshot.
            credentials, chain_region = _from_chain()
            if credentials is None:
                credentials = botocore.credentials.Credentials(ak, sk, st)
            if region is None:
                region = chain_region
        elif ak and sk:
            # Case 3 — long-lived static (AKIA) env creds.
            credentials = botocore.credentials.Credentials(ak, sk, st)
        else:
            # Case 4 — no env keys at all; full chain.
            credentials, chain_region = _from_chain()
            if region is None:
                region = chain_region

        if credentials is None or not region:
            return None
        return (credentials, region)


_BEDROCK_ANTHROPIC_VERSION = "bedrock-2023-05-31"


def _ensure_anthropic_version(body: bytes) -> bytes:
    """Add ``anthropic_version`` to a JSON request body if missing.

    Mantle inherits this field requirement from the legacy InvokeModel
    Bedrock surface — the request body must declare which Anthropic
    API version the body schema follows.  The public Anthropic SDK
    doesn't add this field (the direct API doesn't need it), so the
    dispatcher injects it on the way to Mantle.  An operator-supplied
    value is preserved.  Non-JSON / empty bodies (e.g.
    ``/v1/messages/count_tokens`` POST with no body, or a GET) pass
    through untouched — Mantle returns its own 4xx if the surface
    requires a body."""
    if not body:
        return body
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body
    if not isinstance(payload, dict):
        return body
    # Only treat the field as operator-supplied when it's a non-empty
    # string.  ``None``, ``""``, numbers, or other types are typos that
    # would otherwise pass through and surface as opaque Bedrock 4xx
    # errors — fill in our default so the request succeeds.
    existing = payload.get("anthropic_version")
    if isinstance(existing, str) and existing:
        return body
    payload["anthropic_version"] = _BEDROCK_ANTHROPIC_VERSION
    return json.dumps(payload).encode("utf-8")


def _build_bearer_mantle_request(
    bearer_token: str, endpoint: str, path: str, body: bytes,
) -> PreparedRequest:
    """Attach a static ``Authorization: Bearer <token>`` header for the
    Bedrock Mantle Anthropic-Messages endpoint.  No body transformation:
    the worker's Anthropic-shape request is forwarded verbatim.  Per
    the Bedrock docs, ``bedrock-mantle.<region>.api.aws`` exposes
    ``/anthropic/v1/messages`` as the native Anthropic Messages surface
    for all Claude models on Bedrock, with bare model IDs (no date
    suffix, no ``-v1:0`` version)."""
    url = endpoint.rstrip("/") + path
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {bearer_token}",
    }
    return PreparedRequest(method="POST", url=url, headers=headers, body=body)


def _build_signed_mantle_request(
    credentials, region: str, endpoint: str, path: str, body: bytes,
) -> PreparedRequest:
    """SigV4-sign a Mantle request.  The signing service name for the
    Mantle endpoint is ``bedrock`` (same as bedrock-runtime); only the
    target URL differs."""
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    url = endpoint.rstrip("/") + path
    aws_req = AWSRequest(
        method="POST", url=url, data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    SigV4Auth(credentials, "bedrock", region).add_auth(aws_req)
    forwarded = dict(aws_req.headers.items())
    for drop in ("Host", "host", "Content-Length", "content-length"):
        forwarded.pop(drop, None)
    return PreparedRequest(method="POST", url=url, headers=forwarded, body=body)


# ---------------------------------------------------------------------------
# Bedrock runtime (legacy InvokeModel) request builders
# ---------------------------------------------------------------------------
#
# These three helpers ship the non-Mantle path: ``bedrock-runtime.
# <region>.amazonaws.com/model/<id>/invoke`` with the model id moved
# from the body into the URL path and ``anthropic_version`` set in the
# body.  Operators select this surface by pointing
# :func:`make_bedrock_client` at the ``runtime`` URL prefix (or by
# setting ``RAPTOR_BEDROCK_API=runtime`` / the per-model ``bedrock_api``
# field).  Same SigV4 signing scheme as Mantle; the streaming-rejected
# semantics are intrinsic to ``InvokeModel`` (non-streaming only — the
# streaming sibling ``InvokeModelWithResponseStream`` uses a different
# response framing and isn't currently routed).


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
    # InvokeModel is non-streaming only. The Anthropic SDK sets ``stream``
    # in the body for ``messages.stream``/``create(stream=True)``;
    # Bedrock's streaming endpoint uses different response framing
    # (``InvokeModelWithResponseStream``) and is out of scope for this
    # path.  Operators wanting streaming on Bedrock should use Mantle.
    if payload.get("stream"):
        raise BedrockTransformError(
            400,
            "bedrock: streaming is not supported on the InvokeModel path "
            "(use RAPTOR_BEDROCK_API=mantle for native SSE streaming)",
        )
    payload.pop("stream", None)
    model = payload.pop("model", None)
    if not isinstance(model, str) or not model:
        raise BedrockTransformError(400, "bedrock: request body missing 'model'")
    payload.setdefault("anthropic_version", _BEDROCK_ANTHROPIC_VERSION)
    new_body = json.dumps(payload).encode("utf-8")
    url = endpoint.rstrip("/") + f"/model/{urllib.parse.quote(model, safe='')}/invoke"
    return url, new_body


def _build_signed_runtime_request(
    credentials, region: str, endpoint: str, body: bytes,
) -> PreparedRequest:
    """Transform + SigV4-sign a bedrock-runtime InvokeModel request.
    The signed ``Authorization`` / ``X-Amz-Date`` / ``X-Amz-Security-Token``
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
    aws_req = AWSRequest(
        method="POST", url=url, data=new_body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    SigV4Auth(credentials, "bedrock", region).add_auth(aws_req)

    forwarded = dict(aws_req.headers.items())
    for drop in ("Host", "host", "Content-Length", "content-length"):
        forwarded.pop(drop, None)
    return PreparedRequest(method="POST", url=url, headers=forwarded, body=new_body)


def _build_bearer_runtime_request(
    bearer_token: str, endpoint: str, body: bytes,
) -> PreparedRequest:
    """Transform + attach a static ``Authorization: Bearer <token>``
    header (Bedrock API-key auth) for a bedrock-runtime InvokeModel
    request. No botocore, no signing — matches what the AWS SDKs send
    when ``AWS_BEARER_TOKEN_BEDROCK`` is set."""
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
        # Two Bedrock surfaces are routed through this rule, chosen by
        # URL prefix the worker addresses:
        #
        #   ``/mantle/...``  → Bedrock Mantle Anthropic Messages
        #                       (``bedrock-mantle.<region>.api.aws/
        #                       anthropic/v1/messages``).  Bare model
        #                       IDs, native streaming, tool use,
        #                       prompt caching.  Default.
        #
        #   ``/runtime/...`` → Bedrock InvokeModel
        #                       (``bedrock-runtime.<region>.amazonaws.
        #                       com/model/<id>/invoke``).  Required
        #                       for models not yet on Mantle, for
        #                       cross-region inference profile IDs
        #                       (``us.``/``eu.``/``global.``), and
        #                       for compliance-pinned ARN-versioned
        #                       IDs.  Non-streaming only.
        #
        # An unprefixed ``/v1/...`` path (the worker's default base URL
        # without an API segment) routes to Mantle for backward
        # compatibility — the same shape the standard Anthropic SDK
        # produces against ``base_url=http://_/bedrock``.  The worker's
        # ``make_bedrock_client(api="runtime"|"mantle")`` chooses the
        # URL prefix at construction time.
        #
        # Auth is the same for both APIs (bearer or SigV4) — only the
        # request transformation and endpoint host differ.
        api = "mantle"
        bedrock_path = path
        if path.startswith("/mantle/") or path == "/mantle":
            api = "mantle"
            bedrock_path = path[len("/mantle"):] or "/"
        elif path.startswith("/runtime/") or path == "/runtime":
            api = "runtime"
            bedrock_path = path[len("/runtime"):] or "/"

        # Security gate: reject any path with a ``..`` segment before
        # forwarding.  Without this, a worker could craft
        # ``/v1/messages/../../some-other-aws-path`` and have httpx
        # normalise the ``..`` away client-side AFTER we've signed —
        # the parent's bearer token / SigV4 signature would attach to
        # an arbitrary URL under the Bedrock host.  Defence-in-depth:
        # the worker isn't expected to send ``..`` here, but a
        # compromised worker shouldn't be able to pivot off RAPTOR's
        # trust boundary.
        if ".." in bedrock_path.split("/"):
            raise BedrockTransformError(
                400, "bedrock: path traversal segment '..' rejected"
            )

        if api == "mantle":
            # Mantle: only ``/v1/messages`` and ``/v1/messages/
            # count_tokens`` are valid worker shapes.  Everything else
            # is either a typo (`/v1/models` — not exposed by Mantle)
            # or an attempt to forward to an unintended path.  Reject
            # explicitly rather than letting an opaque AWS 4xx propagate.
            if bedrock_path not in (
                "/v1/messages", "/v1/messages/count_tokens",
            ):
                raise BedrockTransformError(
                    400,
                    f"bedrock: path {bedrock_path!r} is not a supported "
                    "Mantle endpoint (expected /v1/messages or "
                    "/v1/messages/count_tokens)",
                )
            # Inject the ``/anthropic`` prefix (Mantle's URL contract)
            # and fill ``anthropic_version`` into the body when missing
            # (Mantle inherits the requirement from InvokeModel; the
            # SDK doesn't add it because the public Anthropic API
            # doesn't need it).
            upstream_path = "/anthropic" + bedrock_path
            upstream_body = _ensure_anthropic_version(body)
            bearer = creds.get("aws_bearer_token")
            if bearer:
                if creds.bedrock_bearer_expired():
                    # Pre-flight gate: don't burn a network round trip
                    # if we already know the JWT exp has passed.
                    raise BedrockTransformError(
                        401,
                        "AWS_BEARER_TOKEN_BEDROCK has expired; "
                        "regenerate the token (Bedrock console) or "
                        "switch to a long-term API key.",
                    )
                endpoint = creds.aws_bedrock_endpoint("mantle")
                if endpoint is None:
                    raise BedrockTransformError(
                        503,
                        "provider not configured: bedrock (no AWS region)",
                    )
                return _build_bearer_mantle_request(
                    bearer, endpoint.rstrip("/"), upstream_path,
                    upstream_body,
                )
            signer = creds.aws_signer("mantle")
            if signer is None:
                raise BedrockTransformError(
                    503, "provider not configured: bedrock",
                )
            credentials, region, endpoint = signer
            return _build_signed_mantle_request(
                credentials, region, endpoint.rstrip("/"),
                upstream_path, upstream_body,
            )

        # Runtime path — InvokeModel.  The request body's ``model``
        # becomes the URL path; the body is rewritten by
        # ``_transform_bedrock_request`` inside the request builders.
        #
        # Only ``/v1/messages`` is InvokeModel-translatable.  Other
        # Anthropic endpoints (``/v1/messages/count_tokens``,
        # ``/v1/models``) have no InvokeModel equivalent — short-
        # circuit with a 400 + actionable guidance rather than letting
        # the worker pay a network round trip to AWS just to get a
        # different opaque 4xx back.
        if bedrock_path != "/v1/messages":
            raise BedrockTransformError(
                400,
                f"bedrock: path {bedrock_path!r} is not supported on "
                "the InvokeModel API (use RAPTOR_BEDROCK_API=mantle "
                "for /v1/messages/count_tokens and the introspection "
                "endpoints)",
            )
        bearer = creds.get("aws_bearer_token")
        if bearer:
            if creds.bedrock_bearer_expired():
                raise BedrockTransformError(
                    401,
                    "AWS_BEARER_TOKEN_BEDROCK has expired; "
                    "regenerate the token (Bedrock console) or "
                    "switch to a long-term API key.",
                )
            endpoint = creds.aws_bedrock_endpoint("runtime")
            if endpoint is None:
                raise BedrockTransformError(
                    503,
                    "provider not configured: bedrock (no AWS region)",
                )
            return _build_bearer_runtime_request(bearer, endpoint, body)
        signer = creds.aws_signer("runtime")
        if signer is None:
            raise BedrockTransformError(
                503, "provider not configured: bedrock",
            )
        credentials, region, endpoint = signer
        return _build_signed_runtime_request(credentials, region, endpoint, body)

    def _bedrock_configured() -> bool:
        # Bearer token (+ a region for the host) OR a resolvable SigV4
        # signer.  Bearer is checked first and cheaply (no botocore
        # probe).  Configured-ness is API-agnostic — both Mantle and
        # runtime need the same creds + region.
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
            upstream_base_url="https://bedrock-mantle-not-configured.invalid",
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
