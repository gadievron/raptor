"""Canonical credential-env vocabulary — the single source of truth.

Environment-variable names that carry credential material, point at
credential/config files, or redirect credential acquisition through an
attacker-suppliable executable. Every strip/allowlist/blocklist surface
that reasons about credential-family names consumes THIS module; no
consumer keeps a private copy of the family (the closure test
``core/security/tests/test_credential_env_closure.py`` walks the
consumer surfaces and asserts vocabulary consumption).

Stdlib-only on purpose: ``core.config`` imports from ``core.security``
at class-definition time, and the trust gate (``cc_trust``) must work
even on degraded installs where ``core.config`` cannot import — this
module must be importable from anywhere with zero dependency risk.

Three tiers, because consumers differ in what they may block:

* ``CREDENTIAL_BEARING_ENV_VARS`` — the value IS the secret.
* ``CREDENTIAL_FILE_POINTER_ENV_VARS`` — the value names a file/dir
  (or selects a profile) that credentials are read from; several of
  the pointed-to formats can name a helper COMMAND the SDK executes
  (AWS ``credential_process``, kubeconfig ``users[].user.exec``,
  docker ``credsStore``, gcloud external-account executables).
* ``CREDENTIAL_EXEC_REDIRECT_ENV_VARS`` — the value itself names a
  program/command executed during credential acquisition or tool
  operation.

``CREDENTIAL_ENV_FAMILY`` is the union — the right set for
hostile-input filters (repo-supplied settings/env scanning, build-
metadata env filtering), where NO member has a legitimate reason to
appear.

``CREDENTIAL_GENERAL_BLOCKLIST_VARS`` is the family minus the
documented runtime re-admits (``GENERAL_BLOCKLIST_EXEMPT_VARS``) —
the right increment for general-purpose blocklists that also filter
RAPTOR's OWN child environments (``RaptorConfig.DANGEROUS_ENV_VARS``
and the sandbox ``strict_env`` sweep that consumes it), where a
handful of members are deliberately carried by trusted lanes.
"""

from __future__ import annotations

# --- Tier 1: the value IS the secret -------------------------------
#
# First-party Claude/Anthropic authentication material. Grouped as a
# tuple because two consumers need exactly this trio in order-stable
# form: the cc_adapter alternate-cloud pop (Bedrock/Vertex children
# have no use for first-party auth) and the proxy-mode strip (the
# dispatcher gateway mints the only credential a proxy-mode child may
# hold). CLAUDE_CODE_OAUTH_TOKEN is the ``claude setup-token``
# long-lived OAuth credential — same posture as ANTHROPIC_API_KEY /
# ANTHROPIC_AUTH_TOKEN everywhere both are handled.
ANTHROPIC_FIRST_PARTY_AUTH_VARS: tuple[str, ...] = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
)

CREDENTIAL_BEARING_ENV_VARS: frozenset[str] = frozenset({
    *ANTHROPIC_FIRST_PARTY_AUTH_VARS,
    # Rides arbitrary headers (including Authorization overrides /
    # gateway secrets) onto every Anthropic API request.
    "ANTHROPIC_CUSTOM_HEADERS",
    # AWS static credential material (SigV4 trio + the Bedrock
    # bearer token).
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    # Composer's inline auth store: the value is a JSON blob of
    # registry credentials (http-basic / bearer / github-oauth) —
    # the secret itself, not a pointer to one.
    "COMPOSER_AUTH",
})

# --- Tier 2: the value points at credential/config material --------
CREDENTIAL_FILE_POINTER_ENV_VARS: frozenset[str] = frozenset({
    # botocore executes `credential_process = <cmd>` from the pointed
    # config; AWS_PROFILE selects which profile (and thus which
    # credential_process) applies — a selector with the same power.
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_PROFILE",
    # google-auth: service-account key path, or an external-account
    # JSON whose credential_source.executable.command is run when
    # GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES permits (tier 3).
    "GOOGLE_APPLICATION_CREDENTIALS",
    # gcloud config dir — credential store + helper configuration.
    "CLOUDSDK_CONFIG",
    # kubeconfig `users[].user.exec` runs an arbitrary command for
    # credential acquisition on any kubectl invocation.
    "KUBECONFIG",
    # docker CLI config dir — credsStore/credHelpers entries invoke
    # `docker-credential-<helper>` binaries.
    "DOCKER_CONFIG",
    # curl/wget credential files and the config dirs they live under
    # (a wgetrc carries http_password / proxy_password and proxy
    # redirects — same class as NETRC).
    "NETRC",
    "CURL_HOME",
    "WGETRC",
    # Azure credential material on disk: the az CLI config dir (token
    # cache + credential store) and the client-certificate path used
    # for service-principal auth by the Azure SDKs.
    "AZURE_CONFIG_DIR",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    # Package-manager configs that carry registry credentials and
    # can redirect installs at credentialed attacker registries.
    "PIP_CONFIG_FILE",
    "NPM_CONFIG_USERCONFIG",
    # Gradle home: init scripts (executed code) + credential stores.
    "GRADLE_USER_HOME",
})

# --- Tier 3: the value names a program that gets executed ----------
CREDENTIAL_EXEC_REDIRECT_ENV_VARS: frozenset[str] = frozenset({
    # git runs these to obtain credentials / reach remotes.
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_PROXY_COMMAND",
    # ssh (and everything that shells out to it) runs this to prompt
    # for passwords when no tty is attached.
    "SSH_ASKPASS",
    # cargo substitutes these binaries for every compile.
    "RUSTC_WRAPPER",
    "RUSTC",
    # gcloud runs this interpreter for every invocation — an
    # exec-redirect sibling of the CLOUDSDK_CONFIG pointer above.
    "CLOUDSDK_PYTHON",
    # Arms google-auth external-account executable credentials.
    "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
})

#: The full family — for hostile-input filters (repo settings env
#: scanning, build-metadata env filtering). No member of this set has
#: a legitimate reason to be set by scanned-repo content.
CREDENTIAL_ENV_FAMILY: frozenset[str] = (
    CREDENTIAL_BEARING_ENV_VARS
    | CREDENTIAL_FILE_POINTER_ENV_VARS
    | CREDENTIAL_EXEC_REDIRECT_ENV_VARS
)

# --- Documented runtime re-admits -----------------------------------
#
# Family members some TRUSTED RAPTOR lane legitimately carries into a
# child environment that later crosses a DANGEROUS_ENV_VARS-consuming
# filter (the sandbox strict_env sweep re-filters caller-supplied env
# by that list). These stay OUT of the general-blocklist increment;
# hostile-input lanes block them via CREDENTIAL_ENV_FAMILY instead.
#
# Carrier lanes (each named so the exemption is auditable):
#   * cc_adapter env-mode children (run_untrusted_networked,
#     strict_env=True): first-party auth on API-key / setup-token
#     installs (ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN /
#     CLAUDE_CODE_OAUTH_TOKEN, plus operator ANTHROPIC_CUSTOM_HEADERS
#     riding the backend overlay), the Bedrock AWS passthrough names
#     (_CC_AWS_PASSTHROUGH_NAMES: AWS_PROFILE / AWS_CONFIG_FILE /
#     AWS_SHARED_CREDENTIALS_FILE) and minted/static AWS credential
#     material for children whose own chain is sandbox-dead.
#   * proxy-mode children: the minted scoped ANTHROPIC_AUTH_TOKEN is
#     the child's ONLY credential by contract.
GENERAL_BLOCKLIST_EXEMPT_VARS: frozenset[str] = frozenset({
    *ANTHROPIC_FIRST_PARTY_AUTH_VARS,
    "ANTHROPIC_CUSTOM_HEADERS",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
})

#: The increment general-purpose blocklists take from the family:
#: every member here is safe to strip from ANY child environment —
#: no RAPTOR runtime lane carries them (verified per-member when the
#: exemption list above was drawn; GIT_ASKPASS/GIT_SSH pins from
#: RaptorConfig.GIT_ENV_VARS survive because every strict_env sweep
#: exempts values matching those pins).
CREDENTIAL_GENERAL_BLOCKLIST_VARS: frozenset[str] = (
    CREDENTIAL_ENV_FAMILY - GENERAL_BLOCKLIST_EXEMPT_VARS
)

# --- Name-shape grammar ---------------------------------------------
#
# Belt over the explicit sets: catches family-shaped names the
# enumeration doesn't know yet (a future CLAUDE_CODE_*_TOKEN, a new
# provider's *_API_KEY). Segment-exact on underscore-split so
# GPG_PUBKEY / SSLKEYLOGFILE-style names don't false-positive.
#
# Plural TOKENS is deliberately ABSENT: real credential names are
# effectively always singular (*_TOKEN), while plural TOKENS names
# count things (CLAUDE_CODE_MAX_OUTPUT_TOKENS / MAX_THINKING_TOKENS /
# MAX_MCP_OUTPUT_TOKENS — documented, commonly committed settings
# knobs). Including it flags those common legitimate keys on every
# consumer surface; excluding it costs nothing observed (no known
# credential is named *_TOKENS, and the explicit sets keep covering
# enumerated members). Two-direction pins live in the unit tests.
# Plural KEYS/SECRETS/... stay: multi-secret blobs genuinely use them
# and no common tooling knob collides.
_CREDENTIAL_NAME_SEGMENTS: frozenset[str] = frozenset({
    "TOKEN",
    "KEY", "KEYS", "APIKEY",
    "SECRET", "SECRETS",
    "CREDENTIAL", "CREDENTIALS",
    "PASSWORD", "PASSWORDS", "PASSWD",
})

# Documented benign operator knobs whose names collide with the
# grammar and are exempted by exact name: the KEY segment in
# CLAUDE_CODE_API_KEY_HELPER_TTL_MS belongs to "apiKeyHelper" (the
# value is a refresh interval in milliseconds, never credential
# material), and KEY itself is load-bearing for *_API_KEY — a
# carve-out, not a segment change. Kept deliberately tiny: every
# entry must be a documented knob whose VALUE is inert.
_CREDENTIAL_SHAPE_EXEMPT_KNOBS: frozenset[str] = frozenset({
    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
})

# Additional segments that mark credential-REDIRECT shapes (config /
# helper-exec pointers) for hostile-input lanes only — too broad for
# general child-env sweeps (plenty of benign *_CONFIG_FILE tooling
# knobs exist in operator environments).
_REDIRECT_NAME_SUFFIXES: tuple[str, ...] = (
    "_CONFIG_FILE",
    "_CREDENTIALS_FILE",
    "_ASKPASS",
)


def is_credential_shaped(name: str) -> bool:
    """True when *name* looks like it carries credential material.

    Case-insensitive, segment-exact on underscore split: any segment
    equal to TOKEN/KEY/SECRET/CREDENTIAL/PASSWORD (and common
    variants) marks the name. ``ANTHROPIC_API_KEY``,
    ``CLAUDE_CODE_OAUTH_TOKEN`` and ``AWS_SECRET_ACCESS_KEY`` match;
    ``GPG_PUBKEY``, ``SSLKEYLOGFILE`` and the documented
    ``CLAUDE_CODE_MAX_OUTPUT_TOKENS`` / ``…_API_KEY_HELPER_TTL_MS``
    settings knobs do not.
    """
    upper = name.upper()
    if upper in _CREDENTIAL_SHAPE_EXEMPT_KNOBS:
        return False
    return any(
        seg in _CREDENTIAL_NAME_SEGMENTS
        for seg in upper.split("_")
    )


def is_credential_redirect_shaped(name: str) -> bool:
    """Shape rule for HOSTILE-INPUT lanes (repo-supplied env keys).

    Everything :func:`is_credential_shaped` matches, plus config-file
    / askpass-style redirect suffixes (``AWS_CONFIG_FILE``-shaped
    names). Deliberately not used on general child-env sweeps —
    benign operator tooling legitimately uses ``*_CONFIG_FILE``
    knobs; repo-supplied settings env has no such excuse.
    """
    if is_credential_shaped(name):
        return True
    upper = name.upper()
    return any(upper.endswith(suffix) for suffix in _REDIRECT_NAME_SUFFIXES)


# --- Model-traffic redirect endpoints -------------------------------
#
# NOT part of CREDENTIAL_ENV_FAMILY: ``ANTHROPIC_BASE_URL`` is a
# documented LLM-lane re-admit (``LLM_ROUTING_ENV_VARS``) and the
# proxy-mode dispatcher itself SETS gateway base URLs on its children
# — family membership would put these names in general blocklists
# that trusted routing lanes must carry them through. This is a shape
# rule for the two symmetric consumers that reason about
# model-traffic redirection:
#
#   * cc_trust's settings-env scan (hostile input): a repo-supplied
#     endpoint name repoints model traffic at an attacker host —
#     prompt/source exfiltration, and on bearer-token installs
#     verbatim credential exfiltration. The CLI honours a DIFFERENT
#     base-URL name per provider mode (a Bedrock install ignores
#     ``ANTHROPIC_BASE_URL`` and reads
#     ``ANTHROPIC_BEDROCK_MANTLE_BASE_URL`` / the per-cloud
#     ``ANTHROPIC_*_BASE_URL`` variants), the JS AWS SDK honours
#     ``AWS_ENDPOINT_URL`` / ``AWS_ENDPOINT_URL_<SERVICE>``, and the
#     ``CLAUDE_CODE_SKIP_*`` flags flip the CLI's auth mode at
#     whatever endpoint won — blocking only the exact primary name
#     leaves the whole variant family open.
#   * cc_adapter's proxy-mode strip: operator endpoint pins must not
#     ride the backend overlay into a proxy-mode child — the caller
#     sets the one true gateway route (and the skip-auth flags THIS
#     mode needs) after the strip.

def is_model_traffic_redirect_shaped(name: str) -> bool:
    """True when *name* is a model-traffic endpoint/auth-mode knob.

    Case-insensitive. Covers the per-provider base-URL family
    (``ANTHROPIC_BASE_URL``, ``ANTHROPIC_BEDROCK[_MANTLE]_BASE_URL``,
    ``ANTHROPIC_VERTEX_BASE_URL``, future variants), the JS AWS SDK
    endpoint overrides (``AWS_ENDPOINT_URL``,
    ``AWS_ENDPOINT_URL_BEDROCK_RUNTIME``, per-service variants), and
    the CLI auth-mode flips (``CLAUDE_CODE_SKIP_*``).
    """
    upper = name.upper()
    if upper.startswith("ANTHROPIC_") and "BASE_URL" in upper:
        return True
    if upper.startswith("AWS_ENDPOINT_URL"):
        return True
    return upper.startswith("CLAUDE_CODE_SKIP_")
