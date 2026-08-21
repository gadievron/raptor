"""AWS IMDS / proxy / credential-chain interaction advisories (doctor).

The failure matrix this covers is easy to fall into and hard to
diagnose after the fact:

  * ``AWS_EC2_METADATA_DISABLED=true`` is routinely recommended as
    probe-noise hygiene on proxied hosts (it stops every AWS SDK from
    spamming the proxy with denied ``169.254.169.254`` probes). But on
    a host whose credential chain actually depends on EC2 IMDS —
    ``credential_source = Ec2InstanceMetadata`` in ``~/.aws/config``,
    or no other credential source anywhere so the SDKs fall through to
    IMDS as the last resort — that same advice silently breaks all AWS
    credential resolution. A real near-miss of exactly that shape
    motivated this check.
  * The converse hazard: an IMDS-dependent chain on a proxied host
    whose ``NO_PROXY`` lacks ``169.254.169.254`` sends link-local IMDS
    calls to the proxy, where they hang or are denied. RAPTOR's own
    children are immune (``core/llm/egress.py`` unions the IMDS IP
    into ``NO_PROXY`` — see ``_NO_PROXY_ONLY`` there), but the
    operator's shell and non-RAPTOR tools are not.

Doctor-only, advisory-only: environment shapes are never failures.
Gated on AWS use being plausible (any ``AWS_*`` variable set, an
``~/.aws/config`` present, or a bedrock provider in the LLM models
config) so non-AWS users never see a line.

Privacy rules, deliberate and load-bearing:

  * ``~/.aws/credentials`` is NEVER opened — only its *existence* is
    consulted (a profile whose keys may live there is classified
    "unable to determine", never guessed).
  * No config values are printed. The only operator-supplied string
    that reaches output is the profile *name*, and even that is
    redacted first (account-id digit runs → ``<acct>``, ARN-shaped
    substrings → ``<arn>``).
  * Ambiguity degrades to silence — doctor never guesses. The single
    "credential chain: unable to determine" line appears only when
    ``AWS_*`` variables are set but the config file is unreadable or
    unparseable.
"""

from __future__ import annotations

import configparser
import json
import logging
import os
import re
from collections.abc import Mapping
from pathlib import Path

logger = logging.getLogger(__name__)

_IMDS_IP = "169.254.169.254"

_IMDS_DISABLED_ENV = "AWS_EC2_METADATA_DISABLED"

# Truthy spellings across the AWS SDK family. botocore honours only
# "true" (case-insensitive); the Go / Java / Node SDKs also parse
# "1"-style booleans. Advisory posture: any of these spellings signals
# operator intent to disable IMDS, and at least one major SDK honours
# each, so warn on all of them.
_TRUTHY = frozenset({"true", "1", "yes", "on"})

# Proxy-presence signal (reads only; RAPTOR's strip/preserve policy for
# these lives in RaptorConfig.PROXY_ENV_VARS).
_PROXY_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
)

# source_profile chains are short in practice; the cap only exists so a
# hostile / broken config cannot make doctor spin.
_MAX_CHAIN_DEPTH = 8

_ACCT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_ARN_RE = re.compile(r"arn:[^\s,'\"]+", re.IGNORECASE)


def _redact(text: str) -> str:
    """Redact account ids and ARN-shaped substrings from a string that
    is about to become operator-visible output (profile names can and
    do embed both)."""
    return _ACCT_RE.sub("<acct>", _ARN_RE.sub("<arn>", text))


def _home(env: Mapping[str, str]) -> Path:
    home = env.get("HOME")
    return Path(home) if home else Path.home()


def _config_path(env: Mapping[str, str]) -> Path:
    explicit = env.get("AWS_CONFIG_FILE")
    if explicit:
        return Path(explicit).expanduser()
    return _home(env) / ".aws" / "config"


def _credentials_path(env: Mapping[str, str]) -> Path:
    explicit = env.get("AWS_SHARED_CREDENTIALS_FILE")
    if explicit:
        return Path(explicit).expanduser()
    return _home(env) / ".aws" / "credentials"


def _bedrock_configured(env: Mapping[str, str]) -> bool:
    """True when the LLM models config declares a bedrock provider.

    Mirrors the lightweight direct-read posture of ``check_llm`` (no
    core.llm import — this runs inside doctor's startup-adjacent path).
    """
    explicit = env.get("RAPTOR_CONFIG")
    path = (
        Path(explicit).expanduser() if explicit
        else _home(env) / ".config" / "raptor" / "models.json"
    )
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    # models.json supports // line comments (see core.llm.detection).
    body = "\n".join(
        line for line in text.splitlines()
        if not line.lstrip().startswith("//")
    )
    try:
        data = json.loads(body)
    except ValueError:
        return False
    models = data.get("models") if isinstance(data, dict) else data
    if not isinstance(models, list):
        return False
    return any(
        isinstance(m, dict) and m.get("provider") == "bedrock"
        for m in models
    )


def _aws_plausible(env: Mapping[str, str]) -> bool:
    if any(k.startswith("AWS_") for k in env):
        return True
    if _config_path(env).is_file():
        return True
    return _bedrock_configured(env)


def _parse_config(path: Path) -> dict[str, dict[str, str]] | None:
    """Structural parse of the AWS shared config file.

    Returns ``{section_name: {key: value}}`` (keys lowercased by
    configparser) or None when unreadable / unparseable. Values are
    consulted structurally and never printed.
    """
    cp = configparser.RawConfigParser()
    try:
        with path.open(encoding="utf-8") as fh:
            cp.read_file(fh)
    except (OSError, UnicodeError, configparser.Error):
        return None
    return {name.strip(): dict(cp.items(name)) for name in cp.sections()}


def _profile_section(
    sections: Mapping[str, Mapping[str, str]], profile: str,
) -> Mapping[str, str] | None:
    """AWS config section for a profile: ``[default]`` (or the tolerated
    ``[profile default]``) for the default profile, ``[profile <name>]``
    (bare ``[<name>]`` tolerated) otherwise."""
    if profile == "default":
        return sections.get("default") or sections.get("profile default")
    return sections.get(f"profile {profile}") or sections.get(profile)


def _walk_profile(
    sections: Mapping[str, Mapping[str, str]],
    name: str,
    seen: set[str],
) -> tuple[str, str]:
    """Classify one profile (following ``source_profile`` chains).

    Returns ``(status, detail)`` with status one of:
      * ``imds``     — the chain depends on EC2 IMDS
      * ``non-imds`` — a static / SSO / process / non-IMDS source
      * ``unknown``  — not determinable without guessing
      * ``none``     — no section / no credential keys (the caller
        continues down the SDK provider chain)
    """
    if name in seen or len(seen) >= _MAX_CHAIN_DEPTH:
        return "unknown", "source_profile cycle or depth limit"
    seen.add(name)
    sec = _profile_section(sections, name)
    if sec is None:
        return "none", "no profile section"
    raw_source = (sec.get("credential_source") or "").strip()
    cred_source = raw_source.lower()
    if cred_source == "ec2instancemetadata":
        return "imds", "credential_source = Ec2InstanceMetadata"
    if cred_source in ("environment", "ecscontainer"):
        # Fixed vocabulary — safe to echo (normalised, not operator
        # free-text).
        canonical = (
            "Environment" if cred_source == "environment"
            else "EcsContainer"
        )
        return "non-imds", f"credential_source = {canonical}"
    if cred_source:
        return "unknown", "unrecognised credential_source"
    if "aws_access_key_id" in sec:
        return "non-imds", "static keys configured in the profile"
    if "sso_session" in sec or "sso_start_url" in sec:
        return "non-imds", "SSO-configured profile"
    if "credential_process" in sec:
        return "non-imds", "credential_process-configured profile"
    if "web_identity_token_file" in sec:
        return "non-imds", "web-identity-configured profile"
    source = (sec.get("source_profile") or "").strip()
    if source:
        status, detail = _walk_profile(sections, source, seen)
        if status == "none":
            # The source profile's keys may live in the credentials
            # file, which is never read here.
            return (
                "unknown",
                "source profile resolves outside the config file",
            )
        return status, f"assume-role chain: {detail}"
    if "role_arn" in sec:
        return "unknown", "role profile without a recognised source"
    return "none", "no credential keys in the profile section"


def _classify_chain(env: Mapping[str, str]) -> tuple[str, str, str]:
    """Determine whether the effective credential chain depends on IMDS.

    Returns ``(status, profile_name, detail)`` with status one of
    ``imds`` / ``non-imds`` / ``unknown`` / ``unparseable``. Structural
    only: ``~/.aws/config`` sections and env-var *presence* — never
    the credentials file, never any secret value.
    """
    profile = (env.get("AWS_PROFILE") or "").strip()
    explicit = bool(profile)
    profile = profile or "default"

    # Environment credentials precede profile resolution when no
    # profile is explicitly selected (with AWS_PROFILE set, botocore
    # drops the env provider entirely, so the profile is
    # authoritative). Checked before the config parse: env creds make
    # the chain determinable even when the config file is not.
    if not explicit and env.get("AWS_ACCESS_KEY_ID"):
        return "non-imds", profile, "static credentials in the environment"

    sections: dict[str, dict[str, str]] = {}
    config_path = _config_path(env)
    if config_path.is_file():
        parsed = _parse_config(config_path)
        if parsed is None:
            return "unparseable", profile, str(config_path)
        sections = parsed

    status, detail = _walk_profile(sections, profile, set())
    if status in ("imds", "non-imds", "unknown"):
        return status, profile, detail

    # status == "none": the profile carries no credential configuration.
    if explicit and _profile_section(sections, profile) is None:
        # AWS_PROFILE names a profile the config file does not define;
        # SDKs error out (or find it in the credentials file, which is
        # never read here) — not determinable.
        return "unknown", profile, "profile not found in config"
    # Walk the rest of the SDK default provider chain structurally.
    if env.get("AWS_WEB_IDENTITY_TOKEN_FILE") or \
            env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") or \
            env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI"):
        return (
            "non-imds", profile,
            "web-identity / container credentials in the environment",
        )
    if _credentials_path(env).exists():
        # Static keys may live there; existence is checked, contents
        # never read — refuse to guess.
        return "unknown", profile, "credentials file present (not read)"
    if explicit and env.get("AWS_ACCESS_KEY_ID"):
        # Env creds + explicit profile: SDKs diverge on which wins.
        return "unknown", profile, "explicit profile with env credentials"
    return (
        "imds", profile,
        "no static, SSO, or process credential source found — SDKs "
        "fall through to EC2 IMDS as the last resort",
    )


def _imds_excluded_from_proxy(env: Mapping[str, str]) -> bool:
    for var in ("NO_PROXY", "no_proxy"):
        for token in (env.get(var) or "").split(","):
            token = token.strip()
            if token == "*" or token.split(":", 1)[0] == _IMDS_IP:
                return True
    return False


def _advisories(env: Mapping[str, str]) -> list[str]:
    if not _aws_plausible(env):
        return []

    status, profile, detail = _classify_chain(env)
    profile = _redact(profile)

    if status == "unparseable":
        if any(k.startswith("AWS_") for k in env):
            return [
                f"AWS credential chain: unable to determine — {detail} "
                f"is unreadable or unparseable; skipping the IMDS "
                f"interaction checks"
            ]
        return []
    if status == "unknown":
        return []

    disabled_raw = (env.get(_IMDS_DISABLED_ENV) or "").strip()
    disabled = disabled_raw.lower() in _TRUTHY
    proxies = [v for v in _PROXY_VARS if env.get(v)]

    out: list[str] = []
    if status == "imds":
        if disabled:
            out.append(
                f"AWS profile '{profile}' depends on EC2 IMDS for "
                f"credentials ({detail}), but {_IMDS_DISABLED_ENV} is "
                f"set — AWS credential resolution on this host will "
                f"fail. Unset {_IMDS_DISABLED_ENV} or move the profile "
                f"to a non-IMDS credential source."
            )
        elif proxies and not _imds_excluded_from_proxy(env):
            out.append(
                f"AWS profile '{profile}' depends on EC2 IMDS for "
                f"credentials ({detail}) and a proxy is configured "
                f"({', '.join(proxies)}) without a NO_PROXY entry for "
                f"{_IMDS_IP} — IMDS calls may route to the proxy and "
                f"hang or be denied. RAPTOR's own subprocesses get the "
                f"exclusion automatically (core/llm/egress.py NO_PROXY "
                f"augmentation); the operator shell and other tools do "
                f"not — add {_IMDS_IP} to NO_PROXY there."
            )
    else:  # non-imds
        if not disabled_raw and proxies:
            out.append(
                f"optional: proxied environment and the AWS credential "
                f"chain does not depend on EC2 IMDS ({detail}) — "
                f"setting {_IMDS_DISABLED_ENV}=true stops AWS SDKs "
                f"probing {_IMDS_IP} through the proxy. Probe-noise "
                f"hygiene only; do NOT set it on hosts whose "
                f"credentials come from an instance role "
                f"(credential_source = Ec2InstanceMetadata) — it "
                f"breaks them."
            )
    return out


def aws_imds_advisories(env: Mapping[str, str] | None = None) -> list[str]:
    """Advisory lines for the AWS IMDS / proxy / credential-chain
    interaction matrix. Empty for non-AWS environments and whenever
    the chain cannot be determined without guessing. Never raises.
    """
    try:
        return _advisories(os.environ if env is None else env)
    except Exception:  # noqa: BLE001 — advisory probe must never break doctor
        logger.debug("aws-imds advisory probe failed", exc_info=True)
        return []
