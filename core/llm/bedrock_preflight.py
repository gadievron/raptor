"""Run-start entitlement preflight for configured Bedrock models.

Bedrock entitlement is scoped per model per region per account — an
IAM role commonly allows exactly one model.  A misconfigured entry
(wrong id, wrong region, un-entitled model) otherwise surfaces as an
AccessDenied forty findings into a run.  This module fires ONE
1-output-token probe per configured ``(model, surface, region,
profile)`` combination at dispatcher startup and turns the failure
modes into operator-actionable warnings up front.

Cost discipline: a success is cached on disk for 24h (keyed by the
combination + auth mode), so steady-state runs pay nothing.  Failures
are never cached — a fixed entitlement is picked up on the next run.
Network problems are NOT warnings (the run may still work; the LLM
client has its own retry story) — they log at debug and skip the
cache.

Probes go through the same request builders the dispatcher uses
(`core.llm.dispatcher.auth`), so a preflight pass is evidence the real
path works, not a lookalike.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from core.llm.config import ModelConfig
    from core.llm.dispatcher.auth import CredentialStore

logger = logging.getLogger(__name__)

_CACHE_PATH = Path(
    os.environ.get("RAPTOR_BEDROCK_PREFLIGHT_CACHE")
    or Path.home() / ".raptor" / "cache" / "bedrock-preflight.json"
)
_CACHE_TTL_S = 24 * 3600
_PROBE_TIMEOUT_S = 15
# Runaway guard: a models.json with many Bedrock entries still fires a
# bounded number of live probes per run.
_MAX_PROBES = 4


def _configured_bedrock_models() -> list["ModelConfig"]:
    """Bedrock ModelConfigs the current run could select: config-file
    entries plus the env-builder result.  Best-effort — resolution
    errors yield an empty list (preflight is advisory)."""
    out: list[ModelConfig] = []
    try:
        from core.llm.config import (
            _build_bedrock_config,
            _get_configured_models,
            _model_config_from_entry,
        )
        for entry in _get_configured_models():
            if not isinstance(entry, dict):
                continue
            try:
                mc = _model_config_from_entry(entry)
            except Exception:  # noqa: BLE001 — skip malformed entries
                continue
            if mc.provider == "bedrock" and mc.model_name:
                out.append(mc)
        env_mc = _build_bedrock_config()
        if env_mc is not None and env_mc.model_name:
            out.append(env_mc)
    except Exception as exc:  # noqa: BLE001 — advisory only
        logger.debug("bedrock preflight: config resolution failed: %s", exc)
    return out


def _cache_key(model: str, surface: str, region: str, profile: str,
               auth_mode: str) -> str:
    return f"{auth_mode}|{profile}|{region}|{surface}|{model}"


def _read_cache() -> dict:
    try:
        data = json.loads(_CACHE_PATH.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_cache(cache: dict) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(json.dumps(cache))
    except OSError as exc:
        logger.debug("bedrock preflight: cache write failed: %s", exc)


def _probe_request(creds: "CredentialStore", mc: "ModelConfig"):
    """Build the signed/bearer 1-token request for *mc* via the
    dispatcher's own builders.  Returns a PreparedRequest or ``None``
    when no auth resolves (that case is already covered by
    ``bedrock_session_warnings``)."""
    from core.llm.dispatcher.auth import (
        _build_bearer_mantle_request,
        _build_bearer_runtime_request,
        _build_signed_mantle_request,
        _build_signed_runtime_request,
    )

    surface = mc.bedrock_api or "mantle"
    profile = mc.aws_profile or None
    region = mc.aws_region or None
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "model": mc.model_name,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "ping"}],
    }).encode("utf-8")

    bearer = creds.get("aws_bearer_token")
    if bearer and not profile and not creds.bedrock_bearer_expired():
        endpoint = creds.aws_bedrock_endpoint(surface, region=region)
        if endpoint is None:
            return None
        if surface == "runtime":
            return _build_bearer_runtime_request(bearer, endpoint, body)
        return _build_bearer_mantle_request(
            bearer, endpoint.rstrip("/"), "/anthropic/v1/messages", body,
        )
    signer = creds.aws_signer(surface, profile=profile, region=region)
    if signer is None:
        return None
    credentials, sig_region, endpoint = signer
    if surface == "runtime":
        return _build_signed_runtime_request(
            credentials, sig_region, endpoint, body,
        )
    return _build_signed_mantle_request(
        credentials, sig_region, endpoint.rstrip("/"),
        "/anthropic/v1/messages", body,
    )


def preflight_configured_bedrock(
    creds: "CredentialStore",
) -> list[str]:
    """Probe each configured Bedrock ``(model, surface, region,
    profile)`` combination once and return operator-actionable warning
    strings for entitlement/identity failures.  Empty when everything
    passes, nothing is configured, or only transient problems occur.
    """
    warnings: list[str] = []
    models = _configured_bedrock_models()
    if not models:
        return warnings

    cache = _read_cache()
    now = time.time()
    seen: set[str] = set()
    probes = 0
    for mc in models:
        surface = mc.bedrock_api or "mantle"
        profile = mc.aws_profile or ""
        region = mc.aws_region or ""
        auth_mode = (
            "bearer" if (creds.get("aws_bearer_token") and not profile)
            else "sigv4"
        )
        key = _cache_key(mc.model_name, surface, region, profile, auth_mode)
        if key in seen:
            continue
        seen.add(key)
        entry = cache.get(key)
        if (isinstance(entry, dict) and entry.get("ok")
                and now - float(entry.get("ts") or 0) < _CACHE_TTL_S):
            continue
        if probes >= _MAX_PROBES:
            logger.debug(
                "bedrock preflight: probe budget reached — skipping %s",
                mc.model_name,
            )
            break
        probes += 1
        outcome = _probe_one(creds, mc)
        if outcome is None:
            cache[key] = {"ok": True, "ts": now}
        elif outcome:
            warnings.append(outcome)
    _write_cache(cache)
    return warnings


def _probe_one(
    creds: "CredentialStore", mc: "ModelConfig",
) -> Optional[str]:
    """One live probe.  ``None`` = entitled (success); ``""`` =
    transient/skip (no warning); non-empty string = warning text."""
    try:
        prepared = _probe_request(creds, mc)
    except Exception as exc:  # noqa: BLE001 — advisory only
        logger.debug("bedrock preflight: build failed for %s: %s",
                     mc.model_name, exc)
        return ""
    if prepared is None:
        return ""
    req = urllib.request.Request(
        prepared.url, data=prepared.body,
        headers=dict(prepared.headers), method=prepared.method,
    )
    try:
        with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT_S):
            pass
        return None
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read(500).decode("utf-8", errors="replace")
        except OSError:
            pass
        if e.code in (401, 403):
            return (
                f"Bedrock preflight: {mc.model_name} "
                f"({mc.bedrock_api or 'mantle'}"
                f"{', ' + mc.aws_region if mc.aws_region else ''}) — "
                f"access denied ({e.code}). The signing identity is not "
                f"entitled to invoke this model in this region; check "
                f"the role's Bedrock policy and the model's region "
                f"availability. {detail}"
            )
        if e.code == 404 or "ResourceNotFound" in detail:
            return (
                f"Bedrock preflight: {mc.model_name} — not found on the "
                f"{mc.bedrock_api or 'mantle'} surface"
                f"{' in ' + mc.aws_region if mc.aws_region else ''} "
                f"(404). Check the model id shape for this surface. "
                f"{detail}"
            )
        # Other 4xx (e.g. parameter deprecations) mean the request
        # REACHED the model with valid auth — entitlement is fine.
        if 400 <= e.code < 500:
            logger.debug(
                "bedrock preflight: %s reachable (HTTP %s: %s)",
                mc.model_name, e.code, detail,
            )
            return None
        logger.debug("bedrock preflight: %s HTTP %s: %s",
                     mc.model_name, e.code, detail)
        return ""
    except Exception as exc:  # noqa: BLE001 — network problems are not warnings
        logger.debug("bedrock preflight: probe failed for %s: %s",
                     mc.model_name, exc)
        return ""
