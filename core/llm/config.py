"""
LLM Configuration — types, config file reading, model selection.

Types: ModelConfig, LLMConfig
Config file: ~/.config/raptor/models.json
Model selection: best thinking model, primary model, fallback models

Static model data (costs, limits, endpoints) lives in model_data.py.
Availability detection (SDK flags, Ollama, Claude Code) lives in detection.py.
"""

import contextlib
import os
import threading as _threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.logging import get_logger

from .detection import (
    OPENAI_SDK_AVAILABLE,
    _get_available_ollama_models,
    _read_config_models,
    _validate_ollama_url,
    bedrock_sigv4_intent,
    detect_llm_availability,
)

# Re-export from submodules for backward compatibility
from .model_data import (
    MODEL_COSTS,
    MODEL_LIMITS,
    PROVIDER_DEFAULT_MODELS,
    PROVIDER_ENDPOINTS,
    PROVIDER_ENV_KEYS,
    PROVIDER_FAST_MODELS,
)

logger = get_logger()


# ---------------------------------------------------------------------------
# Default token budgets when MODEL_LIMITS doesn't carry an entry for a
# specific model. Centralised so a model bump only needs one edit, not
# the four-to-six call-sites that previously each spelled out the
# integers inline:
#
#   - ``_build_anthropic_config``        : Anthropic frontier (1M context, 32k output)
#   - ``_build_openai_config``           : OpenAI frontier (1M context, 32k output)
#   - ``_build_ollama_config`` cold path : conservative local model defaults
#   - ``_get_configured_models`` ``max_tokens=64000`` user-supplied model entries
#
# Operators can override per-model via models.json; these are the
# floors used when MODEL_LIMITS / models.json don't carry a value.
_DEFAULT_MAX_CONTEXT_FRONTIER: int = 1_000_000   # current frontier (Sonnet/Opus 4.x, GPT-4.x)
_DEFAULT_MAX_CONTEXT_LOCAL: int = 32_000          # local-quant Ollama default
_DEFAULT_MAX_OUTPUT_FRONTIER: int = 32_000        # frontier output cap
_DEFAULT_MAX_OUTPUT_USER_CONFIGURED: int = 64_000  # models.json-supplied model output cap
_DEFAULT_MAX_OUTPUT_LOCAL: int = 4_096            # local quant safe default


# ---------------------------------------------------------------------------
# Config file reading
# ---------------------------------------------------------------------------

def _get_configured_models() -> list[dict]:
    """
    Get all models from RAPTOR config file.

    Returns list of model configurations with keys:
        provider, model, api_key (optional), role (optional),
        max_context (optional), max_output (optional)

    Config path resolution:
    1. RAPTOR_CONFIG environment variable
    2. ~/.config/raptor/models.json

    The JSON file supports // line comments (stripped before parsing).
    Uses _read_config_models() from detection.py for shared parsing logic.
    """
    return _read_config_models()


# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------

_cached_thinking_model: Optional['ModelConfig'] = None
_thinking_model_checked: bool = False
_thinking_model_lock = _threading.Lock()


def _get_best_thinking_model() -> Optional['ModelConfig']:
    """
    Automatically select the best thinking/reasoning model from config.
    Cached per-process.

    Priority:
    1. Most capable models (Opus > gpt-5.4-pro > o3)
    2. Strong models (gpt-5.2 > o4-mini > Mistral Large)
    3. Fallback (Sonnet > Gemini Pro > Gemini Flash)

    Returns ModelConfig for best available thinking model, or None if none found.
    """
    # Cache successful resolutions only. Pre-fix `_thinking_model_checked`
    # was set to True even when the result was None, so a process that
    # probed once before the operator created `~/.config/raptor/models.json`
    # would never see the new config in the same session — every
    # subsequent call short-circuited to the cached None. Recomputing
    # the lookup when the cached value is None is cheap (single JSON
    # file read; the consumer's surrounding code is already doing
    # network LLM calls), so the trade-off is clear: tiny re-probe cost
    # vs. silent-stale-config bug.
    global _cached_thinking_model, _thinking_model_checked
    if _thinking_model_checked and _cached_thinking_model is not None:
        return _cached_thinking_model

    with _thinking_model_lock:
        if _thinking_model_checked and _cached_thinking_model is not None:
            return _cached_thinking_model

        models = _get_configured_models()
        if not models:
            return None

        # Define priority order for thinking models (best first)
        thinking_model_patterns = [
            # Tier 1: Most capable models
            ("anthropic", "claude-opus-4-6", 110),
            ("openai", "gpt-5.4-pro", 100),
            ("openai", "gpt-5.4", 95),
            ("openai", "o3", 90),

            # Tier 2: Strong models
            ("openai", "gpt-5.2", 80),
            ("openai", "o4-mini", 78),
            ("mistral", "mistral-large-latest", 75),

            # Tier 3: Latest capable models (fallback)
            ("anthropic", "claude-sonnet-4-6", 70),
            ("gemini", "gemini-3.1-pro-preview", 68),
            ("gemini", "gemini-2.5-pro", 65),
            ("gemini", "gemini-3.7-flash", 60),
            ("gemini", "gemini-3.6-flash", 58),
            ("gemini", "gemini-2.5-flash", 55),
        ]

        # Find best matching model
        best_model = None
        best_score = -1

        for model_entry in models:
            if not isinstance(model_entry, dict):
                logger.debug("Skipping malformed model entry (not a dict): %s", type(model_entry))
                continue

            try:
                entry_provider = model_entry.get('provider', '')
                if entry_provider is None:
                    entry_provider = ''

                entry_model = model_entry.get('model', '')
                if entry_model is None:
                    entry_model = ''
                # Default to best known model for provider if not specified
                if not entry_model and entry_provider:
                    entry_model = PROVIDER_DEFAULT_MODELS.get(entry_provider, '')

                entry_role = model_entry.get('role', '')
                if entry_role is None:
                    entry_role = ''

                # Score this model
                for pattern_provider, pattern_model, base_score in thinking_model_patterns:
                    if entry_provider == pattern_provider and entry_model == pattern_model:
                        # Boost score if explicitly tagged as reasoning/thinking
                        effective_score = base_score
                        if entry_role in ('thinking', 'reasoning'):
                            effective_score += 10

                        if effective_score > best_score:
                            best_score = effective_score

                            # Resolve API key: entry-level, then env var
                            api_key = model_entry.get('api_key')
                            if not api_key:
                                env_key = PROVIDER_ENV_KEYS.get(entry_provider)
                                if env_key:
                                    api_key = os.getenv(env_key)

                            # Determine cost
                            cost_info = MODEL_COSTS.get(entry_model, {})
                            cost_per_1k = (cost_info.get('input', 0.005) + cost_info.get('output', 0.005)) / 2

                            # Determine max_tokens and max_context from config or limits
                            limits = MODEL_LIMITS.get(entry_model, {})
                            max_tokens = model_entry.get(
                                'max_output',
                                limits.get('max_output', _DEFAULT_MAX_OUTPUT_USER_CONFIGURED),
                            )
                            max_context = model_entry.get(
                                'max_context',
                                limits.get('max_context', _DEFAULT_MAX_CONTEXT_LOCAL),
                            )

                            # Set api_base for non-Anthropic providers. For
                            # ``ollama`` specifically, prefer the operator-
                            # configured ``RaptorConfig.OLLAMA_HOST`` over
                            # the ``localhost:11434`` default; otherwise an
                            # operator running a remote Ollama server gets a
                            # ``Connection refused`` against their loopback
                            # interface even though the rest of the codebase
                            # (``_build_ollama_config`` /
                            # ``_ollama_check_url``) correctly honours the
                            # configured host. Explicit ``api_base`` in
                            # ``model_entry`` wins over both — handled below
                            # via the ``Optional overrides from config``
                            # path.
                            if entry_provider == "ollama":
                                from core.config import RaptorConfig
                                ollama_base = _validate_ollama_url(
                                    RaptorConfig.OLLAMA_HOST,
                                )
                                api_base = f"{ollama_base.rstrip('/')}/v1"
                            else:
                                api_base = PROVIDER_ENDPOINTS.get(entry_provider)

                            # Optional overrides from config
                            timeout = model_entry.get('timeout', 120)

                            best_model = ModelConfig(
                                provider=entry_provider,
                                model_name=entry_model,
                                api_key=api_key,
                                api_base=api_base,
                                max_tokens=max_tokens,
                                max_context=max_context,
                                timeout=timeout,
                                temperature=0.7,
                                cost_per_1k_tokens=cost_per_1k,
                                role=entry_role or None,
                            )
                        break

            except Exception as e:  # noqa: BLE001 — malformed entries skipped
                logger.debug("Error processing model entry %s: %s", model_entry.get('model', 'unknown'), e)
                continue

        if best_model:
            logger.debug("Auto-selected thinking model: %s/%s (score: %s)", best_model.provider, best_model.model_name, best_score)

        _cached_thinking_model = best_model
        _thinking_model_checked = best_model is not None
        return best_model


# ---------------------------------------------------------------------------
# Per-provider config builders.
# ---------------------------------------------------------------------------
#
# Each builder returns a ``ModelConfig`` if the provider is usable in the
# current environment, otherwise ``None``. ``_get_default_primary_model``
# iterates these in order; ``prefer=...`` re-orders the iteration so a
# consumer can express its own preference (e.g., cve-diff prefers
# Anthropic for cache-control savings) without depending on the default
# autodetect order — which would silently regress consumer behaviour if
# the default were ever re-tuned for other reasons.


def _build_anthropic_config() -> Optional['ModelConfig']:
    if not os.getenv("ANTHROPIC_API_KEY"):
        return None
    default_model = PROVIDER_DEFAULT_MODELS["anthropic"]
    limits = MODEL_LIMITS.get(default_model, {})
    costs = MODEL_COSTS.get(default_model, {})
    return ModelConfig(
        provider="anthropic",
        model_name=default_model,
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        max_tokens=limits.get("max_output", _DEFAULT_MAX_OUTPUT_FRONTIER),
        max_context=limits.get("max_context", _DEFAULT_MAX_CONTEXT_FRONTIER),
        temperature=0.7,
        cost_per_1k_tokens=(costs.get("input", 0.015) + costs.get("output", 0.075)) / 2,
    )


def _build_openai_compat_config(provider_name: str) -> Optional['ModelConfig']:
    """Generic builder for OpenAI / Gemini / Mistral — same shape, different env var + endpoint."""
    env_var_map = {"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY", "mistral": "MISTRAL_API_KEY"}
    api_key = os.getenv(env_var_map[provider_name])
    if not api_key:
        return None
    # All three providers route through OpenAICompatibleProvider
    # downstream — without the openai SDK installed, that path
    # crashes at provider construction. Skip the builder up-front so
    # the resolver falls through to the next candidate (Ollama,
    # ClaudeCode) instead of detecting a usable API key, advertising
    # the model to the operator, then crashing the next LLM call.
    if not OPENAI_SDK_AVAILABLE:
        logger.debug(
            "Skipping %s config: %s key present but openai SDK not "
            "installed (pip install openai)",
            provider_name, env_var_map[provider_name],
        )
        return None
    default_model = PROVIDER_DEFAULT_MODELS[provider_name]
    limits = MODEL_LIMITS.get(default_model, {})
    costs = MODEL_COSTS.get(default_model, {})
    avg_cost = (costs.get("input", 0.005) + costs.get("output", 0.005)) / 2 if costs else 0.002
    return ModelConfig(
        provider=provider_name,
        model_name=default_model,
        api_key=api_key,
        api_base=PROVIDER_ENDPOINTS[provider_name],
        # OpenAI-family providers (OpenAI, Mistral, Cohere) — historical
        # default tuned for GPT-4.x-class models. Frontier defaults
        # would over-allocate for older models still routed through this
        # builder; the per-model ``MODEL_LIMITS`` entry takes precedence
        # when present so the fallback only kicks in for unfamiliar
        # models.
        max_tokens=limits.get("max_output", 8192),
        max_context=limits.get("max_context", 128_000),
        temperature=0.7,
        cost_per_1k_tokens=avg_cost,
    )


def _build_ollama_config() -> Optional['ModelConfig']:
    from core.config import RaptorConfig
    ollama_models = _get_available_ollama_models()
    if not ollama_models:
        return None
    preferred = ['mistral', 'qwen', 'codellama', 'llama', 'gemma', 'deepseek-coder', 'deepseek']
    selected_model = ollama_models[0]
    found = False
    for pref in preferred:
        for model in ollama_models:
            if pref in model.lower():
                selected_model = model
                found = True
                break
        if found:
            break
    ollama_base = _validate_ollama_url(RaptorConfig.OLLAMA_HOST)
    # Look up the actual limits when known. Pre-fix the log claimed
    # "using defaults (max_context=32000, max_output=4096)" but the
    # construction only passed `max_tokens=4096` and let max_context
    # fall through to ModelConfig's class default — known models
    # never benefited from MODEL_LIMITS and got the same defaults
    # as unknown ones. Now: known → use the registered limits;
    # unknown → keep the historical 32000/4096 defaults but log it.
    limits = MODEL_LIMITS.get(selected_model)
    if limits is None:
        logger.info(
            f"Model '{selected_model}' not in MODEL_LIMITS — using defaults "
            f"(max_context={_DEFAULT_MAX_CONTEXT_LOCAL}, "
            f"max_output={_DEFAULT_MAX_OUTPUT_LOCAL}). "
            f"Override in models.json if needed."
        )
        max_output = _DEFAULT_MAX_OUTPUT_LOCAL
        max_context = _DEFAULT_MAX_CONTEXT_LOCAL
    else:
        max_output = limits.get("max_output", _DEFAULT_MAX_OUTPUT_LOCAL)
        max_context = limits.get("max_context", _DEFAULT_MAX_CONTEXT_LOCAL)
    return ModelConfig(
        provider="ollama",
        model_name=selected_model,
        api_base=f"{ollama_base}/v1",
        max_tokens=max_output,
        max_context=max_context,
        temperature=0.7,
        cost_per_1k_tokens=0.0,
    )


# Sentinel model name for the claudecode fallback: "inherit whatever
# model the operator's `claude` CLI session is configured to use".
# ClaudeCodeLLMProvider omits `--model` when it sees this, so the
# subprocess resolves its model exactly like an interactive session
# (settings.json, ANTHROPIC_MODEL, Bedrock/Vertex model mapping).
# Hardcoding a name here breaks installs whose backend doesn't serve
# that ID — e.g. a Bedrock-backed CLI with no mapping for the bare
# Anthropic name hangs/fails on every call. Operators who want a
# specific model on the claudecode provider set it in models.json.
CLAUDECODE_SESSION_MODEL = "session-default"


def _resolve_claudecode_model() -> str:
    """Model name for the claudecode fallback config.

    Resolution order:

    1. ``RAPTOR_CC_MODEL`` — explicit operator pin, passed to
       ``claude -p --model`` verbatim.
    2. The cached pre-flight probe result (``cc_probe``): the
       backend-resolved identity of the CLI session's own default
       (e.g. a Bedrock id). Pinning it makes the transport
       deterministic — a mid-run settings.json edit can no longer
       silently switch models — gives the scorecard a real name, and
       lets ``rpm_for``/``derive_max_workers`` resolve actual
       capacity limits (the ``session-default`` sentinel resolves to
       0 RPM, which serialised every review loop to one worker).
       Safe on alternate backends because the id came from THIS
       backend's own result envelope, not a hardcoded Anthropic
       name. Cache-only — never runs a live probe here.
       ``RAPTOR_CC_PIN_MODEL=0`` opts out.
    3. The ``session-default`` sentinel (probe cache cold or pinning
       disabled): ``--model`` is omitted and the subprocess resolves
       its model like an interactive session.
    """
    import os
    explicit = os.environ.get("RAPTOR_CC_MODEL", "").strip()
    if explicit:
        return explicit
    if os.environ.get("RAPTOR_CC_PIN_MODEL", "1") != "0":
        # cached_cc_session_model handles cache-read errors itself;
        # only residual filesystem races (which() / stat paths) are a
        # legitimate reason to fall through to the sentinel.
        with contextlib.suppress(OSError):
            from core.llm.cc_probe import cached_cc_session_model
            cached = cached_cc_session_model()
            if cached:
                return cached
    return CLAUDECODE_SESSION_MODEL


def _build_claudecode_config() -> Optional['ModelConfig']:
    """Last-resort fallback: ``claude`` CLI on PATH, no API key needed.
    Slower (subprocess + ``--json-schema`` structured output for
    tool-use) but works for users who only have Claude Code installed.

    ``timeout=600`` is calibrated from real-CC runs: simple turns are
    5-15s, ``--json-schema`` against a rich tool catalog 60-180s, and
    audit-sized structured reviews (large system prompt + context
    slice) measured 170s+ on Bedrock-backed CLIs — the previous 300s
    ceiling killed the heaviest re-review calls after they had already
    billed. Cloud APIs default to 120s in ``ModelConfig`` (well-tuned
    for them); CC's subprocess + structured-output overhead needs more.
    """
    import shutil
    if not shutil.which("claude"):
        return None
    model_name = _resolve_claudecode_model()
    if model_name != CLAUDECODE_SESSION_MODEL:
        # Real identity known — use ITS limits (normalised through
        # the same alias/Bedrock-prefix stripping as rpm_for).
        # Unknown ids (an operator's RAPTOR_CC_MODEL alias) keep the
        # flagship-proxy defaults rather than raising.
        from core.llm.model_data import context_window_for, max_output_for
        try:
            max_tokens = max_output_for(model_name)
        except KeyError:
            max_tokens = 32000
        try:
            max_context = context_window_for(model_name)
        except KeyError:
            max_context = 1000000
    else:
        # Capacity limits are unknowable without asking the CLI which
        # model it will use; assume the current Anthropic flagship's
        # as a proxy.
        limits = MODEL_LIMITS.get(PROVIDER_DEFAULT_MODELS["anthropic"], {})
        max_tokens = limits.get("max_output", 32000)
        max_context = limits.get("max_context", 1000000)
    return ModelConfig(
        provider="claudecode",
        model_name=model_name,
        api_key=None,
        max_tokens=max_tokens,
        max_context=max_context,
        temperature=0.7,
        timeout=600,
        cost_per_1k_tokens=0.0,
    )


def _cc_bedrock_topology() -> tuple[str | None, str | None]:
    """``(surface, model)`` observed from a Claude Code install that is
    itself on Bedrock — the backfill source for minimal Bedrock config
    (an entry or env opt-in that omits the surface or model).  A CC
    session working against Bedrock is live proof of a valid
    (surface, model, region, entitlement) combination, so it is the
    best available default when the operator left a field blank.

    ``(None, None)`` when CC is not on Bedrock: in that case CC's
    model id is direct-API-shaped and must never leak into a Bedrock
    request.  Backfill never *selects* the provider — that stays an
    explicit statement (config entry / RAPTOR_BEDROCK_* / bearer).

    The model comes from the cc-probe cache when warm (the
    backend-resolved identity — authoritative over env, and its cache
    signature covers the CC env AND ~/.claude/settings.json mtime),
    else from the ``ANTHROPIC_MODEL`` env pin.  Cache-only: this never
    spawns a probe call.
    """
    if not os.getenv("CLAUDE_CODE_USE_BEDROCK"):
        return None, None
    surface = "mantle" if os.getenv("CLAUDE_CODE_USE_MANTLE") else "runtime"
    model: str | None = None
    try:
        from core.llm.cc_probe import cached_cc_session_model
        model = cached_cc_session_model()
    except Exception as e:  # noqa: BLE001 — backfill is best-effort
        logger.debug("cc-probe cache read failed: %s", e)
    model = model or os.getenv("ANTHROPIC_MODEL") or None
    return surface, model


def _build_bedrock_config() -> Optional['ModelConfig']:
    """Builder for AWS Bedrock — fires on an explicit opt-in signal:
    ``AWS_BEARER_TOKEN_BEDROCK`` (bearer auth), or one of the
    RAPTOR-specific env vars ``RAPTOR_BEDROCK_MODEL`` /
    ``RAPTOR_BEDROCK_PROFILE`` (SigV4 auth — the dispatcher signs with
    the resolved AWS credential chain; ``api_key`` stays ``None`` by
    design).  Ambient AWS credentials alone (AWS_PROFILE, credentials
    file) never fire this builder — selection is always an explicit
    statement.  Returns a bare Bedrock model id; Bedrock Mantle (the
    dispatcher's upstream) routes by hostname
    (``bedrock-mantle.<region>.api.aws``), not by model-id prefix — so
    model IDs are bare (``anthropic.claude-haiku-4-5``) regardless of
    region.

    Without this, ``has_bedrock=True`` in detection.py would report
    "LLM available" but ``_get_default_primary_model()`` would fall
    through to the next provider, leaving operators with a detection-
    selection mismatch (PR #696 review point 2).

    Credential-isolation contract: when running under the dispatcher
    (the supported deployment), ``CredentialStore.__init__`` has
    ALREADY read-and-popped ``AWS_BEARER_TOKEN_BEDROCK`` from env by
    the time any worker constructs ``LLMConfig()``.  This builder
    then sees ``os.getenv(...)`` return ``None`` and returns ``None``;
    ``has_dispatcher_route`` carries detection and the dispatcher
    injects auth at the request level from the parent-held bearer.
    The api_key field below is populated ONLY in the direct (non-
    dispatcher) startup path — when CredentialStore hasn't run.  In
    that path the bearer ends up in the parent's in-process LLMConfig
    but workers spawned from that parent inherit an env without the
    bearer (CredentialStore popped it when the dispatcher was later
    initialized) so credential isolation is preserved across the
    process boundary regardless.
    """
    bearer = os.getenv("AWS_BEARER_TOKEN_BEDROCK")
    sigv4_selected = bool(
        os.getenv("RAPTOR_BEDROCK_MODEL")
        or os.getenv("RAPTOR_BEDROCK_PROFILE")
    )
    if not bearer and not sigv4_selected:
        return None
    # Surface: explicit env wins; else inherit from a Bedrock-backed
    # Claude Code install (its surface is proven working); else
    # mantle.  Per-model overrides live in models.json (handled by
    # ``_model_config_from_entry``).  Unrecognised values fall back to
    # mantle with a quiet log — we don't hard-fail here because the
    # builder runs at import time and a noisy traceback would block
    # startup over a typo.
    cc_surface, cc_model = _cc_bedrock_topology()
    bedrock_api = (
        os.getenv("RAPTOR_BEDROCK_API") or cc_surface or "mantle"
    ).lower()
    if bedrock_api not in ("mantle", "runtime"):
        bedrock_api = "mantle"
    # Model: the operator's pinned id wins; else inherit CC's model,
    # but only same-surface (bare vs prefixed id shapes are
    # surface-specific — a cross-surface inherit would produce opaque
    # 4xxs); else the same bare default Anthropic chooses.
    # Config-file entries override all of these (they resolve via
    # ``_model_config_from_entry``, not here).
    from core.security.llm_family import bare_model_id
    pinned_model = os.getenv("RAPTOR_BEDROCK_MODEL")
    if pinned_model:
        model_name = pinned_model
        bare_default = bare_model_id(pinned_model)
    elif cc_model and cc_surface == bedrock_api:
        model_name = cc_model
        bare_default = bare_model_id(cc_model)
    else:
        bare_default = PROVIDER_DEFAULT_MODELS.get("anthropic", "")
        if not bare_default:
            return None
        model_name = f"anthropic.{bare_default}"
    # Surface-keyed id normalization, same contract as
    # ``_model_config_from_entry``: Mantle takes bare ids only;
    # runtime ids pass verbatim with a region-compatibility warning.
    from core.llm.bedrock_prefixes import (
        mantle_model_id,
        prefix_region_mismatch,
    )
    if bedrock_api == "mantle":
        model_name = mantle_model_id(model_name)
    else:
        check_region = (os.getenv("RAPTOR_BEDROCK_REGION")
                        or os.getenv("AWS_REGION")
                        or os.getenv("AWS_DEFAULT_REGION") or "")
        mismatch = prefix_region_mismatch(model_name, check_region)
        if mismatch:
            logger.warning("bedrock: %s", mismatch)
    limits = MODEL_LIMITS.get(bare_default, {})
    costs = MODEL_COSTS.get(bare_default, {})
    avg_cost_per_1k = (
        (costs.get("input", 0.005) + costs.get("output", 0.025)) / 2
    )
    return ModelConfig(
        provider="bedrock",
        model_name=model_name,
        # Bearer token IS the auth when present; carried in api_key so
        # downstream providers can pick it up via the dispatcher.  In
        # SigV4 mode this stays None — the dispatcher resolves the AWS
        # credential chain and signs per request.
        api_key=bearer,
        # Worker-leg request timeout. Must cover a full non-streaming
        # frontier generation and match the dispatcher's forwarding-leg
        # ceiling (``_UPSTREAM_DEFAULT_TIMEOUT_S = 600`` — its contract
        # note says the upstream leg must be AT LEAST the largest
        # worker-side timeout, which pins the worker side at <= 600).
        # At the 120s dataclass default every Bedrock generation longer
        # than 120s died inside the SDK's silent internal retries: the
        # worker abandons the request at 120s and re-sends, while the
        # dispatcher's upstream leg keeps each abandoned generation
        # running to completion — billed upstream, booked nowhere, and
        # surfacing only as dispatcher BrokenPipeError audit rows when
        # the write-back hits the closed worker socket (observed live:
        # 200-360s audit calls, 3x duplicated). Call classes that want
        # a tighter wall still get it per request via ``timeout_s``.
        timeout=600,
        max_tokens=limits.get("max_output", _DEFAULT_MAX_OUTPUT_FRONTIER),
        max_context=limits.get("max_context", _DEFAULT_MAX_CONTEXT_FRONTIER),
        temperature=0.7,
        cost_per_1k_tokens=avg_cost_per_1k,
        bedrock_api=bedrock_api,
        aws_profile=os.getenv("RAPTOR_BEDROCK_PROFILE") or None,
        aws_region=os.getenv("RAPTOR_BEDROCK_REGION") or None,
    )


def _build_claudecode_resumable_config() -> Optional['ModelConfig']:
    """CC with session persistence — ``--resume`` reuses the session
    across subprocess calls for near-zero input cost on turn 2+."""
    base = _build_claudecode_config()
    if base is None:
        return None
    from dataclasses import replace
    return replace(base, provider="claudecode-resumable")


_PROVIDER_BUILDERS = {
    "anthropic":  _build_anthropic_config,
    "openai":     lambda: _build_openai_compat_config("openai"),
    "gemini":     lambda: _build_openai_compat_config("gemini"),
    "mistral":    lambda: _build_openai_compat_config("mistral"),
    "bedrock":    _build_bedrock_config,
    "ollama":     _build_ollama_config,
    "claudecode": _build_claudecode_config,
    "claudecode-resumable": _build_claudecode_resumable_config,
}

# Default order. Anthropic first (cache-control + task-budget beta —
# the only provider where those matter natively).  Bedrock surfaces
# after the direct cloud providers — operators who opt-in to Bedrock
# explicitly via ``AWS_BEARER_TOKEN_BEDROCK`` will hit it before the
# autodetect falls through to Ollama / Claude Code.  Ollama before
# claudecode because Ollama is a deliberate operator setup; CC is the
# absolute last resort.
_DEFAULT_PROVIDER_ORDER = (
    "anthropic", "openai", "gemini", "mistral", "bedrock",
    "ollama", "claudecode",
)


# Operator's explicit primary model. Set by CLIs that expose --model
# so every downstream ``LLMConfig()`` no-arg construction honours the
# operator's directive. Without this, ``_get_default_primary_model()``
# would silently prefer a models.json-configured "thinking model"
# (typically Gemini) over the ANTHROPIC_API_KEY env-var route the
# operator's --model resolves through — breaking the "if I pass
# --model, use it" contract on every sub-consumer inside the run.
#
# Contract: process-wide. Once set, every subsequent LLMConfig() /
# ``get_client()`` / ``_get_default_primary_model()`` call returns
# this model as the primary. Set once at operator-facing CLI entry;
# never mutated mid-run.
_operator_primary_override: Optional['ModelConfig'] = None


def set_operator_primary_override(model: Optional['ModelConfig']) -> None:
    """Pin the process-wide primary to ``model``, or ``None`` to clear.

    Called by operator-facing CLIs after they resolve the operator's
    ``--model`` flag, so no downstream consumer accidentally falls
    through to a models.json-configured "thinking model" (which is
    the shape of the pre-fix regression that inflated per-iteration
    cost ~20× on tool-loop runs).
    """
    global _operator_primary_override
    _operator_primary_override = model


def _config_bedrock_primary() -> Optional['ModelConfig']:
    """First config-file Bedrock entry eligible to serve as the
    default model for API work.

    Bedrock is the one provider whose entries the thinking-model
    scorer can never match (its pattern table is keyed to direct
    cloud providers) and whose env builder ignores the config file —
    without this hook a role-less Bedrock entry could never become
    the auto-selected primary.  Scoped to Bedrock deliberately so no
    other provider's selection semantics change.

    Eligible = resolves to provider "bedrock", carries no role (the
    "default for API work" convention) or an analysis/code role, and
    can authenticate (bearer or SigV4 signal).  Entries with an
    auxiliary role (fallback / consensus / judge / aggregate) are
    auxiliaries by declaration and never become primary here.
    """
    from core.security.llm_family import provider_of as _provider_of
    for entry in _get_configured_models():
        if not isinstance(entry, dict):
            continue
        provider = entry.get("provider", "")
        if not provider and entry.get("model"):
            provider = _provider_of(entry.get("model", "")) or ""
        if provider != "bedrock":
            continue
        if (entry.get("role") or None) not in (None, "analysis", "code"):
            continue
        mc = _model_config_from_entry(entry)
        if _entry_auth_resolvable(mc):
            return mc
    return None


def _get_default_primary_model(
    prefer: list[str] | None = None,
) -> Optional['ModelConfig']:
    """
    Get default primary model based on available providers.

    Resolution order:
    0. **Operator override** (``set_operator_primary_override``).
       When an operator-facing CLI has resolved ``--model`` and
       pinned it, honour that directive across every downstream
       consumer, unconditionally. Beats every other step; ``prefer``
       is ignored (operator's explicit choice trumps consumer hint).
    1. **Preferred providers via env var** (when ``prefer`` set).
       Try each named provider in order; skip silently if absent.
    2. **Operator's thinking-model config** (``~/.config/raptor/models.json``).
       Honoured even when ``prefer`` is set — picks up
       provider+key combinations that don't fit the env-var
       convention (e.g. Gemini via Vertex auth). When ``prefer`` is
       set, only return it if its provider matches the preference.
       2b: a config-file Bedrock entry without an auxiliary role —
       the thinking-model scorer can't match Bedrock ids, so those
       entries get their own step (see ``_config_bedrock_primary``).
    3. **Default-order autodetect** via env var: Anthropic > OpenAI
       > Gemini > Mistral > Ollama > Claude Code (subprocess,
       absolute last resort).

    ``prefer`` is lenient: unknown / unavailable preferred providers
    are silently skipped. A consumer expresses preference via this
    arg to avoid depending on the default-order convention staying
    Anthropic-first — e.g. cve-diff prefers Anthropic for
    ``cache_control`` + task-budget savings, and that linkage should
    be explicit in code rather than coincidence with the default.
    """
    if _operator_primary_override is not None:
        return _operator_primary_override
    if isinstance(prefer, str):
        prefer = [prefer]
    prefer_set = set(prefer) if prefer else None

    # Step 1: preferred providers via env var (consumer's explicit
    # signal — try them before any other detection).
    if prefer:
        for name in prefer:
            builder = _PROVIDER_BUILDERS.get(name)
            if builder is None:
                logger.warning(
                    f"_get_default_primary_model: unknown preferred "
                    f"provider {name!r} — skipping"
                )
                continue
            config = builder()
            if config is not None:
                return config

    # Step 2: operator's thinking-model config (file-based; covers
    # non-env-var setups like Gemini via Vertex). The operator's
    # explicit choice beats env-var defaults — if they configured
    # Gemini in ``~/.config/raptor/models.json``, respect that even
    # when OPENAI_API_KEY happens to be set as an env var.
    #
    # When `prefer` is set, the cached thinking model is only honoured
    # if its provider matches the preference list — otherwise we'd
    # return e.g. an OpenAI thinking model to a consumer that
    # explicitly preferred Anthropic, defeating the prefer arg's
    # entire purpose. The docstring above promises this; pre-fix the
    # check was missing and the cached-thinking-model path silently
    # ignored `prefer`.
    thinking_model = _get_best_thinking_model()
    if (thinking_model
            and _entry_auth_resolvable(thinking_model)
            and (prefer_set is None or thinking_model.provider in prefer_set)):
        if not getattr(_get_default_primary_model, "_logged", False):
            logger.info(
                f"Using automatic thinking model: "
                f"{thinking_model.provider}/{thinking_model.model_name}"
            )
            _get_default_primary_model._logged = True
        return thinking_model

    # Step 2b: a config-file Bedrock entry with no auxiliary role is
    # the operator's declared default for API work — the thinking-model
    # scorer above can never match it (see ``_config_bedrock_primary``).
    bedrock_primary = _config_bedrock_primary()
    if (bedrock_primary is not None
            and (prefer_set is None or "bedrock" in prefer_set)):
        if not getattr(_get_default_primary_model, "_bedrock_logged", False):
            logger.info(
                f"Using configured Bedrock model: "
                f"{bedrock_primary.model_name} "
                f"({bedrock_primary.bedrock_api})"
            )
            _get_default_primary_model._bedrock_logged = True
        return bedrock_primary

    # Step 3: default-order autodetect via env vars. Skip providers
    # already tried in step 1.
    for name in _DEFAULT_PROVIDER_ORDER:
        if prefer_set is not None and name in prefer_set:
            continue
        builder = _PROVIDER_BUILDERS[name]
        config = builder()
        if config is not None:
            return config

    return None


def _model_config_from_entry(entry: dict) -> 'ModelConfig':
    """Build a ModelConfig from a config file entry.

    API key resolution: inline api_key → provider env var.
    Other config fields (timeout, max_context, max_output) are honoured.
    Bedrock entries additionally honour ``bedrock_api`` (surface),
    ``aws_profile`` (signing profile name) and ``region``; a minimal
    ``{"provider": "bedrock"}`` entry backfills surface and model from
    a Bedrock-backed Claude Code install (see
    :func:`_cc_bedrock_topology`).

    When the entry omits ``provider`` but specifies a model id whose
    shape implies a routing provider (Bedrock-prefixed Claude / Meta
    / Mistral / Cohere), the provider is derived via :func:`provider_of`
    so config-file entries like
    ``{"model": "us.anthropic.claude-opus-4-7"}`` route via Bedrock
    automatically without the operator having to spell out
    ``"provider": "bedrock"``.
    """
    from core.security.llm_family import provider_of as _provider_of
    provider = entry.get("provider", "")
    model_name = entry.get("model", "")
    if not provider and model_name:
        derived = _provider_of(model_name)
        if derived:
            provider = derived
    if not model_name and provider:
        model_name = PROVIDER_DEFAULT_MODELS.get(provider, "")
    if not model_name and provider in ("claudecode", "claudecode-resumable"):
        # CLI transport: same backend-resolved / sentinel model the env
        # builder would pick — a bare {"provider": "claudecode"} entry
        # is valid config.
        model_name = _resolve_claudecode_model()

    # Bedrock: resolve the surface first (the model backfill below is
    # surface-keyed), then backfill a missing model.  Surface ladder:
    # entry field → RAPTOR_BEDROCK_API env → a Bedrock-backed Claude
    # Code install's surface → mantle.  Unrecognised values snap to
    # mantle, same defensive shape as ``_build_bedrock_config``.
    if provider == "bedrock":
        cc_surface, cc_model = _cc_bedrock_topology()
        bedrock_api = (
            entry.get("bedrock_api")
            or os.getenv("RAPTOR_BEDROCK_API")
            or cc_surface
            or "mantle"
        ).lower()
        if bedrock_api not in ("mantle", "runtime"):
            bedrock_api = "mantle"
        if not model_name:
            # Minimal entry ({"provider": "bedrock"}): inherit the
            # model a working CC install resolved — but only
            # same-surface (bare vs prefixed id shapes are
            # surface-specific); else the bare Anthropic default.
            if cc_model and cc_surface == bedrock_api:
                model_name = cc_model
            else:
                if cc_model and cc_surface != bedrock_api:
                    logger.warning(
                        "bedrock config entry pins surface %r but the "
                        "Claude Code install uses %r — not inheriting "
                        "its model id (surface-specific shape); set "
                        "'model' explicitly in the entry",
                        bedrock_api, cc_surface,
                    )
                bare_default = PROVIDER_DEFAULT_MODELS.get("anthropic", "")
                if bare_default:
                    model_name = f"anthropic.{bare_default}"
    else:
        bedrock_api = "mantle"

    api_key = entry.get("api_key")
    if not api_key:
        env_key = PROVIDER_ENV_KEYS.get(provider)
        if env_key:
            api_key = os.getenv(env_key)
    # Bedrock-routed entries pick up the bearer (when present) the
    # same way other providers pick up their env-var key — gives
    # operators a single way to express "use this Bedrock model"
    # in config without also setting an explicit provider field.
    if not api_key and provider == "bedrock":
        api_key = os.getenv("AWS_BEARER_TOKEN_BEDROCK")

    from core.llm.model_data import _strip_dated_alias
    from core.security.llm_family import bare_model_id as _bare_model_id
    undated = _strip_dated_alias(model_name)
    # Peel Bedrock prefixes too (``anthropic.claude-x`` /
    # ``us.anthropic.claude-x``) so prefixed entries resolve real
    # catalog limits/costs instead of the 0.005 fallback rate.
    bare = _bare_model_id(model_name)
    limits = (MODEL_LIMITS.get(model_name, {})
              or MODEL_LIMITS.get(undated, {})
              or MODEL_LIMITS.get(bare, {}))
    costs = (MODEL_COSTS.get(model_name, {})
             or MODEL_COSTS.get(undated, {})
             or MODEL_COSTS.get(bare, {}))
    cost_per_1k = (costs.get("input", 0.005) + costs.get("output", 0.005)) / 2

    # Honour the operator-configured remote Ollama host (see
    # ``_get_configured_models`` for the same fix in the cold-start
    # path); ``PROVIDER_ENDPOINTS["ollama"]`` is a localhost default
    # that's wrong for any operator running Ollama on a separate
    # machine. Validator surface mirrors ``_build_ollama_config`` so
    # an OLLAMA_HOST without a scheme fails the same way here.
    if provider == "ollama":
        from core.config import RaptorConfig
        ollama_base = _validate_ollama_url(RaptorConfig.OLLAMA_HOST)
        api_base = f"{ollama_base.rstrip('/')}/v1"
    else:
        api_base = PROVIDER_ENDPOINTS.get(provider)
    # Bedrock-only: per-model signing profile and region (both
    # non-secret names — the signer resolves the actual credential).
    # Region ladder: entry field → RAPTOR_BEDROCK_REGION env; ``None``
    # leaves ambient resolution (env region, then the signing
    # profile's configured region) to the dispatcher.
    if provider == "bedrock":
        aws_profile = entry.get("aws_profile") or None
        aws_region = (
            entry.get("region")
            or os.getenv("RAPTOR_BEDROCK_REGION")
            or None
        )
        # Surface-keyed id normalization: Mantle takes ONLY bare
        # ``<provider>.<model>`` ids (lossless fixes applied
        # automatically); runtime ids pass verbatim (prefixed ids,
        # versioned ids and ARNs are all legal there) with a loud
        # warning when the geographic prefix contradicts the region.
        if model_name:
            from core.llm.bedrock_prefixes import (
                mantle_model_id,
                prefix_region_mismatch,
            )
            if bedrock_api == "mantle":
                normalized = mantle_model_id(model_name)
                if normalized != model_name:
                    logger.info(
                        "bedrock: normalized model id %r -> %r for the "
                        "mantle surface (bare ids only)",
                        model_name, normalized,
                    )
                    model_name = normalized
            else:
                check_region = aws_region or os.getenv("AWS_REGION") \
                    or os.getenv("AWS_DEFAULT_REGION") or ""
                mismatch = prefix_region_mismatch(model_name, check_region)
                if mismatch:
                    logger.warning("bedrock: %s", mismatch)
    else:
        aws_profile = None
        aws_region = None
    return ModelConfig(
        provider=provider,
        model_name=model_name,
        api_key=api_key,
        api_base=api_base,
        max_tokens=entry.get("max_output", limits.get("max_output", 8192)),
        max_context=entry.get("max_context", limits.get("max_context", _DEFAULT_MAX_CONTEXT_LOCAL)),
        timeout=entry.get("timeout", 120),
        temperature=0.7,
        cost_per_1k_tokens=cost_per_1k,
        role=entry.get("role") or None,
        bedrock_api=bedrock_api,
        aws_profile=aws_profile,
        aws_region=aws_region,
    )


def _build_fast_model_for(primary: 'ModelConfig') -> Optional['ModelConfig']:
    """Construct a same-provider fast/cheap-tier ModelConfig given the
    operator's primary. Returns ``None`` when the primary's provider
    has no fast-model mapping (Ollama, Claude Code) — in that case we
    leave ``specialized_models`` alone and the operator can configure
    explicitly.

    Reuses the primary's API key and api_base because the fast model
    sits on the same provider endpoint and authenticates with the
    same credential. Pulls cost / context limits from the model_data
    catalog so the same lookup tables drive both flagship and fast
    tiers — a future model addition only needs catalog entries, not
    plumbing changes here.
    """
    fast_name = PROVIDER_FAST_MODELS.get(primary.provider)
    if not fast_name:
        return None

    limits = MODEL_LIMITS.get(fast_name, {})
    costs = MODEL_COSTS.get(fast_name, {})
    cost_per_1k = (costs.get("input", 0.0) + costs.get("output", 0.0)) / 2

    # Same Ollama-host fix as the cold-start + user-config paths —
    # inherit ``primary.api_base`` for Ollama since the primary was
    # built with the operator-configured ``OLLAMA_HOST`` already, and
    # the localhost default in ``PROVIDER_ENDPOINTS`` would override
    # it. For other providers ``PROVIDER_ENDPOINTS`` is correct
    # (api.openai.com etc.).
    if primary.provider == "ollama":
        api_base = primary.api_base
    else:
        api_base = PROVIDER_ENDPOINTS.get(primary.provider) or primary.api_base
    return ModelConfig(
        provider=primary.provider,
        model_name=fast_name,
        api_key=primary.api_key,
        api_base=api_base,
        # Fast-tier work (verdicts, classification) is short-output by
        # design — no need to inherit the primary's max_tokens, which
        # may be sized for code-generation. Use the catalog default,
        # which is already provider-appropriate for the small model.
        max_tokens=limits.get("max_output", _DEFAULT_MAX_OUTPUT_LOCAL),
        max_context=limits.get("max_context", _DEFAULT_MAX_CONTEXT_LOCAL),
        timeout=primary.timeout,
        # Lower temperature than the primary's default — the workloads
        # routed here (yes/no, classify) don't benefit from sampling
        # variance and are more deterministic at lower temperature.
        temperature=0.0,
        cost_per_1k_tokens=cost_per_1k,
    )


def _entry_auth_resolvable(mc: 'ModelConfig') -> bool:
    """True when a config-file entry can authenticate at call time.

    Most providers need ``api_key`` (inline or env-resolved).  Bedrock
    is the exception: in SigV4 mode ``api_key`` is ``None`` by design —
    the dispatcher resolves the AWS credential chain (profile / SSO /
    IMDS / static keys) and signs per request — so the entry counts
    when the environment carries either the bearer token or any SigV4
    credential signal.
    """
    if mc.api_key:
        return True
    if mc.provider == "bedrock":
        return bool(
            os.getenv("AWS_BEARER_TOKEN_BEDROCK")
        ) or bedrock_sigv4_intent()
    if mc.provider in ("claudecode", "claudecode-resumable"):
        # CLI transport authenticates through the installed ``claude``
        # binary's own session — no key to carry.  Lets an operator
        # declare CC as an explicit safety net behind an API primary
        # ({"provider": "claudecode", "role": "fallback"}).
        import shutil
        return shutil.which("claude") is not None
    return False


def _get_default_fallback_models() -> list['ModelConfig']:
    """
    Get default fallback models based on primary model tier.

    Reads config file first — entries with role="fallback" (or entries
    that aren't the primary model) become fallbacks. API keys resolve
    from config inline, then env var.

    For providers not covered by the config file, falls back to env var
    detection (original behaviour).

    Returns ALL available models; client.py filters to same tier as primary.
    """
    from core.config import RaptorConfig

    availability = detect_llm_availability()
    if not availability.external_llm:
        return []

    fallbacks = []
    config_providers = set()  # Track which providers the config covers

    # --- Config file entries first ---
    primary = _get_default_primary_model()
    primary_key = (primary.provider, primary.model_name) if primary else None

    for entry in _get_configured_models():
        if not isinstance(entry, dict):
            continue
        provider = entry.get("provider", "")
        model_name = entry.get("model", "")
        if not model_name and provider:
            model_name = PROVIDER_DEFAULT_MODELS.get(provider, "")

        # Skip the primary model
        if primary_key and (provider, model_name) == primary_key:
            continue

        mc = _model_config_from_entry(entry)
        if _entry_auth_resolvable(mc):
            fallbacks.append(mc)
            config_providers.add(provider)

    # --- Env var fallback for providers not in config ---
    def _is_primary(provider, model):
        return primary_key and (provider, model) == primary_key

    if "anthropic" not in config_providers and os.getenv("ANTHROPIC_API_KEY"):
        for model_name in ["claude-opus-4-6", "claude-sonnet-4-6"]:
            if _is_primary("anthropic", model_name):
                continue
            limits = MODEL_LIMITS.get(model_name, {})
            costs = MODEL_COSTS.get(model_name, {})
            fallbacks.append(ModelConfig(
                provider="anthropic",
                model_name=model_name,
                api_key=os.getenv("ANTHROPIC_API_KEY"),
                max_tokens=limits.get("max_output", 32000),
                max_context=limits.get("max_context", 1000000),
                temperature=0.7,
                cost_per_1k_tokens=(costs.get("input", 0.003) + costs.get("output", 0.015)) / 2,
            ))

    if "openai" not in config_providers and os.getenv("OPENAI_API_KEY"):
        for model_name in ["gpt-5.4", "gpt-5.2"]:
            if _is_primary("openai", model_name):
                continue
            limits = MODEL_LIMITS.get(model_name, {})
            costs = MODEL_COSTS.get(model_name, {})
            fallbacks.append(ModelConfig(
                provider="openai",
                model_name=model_name,
                api_key=os.getenv("OPENAI_API_KEY"),
                api_base=PROVIDER_ENDPOINTS["openai"],
                max_tokens=limits.get("max_output", 16384),
                max_context=limits.get("max_context", 128000),
                temperature=0.7,
                cost_per_1k_tokens=(costs.get("input", 0.006) + costs.get("output", 0.030)) / 2,
            ))

    if "gemini" not in config_providers and os.getenv("GEMINI_API_KEY"):
        for model_name in ["gemini-2.5-pro", "gemini-2.5-flash"]:
            if _is_primary("gemini", model_name):
                continue
            limits = MODEL_LIMITS.get(model_name, {})
            costs = MODEL_COSTS.get(model_name, {})
            fallbacks.append(ModelConfig(
                provider="gemini",
                model_name=model_name,
                api_key=os.getenv("GEMINI_API_KEY"),
                api_base=PROVIDER_ENDPOINTS["gemini"],
                max_tokens=limits.get("max_output", 8192),
                max_context=limits.get("max_context", 1000000),
                temperature=0.7,
                cost_per_1k_tokens=(costs.get("input", 0.002) + costs.get("output", 0.010)) / 2,
            ))

    if (
        "mistral" not in config_providers
        and os.getenv("MISTRAL_API_KEY")
        and not _is_primary("mistral", "mistral-large-latest")
    ):
        fallbacks.append(ModelConfig(
                provider="mistral",
                model_name="mistral-large-latest",
                api_key=os.getenv("MISTRAL_API_KEY"),
                api_base=PROVIDER_ENDPOINTS["mistral"],
                max_tokens=8192,
                max_context=128000,
                temperature=0.7,
                cost_per_1k_tokens=0.002,
            ))

    # Add local models
    ollama_models = _get_available_ollama_models()
    if ollama_models:
        ollama_base = _validate_ollama_url(RaptorConfig.OLLAMA_HOST)
        for model in ollama_models[:3]:
            fallbacks.append(ModelConfig(
                provider="ollama",
                model_name=model,
                api_base=f"{ollama_base}/v1",
                max_tokens=4096,
                temperature=0.7,
                cost_per_1k_tokens=0.0,
            ))

    return fallbacks


# ---------------------------------------------------------------------------
# Model role resolution
# ---------------------------------------------------------------------------

VALID_ROLES = {"analysis", "code", "consensus", "fallback", "judge", "aggregate"}


def get_configured_models() -> list[dict]:
    """Return all model entries from the operator's config file."""
    return _get_configured_models()


def model_config_from_entry(entry: dict) -> 'ModelConfig':
    """Build a ModelConfig from a config-file entry dict."""
    return _model_config_from_entry(entry)


def resolve_model_roles(
    primary_model: Optional['ModelConfig'] = None,
    fallback_models: list['ModelConfig'] | None = None,
) -> dict[str, Any]:
    """Resolve model roles from configured models.

    If no roles are specified, applies defaults:
    - First model → analysis + code
    - Additional models → fallback

    Returns:
        {analysis_model: ModelConfig, code_model: ModelConfig,
         consensus_models: [ModelConfig], judge_models: [ModelConfig],
         aggregate_models: [ModelConfig], fallback_models: [ModelConfig]}

    Raises:
        ConfigError on invalid role configurations.
    """
    # All three branches below return the same 6-key shape so callers
    # can iterate the dict without per-branch missing-key handling.
    # Pre-fix the empty-config branch missed `analysis_models` and
    # `judge_models`, and the no-roles default branch missed
    # `analysis_models` — consumers calling
    # `roles["analysis_models"]` crashed with KeyError if the empty
    # or no-roles branch produced the dict.
    if primary_model is None and not fallback_models:
        return {
            "analysis_model": None,
            "analysis_models": [],
            "code_model": None,
            "consensus_models": [],
            "judge_models": [],
            "aggregate_models": [],
            "fallback_models": [],
        }

    all_models = []
    if primary_model:
        all_models.append(primary_model)
    if fallback_models:
        all_models.extend(fallback_models)

    # Check if any model has a role set
    has_roles = any(m.role for m in all_models)

    if not has_roles:
        # Default: first model = analysis + code, rest = fallback
        first = all_models[0] if all_models else None
        return {
            "analysis_model": first,
            "analysis_models": [first] if first is not None else [],
            "code_model": first,
            "consensus_models": [],
            "judge_models": [],
            "aggregate_models": [],
            "fallback_models": all_models[1:] if len(all_models) > 1 else [],
        }

    # Validate roles
    _validate_model_roles(all_models)

    # Resolve by role
    analysis = [m for m in all_models if m.role == "analysis"]
    code = [m for m in all_models if m.role == "code"]
    consensus = [m for m in all_models if m.role == "consensus"]
    judge = [m for m in all_models if m.role == "judge"]
    aggregate = [m for m in all_models if m.role == "aggregate"]
    fallbacks = [m for m in all_models if m.role == "fallback" or m.role is None]

    analysis_model = analysis[0] if analysis else (all_models[0] if all_models else None)
    code_model = code[0] if code else analysis_model

    return {
        "analysis_model": analysis_model,
        "analysis_models": analysis if analysis else ([all_models[0]] if all_models else []),
        "code_model": code_model,
        "consensus_models": consensus,
        "judge_models": judge,
        "aggregate_models": aggregate,
        "fallback_models": fallbacks,
    }


def _validate_model_roles(models: list['ModelConfig']) -> None:
    """Validate model role configuration. Raises ConfigError on invalid combos."""
    roles = [m.role for m in models if m.role]

    # Check for invalid role names
    for m in models:
        if m.role and m.role not in VALID_ROLES:
            raise ConfigError(
                f"Invalid role '{m.role}' for model {m.model_name}. "
                f"Valid roles: {', '.join(sorted(VALID_ROLES))}"
            )

    analysis_count = roles.count("analysis")
    code_count = roles.count("code")
    has_analysis = analysis_count > 0
    has_consensus = "consensus" in roles
    has_code = code_count > 0
    only_fallback = all(r == "fallback" for r in roles) if roles else False

    has_judge = "judge" in roles
    has_aggregate = "aggregate" in roles

    if has_consensus and not has_analysis:
        raise ConfigError("Consensus models configured without an analysis model")

    if has_judge and not has_analysis:
        raise ConfigError("Judge models configured without an analysis model")

    if has_aggregate and not has_analysis:
        raise ConfigError("Aggregate model configured without an analysis model")

    if has_code and not has_analysis:
        raise ConfigError("Code model configured without an analysis model")

    if roles.count("aggregate") > 1:
        raise ConfigError(
            "Multiple models with role 'aggregate'. Only one aggregate model is supported"
        )

    # Multiple analysis models is valid (multi-model mode)

    if code_count > 1:
        raise ConfigError(
            "Multiple models with role 'code'. Only one code model is supported"
        )

    if only_fallback:
        raise ConfigError(
            "All models are configured as fallback with no analysis model. "
            "Set role to 'analysis' on at least one model."
        )

    # Check for same model with two *incompatible* roles.
    # analysis+consensus is the conflict (use consensus role instead).
    # Same model for consensus+judge is fine — distinct tasks.
    _CONFLICTING_PAIRS = {frozenset({"analysis", "consensus"})}
    seen: dict[tuple[str, str], set[str]] = {}
    for m in models:
        if m.role:
            key = (m.provider, m.model_name)
            seen.setdefault(key, set()).add(m.role)
    for key, model_roles in seen.items():
        for pair in _CONFLICTING_PAIRS:
            if pair <= model_roles:
                raise ConfigError(
                    f"Model {key[1]} ({key[0]}) has conflicting roles: "
                    f"{sorted(pair)}"
                )


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Configuration validation error."""


@dataclass
class ModelConfig:
    """Configuration for a specific model."""
    provider: str  # "anthropic", "openai", "mistral", "ollama", "gemini"
    model_name: str  # "claude-opus-4-6", "gpt-5.2", "llama3:70b", etc.
    api_key: str | None = None
    api_base: str | None = None  # For non-Anthropic providers
    max_tokens: int = 4096
    max_context: int = 32000
    temperature: float = 0.7
    timeout: int = 120
    cost_per_1k_tokens: float = 0.0  # Fallback rate — used only when model not in MODEL_COSTS
    enabled: bool = True
    role: str | None = None  # "analysis", "code", "consensus", "fallback", "judge", "aggregate"
    # Bedrock-only: which Bedrock surface to route this model through.
    # ``"mantle"`` (default) → ``bedrock-mantle.<region>.api.aws/anthropic/
    # v1/messages`` (native Anthropic Messages API, bare model IDs, full
    # feature support).  ``"runtime"`` → legacy InvokeModel at
    # ``bedrock-runtime.<region>.amazonaws.com/model/<id>/invoke``
    # (required for models not on Mantle or for cross-region inference
    # profile IDs).  Ignored for non-Bedrock providers.  Set globally via
    # ``RAPTOR_BEDROCK_API`` or per-model via the ``bedrock_api`` field
    # in ``models.json``.
    bedrock_api: str = "mantle"
    # Bedrock-only: pin the AWS profile that signs this model's
    # requests (a profile NAME — non-secret; the credential itself is
    # resolved by the dispatcher's signer at request time).  ``None``
    # → ambient resolution (RAPTOR_BEDROCK_PROFILE / AWS_PROFILE /
    # credential chain).  Set per-model via ``aws_profile`` in
    # ``models.json``.
    aws_profile: str | None = None
    # Bedrock-only: region used for BOTH the endpoint hostname and the
    # SigV4 signing scope — one value, they must agree.  ``None`` →
    # ambient resolution (AWS_REGION / AWS_DEFAULT_REGION, then the
    # signing profile's configured region).  Set per-model via
    # ``region`` in ``models.json`` or globally via
    # ``RAPTOR_BEDROCK_REGION``.
    aws_region: str | None = None


def _shared_prefix_len(a: str, b: str) -> int:
    """Length of the common case-insensitive prefix of two model names —
    the specificity score for credential reuse (longer = closer relative)."""
    a, b = a.lower(), b.lower()
    n = 0
    for ca, cb in zip(a, b, strict=False):
        if ca != cb:
            break
        n += 1
    return n


def _default_cache_ttl() -> float | None:
    """Default LLM-cache TTL: 24h, env-overridable.

    ``RAPTOR_LLM_CACHE_TTL_S`` accepts a number of seconds, or
    ``none`` / ``off`` / ``0`` (or any non-positive value) to disable
    expiry entirely. A garbled value falls back to the 24h default —
    unlike audit-data deletion, cache expiry only costs a re-query, so
    defaulting on a bad value is safe.
    """
    raw = os.environ.get("RAPTOR_LLM_CACHE_TTL_S", "").strip().lower()
    if not raw:
        return 86_400.0
    if raw in ("none", "off"):
        return None
    try:
        val = float(raw)
    except ValueError:
        return 86_400.0
    return val if val > 0 else None


@dataclass
class LLMConfig:
    """Main LLM configuration for RAPTOR."""

    # Primary model (fastest/most capable). None when no provider is available.
    primary_model: ModelConfig | None = field(default_factory=_get_default_primary_model)

    # Fallback models (in priority order)
    fallback_models: list[ModelConfig] = field(default_factory=_get_default_fallback_models)

    # Analysis-specific models (for different task types)
    specialized_models: dict[str, ModelConfig] = field(default_factory=dict)

    # Global settings
    enable_fallback: bool = True
    max_retries: int = 3
    retry_delay: float = 2.0
    retry_delay_remote: float = 5.0
    enable_caching: bool = True
    cache_dir: Path = Path("out/llm_cache")
    # Drop cache entries older than this on read. Default 24h: repeat
    # queries within a working day stay free and deterministic, while a
    # verdict from last month's model behaviour doesn't silently steer
    # today's analysis (the cache key pins the model NAME, so this
    # guards same-name drift — alias re-points, provider-side updates —
    # not model switches, which miss naturally). Entries without a
    # timestamp predate the TTL field and are honoured rather than
    # mass-evicted on upgrade. Override via RAPTOR_LLM_CACHE_TTL_S:
    # seconds, or "none"/"off"/0 to never expire.
    cache_ttl_seconds: float | None = field(default_factory=_default_cache_ttl)
    # Cap cache size by number of entries. After each successful save
    # the oldest files (by mtime) are evicted until at or under this
    # cap. None = no eviction (cache grows unboundedly — the pre-cap
    # default; out/llm_cache accumulated for the life of the install).
    # The directory-walk per save is O(N); the 10k default sits at the
    # documented comfort limit of that walk, beyond which a real cache
    # backend would be more appropriate.
    cache_max_entries: int | None = 10_000
    enable_cost_tracking: bool = True
    max_cost_per_scan: float = 10.0  # USD
    # Model scorecard (core/llm/scorecard) — track per-model
    # reliability across decision classes and use measured miss-rate
    # to gate fast-tier short-circuit decisions. None or False
    # means consumers run their full path without scorecard
    # consultation. RAPTOR_SCORECARD_PATH overrides the default so
    # tests and sandboxed runs can isolate the on-disk reliability
    # data (read at construction time, per config instance).
    scorecard_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get("RAPTOR_SCORECARD_PATH")
            or "out/llm_scorecard.json"
        )
    )
    scorecard_enabled: bool = True
    # When False, do not retain disagreement-sample reasoning text.
    # Defense-in-depth privacy switch for operators on shared
    # infrastructure where the LLM's reasoning summary may quote
    # source code under analysis.
    scorecard_retain_samples: bool = True
    # Probability (0-1) that a call to a trusted (short-circuiting)
    # cell still runs full ANALYSE so fresh ground-truth comparison
    # data keeps flowing in — drift detection via random sampling.
    # Default 5%: catches drift within ~20-60 trusted calls while
    # preserving most of the savings (~95% short-circuit retained).
    # Set 0.0 to disable (trusted = forever-trusted until manual
    # reset); set higher to validate more aggressively.
    scorecard_shadow_rate: float = 0.05

    # Freshness half-life (days) for age-weighting scorecard reliability counts at
    # verdict time. Recent observations dominate stale ones, so a model that
    # regressed behind a floating alias (notably Gemini, which exposes no
    # version signal) surfaces instead of being averaged against its own past.
    # ``None`` (default) DISABLES weighting — counts are summed unweighted,
    # identical to the pre-freshness behaviour. Enabling lowers the effective
    # sample size, so confirm the cold-start impact with the offline measurement
    # before turning it on by default. See the design memo.
    scorecard_freshness_half_life_days: float | None = None

    def __post_init__(self) -> None:
        """Seed ``specialized_models`` with same-provider fast-tier
        defaults for routing-light task types (binary verdicts,
        classification). Operator-set entries are preserved — we only
        fill slots the operator hasn't claimed.

        Skips silently when:
          * no primary model is available (no provider to map from);
          * the primary's provider has no entry in
            ``PROVIDER_FAST_MODELS`` (Ollama, Claude Code) — those
            providers don't have a meaningful "smaller, cheaper"
            sibling within the family that we can pick automatically.
        """
        from .task_types import FAST_TIER_TASKS

        if self.primary_model is None:
            return
        fast_config = _build_fast_model_for(self.primary_model)
        if fast_config is None:
            return
        for task in FAST_TIER_TASKS:
            self.specialized_models.setdefault(task, fast_config)

    def _configured_models(self) -> list[ModelConfig]:
        """Every model the operator has configured: primary + fallbacks +
        specialized."""
        models: list[ModelConfig] = []
        if self.primary_model is not None:
            models.append(self.primary_model)
        models.extend(self.fallback_models or [])
        models.extend((self.specialized_models or {}).values())
        return models

    def config_for_model(self, model_id: str) -> ModelConfig:
        """Build a ModelConfig for an arbitrary ``model_id``, reusing the
        most specific credential already configured.

        Resolution, most specific first:
          1. an exact configured entry for ``model_id`` — returned as-is, so
             its per-model settings (temperature, base, role) are preserved;
          2. shorthand expansion — a bare token like ``"haiku"`` / ``"opus"``
             is looked up as a hyphen-separated segment of some configured
             model's bare name. When exactly one configured model matches,
             its full entry is returned as if that name had been passed.
             Ambiguous (>1 match) raises with the candidate list; missing
             (0 matches) falls through to (3);
          3. otherwise, among configured models of the same provider that
             carry a credential, the one whose name shares the longest prefix
             with ``model_id`` — a configured ``claude-opus-4-6`` lends its
             key to ``claude-opus-4-8`` ahead of a ``claude-haiku-*`` entry;
             its api_key / api_base are borrowed onto a config for ``model_id``;
          4. otherwise a bare config (api_key=None) so the SDK / dispatcher /
             provider env var supplies the credential at call time.
        """
        from core.llm.model_data import _strip_dated_alias
        from core.security.llm_family import (
            bare_model_id,
            provider_of,
            resolve_model_shorthand,
            unknown_model_message,
        )

        candidates = self._configured_models()
        bare = bare_model_id(model_id)
        for mc in candidates:
            if mc.model_name == model_id or mc.model_name == bare:
                return mc
            if _strip_dated_alias(mc.model_name) == bare:
                return mc

        # Shorthand expansion: when the operator passes a bare tier token
        # like ``"haiku"`` / ``"opus"`` / ``"sonnet"``, match it against the
        # hyphen-separated segments of each configured model's bare name.
        # Only when exactly one configured model matches — ambiguous or
        # missing input falls through to provider_of and the loud-failure
        # path below. Zero-match shorthand is left for provider_of to
        # surface the standard error; multi-match raises inside
        # resolve_model_shorthand with the candidate list so the operator
        # can pick.
        resolved = resolve_model_shorthand(
            model_id, [mc.model_name for mc in candidates],
        )
        if resolved is not None:
            for mc in candidates:
                if mc.model_name == resolved:
                    logger.info(
                        f"Resolved shorthand '{model_id}' -> "
                        f"'{mc.model_name}' from configured models"
                    )
                    return mc

        if model_id in _PROVIDER_BUILDERS:
            mc = _PROVIDER_BUILDERS[model_id]()
            if mc is not None:
                return mc

        provider = provider_of(model_id)
        if not provider:
            # Fail loudly rather than synthesizing a keyless, provider-less
            # config that fails opaquely downstream — an explicit override
            # with an unrecognizable name is almost always a typo / nickname.
            raise ValueError(unknown_model_message(model_id))
        same_provider = [
            mc for mc in candidates if mc.provider == provider and mc.api_key
        ]
        if same_provider:
            target = bare_model_id(model_id)
            best = max(
                same_provider,
                key=lambda mc: _shared_prefix_len(
                    target, bare_model_id(mc.model_name)
                ),
            )
            limits = MODEL_LIMITS.get(bare) or MODEL_LIMITS.get(
                _strip_dated_alias(bare), {},
            )
            return ModelConfig(
                provider=provider,
                model_name=bare_model_id(model_id),
                api_key=best.api_key,
                api_base=best.api_base,
                max_tokens=limits.get("max_output", best.max_tokens),
                max_context=limits.get("max_context", best.max_context),
            )
        return ModelConfig(provider=provider, model_name=bare_model_id(model_id))

    def to_file(self, config_path: Path) -> None:
        """Save a MINIMAL snapshot of this configuration to JSON.

        **What this writes:** the primary model's provider+model_name
        and the `enable_fallback` flag. NOTHING ELSE.

        **What this does NOT write:**
          * api_key / api_base — credentials should not be persisted to
            on-disk config; round-trip via env vars / CLI flags.
          * max_tokens / max_context / temperature / etc. — these are
            looked up from the model registry by name at load time
            so the persisted file stays small and stable across model
            registry updates.
          * fallback_models / specialized_models — multi-model setups
            should be authored in `~/.config/raptor/models.json`
            (the canonical operator config), not in a CLI-emitted
            snapshot.
          * Budget / retry / cache settings — defaults from
            `LLMConfig` are intentionally re-applied each run so
            operator changes take effect.

        This file is intended for the CLI's "save current run config"
        feature only. Callers that need full round-trip serialisation
        should construct config explicitly from the operator's
        `~/.config/raptor/models.json` rather than via this method.

        Mode 0o600 so the file isn't world-readable even though it
        deliberately omits credentials — defence in depth against
        future field additions.
        """
        from core.json import save_json
        primary = None
        if self.primary_model:
            primary = {
                "provider": self.primary_model.provider,
                "model_name": self.primary_model.model_name,
            }
        save_json(config_path, {
            "primary_model": primary,
            "fallback_enabled": self.enable_fallback,
        }, mode=0o600)

    def get_model_for_task(self, task_type: str) -> ModelConfig | None:
        """Get the model registered for `task_type`, falling back to
        ``primary_model``. Returns None if neither is configured.

        The signature was previously typed `-> ModelConfig` despite
        the `return self.primary_model` falling through to a field
        that is `Optional[ModelConfig]` — a typing lie that caused
        downstream callers to skip None-guards and crash with
        AttributeError on `None.max_context` / `None.provider` /
        etc. Caller `LLMClient.generate` now also guards (batch 080),
        but the signature should match reality so type-checkers
        catch new callers that miss the guard.
        """
        if task_type in self.specialized_models:
            model = self.specialized_models[task_type]
            if model.enabled:
                return model
        return self.primary_model

