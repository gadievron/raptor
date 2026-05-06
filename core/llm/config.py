#!/usr/bin/env python3
"""
LLM Configuration — types, config file reading, model selection.

Types: ModelConfig, LLMConfig
Config file: ~/.config/raptor/models.json
Model selection: best thinking model, primary model, fallback models

Static model data (costs, limits, endpoints) lives in model_data.py.
Availability detection (SDK flags, Ollama, Claude Code) lives in detection.py.
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import json

from core.logging import get_logger

# Re-export from submodules for backward compatibility
from .model_data import (
    PROVIDER_ENDPOINTS, PROVIDER_DEFAULT_MODELS,
    MODEL_COSTS, MODEL_LIMITS, PROVIDER_ENV_KEYS,
)
from .detection import (
    OPENAI_SDK_AVAILABLE, ANTHROPIC_SDK_AVAILABLE,
    LLMAvailability, detect_llm_availability,
    _get_available_ollama_models, _validate_ollama_url,
    _read_config_models,
)

logger = get_logger()


# ---------------------------------------------------------------------------
# Config file reading
# ---------------------------------------------------------------------------

def _get_configured_models() -> List[Dict]:
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
    global _cached_thinking_model, _thinking_model_checked
    if _thinking_model_checked:
        return _cached_thinking_model

    _thinking_model_checked = True

    models = _get_configured_models()
    if not models:
        _cached_thinking_model = None
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
        ("gemini", "gemini-2.5-pro", 65),
        ("gemini", "gemini-2.5-flash", 55),
    ]

    # Find best matching model
    best_model = None
    best_score = -1

    for model_entry in models:
        if not isinstance(model_entry, dict):
            logger.debug(f"Skipping malformed model entry (not a dict): {type(model_entry)}")
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
                        max_tokens = model_entry.get('max_output', limits.get('max_output', 64000))
                        max_context = model_entry.get('max_context', limits.get('max_context', 32000))

                        # Set api_base for non-Anthropic providers
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

        except Exception as e:
            logger.debug(f"Error processing model entry {model_entry.get('model', 'unknown')}: {e}")
            continue

    if best_model:
        logger.info(f"Auto-selected thinking model: {best_model.provider}/{best_model.model_name} (score: {best_score})")

    _cached_thinking_model = best_model
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
        max_tokens=limits.get("max_output", 32000),
        max_context=limits.get("max_context", 1000000),
        temperature=0.7,
        cost_per_1k_tokens=(costs.get("input", 0.015) + costs.get("output", 0.075)) / 2,
    )


def _build_openai_compat_config(provider_name: str) -> Optional['ModelConfig']:
    """Generic builder for OpenAI / Gemini / Mistral — same shape, different env var + endpoint."""
    env_var_map = {"openai": "OPENAI_API_KEY", "gemini": "GEMINI_API_KEY", "mistral": "MISTRAL_API_KEY"}
    api_key = os.getenv(env_var_map[provider_name])
    if not api_key:
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
        max_tokens=limits.get("max_output", 8192),
        max_context=limits.get("max_context", 128000),
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
    for pref in preferred:
        for model in ollama_models:
            if pref in model.lower():
                selected_model = model
                break
        if selected_model != ollama_models[0]:
            break
    ollama_base = _validate_ollama_url(RaptorConfig.OLLAMA_HOST)
    if selected_model not in MODEL_LIMITS:
        logger.info(
            f"Model '{selected_model}' not in MODEL_LIMITS — using defaults "
            f"(max_context=32000, max_output=4096). Override in models.json if needed."
        )
    return ModelConfig(
        provider="ollama",
        model_name=selected_model,
        api_base=f"{ollama_base}/v1",
        max_tokens=4096,
        temperature=0.7,
        cost_per_1k_tokens=0.0,
    )


def _build_claudecode_config() -> Optional['ModelConfig']:
    """Last-resort fallback: ``claude`` CLI on PATH, no API key needed.
    Slower (subprocess + ``--json-schema`` structured output for
    tool-use) but works for users who only have Claude Code installed.

    ``timeout=300`` is calibrated from real-CC runs: simple turns are
    5-15s, ``--json-schema`` against a rich tool catalog can push to
    60-180s. 300s gives 2-3x headroom for worst case without letting
    a single turn consume a whole ``ToolUseLoop.max_seconds`` budget.
    Cloud APIs default to 120s in ``ModelConfig`` (well-tuned for
    them); CC's subprocess + structured-output overhead needs more.
    """
    import shutil
    if not shutil.which("claude"):
        return None
    default_model = PROVIDER_DEFAULT_MODELS["anthropic"]
    limits = MODEL_LIMITS.get(default_model, {})
    return ModelConfig(
        provider="claudecode",
        model_name=default_model,
        api_key=None,
        max_tokens=limits.get("max_output", 32000),
        max_context=limits.get("max_context", 1000000),
        temperature=0.7,
        timeout=300,
        cost_per_1k_tokens=0.0,
    )


_PROVIDER_BUILDERS = {
    "anthropic":  _build_anthropic_config,
    "openai":     lambda: _build_openai_compat_config("openai"),
    "gemini":     lambda: _build_openai_compat_config("gemini"),
    "mistral":    lambda: _build_openai_compat_config("mistral"),
    "ollama":     _build_ollama_config,
    "claudecode": _build_claudecode_config,
}

# Default order. Anthropic first (cache-control + task-budget beta —
# the only provider where those matter natively). Ollama before
# claudecode because Ollama is a deliberate operator setup; CC is the
# absolute last resort.
_DEFAULT_PROVIDER_ORDER = (
    "anthropic", "openai", "gemini", "mistral", "ollama", "claudecode",
)


def _get_default_primary_model(
    prefer: Optional[List[str]] = None,
) -> Optional['ModelConfig']:
    """
    Get default primary model based on available providers.

    Resolution order:
    1. **Preferred providers via env var** (when ``prefer`` set).
       Try each named provider in order; skip silently if absent.
    2. **Operator's thinking-model config** (``~/.config/raptor/models.json``).
       Honoured even when ``prefer`` is set — picks up
       provider+key combinations that don't fit the env-var
       convention (e.g. Gemini via Vertex auth). When ``prefer`` is
       set, only return it if its provider matches the preference.
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
    thinking_model = _get_best_thinking_model()
    if thinking_model and thinking_model.api_key:
        logger.info(
            f"Using automatic thinking model: "
            f"{thinking_model.provider}/{thinking_model.model_name}"
        )
        return thinking_model

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


def _model_config_from_entry(entry: Dict) -> 'ModelConfig':
    """Build a ModelConfig from a config file entry.

    API key resolution: inline api_key → provider env var.
    Other config fields (timeout, max_context, max_output) are honoured.
    """
    provider = entry.get("provider", "")
    model_name = entry.get("model", "")
    if not model_name and provider:
        model_name = PROVIDER_DEFAULT_MODELS.get(provider, "")

    api_key = entry.get("api_key")
    if not api_key:
        env_key = PROVIDER_ENV_KEYS.get(provider)
        if env_key:
            api_key = os.getenv(env_key)

    limits = MODEL_LIMITS.get(model_name, {})
    costs = MODEL_COSTS.get(model_name, {})
    cost_per_1k = (costs.get("input", 0.005) + costs.get("output", 0.005)) / 2

    return ModelConfig(
        provider=provider,
        model_name=model_name,
        api_key=api_key,
        api_base=PROVIDER_ENDPOINTS.get(provider),
        max_tokens=entry.get("max_output", limits.get("max_output", 8192)),
        max_context=entry.get("max_context", limits.get("max_context", 32000)),
        timeout=entry.get("timeout", 120),
        temperature=0.7,
        cost_per_1k_tokens=cost_per_1k,
        role=entry.get("role") or None,
    )


def _get_default_fallback_models() -> List['ModelConfig']:
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
    primary = _get_best_thinking_model()
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
        if mc.api_key:
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

    if "mistral" not in config_providers and os.getenv("MISTRAL_API_KEY"):
        if not _is_primary("mistral", "mistral-large-latest"):
            fallbacks.append(ModelConfig(
                provider="mistral",
                model_name="mistral-large-latest",
                api_key=os.getenv("MISTRAL_API_KEY"),
                api_base=PROVIDER_ENDPOINTS["mistral"],
                max_tokens=128000,
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


def resolve_model_roles(
    primary_model: Optional['ModelConfig'] = None,
    fallback_models: Optional[List['ModelConfig']] = None,
) -> Dict[str, Any]:
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
    if primary_model is None and not fallback_models:
        return {
            "analysis_model": None,
            "analysis_models": [],
            "code_model": None,
            "consensus_models": [],
            "fallback_models": [],
            "judge_models": [],
            "aggregate_models": [],
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
        return {
            "analysis_model": all_models[0] if all_models else None,
            "analysis_models": [all_models[0]] if all_models else [],
            "code_model": all_models[0] if all_models else None,
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


def _validate_model_roles(models: List['ModelConfig']) -> None:
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
    pass


@dataclass
class ModelConfig:
    """Configuration for a specific model."""
    provider: str  # "anthropic", "openai", "mistral", "ollama", "gemini"
    model_name: str  # "claude-opus-4-6", "gpt-5.2", "llama3:70b", etc.
    api_key: Optional[str] = None
    api_base: Optional[str] = None  # For non-Anthropic providers
    max_tokens: int = 4096
    max_context: int = 32000
    temperature: float = 0.7
    timeout: int = 120
    cost_per_1k_tokens: float = 0.0  # Fallback rate — used only when model not in MODEL_COSTS
    enabled: bool = True
    role: Optional[str] = None  # "analysis", "code", "consensus", "fallback", "judge", "aggregate"


@dataclass
class LLMConfig:
    """Main LLM configuration for RAPTOR."""

    # Primary model (fastest/most capable). None when no provider is available.
    primary_model: Optional[ModelConfig] = field(default_factory=_get_default_primary_model)

    # Fallback models (in priority order)
    fallback_models: List[ModelConfig] = field(default_factory=_get_default_fallback_models)

    # Analysis-specific models (for different task types)
    specialized_models: Dict[str, ModelConfig] = field(default_factory=dict)

    # Global settings
    enable_fallback: bool = True
    max_retries: int = 3
    retry_delay: float = 2.0
    retry_delay_remote: float = 5.0
    enable_caching: bool = True
    cache_dir: Path = Path("out/llm_cache")
    # Optional: drop cache entries older than this on read. None = no
    # TTL. Useful when an upgraded model would now produce different
    # output for a previously-cached prompt.
    cache_ttl_seconds: Optional[float] = None
    # Optional: cap cache size by number of entries. After each
    # successful save the oldest files (by mtime) are evicted until at
    # or under this cap. None = no eviction (cache grows unboundedly).
    # The directory-walk per save is O(N); fine to ~10k entries, beyond
    # which a real cache backend would be more appropriate.
    cache_max_entries: Optional[int] = None
    enable_cost_tracking: bool = True
    max_cost_per_scan: float = 10.0  # USD

    def to_file(self, config_path: Path) -> None:
        """Save configuration to JSON file with restrictive permissions."""
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

    def get_model_for_task(self, task_type: str) -> ModelConfig:
        """Get the appropriate model for a specific task type."""
        if task_type in self.specialized_models:
            model = self.specialized_models[task_type]
            if model.enabled:
                return model
        return self.primary_model

    def get_available_models(self) -> List[ModelConfig]:
        """Get list of all available models (primary + fallbacks)."""
        models = [self.primary_model] if self.primary_model else []
        if self.enable_fallback:
            models.extend(self.fallback_models)
        return [m for m in models if m.enabled]

    def get_retry_delay(self, api_base: Optional[str] = None) -> float:
        """Get appropriate retry delay based on server location."""
        if api_base and ("localhost" not in api_base and "127.0.0.1" not in api_base):
            return self.retry_delay_remote
        return self.retry_delay
