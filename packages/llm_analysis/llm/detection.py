#!/usr/bin/env python3
"""
LLM availability detection.

Answers the question "what's available?" — SDK presence, API keys,
Ollama reachability, Claude Code, config file migration.

Single source of truth: all callers should use detect_llm_availability()
instead of ad-hoc env var or PATH checks.
"""

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import requests

# Add parent directories to path for core imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()

# SDK availability flags — canonical source, imported by other modules
try:
    import openai as _openai_module
    OPENAI_SDK_AVAILABLE = True
except ImportError:
    OPENAI_SDK_AVAILABLE = False

try:
    import anthropic as _anthropic_module
    ANTHROPIC_SDK_AVAILABLE = True
except ImportError:
    ANTHROPIC_SDK_AVAILABLE = False


@dataclass
class LLMAvailability:
    """Result of LLM availability detection.

    Single source of truth — no caller should check env vars,
    PATH, or Ollama endpoints directly.
    """
    external_llm: bool  # An LLM reachable via SDK (cloud keys, Ollama, config file)
    claude_code: bool   # Claude Code is available (running inside it, or installed on PATH)
    llm_available: bool  # Someone will do the reasoning work (external_llm or claude_code)


def _validate_ollama_url(url: str) -> str:
    """Validate and normalize Ollama URL."""
    url = url.rstrip('/')
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid Ollama URL (must start with http:// or https://): {url}")
    return url


_cached_ollama_models: Optional[List[str]] = None
_ollama_checked: bool = False


def _get_available_ollama_models() -> List[str]:
    """Get list of available Ollama models. Cached per-process to avoid repeated HTTP checks."""
    global _cached_ollama_models, _ollama_checked
    if _ollama_checked:
        return _cached_ollama_models or []

    _ollama_checked = True
    try:
        ollama_url = _validate_ollama_url(RaptorConfig.OLLAMA_HOST)
        response = requests.get(f"{ollama_url}/api/tags", timeout=2)
        if response.status_code == 200:
            data = response.json()
            _cached_ollama_models = [model['name'] for model in data.get('models', [])]
            return _cached_ollama_models
    except Exception as e:
        ollama_display = RaptorConfig.OLLAMA_HOST if 'localhost' in RaptorConfig.OLLAMA_HOST or '127.0.0.1' in RaptorConfig.OLLAMA_HOST else '[REMOTE-OLLAMA]'
        logger.debug(f"Could not connect to Ollama at {ollama_display}: {e}")
    _cached_ollama_models = []
    return []


def _check_litellm_installed():
    """Warn if compromised litellm versions are still installed."""
    try:
        from importlib.metadata import version as pkg_version, PackageNotFoundError
        try:
            installed = pkg_version("litellm")
            if installed in ("1.82.7", "1.82.8"):
                print(
                    f"\n  ⚠️  WARNING: litellm=={installed} is installed and contains malicious code.\n"
                    f"  RAPTOR no longer uses litellm, but the package can still harm your system.\n"
                    f"  Remove it: pip uninstall litellm\n"
                    f"  Ref: https://github.com/BerriAI/litellm/issues/24518\n"
                )
        except PackageNotFoundError:
            pass
    except ImportError:
        pass


def _check_litellm_migration():
    """Print migration guidance if old LiteLLM config exists but new config does not."""
    try:
        old_config = Path.home() / ".config/litellm/config.yaml"
        new_config = Path.home() / ".config/raptor/models.json"
    except RuntimeError:
        # Path.home() can fail in environments with no HOME set
        return

    if old_config.exists() and not new_config.exists():
        print(
            "\n  [raptor] Found ~/.config/litellm/config.yaml but no ~/.config/raptor/models.json\n"
            "  LiteLLM is no longer used. Migrate your models to the new JSON format:\n"
            "\n"
            "    mkdir -p ~/.config/raptor\n"
            "    cat > ~/.config/raptor/models.json << 'EOF'\n"
            "    [\n"
            '      {"provider": "anthropic", "model": "claude-sonnet-4-6"},\n'
            '      {"provider": "openai",    "model": "gpt-5.2", "api_key": "sk-..."}\n'
            "    ]\n"
            "    EOF\n"
            "\n"
            "  API keys can be set via env vars (ANTHROPIC_API_KEY, etc.) or in the JSON.\n"
        )


def _read_config_models() -> list:
    """Read model entries from RAPTOR config file.

    Shared config file parsing — used by both detection and config modules.
    Returns a list of model dicts, or empty list on any error.
    """
    import json
    try:
        config_path_str = os.getenv('RAPTOR_CONFIG')
        if config_path_str:
            config_path = Path(config_path_str).resolve()
        else:
            config_path = Path.home() / ".config/raptor/models.json"

        if not config_path.exists():
            return []

        raw = config_path.read_text()
        if not raw.strip():
            return []

        # Strip // line comments
        lines = [l for l in raw.splitlines() if not l.lstrip().startswith("//")]
        data = json.loads("\n".join(lines))

        # Accept both {"models": [...]} and bare [...]
        if isinstance(data, dict):
            model_list = data.get("models", [])
            return model_list if isinstance(model_list, list) else []
        elif isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def _config_has_keyed_models() -> bool:
    """Check if the RAPTOR config file has any model with an API key.

    Uses _read_config_models() for parsing, then checks for api_key
    fields or matching env vars. Doesn't depend on config.py.
    """
    from .model_data import PROVIDER_ENV_KEYS

    for entry in _read_config_models():
        if not isinstance(entry, dict):
            continue
        if entry.get("api_key"):
            return True
        provider = entry.get("provider", "")
        env_key = PROVIDER_ENV_KEYS.get(provider)
        if env_key and os.getenv(env_key):
            return True

    return False


_cached_llm_availability: Optional[LLMAvailability] = None


def detect_llm_availability() -> LLMAvailability:
    """
    Single source of truth for LLM availability.

    Checks all possible LLM sources once and returns cached flags that
    all callers should use instead of ad-hoc env var checks.
    Result is cached per-process to avoid repeated Ollama HTTP checks.

    Returns:
        LLMAvailability with three flags: external_llm, claude_code, llm_available
    """
    global _cached_llm_availability
    if _cached_llm_availability is not None:
        return _cached_llm_availability

    _check_litellm_installed()
    _check_litellm_migration()

    # Check cloud API keys, gated on SDK availability
    has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY")) and (ANTHROPIC_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE)
    has_openai = bool(os.getenv("OPENAI_API_KEY")) and OPENAI_SDK_AVAILABLE
    has_gemini = bool(os.getenv("GEMINI_API_KEY")) and OPENAI_SDK_AVAILABLE
    has_mistral = bool(os.getenv("MISTRAL_API_KEY")) and OPENAI_SDK_AVAILABLE

    has_cloud_keys = has_anthropic or has_openai or has_gemini or has_mistral

    # Check config file for models with valid keys (no import from config.py
    # needed — just check if any model entry has an API key, either inline
    # or via env var for its provider)
    has_config_file = False
    if not has_cloud_keys:
        has_config_file = _config_has_keyed_models()

    # Check Ollama reachability (requires OpenAI SDK for API calls)
    has_ollama = OPENAI_SDK_AVAILABLE and bool(_get_available_ollama_models())

    # Check Claude Code environment
    in_claude_code = bool(os.getenv("CLAUDECODE"))
    claude_on_path = shutil.which("claude") is not None
    claude_code = in_claude_code or claude_on_path

    external_llm = has_cloud_keys or has_config_file or has_ollama

    availability = LLMAvailability(
        external_llm=external_llm,
        claude_code=claude_code,
        llm_available=external_llm or claude_code,
    )

    logger.info(
        f"LLM availability: external_llm={availability.external_llm}, "
        f"claude_code={availability.claude_code}, "
        f"llm_available={availability.llm_available}"
    )

    _cached_llm_availability = availability
    return availability
