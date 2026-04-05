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

try:
    from google import genai as _genai_module
    GENAI_SDK_AVAILABLE = True
except ImportError:
    GENAI_SDK_AVAILABLE = False


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


def _check_litellm_installed() -> bool:
    """Check for litellm: auto-migrate config if present, stop if compromised.

    Returns True if litellm was found (migration handled here), False otherwise.
    """
    try:
        from importlib.metadata import version as pkg_version, PackageNotFoundError
        try:
            installed = pkg_version("litellm")

            # litellm is installed — PyYAML is guaranteed (transitive dep).
            # Pre-emptively migrate config before any other checks.
            try:
                old_config = Path.home() / ".config/litellm/config.yaml"
                new_config = Path.home() / ".config/raptor/models.json"
                if old_config.exists() and not new_config.exists():
                    _try_auto_migrate(old_config, new_config)
            except Exception:
                pass  # Migration is best-effort

            if installed in ("1.82.7", "1.82.8"):
                msg = (
                    f"\n  ⚠️  WARNING: litellm=={installed} is installed and contains malicious code.\n"
                    f"  It exfiltrates API keys, SSH keys, and cloud credentials.\n"
                    f"  RAPTOR no longer uses litellm, but the package can still harm your system.\n"
                    f"\n"
                )
                if installed == "1.82.8":
                    msg += (
                        f"  Version 1.82.8 runs on ANY Python startup via a .pth file.\n"
                        f"  Do NOT use pip to remove it — pip invokes Python, triggering the payload.\n"
                        f"\n"
                        f"  Safe removal (no Python invoked):\n"
                        f"    find / -path '*/litellm*' -name '*.pth' -delete 2>/dev/null\n"
                        f"    find / -path '*/site-packages/litellm*' -exec rm -rf {{}} + 2>/dev/null\n"
                        f"\n"
                        f"  Then rotate all API keys, SSH keys, and cloud credentials.\n"
                    )
                else:
                    msg += (
                        f"  Remove it: pip uninstall litellm\n"
                    )
                msg += (
                    f"\n"
                    f"  Ref: https://github.com/BerriAI/litellm/issues/24518\n"
                )
                print(msg)
                raise SystemExit(
                    f"RAPTOR cannot run with litellm {installed} installed. "
                    f"Remove it using the instructions above, then try again. "
                    f"Ref: https://github.com/BerriAI/litellm/issues/24518"
                )

            return True  # litellm found, migration handled
        except PackageNotFoundError:
            return False  # litellm not installed
    except ImportError:
        return False  # importlib.metadata not available


def _try_auto_migrate(old_config: Path, new_config: Path) -> bool:
    """Attempt to auto-migrate LiteLLM YAML config to RAPTOR JSON.

    Only runs if PyYAML is installed (e.g. as a transitive dependency).
    Does not require or import litellm.

    Returns True if migration succeeded, False if it couldn't run.
    """
    try:
        import yaml
    except ImportError:
        return False

    import json
    from .model_data import PROVIDER_ENV_KEYS

    try:
        with open(old_config) as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data.get('model_list'), list):
            return False

        models = []
        for entry in data['model_list']:
            if not isinstance(entry, dict):
                continue

            params = entry.get('litellm_params', {}) or {}
            underlying = params.get('model', '')
            if not underlying or '/' not in underlying:
                continue

            provider = underlying.split('/')[0]
            model_name = underlying.split('/', 1)[1]

            model_entry = {"provider": provider, "model": model_name}

            # Resolve API key
            api_key_val = params.get('api_key', '')
            if api_key_val and isinstance(api_key_val, str):
                if api_key_val.startswith('os.environ/'):
                    env_var = api_key_val.replace('os.environ/', '')
                    key = os.getenv(env_var)
                    if key:
                        # Don't store resolved keys — env var takes precedence
                        pass
                    else:
                        # Env var not set, store a placeholder
                        model_entry["api_key"] = f"${{{env_var}}}"
                else:
                    model_entry["api_key"] = api_key_val

            models.append(model_entry)

        if not models:
            return False

        # Write new config
        from core.json import save_json
        save_json(new_config, {"models": models})
        os.chmod(new_config, 0o600)

        # Check if any keys need attention
        needs_keys = any(
            e.get("api_key", "").startswith("${") or "api_key" not in e
            for e in models
        )
        key_msg = ""
        if needs_keys:
            key_msg = (
                f"\n"
                f"  ⚠️  Some models need API keys. Either:\n"
                f"    - Set env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.), or\n"
                f"    - Replace placeholders in the JSON with actual keys\n"
            )

        print(
            f"\n  [raptor] Auto-migrated LiteLLM config → {new_config}\n"
            f"  Converted {len(models)} model(s) from {old_config}\n"
            f"{key_msg}"
            f"\n"
            f"  Your old config at {old_config} was not modified.\n"
        )
        return True

    except Exception as e:
        logger.debug(f"Auto-migration failed: {e}")
        return False


def _check_litellm_migration():
    """Print migration guidance if old LiteLLM config exists but new config does not."""
    try:
        old_config = Path.home() / ".config/litellm/config.yaml"
        new_config = Path.home() / ".config/raptor/models.json"
    except RuntimeError:
        # Path.home() can fail in environments with no HOME set
        return

    if old_config.exists() and not new_config.exists():
        # Try auto-migration if PyYAML happens to be installed
        if _try_auto_migrate(old_config, new_config):
            return

        # Manual migration guidance
        sample = generate_sample_config()
        sample_indented = "\n".join("    " + line for line in sample.splitlines())
        print(
            "\n  [raptor] LiteLLM is no longer used. Your config needs migrating.\n"
            "\n"
            "  Found:    ~/.config/litellm/config.yaml\n"
            "  Expected: ~/.config/raptor/models.json\n"
            "\n"
            "  Create the new config:\n"
            "\n"
            "    mkdir -p ~/.config/raptor\n"
            "    cat > ~/.config/raptor/models.json << 'EOF'\n"
            f"{sample_indented}\n"
            "    EOF\n"
            "    chmod 600 ~/.config/raptor/models.json\n"
            "\n"
            "  Copy your API keys from the old config into the new one, or\n"
            "  set them as env vars (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.).\n"
            "\n"
            "  Your old config at ~/.config/litellm/config.yaml is not modified.\n"
            "  Delete it when you're done migrating (if no other tools use it).\n"
        )


def generate_sample_config() -> str:
    """Generate a sample models.json config from current defaults.

    Uses PROVIDER_DEFAULT_MODELS so the example stays in sync with
    the actual defaults. Includes a commented example showing the
    api_key field format. Called by migration guidance and CLI help.
    """
    from .model_data import PROVIDER_DEFAULT_MODELS
    import json

    models = []
    for provider, model in PROVIDER_DEFAULT_MODELS.items():
        models.append({"provider": provider, "model": model})

    raw = json.dumps({"models": models}, indent=2)

    # Add a commented example showing how to add an API key.
    # Our JSON parser strips // comments, so this is safe to copy-paste.
    raw += "\n// To add API keys inline (alternative to env vars):\n"
    raw += '// {"provider": "anthropic", "model": "claude-opus-4-6", "api_key": "sk-ant-..."}\n'

    return raw


def _read_config_models() -> list:
    """Read model entries from RAPTOR config file.

    Shared config file parsing — used by both detection and config modules.
    Returns a list of model dicts, or empty list on any error.
    """
    import json
    try:
        from core.json import load_json_with_comments

        config_path_str = os.getenv('RAPTOR_CONFIG')
        if config_path_str:
            config_path = Path(config_path_str).resolve()
        else:
            config_path = Path.home() / ".config/raptor/models.json"

        data = load_json_with_comments(config_path)
        if data is None:
            return []

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
    """Check if the RAPTOR config file has any usable model.

    A model is usable if it has an API key (inline or via env var)
    AND the required SDK is installed to talk to its provider.
    """
    from .model_data import PROVIDER_ENV_KEYS

    for entry in _read_config_models():
        if not isinstance(entry, dict):
            continue

        provider = entry.get("provider", "")

        # Check SDK availability for this provider
        if provider == "anthropic":
            if not (ANTHROPIC_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE):
                continue
        elif provider == "ollama":
            if not OPENAI_SDK_AVAILABLE:
                continue
        elif provider == "gemini":
            if not (GENAI_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE):
                continue
        elif provider in ("openai", "mistral"):
            if not OPENAI_SDK_AVAILABLE:
                continue
        else:
            if not OPENAI_SDK_AVAILABLE:
                continue

        # Check if model has a key
        if entry.get("api_key"):
            return True
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

    litellm_found = _check_litellm_installed()
    if not litellm_found:
        # Only check for old config if litellm isn't installed
        # (if it is, _check_litellm_installed already handled migration)
        _check_litellm_migration()

    # Check cloud API keys, gated on SDK availability
    has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY")) and (ANTHROPIC_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE)
    has_openai = bool(os.getenv("OPENAI_API_KEY")) and OPENAI_SDK_AVAILABLE
    has_gemini = bool(os.getenv("GEMINI_API_KEY")) and (GENAI_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE)
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

    logger.debug(
        f"LLM availability: external_llm={availability.external_llm}, "
        f"claude_code={availability.claude_code}, "
        f"llm_available={availability.llm_available}"
    )

    # Warn about specific misconfigurations
    _warn_unusable_keys()

    _cached_llm_availability = availability
    return availability


def _warn_unusable_keys():
    """Warn if API keys are set but the required SDK is missing."""
    from .model_data import PROVIDER_ENV_KEYS

    sdk_requirements = {
        "anthropic": ("anthropic or openai", ANTHROPIC_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE),
        "openai": ("openai", OPENAI_SDK_AVAILABLE),
        "gemini": ("google-genai or openai", GENAI_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE),
        "mistral": ("openai", OPENAI_SDK_AVAILABLE),
    }

    for provider, env_var in PROVIDER_ENV_KEYS.items():
        if os.getenv(env_var):
            sdk_name, available = sdk_requirements.get(provider, ("openai", OPENAI_SDK_AVAILABLE))
            if not available:
                logger.warning(
                    f"{env_var} is set but the {sdk_name} SDK is not installed. "
                    f"Install with: pip install {sdk_name.split(' or ')[0]}"
                )
