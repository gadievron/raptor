"""RAPTOR startup — environment checks and session initialisation.

Gathers system status (tools, LLM, env, active project), formats
the startup banner, writes .startup-output, and sets up CLAUDE_ENV_FILE.

Entry point: `python3 -m core.startup.init`
"""

import logging
import os
import shutil
import sys
from pathlib import Path

from . import REPO_ROOT
from .banner import format_banner, read_logo, read_random_quote

sys.path.insert(0, str(REPO_ROOT))
OUTPUT_FILE = REPO_ROOT / ".startup-output"


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_tools() -> tuple[list, list, set]:
    """Check for required external tools.

    Returns (results, warnings, unavailable_features).
    """
    from core.config import RaptorConfig

    results = []
    available = set()
    for name in sorted(RaptorConfig.TOOL_DEPS):
        found = bool(shutil.which(RaptorConfig.TOOL_DEPS[name]["binary"]))
        results.append((name, found))
        if found:
            available.add(name)

    warnings = []
    unavailable_features = set()

    # Group checks (e.g., need at least one scanner)
    for group_name, group in RaptorConfig.TOOL_GROUPS.items():
        members = sorted(n for n, d in RaptorConfig.TOOL_DEPS.items() if d.get("group") == group_name)
        if not any(m in available for m in members):
            warnings.append(f"{group['affects']} unavailable \u2014 no scanner ({' or '.join(members)})")
            for cmd in group["affects"].split(", "):
                unavailable_features.add(cmd.strip())

    # Individual checks (skip group members)
    for name in sorted(RaptorConfig.TOOL_DEPS):
        dep = RaptorConfig.TOOL_DEPS[name]
        if name in available or dep.get("group"):
            continue
        severity = dep.get("severity", "degrades")
        label = "unavailable" if severity == "required" else "limited"
        warnings.append(f"{dep['affects']} {label} \u2014 {name} not found")
        if severity == "required":
            for cmd in dep["affects"].split(", "):
                unavailable_features.add(cmd.strip())

    return results, warnings, unavailable_features


def check_llm() -> tuple[list, list]:
    """Check LLM availability via config file + lightweight key validation.

    Reads ~/.config/raptor/models.json directly and tests API keys with
    simple HTTP requests — avoids importing heavy SDKs (~4.5s of imports).

    Returns (lines, warnings).
    """
    import json
    from concurrent.futures import ThreadPoolExecutor, as_completed

    lines = []
    warnings = []

    try:
        # Read config
        config_path = Path.home() / ".config/raptor/models.json"
        models = []
        if config_path.exists():
            try:
                data = json.loads(config_path.read_text())
                models = data.get("models", []) if isinstance(data, dict) else data
            except (json.JSONDecodeError, OSError):
                pass

        # Also check env vars for providers not in models.json
        env_keys = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "gemini": "GEMINI_API_KEY",
            "mistral": "MISTRAL_API_KEY",
        }
        config_providers = {m.get("provider") for m in models}
        for provider, env_var in env_keys.items():
            key = os.getenv(env_var)
            if key and provider not in config_providers:
                models.append({"provider": provider, "model": "default", "api_key": key, "_from_env": True})

        if models:
            # Validate keys in parallel
            key_status = {}
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {}
                seen = set()
                for m in models:
                    provider = m.get("provider", "unknown")
                    api_key = m.get("api_key") or os.getenv(env_keys.get(provider, ""))
                    if not api_key or provider in seen:
                        continue
                    seen.add(provider)
                    futures[pool.submit(_test_key, provider, api_key, m.get("api_base"))] = provider
                for future in as_completed(futures, timeout=5):
                    provider = futures[future]
                    try:
                        key_status[provider] = future.result()
                    except Exception:
                        key_status[provider] = False

            # Build output lines (same format as before)
            primary = models[0]
            provider = primary.get("provider", "unknown")
            model = primary.get("model", primary.get("model_name", "unknown"))
            src = _key_source(provider, primary)
            lines.append(f"   llm: {provider}/{model} (primary, {src})")

            if key_status.get(provider) is False:
                warnings.append(f"{provider} API key validation failed")

            for fm in models[1:4]:
                fp = fm.get("provider", "unknown")
                fn = fm.get("model", fm.get("model_name", "unknown"))
                if f"{fp}/{fn}" != f"{provider}/{model}":
                    role = fm.get("role", "fallback")
                    lines.append(f"        {fp}/{fn} ({role}, {_key_source(fp, fm)})")
                    if key_status.get(fp) is False:
                        warnings.append(f"{fp} API key validation failed")
        else:
            lines.append("   llm: no external LLM configured")

        if shutil.which("claude"):
            lines.append("        claude code \u2713")

    except Exception as e:
        lines.append("   llm: detection error")
        warnings.append(f"LLM detection: {e}")

    return lines, warnings


def _test_key(provider: str, api_key: str, api_base: str = None) -> bool:
    """Lightweight API key smoke test — no SDK imports."""
    import requests

    timeout = 3
    try:
        if provider == "gemini":
            r = requests.get(
                f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}",
                timeout=timeout,
            )
            return r.status_code == 200
        elif provider == "openai":
            base = (api_base or "https://api.openai.com").rstrip("/")
            r = requests.get(
                f"{base}/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            return r.status_code == 200
        elif provider == "anthropic":
            r = requests.get(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
                timeout=timeout,
            )
            return r.status_code == 200
        elif provider == "mistral":
            r = requests.get(
                "https://api.mistral.ai/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            return r.status_code == 200
        elif provider == "ollama":
            base = (api_base or "http://localhost:11434").rstrip("/")
            r = requests.get(f"{base}/api/tags", timeout=timeout)
            return r.status_code == 200
        else:
            return True  # Unknown provider — can't test, assume OK
    except requests.RequestException:
        return False


def _key_source(provider: str, model_entry: dict = None) -> str:
    if provider == "ollama":
        return "local"
    env_keys = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "mistral": "MISTRAL_API_KEY",
    }
    if model_entry and model_entry.get("_from_env"):
        return f"via {env_keys.get(provider, 'env')}"
    env_var = env_keys.get(provider, "")
    if env_var and os.getenv(env_var):
        return f"via {env_var}"
    return "via models.json"


def check_env(unavailable_features: set) -> tuple[list, list]:
    """Check environment: output dir, disk, config vars, tree-sitter.

    Returns (env_parts, warnings).
    """
    from core.config import RaptorConfig

    parts = []
    warnings = []

    out_dir = RaptorConfig.get_out_dir()
    out_ok = out_dir.exists() and os.access(out_dir, os.W_OK)
    parts.append("out/ \u2713" if out_ok else "out/ \u2717")
    if not out_ok:
        warnings.append("out/ directory not writable")

    try:
        stat = os.statvfs(str(out_dir if out_dir.exists() else REPO_ROOT))
        free_bytes = stat.f_bavail * stat.f_frsize
        free_gb = free_bytes / (1024 ** 3)
        parts.append(f"disk {free_gb:.0f} GB free" if free_gb >= 1 else f"disk {free_bytes / (1024**2):.0f} MB free")
        if free_gb < 5 and "/fuzz" not in unavailable_features:
            warnings.append(f"Low disk space ({free_gb:.1f} GB) \u2014 fuzzing may fail")
    except OSError:
        pass

    if os.getenv("RAPTOR_OUT_DIR"):
        parts.append(f"RAPTOR_OUT_DIR={os.getenv('RAPTOR_OUT_DIR')}")
    if os.getenv("RAPTOR_CONFIG"):
        parts.append(f"RAPTOR_CONFIG={os.getenv('RAPTOR_CONFIG')}")

    if not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        warnings.append("/oss-forensics unavailable \u2014 BigQuery not configured")

    # Tree-sitter inventory enrichment
    try:
        from core.inventory.extractors import _get_ts_languages
        ts_langs = _get_ts_languages()
        if ts_langs:
            parts.append(f"tree-sitter \u2713 ({', '.join(ts_langs)})")
        else:
            parts.append("tree-sitter \u2717")
    except Exception:
        pass

    return parts, warnings


def check_active_project() -> str | None:
    """Return a one-line project status string, or None if no active project."""
    try:
        from . import PROJECTS_DIR, get_active_name
        name = get_active_name()
        if not name:
            return None
        from core.json import load_json
        data = load_json(PROJECTS_DIR / f"{name}.json")
        if not data:
            return None
        proj_target = data.get("target", "")
        auto_marker = PROJECTS_DIR / ".auto"
        if auto_marker.exists() and auto_marker.read_text().strip() == name:
            return f"Auto-activated project: {name} ({proj_target}) \u2014 `/project none` to clear"
        return f"Project: {name} ({proj_target}) \u2014 `/project none` to clear"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Environment setup
# ---------------------------------------------------------------------------

def setup_env_file():
    """Add bin/ to PATH via CLAUDE_ENV_FILE.

    Covers direct `claude` launches where bin/raptor didn't set PATH.
    Harmless duplicate if it did.
    """
    env_file = os.environ.get("CLAUDE_ENV_FILE")
    if not env_file:
        return
    repo_root = str(REPO_ROOT)
    bin_dir = str(REPO_ROOT / "bin")
    try:
        existing = Path(env_file).read_text() if Path(env_file).exists() else ""
        additions = []
        if bin_dir not in existing:
            additions.append(f'export PATH="$PATH:{bin_dir}"')
        if "RAPTOR_DIR" not in existing:
            additions.append(f'export RAPTOR_DIR="{repo_root}"')
        if additions:
            with open(env_file, "a") as f:
                f.write("\n".join(additions) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logo = read_logo()
    quote = read_random_quote()

    try:
        logging.disable(logging.WARNING)

        tool_results, tool_warnings, unavailable = check_tools()
        llm_lines, llm_warnings = check_llm()
        env_parts, env_warnings = check_env(unavailable)
        project_line = check_active_project()

        logging.disable(logging.NOTSET)

        output = format_banner(
            logo, quote, tool_results, tool_warnings,
            llm_lines, llm_warnings, env_parts, env_warnings,
            project_line,
        )
    except Exception:
        output = f"{logo}\n\nraptor:~$ {quote}"

    OUTPUT_FILE.write_text(output)
    print(output)


if __name__ == "__main__":
    main()
