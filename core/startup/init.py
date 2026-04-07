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
    """Check LLM availability and configuration.

    Returns (lines, warnings).
    """
    lines = []
    warnings = []

    try:
        from packages.llm_analysis.llm.detection import (
            detect_llm_availability, OPENAI_SDK_AVAILABLE, ANTHROPIC_SDK_AVAILABLE,
        )
        from packages.llm_analysis.llm.model_data import PROVIDER_ENV_KEYS

        avail = detect_llm_availability()

        # SDK mismatch warnings
        sdk_reqs = {
            "anthropic": ("anthropic", ANTHROPIC_SDK_AVAILABLE or OPENAI_SDK_AVAILABLE),
            "openai": ("openai", OPENAI_SDK_AVAILABLE),
            "gemini": ("openai", OPENAI_SDK_AVAILABLE),
            "mistral": ("openai", OPENAI_SDK_AVAILABLE),
        }
        for provider, env_var in PROVIDER_ENV_KEYS.items():
            if os.getenv(env_var):
                sdk_name, ok = sdk_reqs.get(provider, ("openai", OPENAI_SDK_AVAILABLE))
                if not ok:
                    warnings.append(f"{env_var} set but {sdk_name} SDK missing \u2014 pip install {sdk_name}")

        if avail.external_llm:
            from packages.llm_analysis.llm.config import LLMConfig
            cfg = LLMConfig()
            if cfg.primary_model:
                pm = cfg.primary_model
                src = _key_source(pm.provider, PROVIDER_ENV_KEYS)
                lines.append(f"   llm: {pm.provider}/{pm.model_name} (primary, {src})")
                for fm in cfg.fallback_models[:3]:
                    if f"{fm.provider}/{fm.model_name}" != f"{pm.provider}/{pm.model_name}":
                        lines.append(f"        {fm.provider}/{fm.model_name} (fallback, {_key_source(fm.provider, PROVIDER_ENV_KEYS)})")
        else:
            lines.append("   llm: no external LLM configured")

        if avail.claude_code:
            lines.append("        claude code \u2713")

    except Exception as e:
        lines.append("   llm: detection error")
        warnings.append(f"LLM detection: {e}")

    return lines, warnings


def _key_source(provider: str, env_keys: dict) -> str:
    if provider == "ollama":
        return "local"
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
        if os.environ.get("RAPTOR_PROJECT_AUTO"):
            return f"Auto-activated project: {name} ({proj_target}) \u2014 `raptor project use none` to clear"
        return f"Project: {name} ({proj_target}) \u2014 `raptor project use none` to clear"
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
    bin_dir = str(REPO_ROOT / "bin")
    try:
        existing = Path(env_file).read_text() if Path(env_file).exists() else ""
        if bin_dir not in existing:
            with open(env_file, "a") as f:
                f.write(f'export PATH="$PATH:{bin_dir}"\n')
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
    setup_env_file()


if __name__ == "__main__":
    main()
