#!/usr/bin/env python3
"""
RAPTOR startup display — prints banner and environment status.

Called by the /raptor skill. Writes output to .startup-output for the LLM to read.
"""

import os
import random
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))
OUTPUT_FILE = REPO_ROOT / ".startup-output"


def _read_logo() -> str:
    path = REPO_ROOT / "raptor-offset"
    return path.read_text().rstrip() if path.exists() else ""


def _read_random_quote() -> str:
    path = REPO_ROOT / "hackers-8ball"
    if path.exists():
        lines = [l.strip() for l in path.read_text().splitlines() if l.strip()]
        if lines:
            return random.choice(lines)
    return '"Hack the planet!"'


def _check_tools() -> tuple[list, list, set]:
    """Returns (results, warnings, unavailable_features)."""
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


def _check_llm() -> tuple[list, list]:
    """Returns (lines, warnings)."""
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


def _check_env(unavailable_features: set) -> tuple[list, list]:
    """Returns (env_parts, warnings)."""
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


def _format(logo, quote, tool_results, tool_warnings, llm_lines, llm_warnings, env_parts, env_warnings):
    lines = []

    if logo:
        lines.append(logo)
        lines.append("")

    # Tools
    tool_parts = [f"{name} {'\u2713' if ok else '\u2717'}" for name, ok in tool_results]
    lines.append(f" tools: {'  '.join(tool_parts)}")

    # Env
    lines.append(f"   env: {'  '.join(env_parts)}")

    # LLM
    lines.extend(llm_lines)

    # Warnings: unavailable first, then limited, then other
    all_raw = tool_warnings + env_warnings + llm_warnings
    ordered = (
        [w for w in all_raw if "unavailable" in w] +
        [w for w in all_raw if "limited" in w] +
        [w for w in all_raw if "unavailable" not in w and "limited" not in w]
    )
    if ordered:
        lines.append(f"  warn: {ordered[0]}")
        for w in ordered[1:]:
            lines.append(f"        {w}")

    lines.append("")
    lines.append("  For defensive security research, education, and authorized penetration testing.")
    lines.append("")
    lines.append(f"raptor:~$ {quote}")

    return "\n".join(lines)


def main():
    logo = _read_logo()
    quote = _read_random_quote()

    try:
        import logging
        logging.disable(logging.WARNING)

        tool_results, tool_warnings, unavailable = _check_tools()
        llm_lines, llm_warnings = _check_llm()
        env_parts, env_warnings = _check_env(unavailable)

        logging.disable(logging.NOTSET)

        output = _format(logo, quote, tool_results, tool_warnings, llm_lines, llm_warnings, env_parts, env_warnings)
    except Exception:
        output = f"{logo}\n\nraptor:~$ {quote}"

    OUTPUT_FILE.write_text(output)
    print(output)


if __name__ == "__main__":
    main()
