"""Read and write raptor's model configuration at ~/.config/raptor/models.json.

Schema (from raptor README):
    {
      "models": [
        {
          "provider": "anthropic" | "openai" | "gemini" | "mistral" | "ollama",
          "model": "<model-id>",
          "api_key": "<raw|${ENV_VAR}>",
          "role": "analysis" | "code" | "consensus" | "fallback"
        },
        …
      ]
    }

Raptor also respects these env vars as auto-detected fallbacks:
    ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, MISTRAL_API_KEY, OLLAMA_HOST
and a budget cap:
    RAPTOR_MAX_COST (float, dollars)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from packages.studio.config import RAPTOR_MODELS_CONFIG

ROLES = ("analysis", "code", "consensus", "fallback")

PROVIDERS = ("anthropic", "openai", "gemini", "mistral", "ollama")

# Env vars raptor auto-detects.
ENV_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai":    "OPENAI_API_KEY",
    "gemini":    "GEMINI_API_KEY",
    "mistral":   "MISTRAL_API_KEY",
    "ollama":    "OLLAMA_HOST",
}

ROLE_DESCRIPTIONS = {
    "analysis":  "Validates and analyses each finding (Stages A–D).",
    "code":      "Writes exploit PoCs and patch code.",
    "consensus": "Second-opinion vote on true positives.",
    "fallback":  "Used if the primary model fails or hits rate limits.",
}


@dataclass
class ModelEntry:
    provider: str = ""
    model: str = ""
    api_key: str = ""
    role: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"provider": self.provider, "model": self.model, "api_key": self.api_key}
        if self.role:
            d["role"] = self.role
        return d

    @property
    def api_key_display(self) -> str:
        if not self.api_key:
            return ""
        if self.api_key.startswith("${") and self.api_key.endswith("}"):
            return self.api_key  # env ref, safe to show
        return self.api_key[:4] + "…" + self.api_key[-4:] if len(self.api_key) > 8 else "••••••"


@dataclass
class ModelConfig:
    entries: list[ModelEntry] = field(default_factory=list)
    raw_path: Path = field(default_factory=lambda: RAPTOR_MODELS_CONFIG)

    def by_role(self, role: str) -> Optional[ModelEntry]:
        for entry in self.entries:
            if entry.role == role:
                return entry
        return None

    def env_fallback(self, provider: str) -> Optional[str]:
        var = ENV_VARS.get(provider)
        if not var:
            return None
        return os.environ.get(var)

    def to_dict(self) -> dict:
        return {"models": [e.to_dict() for e in self.entries]}


def load_models_config(path: Path = RAPTOR_MODELS_CONFIG) -> ModelConfig:
    if not path.is_file():
        return ModelConfig(entries=[], raw_path=path)
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return ModelConfig(entries=[], raw_path=path)

    entries: list[ModelEntry] = []
    for m in (data.get("models") or []):
        if not isinstance(m, dict):
            continue
        entries.append(
            ModelEntry(
                provider=m.get("provider", ""),
                model=m.get("model", ""),
                api_key=m.get("api_key", ""),
                role=m.get("role"),
            )
        )
    return ModelConfig(entries=entries, raw_path=path)


def save_models_config(config: ModelConfig, path: Path = RAPTOR_MODELS_CONFIG) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config.to_dict(), indent=2) + "\n")


def env_status() -> dict[str, dict]:
    """Snapshot which env vars are set, for the settings UI."""
    out: dict[str, dict] = {}
    for provider, var in ENV_VARS.items():
        val = os.environ.get(var)
        out[provider] = {
            "env_var": var,
            "is_set": bool(val),
            "display": "(set)" if val else "",
        }
    return out


def current_budget_cap() -> Optional[float]:
    raw = os.environ.get("RAPTOR_MAX_COST")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None
