"""Validated, bundled registry of static-auth model gateways.

Stdlib-only leaf: configuration and security code import this without
initialising provider SDKs (the LLM package exports are lazy). Read once before sandbox children are forked.
The registry is installation data, never loaded from a scanned project.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from core.json import load_json_with_comments
from core.llm.model_brokers._env_ownership import python_credential_names


@dataclass(frozen=True)
class ModelBroker:
    name: str
    upstream_base_url: str
    api_path: str
    protocol: str = "openai"
    auth_scheme: str = "Bearer"
    credential_suffix: str = "API_KEY"

    @property
    def api_key_env(self) -> str:
        # Python derives the name; JSON cannot redirect credential lookup.
        return f"{self.name.upper()}_{self.credential_suffix}"

    @property
    def api_base(self) -> str:
        return self.upstream_base_url + self.api_path


# Python owns the native namespace. JSON cannot override providers or borrow
# their credentials, including aliases used by model-family resolution.
NATIVE_PROVIDER_NAMES = frozenset({
    "anthropic", "claude", "openai", "gemini", "google", "cohere", "mistral",
    "mistralai", "azure", "azure_openai", "bedrock", "vertex", "vertexai",
    "ollama", "claudecode", "claude_code", "claudecode_resumable",
    "meta", "meta_llama", "qwen", "deepseek", "yi", "phi",
    "claudecode-resumable", "claude-code", "claude-code-resumable",
    "claude_code_resumable",
})


def read_broker_key(broker: ModelBroker, *, consume: bool = False) -> str | None:
    """Read only the broker's derived credential; consume it in the parent."""
    _validate_credential_owner(broker)
    read = os.environ.pop if consume else os.environ.get
    return read(broker.api_key_env, None)


def _validate_credential_owner(broker: ModelBroker) -> None:
    if broker.api_key_env in python_credential_names():
        raise ValueError(f"Broker credential conflicts with Python-owned environment variable: {broker.api_key_env}")


def load_model_brokers(path: Path) -> tuple[ModelBroker, ...]:
    """Reject malformed registry data at startup, before handling credentials."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{path}: duplicate field {key!r}")
            result[key] = value
        return result

    data = load_json_with_comments(path, object_pairs_hook=unique_object)
    if (not isinstance(data, dict) or set(data) != {"version", "brokers"}
            or type(data["version"]) is not int or data["version"] != 1
            or not isinstance(data["brokers"], list)):
        raise ValueError(f"{path}: expected version 1 broker registry")
    brokers = []
    names = set()
    fields = set(ModelBroker.__dataclass_fields__)
    for entry in data["brokers"]:
        if (not isinstance(entry, dict) or set(entry) - fields
                or not fields - {"protocol", "auth_scheme", "credential_suffix"} <= set(entry)):
            raise ValueError(f"{path}: broker requires name, upstream_base_url and api_path; allowed fields: {sorted(fields)}")
        if any(not isinstance(entry[key], str) for key in entry):
            raise ValueError(f"{path}: broker text fields must be strings")
        broker = ModelBroker(**entry)
        if broker.auth_scheme not in {"Bearer", "Token"}:
            raise ValueError(f"{path}: auth_scheme must be Bearer or Token")
        if broker.credential_suffix not in {"API_KEY", "API_TOKEN"}:
            raise ValueError(f"{path}: credential_suffix must be API_KEY or API_TOKEN")
        if (not re.fullmatch(r"[a-z][a-z0-9_]*", broker.name)
                or broker.name in NATIVE_PROVIDER_NAMES or broker.name in names):
            raise ValueError(f"{path}: invalid, reserved or duplicate broker name {broker.name!r}")
        _validate_credential_owner(broker)
        url = urlsplit(broker.upstream_base_url)
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.password is not None or url.path or url.query or url.fragment
                or any(c.isspace() for c in broker.upstream_base_url)
                or "?" in broker.upstream_base_url or "#" in broker.upstream_base_url):
            raise ValueError(f"{path}: {broker.name} upstream must be a bare HTTPS origin")
        # Accessing port also rejects malformed/non-numeric/out-of-range ports.
        _ = url.port
        if broker.protocol not in {"openai", "http"}:
            raise ValueError(f"{path}: unsupported protocol for {broker.name}")
        if broker.api_path and not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+", broker.api_path):
            raise ValueError(f"{path}: api_path must be an absolute path without URL components")
        names.add(broker.name)
        brokers.append(broker)
    return tuple(brokers)


BROKER_REGISTRY_ERROR: str | None = None
try:
    MODEL_BROKERS = load_model_brokers(Path(__file__).with_name("registry.json"))
except (OSError, ValueError) as exc:
    # A broken optional catalog must not disable native providers or tools.
    # Disable the whole catalog rather than accepting a partial routing table.
    MODEL_BROKERS = ()
    BROKER_REGISTRY_ERROR = str(exc)
    logging.getLogger(__name__).error("Model broker registry disabled: %s", exc)


def model_broker(name: str) -> ModelBroker | None:
    """Return a validated broker; native Python provider names always win."""
    if not isinstance(name, str) or not name or name.lower() in NATIVE_PROVIDER_NAMES:
        return None
    if BROKER_REGISTRY_ERROR is not None:
        raise RuntimeError(f"Model broker registry is unavailable: {BROKER_REGISTRY_ERROR}")
    return next((broker for broker in MODEL_BROKERS if broker.name == name.lower()), None)
