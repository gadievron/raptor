"""Operator settings for trusted RAPTOR dispatch across Codex shell filtering.

Reuse RAPTOR's credential and routing vocabularies. Never copy a whole host
environment, shell startup controls, or dispatcher FD credentials. Values
stay in the broker environment and private transient replies, not persistent
session context or launcher argv.
"""
import os

from core.config import RaptorConfig

_SESSION_KEYS = frozenset({
    'RAPTOR_DIR', 'RAPTOR_SESSION_PID', 'RAPTOR_SESSION_TOKEN',
    'RAPTOR_CODEX_CONTEXT_ID', 'RAPTOR_REGISTRY_HOME',
})
_NAMES = frozenset({
    'RAPTOR_CONFIG',
    *(key for key in RaptorConfig.SAFE_ENV_ALLOWLIST
      if key.startswith('RAPTOR_') and key not in _SESSION_KEYS),
    *RaptorConfig.LLM_API_KEY_VARS,
    *RaptorConfig.LLM_ROUTING_ENV_VARS,
    *RaptorConfig.PROXY_ENV_VARS,
})


def allowed_name(name):
    return isinstance(name, str) and '\0' not in name and '=' not in name and (
        name in _NAMES or name.startswith(RaptorConfig.LLM_ROUTING_ENV_PREFIXES))


def snapshot():
    return {key: value for key, value in os.environ.items() if allowed_name(key)}


def install(values):
    """Replace this process's settings, including values absent at launch."""
    for key in list(os.environ):
        if allowed_name(key):
            os.environ.pop(key)
    os.environ.update({key: value for key, value in values.items() if allowed_name(key)})
