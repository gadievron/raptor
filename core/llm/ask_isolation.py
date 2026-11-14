"""Trusted bootstrap for the opt-in single-provider keyless ask worker.

No OS isolation is claimed here. The worker receives public model metadata,
a dispatcher capability and prompt data, rather than provider keys or config.
"""

from __future__ import annotations

import json
import math
import os
import socket
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

from core.json import dumps_canonical
from core.llm.catalog import prepare_catalog
from core.llm.catalog_bootstrap import send_catalog
from core.llm.config import ModelConfig
from core.llm.dispatcher.auth import ProviderRule
from core.llm.dispatcher.server import LLMDispatcher
from core.llm.dispatcher.spawn import spawn_worker
from core.sandbox._capture import BoundedCommunicator

MAX_ASK_BYTES = 8 * 1024 * 1024


class IsolatedAskError(RuntimeError):
    """No implicit direct-auth fallback is allowed from this path."""


def _rule_for(model: ModelConfig) -> ProviderRule:
    from core.llm.detection import _sdk_available
    from core.llm.model_data import PROVIDER_ENDPOINTS

    sdk = {"anthropic": "ANTHROPIC_SDK_AVAILABLE", "gemini": "GENAI_SDK_AVAILABLE"}
    if (model.provider not in sdk or not model.enabled
            or not isinstance(model.api_key, str) or not model.api_key
            or model.api_base not in (None, PROVIDER_ENDPOINTS.get(model.provider))):
        raise IsolatedAskError("Keyless ask requires a standard Anthropic or Gemini API-key configuration")
    if (not model.model_name or not model.model_name[0].isascii()
            or not model.model_name[0].isalnum() or len(model.model_name) > 256
            or any(not char.isascii() or not (char.isalnum() or char in "._-")
                   for char in model.model_name)):
        raise IsolatedAskError("Keyless ask currently requires a simple provider model identifier")
    if not _sdk_available(sdk[model.provider]):
        raise IsolatedAskError("Keyless ask requires the provider's native SDK")
    if model.provider == "anthropic" and any(os.environ.get(name) for name in (
        "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
    )):
        raise IsolatedAskError("Custom Anthropic authentication or endpoints require the compatibility path")
    if model.provider == "gemini" and any(
        name.startswith("GOOGLE_") and name != "GOOGLE_API_KEY" for name in os.environ
    ):
        # Conservative development scope: do not reinterpret cloud/SDK routing
        # settings as a direct API-key setup. Ordinary asks retain that support.
        raise IsolatedAskError("Additional Google SDK setup requires the compatibility path")
    key = model.api_key  # Pin the selected entry's identity; never seed by provider order.
    if model.provider == "anthropic":
        return ProviderRule(
            name="anthropic", upstream_base_url="https://api.anthropic.com",
            inject_headers=lambda: {"x-api-key": key, "anthropic-version": "2023-06-01"},
        )
    return ProviderRule(
        name="gemini", upstream_base_url="https://generativelanguage.googleapis.com",
        inject_headers=lambda: {"x-goog-api-key": key},
    )


def decode_ask_response(raw: bytes, model: ModelConfig):
    """Validate bounded worker output before allowing it into CLI formatting."""
    from core.llm.providers import LLMResponse

    try:
        if len(raw) > MAX_ASK_BYTES:
            raise ValueError
        data = json.loads(raw)
        if type(data) is not dict or set(data) != {"content", "model", "provider", "tokens_used", "cost"}:
            raise ValueError
        if (not isinstance(data["content"], str) or data["model"] != model.model_name
                or data["provider"] != model.provider
                or type(data["tokens_used"]) is not int or data["tokens_used"] < 0
                or type(data["cost"]) not in (int, float) or data["cost"] < 0
                or data["cost"] > 2**53 - 1 or not math.isfinite(data["cost"])):
            raise ValueError
        return LLMResponse(**data, finish_reason="stop")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise IsolatedAskError("Invalid response from keyless ask worker") from None


def run_isolated_ask(model: ModelConfig, prompt: str, system_prompt: str | None,
                     *, max_tokens: int = 4096, temperature: float | None = None):
    """One free-form ask; explicitly selected provider/account, no model fallback."""
    from core.config import RaptorConfig

    if os.name != "posix":
        raise IsolatedAskError("Keyless ask descriptor handoff currently requires POSIX")
    rule = _rule_for(model)
    prepared = prepare_catalog([model])
    request = dumps_canonical({
        "prompt": prompt, "system_prompt": system_prompt,
        "max_tokens": max_tokens, "temperature": temperature,
    }).encode("utf-8")
    if len(request) > MAX_ASK_BYTES:
        raise IsolatedAskError("Keyless ask input exceeds size limit")
    env = RaptorConfig.get_safe_env(preserve_proxy=True)
    RaptorConfig.strip_llm_env_vars(env)
    for name in ("RAPTOR_CONFIG", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT"):
        env.pop(name, None)
    env["RAPTOR_LLM_QUIET"] = "1"
    # This worker has one generation capability and dies with its parent.
    # Proactive renewal would otherwise consume its one-request budget.
    env["RAPTOR_LLM_TOKEN_RENEW"] = "0"
    dispatcher = LLMDispatcher(
        run_id=f"ask-{uuid.uuid4().hex[:8]}", rules={rule.name: rule},
        token_budget=1, token_ttl_s=math.ceil(model.timeout + 20),
        generation_routes={model.provider: model.model_name},
    )
    proc = None
    capture = BoundedCommunicator(MAX_ASK_BYTES)
    try:
        with _catalog_pair() as pair:
            sender, receiver = pair
            proc = spawn_worker(
                dispatcher,
                [sys.executable, "-m", "core.llm.ask_worker", str(receiver.fileno())],
                label="keyless-ask", env=env, pass_fds=(receiver.fileno(),),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(Path(__file__).resolve().parents[2]),
            )
            receiver.close()
            send_catalog(sender, prepared.public)
            capture.attach(proc)
            out, _err = capture.communicate(input=request, timeout=model.timeout + 15)
            if proc.returncode != 0:
                raise IsolatedAskError("Keyless ask worker failed; no direct-auth fallback was attempted")
            return decode_ask_response(out, model)
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()
        dispatcher.shutdown()


@contextmanager
def _catalog_pair():
    sender, receiver = socket.socketpair()
    try:
        yield sender, receiver
    finally:
        sender.close()
        receiver.close()
