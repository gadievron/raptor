"""Fresh-process keyless ask execution using only an inherited public catalog."""

from __future__ import annotations

import json
import logging
import math
import os
import socket
import sys

from core.json import dumps_canonical
from core.llm.catalog import llm_config_from_catalog
from core.llm.catalog_bootstrap import receive_catalog

_MAX_BYTES = 8 * 1024 * 1024


def execute_request(catalog, raw: bytes):
    from core.llm.transcript import build_llm_client

    if not os.environ.get("RAPTOR_LLM_SOCKET") or not os.environ.get("RAPTOR_LLM_TOKEN_FD"):
        raise ValueError("Missing keyless ask proxy capability")
    if len(catalog.routes) != 1 or len(raw) > _MAX_BYTES:
        raise ValueError("Expected a bounded single-route ask")
    request = json.loads(raw)
    if type(request) is not dict or set(request) != {"prompt", "system_prompt", "max_tokens", "temperature"}:
        raise ValueError("Invalid keyless ask request")
    if (not isinstance(request["prompt"], str) or not request["prompt"].strip()
            or request["system_prompt"] is not None and not isinstance(request["system_prompt"], str)
            or type(request["max_tokens"]) is not int or not 0 < request["max_tokens"] <= 2**31 - 1):
        raise ValueError("Invalid keyless ask prompt or token limit")
    temp = request["temperature"]
    if temp is not None and (type(temp) not in (int, float) or temp < 0 or temp > 2
                             or not math.isfinite(temp)):
        raise ValueError("Invalid keyless ask temperature")
    config = llm_config_from_catalog(catalog, catalog.routes[0].route_id)
    client = build_llm_client(config, catalog=catalog)
    kwargs = {"model_config": config.primary_model, "max_tokens": request["max_tokens"]}
    if temp is not None:
        kwargs["temperature"] = temp
    return client.generate(request["prompt"], system_prompt=request["system_prompt"], **kwargs)


def main() -> int:
    logging.disable(logging.CRITICAL)
    try:
        if len(sys.argv) != 2:
            raise ValueError("Expected catalog descriptor")
        with socket.socket(fileno=int(sys.argv[1])) as bootstrap:
            catalog = receive_catalog(bootstrap)
        response = execute_request(catalog, sys.stdin.buffer.read(_MAX_BYTES + 1))
        payload = dumps_canonical({
            "content": response.content, "model": response.model,
            "provider": response.provider, "tokens_used": response.tokens_used,
            "cost": response.cost,
        }).encode("utf-8")
        if len(payload) > _MAX_BYTES:
            raise ValueError("Keyless ask response too large")
        sys.stdout.buffer.write(payload)
        return 0
    except Exception:
        # Never echo prompts, raw input, provider headers or private exceptions.
        sys.stderr.write("keyless ask worker failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
