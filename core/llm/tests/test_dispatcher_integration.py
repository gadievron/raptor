"""Phase B integration tests: ``core/llm/providers.py`` + dispatcher.

Confirms each Provider's ``__init__`` takes the dispatcher route when
``RAPTOR_LLM_SOCKET`` is set in the worker's env, and the env-direct
fallback when it isn't. These prove the additive behaviour we relied
on for "Phase B can't break anything until Phase C".

The full subprocess-end-to-end is exercised in
``test_e2e_credentials_isolation_through_providers`` below.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading

import httpx
import pytest

from core.llm.config import ModelConfig
from core.llm.dispatcher.auth import CredentialStore, ProviderRule
from core.llm.dispatcher.server import LLMDispatcher


# ---------------------------------------------------------------------------
# Fixtures: dispatcher + captive upstream
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_creds():
    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {
        "anthropic": "test-anthropic-secret",
        "openai":    "test-openai-secret",
        "gemini":    "test-gemini-secret",
    }
    return creds


class _CaptiveUpstream:
    def __init__(self, body: bytes = b'{"ok":true}'):
        self.captured: dict = {}
        self._body = body
        outer = self

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw): return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                outer.captured["headers"] = {k: v for k, v in self.headers.items()}
                outer.captured["path"] = self.path
                outer.captured["body"] = body
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(outer._body)))
                self.end_headers()
                self.wfile.write(outer._body)

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _H)
        self.host, self.port = self._server.server_address
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


def _wired_dispatcher(creds, tmp_path, provider: str, upstream: _CaptiveUpstream):
    """Build a dispatcher with the chosen provider's upstream rewritten
    to the captive HTTP server. Returns the dispatcher."""
    d = LLMDispatcher(
        run_id=f"providers-{provider}",
        creds=creds,
        audit_path=tmp_path / "audit.jsonl",
        token_ttl_s=3600, token_budget=100,
    )
    original = d._rules[provider]
    d._rules[provider] = ProviderRule(
        name=original.name,
        upstream_base_url=upstream.base_url,
        inject_headers=original.inject_headers,
        strip_request_headers=original.strip_request_headers,
    )
    return d


# ---------------------------------------------------------------------------
# Dispatcher-route selection at provider __init__
# ---------------------------------------------------------------------------


class TestProviderRouteSelection:
    """Each Provider's ``__init__`` must pick the dispatcher path
    when ``RAPTOR_LLM_SOCKET`` is set, and the direct-SDK path
    otherwise. Tested without making a real LLM call by inspecting
    the constructed client's transport configuration."""

    def test_anthropic_provider_uses_dispatcher_when_socket_set(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        pytest.importorskip("anthropic")
        upstream = _CaptiveUpstream()
        d = _wired_dispatcher(fake_creds, tmp_path, "anthropic", upstream)
        try:
            _, fd = d.allocate_worker(label="ant-init")
            monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(d.socket_path))
            monkeypatch.setenv("RAPTOR_LLM_TOKEN_FD", str(fd))

            # Reset the worker-side token cache so this test sees the
            # fresh FD instead of one from a previous test.
            from core.llm.dispatcher import client as _client
            _client._cached_token = None

            from core.llm.providers import AnthropicProvider
            cfg = ModelConfig(provider="anthropic", model_name="claude-3-haiku-20240307")
            cfg.api_key = "should-not-be-used"
            provider = AnthropicProvider(cfg)

            # Dispatcher path constructs the client with a UDS transport;
            # the SDK's underlying httpx instance carries that.
            httpx_client = provider.client._client
            transport = httpx_client._transport
            assert isinstance(transport, httpx.HTTPTransport)
            # The SDK's base_url on the dispatcher path is the dummy http://_/...
            assert "http://_/anthropic" in str(provider.client.base_url)
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_anthropic_provider_uses_direct_sdk_when_no_socket(
        self, monkeypatch,
    ):
        pytest.importorskip("anthropic")
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        from core.llm.providers import AnthropicProvider
        cfg = ModelConfig(provider="anthropic", model_name="claude-3-haiku-20240307")
        cfg.api_key = "test-key"
        provider = AnthropicProvider(cfg)
        # Direct path: base_url is the real anthropic endpoint, NOT
        # the dispatcher's dummy host.
        assert "http://_/" not in str(provider.client.base_url)

    def test_openai_provider_uses_dispatcher_when_socket_set(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        pytest.importorskip("openai")
        upstream = _CaptiveUpstream()
        d = _wired_dispatcher(fake_creds, tmp_path, "openai", upstream)
        try:
            _, fd = d.allocate_worker(label="oai-init")
            monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(d.socket_path))
            monkeypatch.setenv("RAPTOR_LLM_TOKEN_FD", str(fd))
            from core.llm.dispatcher import client as _client
            _client._cached_token = None

            from core.llm.providers import OpenAICompatibleProvider
            cfg = ModelConfig(provider="openai", model_name="gpt-5")
            cfg.api_key = "should-not-be-used"
            provider = OpenAICompatibleProvider(cfg)
            assert "http://_/openai" in str(provider.client.base_url)
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_openai_compat_does_NOT_use_dispatcher_for_ollama(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        """Critical isolation: the OpenAI-compatible provider class
        is shared with Ollama, vLLM, LM Studio, etc. Those have no
        creds to isolate and a custom ``api_base``. Even with
        ``RAPTOR_LLM_SOCKET`` set, the dispatcher path must NOT be
        taken for ``provider != "openai"``."""
        pytest.importorskip("openai")
        upstream = _CaptiveUpstream()
        d = _wired_dispatcher(fake_creds, tmp_path, "openai", upstream)
        try:
            _, fd = d.allocate_worker(label="ollama-init")
            monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(d.socket_path))
            monkeypatch.setenv("RAPTOR_LLM_TOKEN_FD", str(fd))
            from core.llm.dispatcher import client as _client
            _client._cached_token = None

            from core.llm.providers import OpenAICompatibleProvider
            cfg = ModelConfig(
                provider="ollama",
                model_name="llama3.1:8b",
            )
            cfg.api_key = "unused"
            cfg.api_base = "http://localhost:11434/v1"
            provider = OpenAICompatibleProvider(cfg)
            # Direct path → base_url is the local Ollama endpoint
            assert "http://_/" not in str(provider.client.base_url)
            assert "11434" in str(provider.client.base_url)
        finally:
            upstream.shutdown()
            d.shutdown()

    def test_gemini_provider_uses_dispatcher_when_socket_set(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        pytest.importorskip("google.genai")
        upstream = _CaptiveUpstream()
        d = _wired_dispatcher(fake_creds, tmp_path, "gemini", upstream)
        try:
            _, fd = d.allocate_worker(label="gem-init")
            monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(d.socket_path))
            monkeypatch.setenv("RAPTOR_LLM_TOKEN_FD", str(fd))
            from core.llm.dispatcher import client as _client
            _client._cached_token = None

            from core.llm.providers import GeminiProvider
            cfg = ModelConfig(provider="gemini", model_name="gemini-2.5-pro")
            cfg.api_key = "should-not-be-used"
            provider = GeminiProvider(cfg)
            # Force lazy client construction
            client = provider.client
            # google-genai stores HttpOptions on _api_client.http_options
            base_url = client._api_client._http_options.base_url
            assert "http://_/gemini" in str(base_url)
        finally:
            upstream.shutdown()
            d.shutdown()


# ---------------------------------------------------------------------------
# End-to-end: real subprocess, no API keys in env, real anthropic SDK
# ---------------------------------------------------------------------------


class TestGrandchildRelay:
    """``raptor_agentic.py --sequential`` spawns
    ``packages/llm_analysis/agent.py`` as a subprocess that itself
    needs LLM access. Phase B's :func:`relay_for_grandchild` lets
    the parent-script pass its already-authenticated session down
    to the grandchild — same socket, same token, fresh inheritable
    FD. After Phase C drops API keys from env, this is the only
    way the grandchild can reach the LLM."""

    def test_relay_for_grandchild_returns_inheritable_fd_with_token(
        self, fake_creds, tmp_path, monkeypatch,
    ):
        d = LLMDispatcher(
            run_id="relay-test", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=60, token_budget=10,
        )
        try:
            _, parent_fd = d.allocate_worker(label="parent")
            monkeypatch.setenv("RAPTOR_LLM_SOCKET", str(d.socket_path))
            monkeypatch.setenv("RAPTOR_LLM_TOKEN_FD", str(parent_fd))
            from core.llm.dispatcher import client as _client
            _client._cached_token = None

            # Parent reads its own token via the cache (simulates
            # what AnthropicProvider did at startup).
            parent_token = _client._get_or_read_token()

            # Now relay to a grandchild: get a fresh FD with the
            # same token, ready for pass_fds=.
            sock, child_fd = _client.relay_for_grandchild()
            try:
                assert sock == str(d.socket_path)
                # FD is inheritable (so subprocess.Popen pass_fds works)
                assert os.get_inheritable(child_fd)
                # And carries the same token value
                relayed_token = os.read(child_fd, 64).decode().strip()
                assert relayed_token == parent_token
            finally:
                try:
                    os.close(child_fd)
                except OSError:
                    pass
        finally:
            d.shutdown()

    def test_grandchild_subprocess_uses_relayed_session(
        self, fake_creds, tmp_path,
    ):
        """End-to-end: parent worker spawned with token; parent
        relays to grandchild; grandchild makes an LLM call through
        the dispatcher; captive upstream sees real key injected."""
        pytest.importorskip("anthropic")
        anthropic_response = json.dumps({
            "id": "msg_grandchild",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-haiku-20240307",
            "content": [{"type": "text", "text": "from grandchild"}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 4, "output_tokens": 3},
        }).encode("utf-8")
        upstream = _CaptiveUpstream(body=anthropic_response)
        d = _wired_dispatcher(fake_creds, tmp_path, "anthropic", upstream)
        try:
            # Parent script: read inherited token, immediately relay
            # to a grandchild that's spawned inline. Mimics what
            # raptor_agentic.py does when it spawns agent.py with
            # the relayed session.
            parent_src = tmp_path / "parent_for_grandchild.py"
            parent_src.write_text(
                "import json, os, subprocess, sys\n"
                "from core.llm.dispatcher.client import relay_for_grandchild\n"
                "sock, child_fd = relay_for_grandchild()\n"
                "child_env = {\n"
                "    'PATH': os.environ.get('PATH', ''),\n"
                "    'PYTHONPATH': os.environ.get('PYTHONPATH', ''),\n"
                "    'RAPTOR_LLM_SOCKET': sock,\n"
                "    'RAPTOR_LLM_TOKEN_FD': str(child_fd),\n"
                "}\n"
                "rc = subprocess.call(\n"
                "    [sys.executable, sys.argv[1]],\n"
                "    env=child_env, pass_fds=(child_fd,),\n"
                ")\n"
                "try:\n"
                "    os.close(child_fd)\n"
                "except OSError:\n"
                "    pass\n"
                "sys.exit(rc)\n",
                encoding="utf-8",
            )
            grandchild_src = tmp_path / "grandchild.py"
            grandchild_src.write_text(
                "import json, os, sys\n"
                "for k in os.environ:\n"
                "    if 'API_KEY' in k or 'API_TOKEN' in k:\n"
                "        sys.exit(f'leaked key in env: {k}')\n"
                "from core.llm.config import ModelConfig\n"
                "from core.llm.providers import AnthropicProvider\n"
                "cfg = ModelConfig(provider='anthropic', model_name='claude-3-haiku-20240307')\n"
                "cfg.api_key = 'dummy'\n"
                "msg = AnthropicProvider(cfg).client.messages.create(\n"
                "    model='claude-3-haiku-20240307',\n"
                "    max_tokens=64,\n"
                "    messages=[{'role':'user','content':'gc'}],\n"
                ")\n"
                "sys.stdout.write(json.dumps({'id': msg.id, 'text': msg.content[0].text}))\n",
                encoding="utf-8",
            )

            from core.llm.dispatcher.spawn import spawn_worker
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )))
            proc = spawn_worker(
                d,
                cmd=[sys.executable, str(parent_src), str(grandchild_src)],
                label="parent-for-relay",
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": repo_root,
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # 30s rather than 20s: matches the timeout used by sibling
            # parent+grandchild subprocess tests in this file (lines
            # 573, 782) and gives parallel xdist runs enough headroom
            # for the 2-deep Python startup chain when CPUs are
            # contended by other workers.
            stdout, stderr = proc.communicate(timeout=30)
            assert proc.returncode == 0, (
                f"parent+grandchild chain failed: rc={proc.returncode} "
                f"stdout={stdout.decode()!r} stderr={stderr.decode()!r}"
            )

            # The grandchild's parsed response landed on stdout
            payload = json.loads(stdout.decode())
            assert payload["id"] == "msg_grandchild"
            assert payload["text"] == "from grandchild"

            # Real key was injected; dummy stripped; token not forwarded
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("x-api-key") == "test-anthropic-secret"
            assert "x-raptor-token" not in sent
        finally:
            upstream.shutdown()
            d.shutdown()


@pytest.fixture
def clear_detection_cache():
    """``detect_llm_availability`` caches its result at module scope.
    Tests that drive different cache values must clear it both before
    and after they run, otherwise they pollute later tests in the
    suite (observed: test_ollama_warning emits an extra "no LLM
    available" warning when our test left a False-cache behind)."""
    from core.llm import detection
    detection._cached_llm_availability = None
    try:
        yield
    finally:
        detection._cached_llm_availability = None


class TestPhaseBChainE2E:
    """Adversarial-grade end-to-end: simulate the full raptor.py →
    raptor_agentic.py → packages/llm_analysis/agent.py chain that
    Phase B is supposed to enable post-Phase-C.

    Three processes:
      1. **outer-parent** (this test) — owns the dispatcher and the
         only credentials. No API keys are ever written into a
         child's environment.
      2. **child** — like raptor_agentic.py: builds a real
         ``AnthropicProvider`` to confirm the in-process LLM path
         works, AND relays its session to a grandchild.
      3. **grandchild** — like agent.py in --sequential mode: builds
         its own ``AnthropicProvider`` and makes an LLM call.

    Asserts the credential-isolation invariants hold across the
    whole chain — not just the leaf — and that ``detect_llm_availability``
    correctly reports ``external_llm=True`` in the grandchild despite
    no API keys in env.
    """

    def test_full_chain_no_api_keys_anywhere(self, fake_creds, tmp_path):
        # Skip if any required SDK is missing (CI containers vary)
        pytest.importorskip("anthropic")

        # Captive upstream that records every request hit
        anthropic_response = json.dumps({
            "id": "msg_chain",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-haiku-20240307",
            "content": [{"type": "text", "text": "chain works"}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 4, "output_tokens": 3},
        }).encode("utf-8")

        # Need to track which process made each request (parent vs
        # grandchild) — capture all of them so we can count.
        all_requests: list[dict] = []
        body_holder = [anthropic_response]
        outer_lock = threading.Lock()

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw): return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                with outer_lock:
                    all_requests.append({
                        "headers": {k: v for k, v in self.headers.items()},
                        "path": self.path,
                        "body": body,
                    })
                resp = body_holder[0]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        upstream_server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        upstream_thread = threading.Thread(
            target=upstream_server.serve_forever, daemon=True,
        )
        upstream_thread.start()
        upstream_base = f"http://{upstream_server.server_address[0]}:{upstream_server.server_address[1]}"

        d = LLMDispatcher(
            run_id="chain-e2e", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=120, token_budget=20,
        )
        original = d._rules["anthropic"]
        d._rules["anthropic"] = ProviderRule(
            name=original.name,
            upstream_base_url=upstream_base,
            inject_headers=original.inject_headers,
            strip_request_headers=original.strip_request_headers,
        )

        try:
            from core.llm.dispatcher.spawn import spawn_worker
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )))

            # ---- grandchild: imports providers, makes LLM call ----
            grandchild_src = tmp_path / "chain_grandchild.py"
            grandchild_src.write_text(
                "import json, os, sys\n"
                # No API key may be in our env
                "for k in os.environ:\n"
                "    if 'API_KEY' in k or 'API_TOKEN' in k:\n"
                "        sys.exit(f'GC: leaked key in env: {k}')\n"
                # detect_llm_availability MUST return external_llm=True
                # in the grandchild despite no keys, because dispatcher
                # socket is set
                "from core.llm.detection import detect_llm_availability, _cached_llm_availability\n"
                "import core.llm.detection as _det\n"
                "_det._cached_llm_availability = None\n"
                "av = detect_llm_availability()\n"
                "if not av.external_llm:\n"
                "    sys.exit(f'GC: detect_llm_availability said external_llm=False')\n"
                # Build a real AnthropicProvider, make a call
                "from core.llm.config import ModelConfig\n"
                "from core.llm.providers import AnthropicProvider\n"
                "cfg = ModelConfig(provider='anthropic', model_name='claude-3-haiku-20240307')\n"
                "cfg.api_key = 'gc-dummy'\n"
                "msg = AnthropicProvider(cfg).client.messages.create(\n"
                "    model='claude-3-haiku-20240307',\n"
                "    max_tokens=64,\n"
                "    messages=[{'role':'user','content':'gc'}],\n"
                ")\n"
                "sys.stdout.write(json.dumps({'who':'grandchild','id':msg.id,'text':msg.content[0].text}))\n",
                encoding="utf-8",
            )

            # ---- child: builds Provider locally + relays to grandchild ----
            child_src = tmp_path / "chain_child.py"
            child_src.write_text(
                "import json, os, subprocess, sys\n"
                # No API keys here either
                "for k in os.environ:\n"
                "    if 'API_KEY' in k or 'API_TOKEN' in k:\n"
                "        sys.exit(f'C: leaked key in env: {k}')\n"
                # In-process LLM call (Phase 4 orchestration shape)
                "from core.llm.config import ModelConfig\n"
                "from core.llm.providers import AnthropicProvider\n"
                "cfg = ModelConfig(provider='anthropic', model_name='claude-3-haiku-20240307')\n"
                "cfg.api_key = 'c-dummy'\n"
                "msg = AnthropicProvider(cfg).client.messages.create(\n"
                "    model='claude-3-haiku-20240307',\n"
                "    max_tokens=64,\n"
                "    messages=[{'role':'user','content':'c'}],\n"
                ")\n"
                "sys.stderr.write(json.dumps({'who':'child','id':msg.id,'text':msg.content[0].text}) + '\\n')\n"
                # Relay to grandchild — same socket, fresh FD with same token
                "from core.llm.dispatcher.client import relay_for_grandchild\n"
                "sock, child_fd = relay_for_grandchild()\n"
                "gc_env = {\n"
                "    'PATH': os.environ.get('PATH',''),\n"
                "    'PYTHONPATH': os.environ.get('PYTHONPATH',''),\n"
                "    'RAPTOR_LLM_SOCKET': sock,\n"
                "    'RAPTOR_LLM_TOKEN_FD': str(child_fd),\n"
                "}\n"
                "rc = subprocess.call(\n"
                "    [sys.executable, sys.argv[1]],\n"
                "    env=gc_env, pass_fds=(child_fd,),\n"
                ")\n"
                "try: os.close(child_fd)\n"
                "except OSError: pass\n"
                "sys.exit(rc)\n",
                encoding="utf-8",
            )

            # ---- spawn the child via the dispatcher (mimics _run_script) ----
            proc = spawn_worker(
                d,
                cmd=[sys.executable, str(child_src), str(grandchild_src)],
                label="chain-child",
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": repo_root,
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=30)
            assert proc.returncode == 0, (
                f"chain failed: rc={proc.returncode}\n"
                f"stdout={stdout.decode()!r}\nstderr={stderr.decode()!r}"
            )

            # ---- grandchild's parsed response landed on stdout ----
            gc_payload = json.loads(stdout.decode().strip())
            assert gc_payload["who"] == "grandchild"
            assert gc_payload["id"] == "msg_chain"
            assert gc_payload["text"] == "chain works"

            # Child's own response landed on stderr (we used stderr to
            # not collide with the grandchild's stdout pass-through)
            child_lines = [l for l in stderr.decode().splitlines()
                           if l.startswith("{")]
            assert len(child_lines) == 1, f"child output not found: {stderr.decode()!r}"
            c_payload = json.loads(child_lines[0])
            assert c_payload["who"] == "child"
            assert c_payload["id"] == "msg_chain"

            # ---- TWO upstream requests (one from child, one from grandchild) ----
            assert len(all_requests) == 2, (
                f"expected 2 upstream requests (child + grandchild), got {len(all_requests)}"
            )

            # ---- credential-isolation invariants on EVERY request ----
            for i, req in enumerate(all_requests):
                sent = {k.lower(): v for k, v in req["headers"].items()}
                assert sent.get("x-api-key") == "test-anthropic-secret", (
                    f"request {i}: real key not injected, got: {sent.get('x-api-key')!r}"
                )
                # Each child uses a different dummy api_key; both must
                # have been stripped before the dispatcher forwarded
                assert sent.get("x-api-key") not in ("c-dummy", "gc-dummy")
                # Capability token must NEVER reach upstream
                assert "x-raptor-token" not in sent, (
                    f"request {i}: capability token leaked upstream"
                )
                # Anthropic-version header was injected by the rule
                assert sent.get("anthropic-version") == "2023-06-01"

            # ---- audit log captured the dispatch events ----
            audit_lines = [
                json.loads(l)
                for l in (tmp_path / "audit.jsonl").read_text().splitlines()
            ]
            dispatched = [a for a in audit_lines if a["event"] == "request.dispatch"]
            assert len(dispatched) == 2, (
                f"expected 2 dispatch events in audit, got {len(dispatched)}"
            )
            # Both should reference the same worker_label (child) since
            # we relayed the token (same token-id prefix). This proves
            # the relay used the same token rather than minting a new
            # one — important for the "α (relax single-use)" decision.
            assert dispatched[0]["token_id"] == dispatched[1]["token_id"]
            assert dispatched[0]["worker_label"] == dispatched[1]["worker_label"]
        finally:
            upstream_server.shutdown()
            upstream_server.server_close()
            d.shutdown()


class TestPhaseBChainE2EGemini:
    """Gemini-specific full-chain E2E. Mirrors :class:`TestPhaseBChainE2E`
    but exercises the ``google.genai`` SDK path through the dispatcher
    end-to-end — operators with only ``GEMINI_API_KEY`` configured (no
    Anthropic) need this to verify the Gemini wiring works in practice,
    not just at construction time. Uses a captive HTTP server so no
    real API key is needed."""

    def test_full_chain_gemini_no_api_keys_anywhere(self, fake_creds, tmp_path):
        pytest.importorskip("google.genai")

        # Minimal valid GenerateContentResponse the SDK can parse
        gemini_response = json.dumps({
            "candidates": [{
                "content": {
                    "parts": [{"text": "gemini chain works"}],
                    "role": "model",
                },
                "finishReason": "STOP",
            }],
            "usageMetadata": {
                "promptTokenCount": 1,
                "candidatesTokenCount": 4,
                "totalTokenCount": 5,
            },
        }).encode("utf-8")

        all_requests: list[dict] = []
        outer_lock = threading.Lock()

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw): return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                with outer_lock:
                    all_requests.append({
                        "headers": {k: v for k, v in self.headers.items()},
                        "path": self.path,
                        "body": body,
                    })
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(gemini_response)))
                self.end_headers()
                self.wfile.write(gemini_response)

        upstream_server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        upstream_thread = threading.Thread(
            target=upstream_server.serve_forever, daemon=True,
        )
        upstream_thread.start()
        upstream_base = (
            f"http://{upstream_server.server_address[0]}:"
            f"{upstream_server.server_address[1]}"
        )

        d = LLMDispatcher(
            run_id="chain-e2e-gemini", creds=fake_creds,
            audit_path=tmp_path / "audit.jsonl",
            token_ttl_s=120, token_budget=20,
        )
        original = d._rules["gemini"]
        d._rules["gemini"] = ProviderRule(
            name=original.name,
            upstream_base_url=upstream_base,
            inject_headers=original.inject_headers,
            strip_request_headers=original.strip_request_headers,
        )

        try:
            from core.llm.dispatcher.spawn import spawn_worker
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )))

            grandchild_src = tmp_path / "gemini_grandchild.py"
            grandchild_src.write_text(
                "import json, os, sys\n"
                "for k in os.environ:\n"
                "    if 'API_KEY' in k or 'API_TOKEN' in k:\n"
                "        sys.exit(f'GC: leaked key in env: {k}')\n"
                # Build GeminiProvider (production path) and call it
                "from core.llm.config import ModelConfig\n"
                "from core.llm.providers import GeminiProvider\n"
                "cfg = ModelConfig(provider='gemini', model_name='gemini-2.5-pro')\n"
                "cfg.api_key = 'gc-dummy'\n"
                # GeminiProvider lazy-builds .client on first access
                "client = GeminiProvider(cfg).client\n"
                "resp = client.models.generate_content(\n"
                "    model='gemini-2.5-pro', contents='gc'\n"
                ")\n"
                # Pull the parsed text out — proves SDK got back a valid response
                "text = resp.candidates[0].content.parts[0].text\n"
                "sys.stdout.write(json.dumps({'who':'grandchild','text':text}))\n",
                encoding="utf-8",
            )

            child_src = tmp_path / "gemini_child.py"
            child_src.write_text(
                "import json, os, subprocess, sys\n"
                "for k in os.environ:\n"
                "    if 'API_KEY' in k or 'API_TOKEN' in k:\n"
                "        sys.exit(f'C: leaked key in env: {k}')\n"
                # In-process Gemini call
                "from core.llm.config import ModelConfig\n"
                "from core.llm.providers import GeminiProvider\n"
                "cfg = ModelConfig(provider='gemini', model_name='gemini-2.5-pro')\n"
                "cfg.api_key = 'c-dummy'\n"
                "client = GeminiProvider(cfg).client\n"
                "resp = client.models.generate_content(\n"
                "    model='gemini-2.5-pro', contents='c'\n"
                ")\n"
                "text = resp.candidates[0].content.parts[0].text\n"
                "sys.stderr.write(json.dumps({'who':'child','text':text}) + '\\n')\n"
                # Relay session to grandchild
                "from core.llm.dispatcher.client import relay_for_grandchild\n"
                "sock, child_fd = relay_for_grandchild()\n"
                "gc_env = {\n"
                "    'PATH': os.environ.get('PATH',''),\n"
                "    'PYTHONPATH': os.environ.get('PYTHONPATH',''),\n"
                "    'RAPTOR_LLM_SOCKET': sock,\n"
                "    'RAPTOR_LLM_TOKEN_FD': str(child_fd),\n"
                "}\n"
                "rc = subprocess.call(\n"
                "    [sys.executable, sys.argv[1]],\n"
                "    env=gc_env, pass_fds=(child_fd,),\n"
                ")\n"
                "try: os.close(child_fd)\n"
                "except OSError: pass\n"
                "sys.exit(rc)\n",
                encoding="utf-8",
            )

            proc = spawn_worker(
                d,
                cmd=[sys.executable, str(child_src), str(grandchild_src)],
                label="chain-child-gemini",
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": repo_root,
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=30)
            assert proc.returncode == 0, (
                f"Gemini chain failed: rc={proc.returncode}\n"
                f"stdout={stdout.decode()!r}\nstderr={stderr.decode()!r}"
            )

            # Grandchild's parsed Gemini response on stdout
            gc_payload = json.loads(stdout.decode().strip())
            assert gc_payload["who"] == "grandchild"
            assert gc_payload["text"] == "gemini chain works"

            # Child's parsed Gemini response on stderr
            child_lines = [l for l in stderr.decode().splitlines()
                           if l.startswith("{")]
            assert len(child_lines) == 1, f"child output not found: {stderr.decode()!r}"
            c_payload = json.loads(child_lines[0])
            assert c_payload["who"] == "child"
            assert c_payload["text"] == "gemini chain works"

            # TWO upstream requests — child + grandchild
            assert len(all_requests) == 2, (
                f"expected 2 upstream requests, got {len(all_requests)}"
            )

            # Credential-isolation invariants on every request
            for i, req in enumerate(all_requests):
                sent = {k.lower(): v for k, v in req["headers"].items()}
                # Real Gemini key injected
                assert sent.get("x-goog-api-key") == "test-gemini-secret", (
                    f"request {i}: Gemini key not injected, got: "
                    f"{sent.get('x-goog-api-key')!r}"
                )
                # Worker-supplied dummies must NOT have flowed upstream
                assert sent.get("x-goog-api-key") not in ("c-dummy", "gc-dummy")
                # Capability token never reaches upstream
                assert "x-raptor-token" not in sent
                # Path was rewritten correctly: dispatcher strips
                # ``/gemini`` prefix; upstream sees the API path proper
                assert req["path"].startswith("/v1beta/models/")

            # Audit confirms two dispatch events sharing one token
            audit_lines = [
                json.loads(l)
                for l in (tmp_path / "audit.jsonl").read_text().splitlines()
            ]
            dispatched = [a for a in audit_lines if a["event"] == "request.dispatch"]
            assert len(dispatched) == 2
            assert dispatched[0]["token_id"] == dispatched[1]["token_id"]
        finally:
            upstream_server.shutdown()
            upstream_server.server_close()
            d.shutdown()


class TestDetectLLMAvailabilityRecognizesDispatcher:
    """``detect_llm_availability`` is consulted by Phase 4 of
    raptor_agentic.py and the prep-only decision in agent.py. After
    Phase C, env has no API keys but ``RAPTOR_LLM_SOCKET`` is set;
    this must still report ``external_llm=True`` so the LLM-using
    branches don't silently degrade to ClaudeCodeProvider."""

    def test_external_llm_true_when_dispatcher_socket_set(
        self, monkeypatch, clear_detection_cache,
    ):
        from core.llm import detection
        for k in (
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
            "GEMINI_API_KEY", "MISTRAL_API_KEY",
        ):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/whatever-not-used.sock")

        result = detection.detect_llm_availability()
        assert result.external_llm is True
        assert result.llm_available is True

    def test_external_llm_false_without_dispatcher_or_keys(
        self, monkeypatch, clear_detection_cache,
    ):
        from core.llm import detection
        for k in (
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
            "GEMINI_API_KEY", "MISTRAL_API_KEY",
            "RAPTOR_LLM_SOCKET",
        ):
            monkeypatch.delenv(k, raising=False)
        # Stub out ollama / config-file checks so this test is
        # hermetic (no /etc/raptor/llm-models.toml dependency, no
        # localhost:11434 reachability dependency).
        monkeypatch.setattr(detection, "_config_has_keyed_models", lambda: False)
        monkeypatch.setattr(detection, "_get_available_ollama_models", lambda: [])

        result = detection.detect_llm_availability()
        assert result.external_llm is False


class TestEndToEndCredentialIsolationThroughProviders:
    """The "we got Phase B right" signal: a subprocess instantiates
    ``AnthropicProvider`` (the production path), no API key in env,
    LLM call succeeds, and the captive upstream confirms the
    dispatcher injected real creds.

    Mirrors the existing dispatcher subprocess test but proves the
    integration via the production provider class (``AnthropicProvider``
    in ``core/llm/providers.py``) — i.e. the actual code RAPTOR analysis
    scripts run."""

    def test_subprocess_via_anthropic_provider_no_env_key(self, fake_creds, tmp_path):
        pytest.importorskip("anthropic")
        anthropic_response = json.dumps({
            "id": "msg_e2e_b",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-haiku-20240307",
            "content": [{"type": "text", "text": "phase B works"}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 4, "output_tokens": 3},
        }).encode("utf-8")
        upstream = _CaptiveUpstream(body=anthropic_response)
        d = _wired_dispatcher(fake_creds, tmp_path, "anthropic", upstream)

        try:
            from core.llm.dispatcher.spawn import spawn_worker

            # Worker imports core.llm.providers.AnthropicProvider, builds
            # a ModelConfig, calls .generate() — exactly the production
            # path. Worker fail-fasts if any LLM API key is in its env.
            worker_src = tmp_path / "phase_b_worker.py"
            worker_src.write_text(
                "import json, os, sys\n"
                "for k in os.environ:\n"
                "    if 'API_KEY' in k or 'API_TOKEN' in k:\n"
                "        sys.exit(f'leaked key in env: {k}')\n"
                "from core.llm.config import ModelConfig\n"
                "from core.llm.providers import AnthropicProvider\n"
                "cfg = ModelConfig(provider='anthropic', model_name='claude-3-haiku-20240307')\n"
                "cfg.api_key = 'dummy-not-used'\n"
                "p = AnthropicProvider(cfg)\n"
                "msg = p.client.messages.create(\n"
                "    model='claude-3-haiku-20240307',\n"
                "    max_tokens=64,\n"
                "    messages=[{'role':'user','content':'hi'}],\n"
                ")\n"
                "sys.stdout.write(json.dumps({'id': msg.id, 'text': msg.content[0].text}))\n",
                encoding="utf-8",
            )

            # Repo root: this file is at core/llm/tests/test_dispatcher_integration.py
            # so four dirname() calls reach the repo root.
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )))
            proc = spawn_worker(
                d,
                cmd=[sys.executable, str(worker_src)],
                label="phase-b-e2e",
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": repo_root,
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=15)
            assert proc.returncode == 0, (
                f"worker failed: rc={proc.returncode} "
                f"stdout={stdout.decode()!r} stderr={stderr.decode()!r}"
            )

            # SDK parsed the response from the captive upstream
            payload = json.loads(stdout.decode())
            assert payload["id"] == "msg_e2e_b"
            assert payload["text"] == "phase B works"

            # Real key injected on the wire; dummy stripped
            sent = {k.lower(): v for k, v in upstream.captured["headers"].items()}
            assert sent.get("x-api-key") == "test-anthropic-secret"
            assert sent.get("x-api-key") != "dummy-not-used"
            assert "x-raptor-token" not in sent
        finally:
            upstream.shutdown()
            d.shutdown()
