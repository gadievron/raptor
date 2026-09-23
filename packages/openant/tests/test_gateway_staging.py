"""Dispatcher-gateway posture for the OpenAnt child (keyless hosts).

Contract under test: when the operator has NO direct Anthropic
credential to hand the child AND this process runs under the RAPTOR
LLM dispatcher, the scan stages a RAPTOR-owned ``raptor-gateway``
provider entry (scoped child token as api_key, the dispatcher's
loopback plane as base_url) and binds the ``raptor-<model>`` profile
to it; the direct-credential posture keeps the pre-gateway behavior
byte-for-byte. Token lifecycle: minted scoped to the scan, present
ONLY inside the staged config (which the scrub removes), revoked
server-side on every exit path, and never logged or reported.

The unit half mocks the dispatcher client at the scanner's import
sites; the integration half runs a REAL ``LLMDispatcher`` with a
captive upstream (no LLM, no network) and proves the staged
credentials authenticate on the loopback plane with the pinned
adapter's wire dialect — and stop authenticating after settlement.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from packages.openant.config import OpenAntConfig
from packages.openant.scanner import (
    _GATEWAY_BUDGET_USD,
    _GATEWAY_PROVIDER_NAME,
    _GATEWAY_REQUEST_BUDGET,
    _GATEWAY_TTL_SLACK_S,
    _OPENANT_LLM_PHASES,
    _OPENANT_MODEL_IDS,
    _XDG_STAGE_DIRNAME,
    _operator_has_direct_credential,
)

_TOKEN = "gw-secret-token-NEVER-LOGGED"
_TOKEN_ID = "cafe0123deadbeef"
_PORT = 45555


def _minted(**over) -> dict:
    base = {
        "token": _TOKEN, "token_id": _TOKEN_ID,
        "expires_at": 4102444800.0,
        "budget_usd": _GATEWAY_BUDGET_USD,
        "request_budget": _GATEWAY_REQUEST_BUDGET,
    }
    base.update(over)
    return base


def _make_fake_core(tmp: Path) -> Path:
    core_dir = tmp / "libs" / "openant-core"
    marker = core_dir / "core"
    marker.mkdir(parents=True)
    (marker / "scanner.py").touch()
    return core_dir


def _staged_config(out_dir: Path) -> dict:
    path = out_dir / _XDG_STAGE_DIRNAME / "openant" / "config.json"
    return json.loads(path.read_text())


class _GatewayHarness(unittest.TestCase):
    """Shared plumbing: a fake core/out_dir plus the four dispatcher
    client seams patched at the scanner's (function-level) import
    sites. Each test drives ``run_openant_scan`` with a fake
    ``core.sandbox.context.run``."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.base = Path(self._td.name)
        self.addCleanup(self._td.cleanup)
        self.core = _make_fake_core(self.base)
        self.out = self.base / "out"
        self.out.mkdir()
        self.config = OpenAntConfig(core_path=self.core)
        self.mint_calls: list = []
        self.revoke_calls: list = []
        self.loopback_calls: list = []
        self.spend_calls: list = []

    def _patches(self, *, mint_raises: Exception | None = None):
        def fake_loopback(**kw):
            self.loopback_calls.append(kw)
            if mint_raises is not None:
                raise mint_raises
            return _PORT

        def fake_mint(**kw):
            self.mint_calls.append(kw)
            return _minted(
                token=f"{_TOKEN}-{len(self.mint_calls)}",
                token_id=f"{_TOKEN_ID}{len(self.mint_calls)}",
            )

        def fake_revoke(token_id, **kw):
            self.revoke_calls.append(token_id)
            return {"revoked": True, "token_id": token_id}

        def fake_spend(token_id, **kw):
            self.spend_calls.append(token_id)
            return {"token_id": token_id, "spent_usd": 0.0123,
                    "requests_made": 3, "unpriced_requests": 0,
                    "last_model": "claude-sonnet-4-6", "status": "active"}

        return (
            patch("core.llm.dispatcher.client.enable_child_loopback",
                  fake_loopback),
            patch("core.llm.dispatcher.client.mint_child_token", fake_mint),
            patch("core.llm.dispatcher.client.revoke_child_token",
                  fake_revoke),
            patch("core.llm.dispatcher.client.child_token_spend",
                  fake_spend),
        )

    def _run(self, fake_sandbox_run, *, env_extra: dict | None = None,
             mint_raises: Exception | None = None) -> dict:
        from packages.openant import scanner
        env = dict(env_extra or {})
        p1, p2, p3, p4 = self._patches(mint_raises=mint_raises)
        with patch.dict(os.environ, env), p1, p2, p3, p4, \
                patch("core.sandbox.context.run", fake_sandbox_run):
            return scanner.run_openant_scan(
                self.base / "repo", self.out, self.config)


class TestPostureSelection(_GatewayHarness):
    """Direct wins; gateway is the keyless-with-dispatcher fallback;
    keyless-without-dispatcher keeps the pre-gateway behavior."""

    @staticmethod
    def _exit2(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="e")

    def test_env_key_is_direct_even_with_dispatcher(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["env"] = kwargs.get("env")
            captured["staged"] = _staged_config(self.out)
            return self._exit2(cmd)

        self._run(fake_run, env_extra={
            "ANTHROPIC_API_KEY": "sk-direct",
            "RAPTOR_LLM_SOCKET": "/nonexistent/llm.sock",
        })
        self.assertEqual(self.mint_calls, [])
        self.assertEqual(self.loopback_calls, [])
        profile = captured["staged"]["llm_configs"]["raptor-sonnet"]
        for phase in _OPENANT_LLM_PHASES:
            self.assertEqual(profile[phase]["provider"], "anthropic")
        self.assertNotIn("llm_providers", captured["staged"])
        self.assertEqual(captured["env"].get("ANTHROPIC_API_KEY"),
                         "sk-direct")

    def test_operator_config_key_is_direct(self):
        xdg = self.base / "xdg"
        cfg = xdg / "openant" / "config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({
            "$schema_version": 2,
            "llm_providers": {"anthropic": {
                "type": "anthropic", "api_key": "sk-op-key"}},
        }))
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
            self.assertTrue(_operator_has_direct_credential())
        self._run(self._exit2, env_extra={
            "XDG_CONFIG_HOME": str(xdg),
            "RAPTOR_LLM_SOCKET": "/nonexistent/llm.sock",
        })
        self.assertEqual(self.mint_calls, [])

    def test_legacy_top_level_key_is_direct(self):
        xdg = self.base / "xdg"
        cfg = xdg / "openant" / "config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({"api_key": "sk-legacy"}))
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
            self.assertTrue(_operator_has_direct_credential())

    def test_keyless_anthropic_entry_is_not_direct(self):
        """api_key: null relies on the absent env var — gateway shape."""
        xdg = self.base / "xdg"
        cfg = xdg / "openant" / "config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({
            "$schema_version": 2,
            "llm_providers": {"anthropic": {
                "type": "anthropic", "api_key": None}},
        }))
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(xdg)}):
            self.assertFalse(_operator_has_direct_credential())

    def test_keyless_without_dispatcher_stays_pre_gateway(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["env"] = kwargs.get("env")
            captured["staged"] = _staged_config(self.out)
            return self._exit2(cmd)

        self._run(fake_run)  # conftest scrubbed both env vars
        self.assertEqual(self.mint_calls, [])
        profile = captured["staged"]["llm_configs"]["raptor-sonnet"]
        self.assertEqual(profile["analyze"]["provider"], "anthropic")
        # Pre-gateway env shape: the (empty) key forward survives.
        self.assertIn("ANTHROPIC_API_KEY", captured["env"])


class TestGatewayStaging(_GatewayHarness):

    def _run_keyless_dispatcher(self, fake_run, **kw):
        return self._run(fake_run, env_extra={
            "RAPTOR_LLM_SOCKET": "/nonexistent/llm.sock",
            # Ambient proxy route — must NOT reach the gateway child.
            "HTTPS_PROXY": "http://proxy.example:3128",
        }, **kw)

    def test_gateway_provider_staged_and_bound(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["env"] = kwargs.get("env")
            captured["staged"] = _staged_config(self.out)
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="e")

        self._run_keyless_dispatcher(fake_run)
        staged = captured["staged"]
        entry = staged["llm_providers"][_GATEWAY_PROVIDER_NAME]
        self.assertEqual(entry["type"], "anthropic")
        self.assertEqual(entry["api_key"], f"{_TOKEN}-1")
        self.assertEqual(entry["base_url"],
                         f"http://127.0.0.1:{_PORT}/anthropic")
        profile = staged["llm_configs"]["raptor-sonnet"]
        for phase in _OPENANT_LLM_PHASES:
            self.assertEqual(profile[phase], {
                "provider": _GATEWAY_PROVIDER_NAME,
                "model": _OPENANT_MODEL_IDS["sonnet"],
            })
        # Child env: no provider credential, no proxy route (the only
        # egress is host loopback, which a proxy hop cannot reach).
        self.assertNotIn("ANTHROPIC_API_KEY", captured["env"])
        for var in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
                    "https_proxy", "http_proxy"):
            self.assertNotIn(var, captured["env"])
        self.assertEqual(captured["env"]["XDG_CONFIG_HOME"],
                         str(self.out / _XDG_STAGE_DIRNAME))

    def test_token_scoped_to_the_scan(self):
        self.config.model = "opus"
        self.config.timeout_seconds = 900
        self._run_keyless_dispatcher(
            lambda cmd, **kw: subprocess.CompletedProcess(
                cmd, 2, stdout="", stderr="e"))
        (mint,) = self.mint_calls
        self.assertEqual(mint["budget_usd"], _GATEWAY_BUDGET_USD)
        self.assertEqual(mint["models"], [_OPENANT_MODEL_IDS["opus"]])
        self.assertEqual(mint["ttl_s"], 900 + _GATEWAY_TTL_SLACK_S)
        self.assertEqual(mint["request_budget"], _GATEWAY_REQUEST_BUDGET)
        self.assertEqual(mint["label"], "openant")

    def test_settled_on_every_exit_path_and_token_never_persists(self):
        """Success, child failure, and launch crash all end with the
        stage scrubbed, the token revoked server-side, and the token
        value absent from every surviving byte: files under out_dir,
        the result dict, and the raptor log stream."""
        def ok_run(cmd, **kwargs):
            (self.out / "pipeline_output.json").write_text(
                json.dumps({"findings": []}))
            return subprocess.CompletedProcess(cmd, 0, stdout="{}",
                                               stderr="")

        def fail_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 2, stdout="",
                                               stderr="boom")

        def raise_run(cmd, **kwargs):
            raise RuntimeError("launch failed")

        for n, fake in enumerate((ok_run, fail_run, raise_run), start=1):
            with self.subTest(exit_path=fake.__name__):
                with self.assertLogs("raptor", level="DEBUG") as logs:
                    result = self._run_keyless_dispatcher(fake)
                token = f"{_TOKEN}-{n}"
                self.assertEqual(self.revoke_calls[-1], f"{_TOKEN_ID}{n}")
                self.assertFalse(
                    (self.out / _XDG_STAGE_DIRNAME).exists())
                for root, _dirs, files in os.walk(self.out):
                    for fname in files:
                        self.assertNotIn(
                            token.encode(),
                            Path(root, fname).read_bytes(),
                            f"token persisted in {fname}")
                self.assertNotIn(token, json.dumps(result))
                self.assertNotIn(token, "\n".join(logs.output))
                # The loggable correlation id IS reported.
                spend = json.loads(
                    (self.out / "openant-gateway-spend.json").read_text())
                self.assertEqual(spend["token_id"], f"{_TOKEN_ID}{n}")
                self.assertEqual(spend["dispatcher_spent_usd"], 0.0123)

    def test_mint_refusal_fails_scan_before_spawn(self):
        def never_run(cmd, **kwargs):
            self.fail("child spawned despite gateway refusal")

        result = self._run_keyless_dispatcher(
            never_run,
            mint_raises=RuntimeError("child-token mint refused (503)"))
        self.assertTrue(result["hard_error"])
        self.assertIn("dispatcher gateway unavailable", result["error"])
        self.assertIn("mint refused", result["error"])
        self.assertEqual(self.revoke_calls, [])  # nothing was minted

    def test_concurrent_scans_get_independent_tokens(self):
        """Two runs (same worker, different out_dirs) mint two tokens
        and each staged config carries its own; both settle."""
        seen = []

        def fake_run(cmd, **kwargs):
            seen.append(_staged_config(Path(kwargs["env"]["XDG_CONFIG_HOME"])
                                       .parent)
                        ["llm_providers"][_GATEWAY_PROVIDER_NAME]["api_key"])
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="e")

        self._run_keyless_dispatcher(fake_run)
        self.out = self.base / "out2"
        self.out.mkdir()
        self._run_keyless_dispatcher(fake_run)
        self.assertEqual(seen, [f"{_TOKEN}-1", f"{_TOKEN}-2"])
        self.assertEqual(self.revoke_calls,
                         [f"{_TOKEN_ID}1", f"{_TOKEN_ID}2"])

    def test_operator_raptor_gateway_entry_replaced_run_local(self):
        """The provider name is RAPTOR-owned: an operator entry of the
        same name is overwritten in the staged copy (warned), and the
        operator's file is untouched."""
        xdg = self.base / "xdg"
        cfg = xdg / "openant" / "config.json"
        cfg.parent.mkdir(parents=True)
        operator_raw = json.dumps({
            "$schema_version": 2,
            "llm_providers": {_GATEWAY_PROVIDER_NAME: {
                "type": "ollama", "base_url": "http://x:11434"}},
        })
        cfg.write_text(operator_raw)
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["staged"] = _staged_config(self.out)
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="e")

        with self.assertLogs("raptor", level="WARNING") as logs:
            self._run(fake_run, env_extra={
                "XDG_CONFIG_HOME": str(xdg),
                "RAPTOR_LLM_SOCKET": "/nonexistent/llm.sock",
            })
        entry = captured["staged"]["llm_providers"][_GATEWAY_PROVIDER_NAME]
        self.assertEqual(entry["type"], "anthropic")
        self.assertEqual(entry["api_key"], f"{_TOKEN}-1")
        self.assertIn("RAPTOR-owned", "\n".join(logs.output))
        self.assertEqual(cfg.read_text(), operator_raw)


class TestGatewayRouteResolution(_GatewayHarness):
    """The gateway dials the front the dispatcher actually serves —
    the same install-level signal proxy-mode CC children trust — and
    on the Bedrock front the model follows the install's pin."""

    def test_default_route_is_first_party_with_pinned_id(self):
        from packages.openant.scanner import _gateway_route
        self.assertEqual(_gateway_route("sonnet"),
                         ("/anthropic", _OPENANT_MODEL_IDS["sonnet"]))

    def test_bedrock_route_rides_the_install_pin_normalized(self):
        from packages.openant.scanner import _gateway_route
        with patch.dict(os.environ, {
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "ANTHROPIC_MODEL": "us.anthropic.claude-fable-5",
        }):
            self.assertEqual(
                _gateway_route("sonnet"),
                ("/bedrock/mantle", "anthropic.claude-fable-5"))

    def test_bedrock_route_without_pin_normalizes_catalog_id(self):
        from packages.openant.scanner import _gateway_route
        with patch.dict(os.environ, {"CLAUDE_CODE_USE_BEDROCK": "1"}):
            self.assertEqual(
                _gateway_route("opus"),
                ("/bedrock/mantle", "anthropic." +
                 _OPENANT_MODEL_IDS["opus"]))

    def test_bedrock_staging_binds_route_model_everywhere(self):
        """Staged base_url, profile model, and the mint allowlist all
        carry the route-resolved id — a profile/token disagreement
        would 403 at the model allowlist."""
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["staged"] = _staged_config(self.out)
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="e")

        self._run(fake_run, env_extra={
            "RAPTOR_LLM_SOCKET": "/nonexistent/llm.sock",
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "ANTHROPIC_MODEL": "anthropic.claude-fable-5",
        })
        staged = captured["staged"]
        entry = staged["llm_providers"][_GATEWAY_PROVIDER_NAME]
        self.assertEqual(entry["base_url"],
                         f"http://127.0.0.1:{_PORT}/bedrock/mantle")
        profile = staged["llm_configs"]["raptor-sonnet"]
        for phase in _OPENANT_LLM_PHASES:
            self.assertEqual(profile[phase]["model"],
                             "anthropic.claude-fable-5")
        (mint,) = self.mint_calls
        self.assertEqual(mint["models"], ["anthropic.claude-fable-5"])


class TestRunCostReconciliation(unittest.TestCase):
    """The run report's cost line is max-of-ledgers: OpenAnt's own
    tracker (blind to models absent from its catalog) vs the gateway
    ledger settlement (absent on direct-credential runs)."""

    def _reconcile(self, oa_out, usage):
        import raptor_openant
        return raptor_openant._reconcile_run_cost(oa_out, usage)

    def test_gateway_ledger_covers_openant_zero(self):
        with tempfile.TemporaryDirectory() as td:
            oa_out = Path(td)
            (oa_out / "openant-gateway-spend.json").write_text(
                json.dumps({"dispatcher_spent_usd": 0.43}))
            cost = self._reconcile(oa_out, {"total_cost_usd": 0.0})
            self.assertEqual(cost["total_usd"], 0.43)
            self.assertEqual(cost["gateway_ledger_usd"], 0.43)

    def test_direct_run_uses_openant_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            cost = self._reconcile(Path(td), {"total_cost_usd": 0.17})
            self.assertEqual(cost["total_usd"], 0.17)
            self.assertEqual(cost["gateway_ledger_usd"], 0.0)

    def test_max_never_sum_and_garbage_tolerated(self):
        with tempfile.TemporaryDirectory() as td:
            oa_out = Path(td)
            (oa_out / "openant-gateway-spend.json").write_text(
                json.dumps({"dispatcher_spent_usd": 0.10}))
            cost = self._reconcile(oa_out, {"total_cost_usd": 0.25})
            self.assertEqual(cost["total_usd"], 0.25)
            cost = self._reconcile(oa_out, {"total_cost_usd": "bogus"})
            self.assertEqual(cost["total_usd"], 0.10)


class TestGatewayAgainstRealDispatcher(unittest.TestCase):
    """Hermetic end-to-end: a real ``LLMDispatcher`` (captive upstream,
    no network) mints through the scanner's own seam, the staged
    credentials authenticate on the loopback plane with the pinned
    adapter's wire dialect (x-api-key + base_url path prefix +
    ``/v1/messages`` join), scope holds, and settlement kills the
    token server-side — a later reuse is refused."""

    def test_staged_credentials_round_trip_then_die_at_settlement(self):
        import http.server
        import threading

        import httpx

        from core.llm.dispatcher import client as dispatcher_client
        from core.llm.dispatcher.auth import CredentialStore, ProviderRule
        from core.llm.dispatcher.server import LLMDispatcher
        from packages.openant import scanner

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                return

            def do_POST(self):
                ln = int(self.headers.get("Content-Length", "0"))
                if ln:
                    self.rfile.read(ln)
                resp = json.dumps({
                    "id": "msg_1", "model": "claude-sonnet-4-6",
                    "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 10, "output_tokens": 2},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        upstream = http.server.HTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=upstream.serve_forever,
                         daemon=True).start()
        creds = CredentialStore.__new__(CredentialStore)
        creds._keys = {"anthropic": "real-key-held-by-dispatcher"}

        with tempfile.TemporaryDirectory() as td:
            d = LLMDispatcher(run_id="oa-gw", creds=creds,
                              audit_path=Path(td) / "audit.jsonl")
            original = d._rules["anthropic"]
            d._rules["anthropic"] = ProviderRule(
                name=original.name,
                upstream_base_url=(
                    f"http://127.0.0.1:{upstream.server_address[1]}"),
                inject_headers=original.inject_headers,
                strip_request_headers=original.strip_request_headers,
            )
            socket_path, token_fd = d.allocate_worker(label="oa-test")
            saved_cache = dispatcher_client._cached_token
            dispatcher_client._cached_token = None
            try:
                with patch.dict(os.environ, {
                    "RAPTOR_LLM_SOCKET": socket_path,
                    "RAPTOR_LLM_TOKEN_FD": str(token_fd),
                }):
                    gateway = scanner._mint_gateway_credentials(
                        OpenAntConfig(core_path=Path(td)))
                    out = Path(td) / "out"
                    out.mkdir()
                    scanner._stage_llm_config(out, "sonnet",
                                              gateway=gateway)
                    staged = _staged_config(out)
                    entry = staged["llm_providers"][_GATEWAY_PROVIDER_NAME]
                    # Dial exactly what the pinned adapter dials: the
                    # staged base_url with the SDK's /v1/messages
                    # appended, credential in x-api-key.
                    with httpx.Client(timeout=10.0) as c:
                        ok = c.post(
                            entry["base_url"] + "/v1/messages",
                            headers={
                                "x-api-key": entry["api_key"],
                                "anthropic-version": "2023-06-01",
                            },
                            json={"model": "claude-sonnet-4-6",
                                  "max_tokens": 8, "messages": []},
                        )
                        self.assertEqual(ok.status_code, 200)
                        # Scope holds under the staged credential.
                        batches = c.post(
                            entry["base_url"] + "/v1/messages/batches",
                            headers={"x-api-key": entry["api_key"]},
                            json={"model": "claude-sonnet-4-6",
                                  "max_tokens": 8, "messages": []},
                        )
                        self.assertEqual(batches.status_code, 403)
                        # Settlement revokes server-side: reuse of the
                        # (still-known) token value is refused.
                        scanner._settle_gateway(gateway, out)
                        dead = c.post(
                            entry["base_url"] + "/v1/messages",
                            headers={"x-api-key": entry["api_key"]},
                            json={"model": "claude-sonnet-4-6",
                                  "max_tokens": 8, "messages": []},
                        )
                        self.assertEqual(dead.status_code, 401)
                    spend = json.loads(
                        (out / "openant-gateway-spend.json").read_text())
                    self.assertEqual(spend["token_id"],
                                     gateway["token_id"])
                    # Both pre-revocation requests count against the
                    # token (the 403'd path probe passed TOKEN
                    # validation before the scope refusal); the
                    # post-revocation attempt does not.
                    self.assertEqual(spend["requests_made"], 2)
                    self.assertNotIn(gateway["token"],
                                     json.dumps(spend))
            finally:
                dispatcher_client._cached_token = saved_cache
                d.shutdown()
                upstream.shutdown()
                upstream.server_close()


if __name__ == "__main__":
    unittest.main()
