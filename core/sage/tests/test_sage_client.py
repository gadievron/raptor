#!/usr/bin/env python3
"""Tests for SAGE client wrapper."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


class TestSageClientHealthCheck(unittest.TestCase):
    """Test sync health check."""

    def test_health_check_disabled(self):
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        config = SageConfig(enabled=False)
        client = SageClient(config)
        self.assertFalse(client.is_available())

    @patch("core.sage.client._ensure_sdk", return_value=False)
    def test_health_check_no_sdk(self, _):
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        config = SageConfig(enabled=True)
        client = SageClient(config)
        self.assertFalse(client.is_available())

    @patch("core.sage.client._ensure_sdk", return_value=True)
    def test_health_check_success(self, _):
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        config = SageConfig(enabled=True, url="http://test:8090")
        client = SageClient(config)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "healthy"}

        with patch("httpx.get", return_value=mock_resp) as mock_get:
            self.assertTrue(client.is_available())
            mock_get.assert_called_once()

    @patch("core.sage.client._ensure_sdk", return_value=True)
    def test_health_check_failure(self, _):
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        client = SageClient(SageConfig(enabled=True))

        with patch("httpx.get", side_effect=ConnectionError("refused")):
            self.assertFalse(client.is_available())

    @patch("core.sage.client._ensure_sdk", return_value=True)
    def test_health_check_bad_status(self, _):
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        client = SageClient(SageConfig(enabled=True))

        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.json.return_value = {}

        with patch("httpx.get", return_value=mock_resp):
            self.assertFalse(client.is_available())


class TestSageClientNoSDK(unittest.TestCase):
    """Test graceful degradation when the SDK isn't importable."""

    def test_embed_no_client(self):
        from core.sage.client import SageClient
        self.assertIsNone(SageClient().embed("test"))

    def test_query_no_client(self):
        from core.sage.client import SageClient
        self.assertEqual(SageClient().query("test", "domain"), [])

    def test_propose_no_client(self):
        from core.sage.client import SageClient
        self.assertFalse(SageClient().propose("test content"))


def _install_mock_sdk(client_mod):
    """Install mock SDK bindings in the client module. Returns (cls, instance)."""
    mock_instance = MagicMock()
    mock_cls = MagicMock(return_value=mock_instance)
    mock_identity_cls = MagicMock()
    mock_identity_cls.default.return_value = MagicMock()

    client_mod._SAGE_SDK_AVAILABLE = True
    client_mod._SyncSageClient = mock_cls
    client_mod._AgentIdentity = mock_identity_cls
    client_mod._MemoryType = SimpleNamespace(
        observation="observation", fact="fact", inference="inference"
    )
    return mock_cls, mock_instance


def _snapshot_sdk(client_mod):
    return (
        client_mod._SAGE_SDK_AVAILABLE,
        client_mod._SyncSageClient,
        client_mod._AgentIdentity,
        client_mod._MemoryType,
    )


def _restore_sdk(client_mod, snapshot):
    (
        client_mod._SAGE_SDK_AVAILABLE,
        client_mod._SyncSageClient,
        client_mod._AgentIdentity,
        client_mod._MemoryType,
    ) = snapshot


class TestSageClientWithMock(unittest.TestCase):
    """Test async methods with mocked sync SDK."""

    def test_query_returns_results(self):
        import core.sage.client as client_mod

        snapshot = _snapshot_sdk(client_mod)
        try:
            _, mock_instance = _install_mock_sdk(client_mod)

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            sc = SageClient(SageConfig(enabled=True))

            mock_instance.embed.return_value = [0.1, 0.2, 0.3]
            mock_record = SimpleNamespace(
                content="heap overflow pattern",
                confidence_score=0.92,
                domain_tag="raptor-fuzzing",
            )
            mock_instance.query.return_value = SimpleNamespace(results=[mock_record])

            results = sc.query("heap overflow", "raptor-fuzzing")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["content"], "heap overflow pattern")
            self.assertEqual(results[0]["confidence"], 0.92)
            self.assertEqual(results[0]["domain"], "raptor-fuzzing")
        finally:
            _restore_sdk(client_mod, snapshot)

    def test_query_back_to_back_uses_cached_sdk_client(self):
        """Regression: two queries in the same process must both succeed.

        The original async-based wrapper silently failed on the second
        call because httpx.AsyncClient was bound to a now-closed event
        loop. The sync SDK client has no such loop affinity — prove it
        stays the same instance across calls.
        """
        import core.sage.client as client_mod

        snapshot = _snapshot_sdk(client_mod)
        try:
            mock_cls, mock_instance = _install_mock_sdk(client_mod)

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            sc = SageClient(SageConfig(enabled=True))
            mock_instance.embed.return_value = [0.1]
            mock_instance.query.return_value = SimpleNamespace(results=[])

            sc.query("first")
            sc.query("second")

            # SDK client constructed once, reused for both queries
            self.assertEqual(mock_cls.call_count, 1)
            self.assertEqual(mock_instance.query.call_count, 2)
        finally:
            _restore_sdk(client_mod, snapshot)

    def test_propose_auto_embeds(self):
        import core.sage.client as client_mod

        snapshot = _snapshot_sdk(client_mod)
        try:
            _, mock_instance = _install_mock_sdk(client_mod)

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            sc = SageClient(SageConfig(enabled=True))
            mock_instance.embed.return_value = [0.1, 0.2]

            self.assertTrue(sc.propose("hello", domain_tag="raptor-findings"))
            mock_instance.embed.assert_called_once_with("hello")
            mock_instance.propose.assert_called_once()
        finally:
            _restore_sdk(client_mod, snapshot)


class TestSageClientEgressProxyRegistration(unittest.TestCase):
    """SAGE registers its host with the in-process egress proxy when
    LLM egress is active so its httpx calls aren't refused by the
    chokepoint.

    See ``core/sage/client.py:_register_with_egress_proxy`` and
    ``core/llm/egress.py`` for the rationale."""

    def setUp(self):
        # Each test starts with the egress module's _enabled flag
        # in a known state; restore on tearDown.
        from core.llm import egress
        self._egress_module = egress
        self._egress_was_enabled = egress._enabled
        egress._enabled = False

    def tearDown(self):
        self._egress_module._enabled = self._egress_was_enabled

    def _set_egress_enabled(self, value: bool) -> None:
        self._egress_module._enabled = value

    def test_no_op_when_egress_not_active(self):
        """LLM egress not enabled → don't touch the proxy singleton.
        Avoids spinning up a chokepoint that nothing will route through
        and prevents false-positive on operators running their own
        local proxy on 127.0.0.1."""
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        self._set_egress_enabled(False)
        with patch("core.sandbox.proxy.get_proxy") as mock_get:
            SageClient(SageConfig(enabled=True, url="http://sage.example.com:9090"))
            mock_get.assert_not_called()

    def test_no_op_for_localhost_url(self):
        """Localhost SAGE bypasses the proxy via NO_PROXY — no
        registration needed."""
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        self._set_egress_enabled(True)
        with patch("core.sandbox.proxy.get_proxy") as mock_get:
            SageClient(SageConfig(enabled=True, url="http://localhost:8090"))
            mock_get.assert_not_called()

    def test_no_op_for_127_0_0_1_url(self):
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        self._set_egress_enabled(True)
        with patch("core.sandbox.proxy.get_proxy") as mock_get:
            SageClient(SageConfig(enabled=True, url="http://127.0.0.1:8090"))
            mock_get.assert_not_called()

    def test_registers_remote_host_when_egress_active(self):
        """Remote SAGE_URL + LLM egress active → register sage's
        host on the proxy allowlist via UNION semantics."""
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        self._set_egress_enabled(True)
        with patch("core.sandbox.proxy.get_proxy") as mock_get:
            SageClient(SageConfig(enabled=True, url="http://sage.example.com:9090"))
            mock_get.assert_called_once()
            # Hostname only, no scheme/port/path
            args, _ = mock_get.call_args
            assert args[0] == ["sage.example.com"]

    def test_proxy_failure_swallowed(self):
        """A failure in get_proxy must not propagate — SAGE has its
        own graceful-degradation contract that should remain
        unchanged by this wiring."""
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        self._set_egress_enabled(True)
        with patch("core.sandbox.proxy.get_proxy",
                   side_effect=RuntimeError("port bind failed")):
            # Must not raise.
            SageClient(SageConfig(enabled=True, url="http://sage.example.com:9090"))

    def test_no_op_when_operator_runs_their_own_local_proxy(self):
        """Adversarial: operator runs e.g. mitmproxy at
        ``127.0.0.1:8888`` and sets HTTPS_PROXY pointing at it. The
        URL pattern alone matches our in-process proxy's pattern, so
        a heuristic-on-HTTPS_PROXY check would false-positive and
        register sage on a chokepoint that isn't ours. Using the
        egress module's ``_enabled`` flag avoids that — the flag is
        only set when ``enable_llm_egress`` actually ran."""
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        # Operator's own proxy pattern in env, but our flag NOT set
        # (LLM egress wasn't actually enabled this process).
        self._set_egress_enabled(False)
        with patch.dict("os.environ", {"HTTPS_PROXY": "http://127.0.0.1:8888"}):
            with patch("core.sandbox.proxy.get_proxy") as mock_get:
                SageClient(SageConfig(enabled=True, url="http://sage.example.com:9090"))
                mock_get.assert_not_called()


class TestSageClientWithFakeSdk(unittest.TestCase):
    """Coverage without mock objects: deterministic fake SDK."""

    def test_propose_and_query_with_fake_sdk(self):
        import core.sage.client as client_mod

        snapshot = _snapshot_sdk(client_mod)
        try:
            class _FakeIdentity:
                @staticmethod
                def default():
                    return object()

            class _FakeRecord:
                def __init__(self, content, confidence_score, domain_tag):
                    self.content = content
                    self.confidence_score = confidence_score
                    self.domain_tag = domain_tag

            class _FakeClient:
                def __init__(self, **_kwargs):
                    self.last_proposed = None

                def embed(self, text):
                    # Deterministic pseudo-embedding for testability.
                    return [float(len(text) % 7), 0.5, 1.0]

                def propose(self, **kwargs):
                    self.last_proposed = kwargs

                def query(self, embedding, domain_tag, top_k):
                    content = f"embedded={embedding[0]} domain={domain_tag} top_k={top_k}"
                    return SimpleNamespace(
                        results=[_FakeRecord(content, 0.88, domain_tag)]
                    )

            client_mod._SAGE_SDK_AVAILABLE = True
            client_mod._SyncSageClient = _FakeClient
            client_mod._AgentIdentity = _FakeIdentity
            client_mod._MemoryType = SimpleNamespace(
                observation="observation", fact="fact", inference="inference"
            )

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            sc = SageClient(SageConfig(enabled=True))
            self.assertTrue(
                sc.propose("seed content", memory_type="observation", domain_tag="raptor-findings")
            )
            rows = sc.query("seed content", "raptor-findings", top_k=2)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["domain"], "raptor-findings")
            self.assertGreater(rows[0]["confidence"], 0.8)
        finally:
            _restore_sdk(client_mod, snapshot)


if __name__ == "__main__":
    unittest.main()
