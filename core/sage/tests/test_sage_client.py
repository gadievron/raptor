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


if __name__ == "__main__":
    unittest.main()
