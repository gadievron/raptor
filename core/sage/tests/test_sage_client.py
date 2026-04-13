#!/usr/bin/env python3
"""Tests for SAGE client wrapper."""

import asyncio
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock


def _mock_sage_sdk():
    """Create mock sage_sdk modules."""
    mock_client_cls = MagicMock()
    mock_identity_cls = MagicMock()
    mock_memory_type = SimpleNamespace(
        observation="observation",
        fact="fact",
        inference="inference",
    )

    mocks = {
        "sage_sdk": MagicMock(),
        "sage_sdk.async_client": MagicMock(AsyncSageClient=mock_client_cls),
        "sage_sdk.auth": MagicMock(AgentIdentity=mock_identity_cls),
        "sage_sdk.models": MagicMock(MemoryType=mock_memory_type),
    }
    return mocks, mock_client_cls, mock_identity_cls, mock_memory_type


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
            result = client.is_available()
            self.assertTrue(result)
            mock_get.assert_called_once()

    @patch("core.sage.client._ensure_sdk", return_value=True)
    def test_health_check_failure(self, _):
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        config = SageConfig(enabled=True)
        client = SageClient(config)

        with patch("httpx.get", side_effect=ConnectionError("refused")):
            result = client.is_available()
            self.assertFalse(result)

    @patch("core.sage.client._ensure_sdk", return_value=True)
    def test_health_check_bad_status(self, _):
        from core.sage.config import SageConfig
        from core.sage.client import SageClient

        config = SageConfig(enabled=True)
        client = SageClient(config)

        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.json.return_value = {}

        with patch("httpx.get", return_value=mock_resp):
            result = client.is_available()
            self.assertFalse(result)


class TestSageClientAsync(unittest.TestCase):
    """Test async methods."""

    def _run(self, coro):
        """Run async test."""
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_embed_no_client(self):
        from core.sage.client import SageClient

        client = SageClient()  # SDK not available
        result = self._run(client.embed("test"))
        self.assertIsNone(result)

    def test_query_no_client(self):
        from core.sage.client import SageClient

        client = SageClient()
        result = self._run(client.query("test", "domain"))
        self.assertEqual(result, [])

    def test_propose_no_client(self):
        from core.sage.client import SageClient

        client = SageClient()
        result = self._run(client.propose("test content"))
        self.assertFalse(result)

    def test_register_no_client(self):
        from core.sage.client import SageClient

        client = SageClient()
        result = self._run(client.register("test-agent"))
        self.assertFalse(result)


class TestSageClientQueryWithMock(unittest.TestCase):
    """Test query with mocked SDK."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_query_returns_results(self):
        import core.sage.client as client_mod

        # Save originals
        orig_available = client_mod._SAGE_SDK_AVAILABLE
        orig_client = client_mod._AsyncSageClient
        orig_identity = client_mod._AgentIdentity
        orig_mt = client_mod._MemoryType

        try:
            # Mock SDK
            mock_client_instance = AsyncMock()
            mock_client_cls = MagicMock(return_value=mock_client_instance)
            mock_identity_cls = MagicMock()
            mock_identity_cls.default.return_value = MagicMock()

            client_mod._SAGE_SDK_AVAILABLE = True
            client_mod._AsyncSageClient = mock_client_cls
            client_mod._AgentIdentity = mock_identity_cls
            client_mod._MemoryType = SimpleNamespace(
                observation="observation", fact="fact", inference="inference"
            )

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            config = SageConfig(enabled=True)
            sc = SageClient(config)

            # Mock embed + query responses
            mock_client_instance.embed.return_value = [0.1, 0.2, 0.3]
            mock_record = SimpleNamespace(
                content="heap overflow pattern",
                confidence_score=0.92,
                domain_tag="raptor-fuzzing",
            )
            mock_client_instance.query.return_value = SimpleNamespace(
                results=[mock_record]
            )

            results = self._run(sc.query("heap overflow", "raptor-fuzzing"))
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["content"], "heap overflow pattern")
            self.assertEqual(results[0]["confidence"], 0.92)
            self.assertEqual(results[0]["domain"], "raptor-fuzzing")
        finally:
            client_mod._SAGE_SDK_AVAILABLE = orig_available
            client_mod._AsyncSageClient = orig_client
            client_mod._AgentIdentity = orig_identity
            client_mod._MemoryType = orig_mt


if __name__ == "__main__":
    unittest.main()
