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
    """Test graceful degradation when SAGE is disabled."""

    def test_embed_no_client(self):
        from core.sage.client import SageClient
        from core.sage.config import SageConfig
        self.assertIsNone(SageClient(SageConfig(enabled=False)).embed("test"))

    def test_query_no_client(self):
        from core.sage.client import SageClient
        from core.sage.config import SageConfig
        self.assertEqual(SageClient(SageConfig(enabled=False)).query("test", "domain"), [])

    def test_propose_no_client(self):
        from core.sage.client import SageClient
        from core.sage.config import SageConfig
        self.assertFalse(SageClient(SageConfig(enabled=False)).propose("test content"))


def _install_mock_sdk(client_mod):
    """Install mock SDK bindings in the client module. Returns (cls, instance)."""
    mock_instance = MagicMock()
    mock_cls = MagicMock(return_value=mock_instance)
    mock_identity_cls = MagicMock()
    mock_identity_cls.default.return_value = MagicMock()

    client_mod._SAGE_SDK_AVAILABLE = True
    client_mod._SyncSageClient = mock_cls
    client_mod._AgentIdentity = mock_identity_cls
    # Mirror the SAGE MemoryType enum: fact | observation |
    # inference | task (docs/reference/python-sdk.md). client.propose's
    # allowlist references all four members directly, so the mock must
    # expose them all or the allowlist build raises AttributeError.
    client_mod._MemoryType = SimpleNamespace(
        observation="observation",
        fact="fact",
        inference="inference",
        task="task",
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

    @patch("core.sage.client._use_direct_embed", return_value=False)
    def test_query_returns_results(self, _mock_direct):
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

    @patch("core.sage.client._use_direct_embed", return_value=False)
    def test_query_back_to_back_uses_cached_sdk_client(self, _mock_direct):
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

    @patch("core.sage.client._use_direct_embed", return_value=False)
    def test_propose_auto_embeds(self, _mock_direct):
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


class TestSageClientTagsAndMinConfidence(unittest.TestCase):
    """SAGE 11.9.2 features: tags on propose, min_confidence on query."""

    @patch("core.sage.client._use_direct_embed", return_value=False)
    def test_propose_passes_tags_when_provided(self, _mock_direct):
        import core.sage.client as client_mod

        snapshot = _snapshot_sdk(client_mod)
        try:
            _, mock_instance = _install_mock_sdk(client_mod)

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            sc = SageClient(SageConfig(enabled=True))
            mock_instance.embed.return_value = [0.1, 0.2]

            sc.propose("hello", tags=["scan", "finding", "xss"])
            kwargs = mock_instance.propose.call_args.kwargs
            self.assertEqual(kwargs["tags"], ["scan", "finding", "xss"])
        finally:
            _restore_sdk(client_mod, snapshot)

    @patch("core.sage.client._use_direct_embed", return_value=False)
    def test_propose_omits_tags_when_none(self, _mock_direct):
        import core.sage.client as client_mod

        snapshot = _snapshot_sdk(client_mod)
        try:
            _, mock_instance = _install_mock_sdk(client_mod)

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            sc = SageClient(SageConfig(enabled=True))
            mock_instance.embed.return_value = [0.1, 0.2]

            sc.propose("hello")
            kwargs = mock_instance.propose.call_args.kwargs
            self.assertNotIn("tags", kwargs)
        finally:
            _restore_sdk(client_mod, snapshot)

    @patch("core.sage.client._use_direct_embed", return_value=False)
    def test_query_passes_min_confidence_when_provided(self, _mock_direct):
        import core.sage.client as client_mod

        snapshot = _snapshot_sdk(client_mod)
        try:
            _, mock_instance = _install_mock_sdk(client_mod)

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            sc = SageClient(SageConfig(enabled=True))
            mock_instance.embed.return_value = [0.1]
            mock_instance.query.return_value = SimpleNamespace(results=[])

            sc.query("test", min_confidence=0.5)
            kwargs = mock_instance.query.call_args.kwargs
            self.assertEqual(kwargs["min_confidence"], 0.5)
        finally:
            _restore_sdk(client_mod, snapshot)

    @patch("core.sage.client._use_direct_embed", return_value=False)
    def test_query_omits_min_confidence_when_none(self, _mock_direct):
        import core.sage.client as client_mod

        snapshot = _snapshot_sdk(client_mod)
        try:
            _, mock_instance = _install_mock_sdk(client_mod)

            from core.sage.config import SageConfig
            from core.sage.client import SageClient

            sc = SageClient(SageConfig(enabled=True))
            mock_instance.embed.return_value = [0.1]
            mock_instance.query.return_value = SimpleNamespace(results=[])

            sc.query("test")
            kwargs = mock_instance.query.call_args.kwargs
            self.assertNotIn("min_confidence", kwargs)
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

    @patch("core.sage.client._use_direct_embed", return_value=False)
    def test_propose_and_query_with_fake_sdk(self, _mock_direct):
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

                def query(self, embedding, domain_tag, top_k, **kwargs):
                    content = f"embedded={embedding[0]} domain={domain_tag} top_k={top_k}"
                    return SimpleNamespace(
                        results=[_FakeRecord(content, 0.88, domain_tag)]
                    )

            client_mod._SAGE_SDK_AVAILABLE = True
            client_mod._SyncSageClient = _FakeClient
            client_mod._AgentIdentity = _FakeIdentity
            client_mod._MemoryType = SimpleNamespace(
                observation="observation", fact="fact", inference="inference",
                task="task",
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


class TestHardenIdentityKeyPerms(unittest.TestCase):
    """The SDK writes the agent key umask-wide; RAPTOR clamps it."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = __import__("pathlib").Path(self.tmp.name) / "ids"
        self.dir.mkdir(mode=0o755)
        self.key = self.dir / "agent.key"
        self.key.write_bytes(b"\x00" * 32)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _mode(path):
        import os
        import stat
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_wide_key_clamped_with_warning(self):
        import os
        os.chmod(self.key, 0o664)
        from core.sage.client import harden_identity_key_perms
        with self.assertLogs("raptor", level="WARNING") as logs:
            harden_identity_key_perms(self.key)
        self.assertEqual(self._mode(self.key), 0o600)
        self.assertEqual(self._mode(self.dir), 0o700)
        self.assertTrue(any("clamping" in line for line in logs.output))

    def test_tight_key_untouched_no_warning(self):
        import logging
        import os
        os.chmod(self.key, 0o600)
        os.chmod(self.dir, 0o700)
        from core.sage.client import harden_identity_key_perms
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        logger = logging.getLogger("raptor")
        logger.addHandler(handler)
        try:
            harden_identity_key_perms(self.key)
        finally:
            logger.removeHandler(handler)
        self.assertEqual(self._mode(self.key), 0o600)
        self.assertFalse(
            [r for r in records if r.levelno >= logging.WARNING],
        )

    def test_missing_key_is_noop(self):
        from core.sage.client import harden_identity_key_perms
        harden_identity_key_perms(self.dir / "absent.key")  # must not raise

    def test_symlink_key_refused(self):
        import os
        target = self.dir / "target"
        target.write_bytes(b"\x00" * 32)
        os.chmod(target, 0o644)
        link = self.dir / "link.key"
        link.symlink_to(target)
        from core.sage.client import harden_identity_key_perms
        with self.assertLogs("raptor", level="WARNING") as logs:
            harden_identity_key_perms(link)
        # The symlink target's permissions must not be touched.
        self.assertEqual(self._mode(target), 0o644)
        self.assertTrue(
            any("not a regular file" in line for line in logs.output),
        )

    def test_default_path_resolves_env_var(self):
        import os
        os.chmod(self.key, 0o664)
        from core.sage.client import harden_identity_key_perms
        with patch.dict(
            os.environ, {"SAGE_IDENTITY_PATH": str(self.key)},
        ):
            harden_identity_key_perms(None)
        self.assertEqual(self._mode(self.key), 0o600)

    def test_home_parent_never_clamped(self):
        import os
        from pathlib import Path
        key = Path(self.tmp.name) / "home" / "stray.key"
        key.parent.mkdir(mode=0o755)
        key.write_bytes(b"\x00" * 32)
        os.chmod(key, 0o664)
        from core.sage.client import harden_identity_key_perms
        with patch("core.sage.client.Path.home",
                   return_value=key.parent):
            harden_identity_key_perms(key)
        self.assertEqual(self._mode(key), 0o600)
        # $HOME itself keeps its mode.
        self.assertEqual(self._mode(key.parent), 0o755)


if __name__ == "__main__":
    unittest.main()


class TestInstallScriptsClampIdentityKey(unittest.TestCase):
    """The install-time scripts provision the identity BEFORE any
    clamped call site runs — the exact mechanism that produced the
    observed group-readable key. Pin the wiring: both scripts clamp
    the umask across creation and harden afterwards."""

    _SCRIPTS = (
        "core/sage/scripts/register_agents.py",
        "core/sage/scripts/seed_sage_knowledge.py",
    )

    def _source(self, rel):
        from pathlib import Path
        root = Path(__file__).resolve().parents[3]
        return (root / rel).read_text(encoding="utf-8")

    def test_umask_clamped_across_identity_creation(self):
        for rel in self._SCRIPTS:
            src = self._source(rel)
            umask_at = src.index("umask(0o077)")
            create_at = src.index("AgentIdentity.default()")
            self.assertLess(
                umask_at, create_at,
                f"{rel}: umask clamp must precede identity creation",
            )

    def test_harden_called_after_creation(self):
        for rel in self._SCRIPTS:
            src = self._source(rel)
            create_at = src.index("AgentIdentity.default()")
            harden_at = src.index("harden_identity_key_perms()")
            self.assertGreater(
                harden_at, create_at,
                f"{rel}: harden must follow identity creation",
            )
