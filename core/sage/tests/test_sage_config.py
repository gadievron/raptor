#!/usr/bin/env python3
"""Tests for SAGE configuration."""

import os
import unittest
from unittest.mock import patch


class TestSageConfig(unittest.TestCase):
    """Test SageConfig defaults and environment variable overrides."""

    def test_default_values(self):
        """Config should have sane defaults."""
        from core.sage.config import SageConfig

        config = SageConfig()
        self.assertFalse(config.enabled)
        self.assertEqual(config.url, "http://localhost:8090")
        self.assertIsNone(config.identity_path)
        self.assertEqual(config.timeout, 15.0)

    @patch.dict(os.environ, {"SAGE_ENABLED": "true"})
    def test_enabled_from_env(self):
        from core.sage.config import SageConfig

        config = SageConfig()
        self.assertTrue(config.enabled)

    @patch.dict(os.environ, {"SAGE_ENABLED": "1"})
    def test_enabled_from_env_numeric(self):
        from core.sage.config import SageConfig

        config = SageConfig()
        self.assertTrue(config.enabled)

    @patch.dict(os.environ, {"SAGE_URL": "http://sage.example.com:9090"})
    def test_url_from_env(self):
        from core.sage.config import SageConfig

        config = SageConfig()
        self.assertEqual(config.url, "http://sage.example.com:9090")

    @patch.dict(os.environ, {"SAGE_TIMEOUT": "30.0"})
    def test_timeout_from_env(self):
        from core.sage.config import SageConfig

        config = SageConfig()
        self.assertEqual(config.timeout, 30.0)

    @patch.dict(os.environ, {"SAGE_IDENTITY_PATH": "/tmp/agent.key"})
    def test_identity_path_from_env(self):
        from core.sage.config import SageConfig

        config = SageConfig()
        self.assertEqual(config.identity_path, "/tmp/agent.key")

    def test_from_env_factory(self):
        from core.sage.config import SageConfig

        config = SageConfig.from_env()
        self.assertIsInstance(config, SageConfig)


class TestSageConfigDefaults(unittest.TestCase):
    """Test that defaults don't bleed across instances."""

    def test_independent_instances(self):
        from core.sage.config import SageConfig

        c1 = SageConfig()
        c2 = SageConfig()
        c1.url = "http://changed:9999"
        self.assertNotEqual(c1.url, c2.url)


if __name__ == "__main__":
    unittest.main()
