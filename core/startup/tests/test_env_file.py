"""Tests for setup_env_file (CLAUDE_ENV_FILE integration)."""

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.startup.init import setup_env_file


class TestSetupEnvFile(unittest.TestCase):

    def test_writes_raptor_dir(self):
        with TemporaryDirectory() as d:
            env_file = Path(d) / "env"
            os.environ["CLAUDE_ENV_FILE"] = str(env_file)
            try:
                setup_env_file()
                content = env_file.read_text()
                self.assertIn("RAPTOR_DIR", content)
                self.assertIn("PATH", content)
            finally:
                os.environ.pop("CLAUDE_ENV_FILE", None)

    def test_no_env_file_does_nothing(self):
        os.environ.pop("CLAUDE_ENV_FILE", None)
        # Should not raise
        setup_env_file()

    def test_idempotent(self):
        with TemporaryDirectory() as d:
            env_file = Path(d) / "env"
            os.environ["CLAUDE_ENV_FILE"] = str(env_file)
            try:
                setup_env_file()
                first = env_file.read_text()
                setup_env_file()
                second = env_file.read_text()
                self.assertEqual(first, second)
            finally:
                os.environ.pop("CLAUDE_ENV_FILE", None)

    def test_preserves_existing_content(self):
        with TemporaryDirectory() as d:
            env_file = Path(d) / "env"
            env_file.write_text('export FOO="bar"\n')
            os.environ["CLAUDE_ENV_FILE"] = str(env_file)
            try:
                setup_env_file()
                content = env_file.read_text()
                self.assertIn('FOO="bar"', content)
                self.assertIn("RAPTOR_DIR", content)
            finally:
                os.environ.pop("CLAUDE_ENV_FILE", None)


if __name__ == "__main__":
    unittest.main()
