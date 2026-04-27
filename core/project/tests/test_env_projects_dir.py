"""RAPTOR_PROJECTS_DIR env var overrides the default ~/.raptor/projects.

Added so test harnesses and companion tooling (e.g. raptor-studio) can point
raptor at an alternate registry without monkey-patching the module constant.
"""

import importlib
import os
import unittest
from pathlib import Path


class TestEnvProjectsDir(unittest.TestCase):

    def _reload_with_env(self, value: str | None):
        """Reload the two modules with RAPTOR_PROJECTS_DIR set (or unset)."""
        saved = os.environ.pop("RAPTOR_PROJECTS_DIR", None)
        try:
            if value is not None:
                os.environ["RAPTOR_PROJECTS_DIR"] = value
            import core.project.project as p
            import core.startup as s
            importlib.reload(p)
            importlib.reload(s)
            return p.PROJECTS_DIR, s.PROJECTS_DIR
        finally:
            os.environ.pop("RAPTOR_PROJECTS_DIR", None)
            if saved is not None:
                os.environ["RAPTOR_PROJECTS_DIR"] = saved
            # restore module state
            import core.project.project as p
            import core.startup as s
            importlib.reload(p)
            importlib.reload(s)

    def test_env_var_overrides_default(self):
        proj, start = self._reload_with_env("/tmp/raptor-env-test")
        self.assertEqual(proj, Path("/tmp/raptor-env-test"))
        self.assertEqual(start, Path("/tmp/raptor-env-test"))

    def test_default_when_unset(self):
        proj, start = self._reload_with_env(None)
        self.assertEqual(proj, Path.home() / ".raptor" / "projects")
        self.assertEqual(start, Path.home() / ".raptor" / "projects")


if __name__ == "__main__":
    unittest.main()
