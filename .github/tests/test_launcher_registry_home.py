"""The launcher's session seeder honours RAPTOR_REGISTRY_HOME.

Why this test exists
--------------------
``bin/raptor`` seeds the AUTHORITATIVE session binding into
``sessions.d`` at launch, and the python readers of that very file
(``core/project/sessions.py``) resolve the registry through the
``core.project.registry_home`` seam — call-time, honouring
``RAPTOR_REGISTRY_HOME``. If the seeder keeps writing the hardcoded
default location while the readers follow the override, an
override-launched session is SPLIT: the binding lands where nothing
will ever read it, and every in-session project resolution silently
sees an unbound session.

Two pins:

* an absolute override relocates the seed — the session entry appears
  under ``<override>/sessions.d`` and nothing is written to the
  default ``$HOME/.local/share/raptor``;
* a set-but-non-absolute override refuses LOUDLY before exec (the
  python seam raises on it; a launcher that silently seeded the
  default registry would split the session exactly as above).

The cases plant a fake ``claude`` on PATH so the launch completes
(or refuses) without ever starting a real session; HOME points into
the sandbox so no real state is touched on any path.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO / "bin" / "raptor"


def _sandbox(d: str) -> dict[str, str]:
    """Env + fake-claude scaffolding shared by the cases."""
    fakebin = Path(d) / "bin"
    fakebin.mkdir()
    fakebin.chmod(0o755)  # umask-proof: a 0777 dir would be scrubbed off PATH
    fake_claude = fakebin / "claude"
    fake_claude.write_text("#!/bin/sh\necho FAKE-CLAUDE-RAN\nexit 97\n")
    fake_claude.chmod(0o755)
    work = Path(d) / "work"
    work.mkdir()
    (Path(d) / "target").mkdir()
    return {
        "HOME": d,
        "PATH": f"{fakebin}:/usr/bin:/bin",
        "RAPTOR_WORK_DIR": str(work),
    }


class TestLauncherRegistryHomeSeam(unittest.TestCase):
    def test_absolute_override_relocates_the_session_seed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            env = _sandbox(d)
            reg = Path(d) / "reg"
            env["RAPTOR_REGISTRY_HOME"] = str(reg)
            proc = subprocess.run(
                ["bash", str(_LAUNCHER), str(Path(d) / "target")],
                capture_output=True, text=True, timeout=120, env=env,
            )
            combined = proc.stdout + proc.stderr
            self.assertIn("FAKE-CLAUDE-RAN", combined,
                          "launch did not reach exec: " + combined)
            seeded = list((reg / "sessions.d").glob("*")) \
                if (reg / "sessions.d").is_dir() else []
            self.assertTrue(
                seeded,
                "no session entry under the override registry: "
                + combined)
            default = Path(d) / ".local" / "share" / "raptor" / "sessions.d"
            self.assertFalse(
                default.exists(),
                "seeder wrote the DEFAULT registry despite the override"
                " — readers and seeder split")

    def test_relative_override_refuses_loudly_before_exec(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            env = _sandbox(d)
            env["RAPTOR_REGISTRY_HOME"] = "relative/reg"
            proc = subprocess.run(
                ["bash", str(_LAUNCHER), str(Path(d) / "target")],
                capture_output=True, text=True, timeout=120, env=env,
            )
            combined = proc.stdout + proc.stderr
            self.assertNotIn(
                "FAKE-CLAUDE-RAN", combined,
                "launcher execed a session with an unusable registry"
                " override")
            self.assertEqual(proc.returncode, 1, combined)
            self.assertIn("RAPTOR_REGISTRY_HOME must be an absolute path",
                          proc.stderr)
            default = Path(d) / ".local" / "share" / "raptor" / "sessions.d"
            self.assertFalse(
                default.exists(),
                "refusal path still seeded the default registry")


if __name__ == "__main__":
    unittest.main()
