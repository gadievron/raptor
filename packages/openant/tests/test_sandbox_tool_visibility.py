"""Live sandbox tool-visibility contract for the openant core.

The scan subprocess's cmd[0] is the openant core's venv Python and its
cwd is the core directory — for a core outside the system dirs (the
--openant-core flag path, typically under the operator home) that
toolchain must ride the sandbox's tool-visibility surface
(``tool_paths=``). Pre-fix the scanner passed the core only as
``readable_paths=`` — a documented no-op under
``restrict_reads=False`` that never enters the mount-ns bind set — so
cmd[0] sat outside the bind tree and every run silently demoted to the
mountless backend (host paths visible by name: exactly the exposure
the mount lane exists to remove).

The live direction runs the REAL pinned core through
``run_openant_scan`` on a mount-capable host with a deliberately
invalid extra argument: reaching OpenAnt's own argparse rejection
proves the venv Python executed, the core was visible as cwd, and the
module imported — all inside the sandbox — while the injected bogus
flag stops the run before any LLM call. The demotion warning must NOT
fire. Hermetic: skipped without mount-ns capability or a pinned
checkout under a non-system path.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from core.sandbox.probes import check_mount_available
from packages.openant.config import OpenAntConfig
from packages.openant.tests.test_pinned_cli_contract import _find_pinned_core

_PINNED_CORE = _find_pinned_core()

_BOGUS_FLAG = "--raptor-visibility-probe"


def _core_exercises_visibility() -> bool:
    """A core under a system dir is inside the default bind tree and
    cannot witness the regression."""
    if _PINNED_CORE is None:
        return False
    return not str(_PINNED_CORE).startswith(("/usr/", "/opt/", "/bin/"))


class TestToolPathsDeclared(unittest.TestCase):
    """Structural pin (runs everywhere): the sandbox invocation
    declares the core on the tool-visibility surface and no longer on
    the no-op readable_paths surface."""

    def test_core_rides_tool_paths(self):
        from packages.openant import scanner
        src = Path(scanner.__file__).read_text()
        call = src.split("sandbox_run(", 1)[1]
        head = call[:2000]
        self.assertIn("tool_paths=[str(config.core_path)]", head)
        self.assertNotIn("readable_paths=", head)


class TestSymlinkedCoreResolved(unittest.TestCase):
    """The documented install layout is a symlink (<raptor-parent>/libs
    -> <clone>/libs). Inside the mount-ns sandbox a symlink spelling
    that crosses a replaced directory (/tmp is a fresh per-sandbox
    tmpfs) exists on the host but not in the child's view — so cmd[0],
    cwd, and the tool_paths bind must all travel at the RESOLVED real
    path, like PYTHONPATH already does."""

    def test_scan_runs_core_at_resolved_path(self):
        import os

        from packages.openant import scanner
        from packages.openant.config import OpenAntConfig

        captured = {}

        def fake_sandbox_run(cmd, **kwargs):
            captured["cmd0"] = cmd[0]
            captured["cwd"] = kwargs.get("cwd")
            captured["tool_paths"] = kwargs.get("tool_paths")
            raise RuntimeError("stop after capture")

        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            real = base / "clone" / "libs" / "openant-core"
            (real / "core").mkdir(parents=True)
            (real / "core" / "scanner.py").touch()
            venv_bin = real / ".venv" / "bin"
            venv_bin.mkdir(parents=True)
            (venv_bin / "python3").touch()
            (venv_bin / "python3").chmod(0o755)
            link_parent = base / "elsewhere"
            link_parent.mkdir()
            os.symlink(base / "clone" / "libs", link_parent / "libs")
            linked = link_parent / "libs" / "openant-core"
            out = base / "out"
            out.mkdir()
            config = OpenAntConfig(core_path=linked)
            with patch("core.sandbox.context.run", fake_sandbox_run):
                result = scanner.run_openant_scan(base, out, config)
            self.assertTrue(result["skipped"])
            resolved = str(real.resolve())
            self.assertEqual(captured["cmd0"],
                             str(Path(resolved) / ".venv" / "bin" / "python3"))
            self.assertEqual(captured["cwd"], resolved)
            self.assertEqual(captured["tool_paths"], [resolved])


@unittest.skipUnless(check_mount_available(),
                     "mount-ns lane not available on this host")
@unittest.skipUnless(_core_exercises_visibility(),
                     "no pinned openant-core under a non-system path")
class TestMountLaneReachesOpenAntArgv(unittest.TestCase):

    def test_scan_from_home_core_reaches_argv_parsing(self):
        from packages.openant import scanner

        orig = scanner._build_command

        def with_bogus_flag(repo, out, cfg):
            return orig(repo, out, cfg) + [_BOGUS_FLAG]

        with tempfile.TemporaryDirectory(dir="/var/tmp") as td:
            base = Path(td)
            src = base / "src"
            src.mkdir()
            (src / "a.py").write_text("x = 1\n")
            out = base / "out"
            out.mkdir()
            config = OpenAntConfig(core_path=_PINNED_CORE)
            with patch.object(scanner, "_build_command", with_bogus_flag), \
                 self.assertLogs(level="INFO") as captured:
                result = scanner.run_openant_scan(src, out, config)

        # The child's OWN argparse rejected the probe flag — the venv
        # Python ran, cwd resolved to the core, the module imported.
        self.assertTrue(result.get("hard_error"),
                        f"expected argparse rejection, got {result!r}")
        self.assertIn(f"unrecognized arguments: {_BOGUS_FLAG}",
                      str(result.get("error")))
        # And it did so WITHOUT the silent mountless demotion the
        # missing tool_paths declaration used to cause.
        logs = "\n".join(captured.output)
        self.assertNotIn("bind-tree isolation unavailable", logs)
        self.assertNotIn("outside the mount-ns bind tree", logs)
        self.assertNotIn("ignored because restrict_reads=False", logs)


if __name__ == "__main__":
    unittest.main()
