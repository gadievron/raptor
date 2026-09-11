#!/usr/bin/env python3
"""Errexit/pipefail resilience of raptor-sage-setup's permission and
teardown helpers.

Three behaviours pinned here, all driven by extracting the real
functions from the script and running them hermetically (stub MCP
wrapper, tmp settings files, no docker, no network):

* ``discover_mcp_tools`` under ``set -euo pipefail``: zero tool names
  surviving the grep filter used to make the pipeline (and thus the
  function) return 1, and ``tools=$(discover_mcp_tools)`` then killed
  the whole install via errexit — before the designed warn-and-continue
  branch for empty output could run. Empty output is now a clean rc 0.

* The uninstall-path jq calls (``revoke_mcp_permissions``,
  ``remove_mcp_entry``, ``disable_sage_env``): a hand-edited/corrupted
  JSON file used to abort teardown mid-way under errexit, skipping the
  boot-payload tombstone step. They now warn and continue.

* ``check_docker``'s sg re-exec builds its argv from ``_ORIG_ARGS``
  with the ``${arr[@]+...}`` empty-array guard (bash < 4.4 under
  ``set -u`` treats an empty array expansion as unbound) and still
  forwards real arguments.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SETUP = REPO_ROOT / "libexec" / "raptor-sage-setup"

HAVE_JQ = shutil.which("jq") is not None


def _extract_function(name: str) -> str:
    text = SETUP.read_text(encoding="utf-8")
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n.*?^\}}$", text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"function {name} not found in raptor-sage-setup"
    return match.group(0)


WRAPPER_NO_TOOLS = """#!/bin/sh
cat >/dev/null
printf '%s\\n' '{"jsonrpc":"2.0","id":1,"result":{}}'
printf '%s\\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"Renamed_Tool9"},{"name":"other_tool"}]}}'
"""

WRAPPER_SAGE_TOOLS = """#!/bin/sh
cat >/dev/null
printf '%s\\n' '{"jsonrpc":"2.0","id":1,"result":{}}'
printf '%s\\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"sage_turn"},{"name":"sage_recall"}]}}'
"""


class _BashHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _script(self, name: str, body: str) -> Path:
        path = self.dir / name
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def _run_driver(self, driver: str, env_extra=None):
        driver_path = self.dir / "driver.sh"
        driver_path.write_text(driver, encoding="utf-8")
        env = dict(os.environ)
        env.update(env_extra or {})
        return subprocess.run(
            ["bash", str(driver_path)],
            capture_output=True, text=True, env=env, timeout=60,
        )


@unittest.skipUnless(HAVE_JQ, "jq not available")
class TestGrantPermissionsEmptyDiscovery(_BashHarness):
    DRIVER = """
set -euo pipefail
declare -a _RAPTOR_TMP_FILES=()
MCP_WRAPPER="$FAKE_WRAPPER"
SETTINGS_LOCAL="$TEST_SETTINGS"
{discover}
{grant}
grant_mcp_permissions
echo "SETUP_CONTINUES"
""".replace("{discover}", _extract_function("discover_mcp_tools")
            ).replace("{grant}", _extract_function("grant_mcp_permissions"))

    def _env(self, wrapper: Path, settings: Path):
        return {"FAKE_WRAPPER": str(wrapper),
                "TEST_SETTINGS": str(settings)}

    def test_zero_surviving_tools_warns_and_continues(self):
        """A tools/list whose names all fail the sage_* filter must not
        errexit-kill the caller — warn, leave settings alone, rc 0."""
        wrapper = self._script("wrapper", WRAPPER_NO_TOOLS)
        settings = self.dir / "settings.local.json"
        settings.write_text('{"permissions":{"allow":[]}}')
        proc = self._run_driver(self.DRIVER, self._env(wrapper, settings))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("SETUP_CONTINUES", proc.stdout)
        self.assertIn("could not discover", proc.stderr)
        self.assertEqual(
            json.loads(settings.read_text()),
            {"permissions": {"allow": []}})

    def test_discovered_sage_tools_still_granted(self):
        wrapper = self._script("wrapper", WRAPPER_SAGE_TOOLS)
        settings = self.dir / "settings.local.json"
        settings.write_text('{"permissions":{"allow":["Bash(ls)"]}}')
        proc = self._run_driver(self.DRIVER, self._env(wrapper, settings))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        allow = json.loads(settings.read_text())["permissions"]["allow"]
        self.assertIn("mcp__sage__sage_turn", allow)
        self.assertIn("mcp__sage__sage_recall", allow)
        self.assertIn("Bash(ls)", allow)


@unittest.skipUnless(HAVE_JQ, "jq not available")
class TestUninstallTeardownContinues(_BashHarness):
    DRIVER = """
set -euo pipefail
declare -a _RAPTOR_TMP_FILES=()
SETTINGS_LOCAL="$TEST_SETTINGS"
MCP="$TEST_MCP"
{remove}
{disable}
{revoke}
remove_mcp_entry
disable_sage_env
revoke_mcp_permissions
echo "TEARDOWN_REACHES_TOMBSTONE"
""".replace("{remove}", _extract_function("remove_mcp_entry")
            ).replace("{disable}", _extract_function("disable_sage_env")
                      ).replace("{revoke}",
                                _extract_function("revoke_mcp_permissions"))

    def _env(self, settings: Path, mcp: Path):
        return {"TEST_SETTINGS": str(settings), "TEST_MCP": str(mcp)}

    def test_malformed_json_files_do_not_abort_teardown(self):
        """Corrupted settings.local.json AND .mcp.json: every helper
        warns and returns 0, so teardown reaches the tombstone step."""
        settings = self.dir / "settings.local.json"
        settings.write_text("{not json at all")
        mcp = self.dir / ".mcp.json"
        mcp.write_text("also { not } json [")
        proc = self._run_driver(self.DRIVER, self._env(settings, mcp))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("TEARDOWN_REACHES_TOMBSTONE", proc.stdout)
        # The corrupted files are left in place for the operator.
        self.assertEqual(settings.read_text(), "{not json at all")
        self.assertEqual(mcp.read_text(), "also { not } json [")

    def test_valid_files_still_torn_down(self):
        settings = self.dir / "settings.local.json"
        settings.write_text(json.dumps({
            "permissions": {"allow": ["mcp__sage__sage_turn", "Bash(ls)"]},
            "env": {"SAGE_ENABLED": "true", "OTHER": "1"},
        }))
        mcp = self.dir / ".mcp.json"
        mcp.write_text(json.dumps({
            "mcpServers": {"sage": {"command": "x"},
                           "other": {"command": "y"}},
        }))
        proc = self._run_driver(self.DRIVER, self._env(settings, mcp))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("TEARDOWN_REACHES_TOMBSTONE", proc.stdout)
        left = json.loads(settings.read_text())
        self.assertEqual(left["permissions"]["allow"], ["Bash(ls)"])
        self.assertNotIn("SAGE_ENABLED", left.get("env", {}))
        self.assertNotIn("sage", json.loads(mcp.read_text())["mcpServers"])


class TestCheckDockerReExec(_BashHarness):
    DRIVER = """
set -euo pipefail
_ORIG_ARGS=({args})
need() { :; }
{check_docker}
check_docker
echo "NOT_REACHED"
""".replace("{check_docker}", _extract_function("check_docker"))

    DOCKER_STUB = """#!/bin/sh
case "$1" in
  compose) exit 0 ;;
  *) exit 1 ;;
esac
"""

    SG_STUB = """#!/bin/sh
if [ "$3" = "docker info" ]; then exit 0; fi
printf '%s' "$3" > "$SG_CAPTURE"
exit 0
"""

    def _run_check_docker(self, args_literal: str):
        bindir = self.dir / "bin"
        bindir.mkdir()
        self._script("bin/docker", self.DOCKER_STUB)
        self._script("bin/sg", self.SG_STUB)
        capture = self.dir / "sg-capture"
        driver = self.DRIVER.replace("{args}", args_literal)
        env = {
            "PATH": f"{bindir}:{os.environ.get('PATH', '')}",
            "SG_CAPTURE": str(capture),
        }
        proc = self._run_driver(driver, env)
        return proc, capture

    def test_zero_args_reexec_does_not_trip_set_u(self):
        """Bare invocation (empty _ORIG_ARGS): the loop must expand to
        nothing — never an unbound-variable abort — and the re-exec
        command carries only the script path."""
        proc, capture = self._run_check_docker("")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("unbound variable", proc.stderr)
        # exec replaced the shell before the sentinel line.
        self.assertNotIn("NOT_REACHED", proc.stdout)
        cmd = capture.read_text()
        self.assertEqual(cmd, f'"{self.dir}/driver.sh"')

    def test_args_survive_the_reexec(self):
        proc, capture = self._run_check_docker("'--install' '--reauthorize'")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        cmd = capture.read_text()
        self.assertIn('"--install"', cmd)
        self.assertIn('"--reauthorize"', cmd)

    def test_empty_array_guard_idiom_is_present(self):
        """The behavioural crash only reproduces on bash < 4.4, which
        CI runners no longer ship — pin the guard idiom in the source
        (same protection as the _RAPTOR_TMP_FILES loop uses)."""
        body = _extract_function("check_docker")
        self.assertIn('${_ORIG_ARGS[@]+"${_ORIG_ARGS[@]}"}', body)


if __name__ == "__main__":
    unittest.main()
