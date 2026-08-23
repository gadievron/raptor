#!/usr/bin/env python3
"""Reauthorization gate tests for raptor-sage-setup's boot payload.

Pre-fix a changed payload printed a diff but was stamped anyway
("informational, never blocking") — a registry-side image swap or a
compromised server self-authorized on the next routine setup run.
Now: first capture displays the payload text; a CHANGED payload
requires explicit confirmation (interactive y/N or --reauthorize) and
otherwise keeps the previous record.

The function under test is extracted from the real script and driven
with a stubbed capture_boot_payload, so the tests are hermetic (no
docker, no network).
"""

import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SETUP = REPO_ROOT / "libexec" / "raptor-sage-setup"


def _extract_function(name: str) -> str:
    text = SETUP.read_text(encoding="utf-8")
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n.*?^\}}$", text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"function {name} not found in raptor-sage-setup"
    return match.group(0)


DRIVER_TEMPLATE = """
set -uo pipefail
declare -a _RAPTOR_TMP_FILES=()
COMPOSE_FILE=/nonexistent/docker-compose.yml
AUTHORIZED_PAYLOAD="$TEST_AUTHORIZED"
REAUTHORIZE="${REAUTHORIZE:-0}"
capture_boot_payload() {
    printf '%s\\n' "$FAKE_PAYLOAD"
}
running_sage_digest() {
    echo "${FAKE_RUNNING_DIGEST:-none}"
}
docker() {
    return 1
}
{function}
authorize_boot_payload
"""


class TestAuthorizeBootPayload(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.authorized = self.dir / ".sage" / "boot-payload.authorized"
        self.driver = DRIVER_TEMPLATE.replace(
            "{function}", _extract_function("authorize_boot_payload"),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, payload: str, *, reauthorize: bool = False,
             running_digest: str = "none"):
        import os
        env = dict(os.environ)
        env["TEST_AUTHORIZED"] = str(self.authorized)
        env["FAKE_PAYLOAD"] = payload
        env["FAKE_RUNNING_DIGEST"] = running_digest
        env["REAUTHORIZE"] = "1" if reauthorize else "0"
        return subprocess.run(
            ["bash", "-c", self.driver],
            capture_output=True, text=True, timeout=30, env=env,
            stdin=subprocess.DEVNULL,
        )

    def test_first_install_displays_and_records(self):
        proc = self._run("### initialize.instructions\nhello agent")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Payload text follows", proc.stdout)
        self.assertIn("hello agent", proc.stdout)
        self.assertTrue(self.authorized.exists())
        self.assertIn(
            "hello agent", self.authorized.read_text(encoding="utf-8"),
        )

    def test_unchanged_payload_restamps_quietly(self):
        payload = "### initialize.instructions\nsteady state"
        self._run(payload)
        proc = self._run(payload)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("unchanged", proc.stdout)
        self.assertTrue(self.authorized.exists())

    def test_changed_payload_refused_non_interactive(self):
        self._run("### initialize.instructions\noriginal payload")
        original = self.authorized.read_text(encoding="utf-8")
        proc = self._run("### initialize.instructions\nINJECTED directive")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Refusing to silently re-authorize", proc.stderr)
        self.assertIn("--reauthorize", proc.stderr)
        # The previous record must survive byte-for-byte.
        self.assertEqual(
            self.authorized.read_text(encoding="utf-8"), original,
        )

    def test_changed_payload_accepted_with_reauthorize_flag(self):
        self._run("### initialize.instructions\noriginal payload")
        proc = self._run(
            "### initialize.instructions\nupgraded payload",
            reauthorize=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Re-authorized (--reauthorize)", proc.stdout)
        self.assertIn(
            "upgraded payload",
            self.authorized.read_text(encoding="utf-8"),
        )

    def test_changed_payload_shows_diff(self):
        self._run("### initialize.instructions\noriginal payload")
        proc = self._run("### initialize.instructions\nchanged payload")
        self.assertIn("-original payload", proc.stdout)
        self.assertIn("+changed payload", proc.stdout)

    def test_stamp_records_running_digest(self):
        digest = "ghcr.io/l33tdawg/sage@sha256:" + "ab" * 32
        proc = self._run(
            "### initialize.instructions\nhello",
            running_digest=digest,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        content = self.authorized.read_text(encoding="utf-8")
        self.assertIn(f"# RunningDigest: {digest}", content)


if __name__ == "__main__":
    unittest.main()
