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

    def _env(self, payload: str, *, reauthorize: bool,
             running_digest: str):
        import os
        env = dict(os.environ)
        env["TEST_AUTHORIZED"] = str(self.authorized)
        env["FAKE_PAYLOAD"] = payload
        env["FAKE_RUNNING_DIGEST"] = running_digest
        env["REAUTHORIZE"] = "1" if reauthorize else "0"
        return env

    def _run(self, payload: str, *, reauthorize: bool = False,
             running_digest: str = "none"):
        return subprocess.run(
            ["bash", "-c", self.driver],
            capture_output=True, text=True, timeout=30,
            env=self._env(payload, reauthorize=reauthorize,
                          running_digest=running_digest),
            stdin=subprocess.DEVNULL,
        )

    def _run_pty(self, payload: str, *, reauthorize: bool = True,
                 running_digest: str = "none"):
        """Run with a PTY on stdin — the operator-terminal shape the
        stamp-replacing --reauthorize path now requires."""
        import os
        import pty
        master, slave = pty.openpty()
        try:
            proc = subprocess.run(
                ["bash", "-c", self.driver],
                capture_output=True, text=True, timeout=30,
                env=self._env(payload, reauthorize=reauthorize,
                              running_digest=running_digest),
                stdin=slave,
            )
        finally:
            os.close(master)
            os.close(slave)
        return proc

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

    def test_changed_payload_accepted_with_reauthorize_at_tty(self):
        """--reauthorize replaces a changed stamp at the operator's
        interactive terminal (PTY stdin)."""
        self._run("### initialize.instructions\noriginal payload")
        proc = self._run_pty(
            "### initialize.instructions\nupgraded payload",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Re-authorized (--reauthorize)", proc.stdout)
        self.assertIn(
            "upgraded payload",
            self.authorized.read_text(encoding="utf-8"),
        )

    def test_changed_payload_reauthorize_refused_without_tty(self):
        """Non-TTY `install --reauthorize` on an EXISTING stamp is the
        same laundering primitive the review --approve TTY gate closed
        (a mid-session prompt-injected run would re-stamp whatever the
        server serves) — refuse and keep the record byte-for-byte."""
        self._run("### initialize.instructions\noriginal payload")
        original = self.authorized.read_text(encoding="utf-8")
        proc = self._run(
            "### initialize.instructions\nINJECTED directive",
            reauthorize=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("requires an interactive terminal", proc.stderr)
        self.assertEqual(
            self.authorized.read_text(encoding="utf-8"), original,
        )

    def test_first_install_reauthorize_without_tty_still_records(self):
        """No existing stamp = nothing to launder: the first capture
        stays non-interactive even with --reauthorize set."""
        proc = self._run(
            "### initialize.instructions\nfresh payload",
            reauthorize=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "fresh payload",
            self.authorized.read_text(encoding="utf-8"),
        )

    def test_changed_payload_shows_diff(self):
        self._run("### initialize.instructions\noriginal payload")
        proc = self._run("### initialize.instructions\nchanged payload")
        self.assertIn("-original payload", proc.stdout)
        self.assertIn("+changed payload", proc.stdout)

    def test_unparseable_sha_header_refused_without_reauthorize(self):
        """S04-26: an existing stamp whose SHA256 header cannot be
        parsed must NOT be silently replaced — that bypasses the
        changed-payload confirmation gate (the comparison needs the
        old hash) and re-stamps whatever the server serves now."""
        self._run("### initialize.instructions\noriginal payload")
        # Corrupt the header line the comparison reads.
        text = self.authorized.read_text(encoding="utf-8")
        corrupted = text.replace("# SHA256: ", "# SHA-BROKEN: ")
        self.authorized.write_text(corrupted, encoding="utf-8")
        proc = self._run("### initialize.instructions\nINJECTED text")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Refusing to replace", proc.stderr)
        self.assertIn("--reauthorize", proc.stderr)
        self.assertEqual(
            self.authorized.read_text(encoding="utf-8"), corrupted,
            "stamp must survive byte-for-byte")

    def test_unparseable_sha_header_replaced_with_reauthorize_at_tty(self):
        self._run("### initialize.instructions\noriginal payload")
        text = self.authorized.read_text(encoding="utf-8")
        self.authorized.write_text(
            text.replace("# SHA256: ", "# SHA-BROKEN: "),
            encoding="utf-8")
        proc = self._run_pty("### initialize.instructions\nfresh payload")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        stamped = self.authorized.read_text(encoding="utf-8")
        self.assertIn("fresh payload", stamped)
        self.assertIn("# SHA256: ", stamped)

    def test_unparseable_sha_header_reauthorize_refused_without_tty(self):
        """The unparseable-header replace path is stamp-replacing too
        — same TTY gate as the changed-payload path."""
        self._run("### initialize.instructions\noriginal payload")
        text = self.authorized.read_text(encoding="utf-8")
        corrupted = text.replace("# SHA256: ", "# SHA-BROKEN: ")
        self.authorized.write_text(corrupted, encoding="utf-8")
        proc = self._run("### initialize.instructions\nfresh payload",
                         reauthorize=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("requires an interactive terminal", proc.stderr)
        self.assertEqual(
            self.authorized.read_text(encoding="utf-8"), corrupted,
        )

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


class TestStampCreationGate(TestAuthorizeBootPayload):
    """Stamp CREATION is TTY-gated when prior-install evidence exists:
    deleting the stamp (or uninstall && install) must not launder a
    hostile payload past the re-authorization gates non-interactively."""

    def test_tombstone_refuses_non_tty_restamp(self):
        self.authorized.parent.mkdir(parents=True, exist_ok=True)
        (self.authorized.parent / "boot-payload.authorized.removed"
         ).write_text("# tombstone\n")
        proc = self._run("### initialize.instructions\nEVIL")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("prior SAGE install", proc.stderr)
        self.assertFalse(self.authorized.exists())

    def test_live_mcp_entry_refuses_non_tty_restamp(self):
        # Direct stamp deletion with a live install: .mcp.json still
        # carries the sage entry — same refusal.
        mcp = self.dir / ".mcp.json"
        mcp.write_text('{"mcpServers": {"sage": {"command": "x"}}}\n')
        self.driver = self.driver.replace(
            'REAUTHORIZE="${REAUTHORIZE:-0}"',
            f'REAUTHORIZE="${{REAUTHORIZE:-0}}"\nMCP="{mcp}"',
        )
        proc = self._run("### initialize.instructions\nEVIL")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse(self.authorized.exists())

    def test_genuine_first_install_still_records_non_tty(self):
        # No tombstone, no mcp entry: the true first install stays
        # non-interactive (the other direction of the gate).
        proc = self._run("### initialize.instructions\nhello agent")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.authorized.exists())


class TestStampCreationGateComposedOrder(TestAuthorizeBootPayload):
    """install_sage snapshots prior-install evidence BEFORE
    generate_mcp_entry writes the sage entry; the gate must key on the
    snapshot, not a live grep of the entry install itself created."""

    def _with_mcp_and_snapshot(self, snapshot: str):
        mcp = self.dir / ".mcp.json"
        # The entry install_sage just generated THIS run.
        mcp.write_text('{"mcpServers": {"sage": {"command": "x"}}}\n')
        self.driver = self.driver.replace(
            'REAUTHORIZE="${REAUTHORIZE:-0}"',
            'REAUTHORIZE="${REAUTHORIZE:-0}"\n'
            f'MCP="{mcp}"\n_SAGE_PRIOR_MCP_ENTRY={snapshot}',
        )

    def test_fresh_machine_first_install_records_despite_new_entry(self):
        # Snapshot says no prior install: the sage entry present in
        # .mcp.json was written by THIS install run — must record.
        self._with_mcp_and_snapshot("0")
        proc = self._run("### initialize.instructions\nhello agent")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.authorized.exists())

    def test_prior_install_snapshot_refuses_non_tty(self):
        self._with_mcp_and_snapshot("1")
        proc = self._run("### initialize.instructions\nEVIL")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertFalse(self.authorized.exists())
