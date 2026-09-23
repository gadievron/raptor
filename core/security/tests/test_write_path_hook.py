"""Robustness tests for the per-agent Write path-allowlist hook.

`.claude/hooks/write-path-allowlist.py` narrows an agent's Write grant
to named artifact basenames. Motivating case: the crash-report-fetcher
reads hostile tracker pages while its WebFetch is constrained by an
anchor file — with an UNRESTRICTED Write grant, a steered fetcher
could append an exfil host to that anchor and the domain hook would
honor it (the "Write exactly ONE artifact" rule was prose, not a
boundary). The hook is exercised as a subprocess with the real
PreToolUse stdin contract (JSON with tool_input.file_path; exit 0
allow / exit 2 block).
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_HOOK = _REPO / ".claude" / "hooks" / "write-path-allowlist.py"


def _run_hook(args, file_path=None, stdin=None):
    if stdin is None:
        stdin = json.dumps(
            {"tool_name": "Write", "tool_input": {"file_path": file_path}})
    proc = subprocess.run(
        [sys.executable, str(_HOOK), *args],
        input=stdin, capture_output=True, text=True, check=False,
    )
    return proc.returncode, proc.stderr


class TestWritePathAllowlist(unittest.TestCase):
    def test_allowed_artifact_passes(self):
        rc, _ = _run_hook(["bug-report.json"],
                          "/work/dir/bug-report.json")
        self.assertEqual(rc, 0)

    def test_other_basename_blocked(self):
        rc, err = _run_hook(["bug-report.json"], "/work/dir/notes.md")
        self.assertEqual(rc, 2)
        self.assertIn("not an allowed artifact", err)

    def test_anchor_write_blocked(self):
        """The escalation the hook exists to stop: rewriting the
        WebFetch anchor that constrains the agent itself."""
        rc, err = _run_hook(
            ["bug-report.json"],
            "/repo/.claude/run/crash-report-fetcher-1.anchor")
        self.assertEqual(rc, 2)

    def test_dot_claude_blocked_even_with_allowed_basename(self):
        rc, err = _run_hook(["bug-report.json"],
                            "/repo/.claude/run/bug-report.json")
        self.assertEqual(rc, 2)
        self.assertIn(".claude", err)

    def test_traversal_blocked(self):
        rc, _ = _run_hook(["bug-report.json"],
                          "/work/../.claude/settings.json")
        self.assertEqual(rc, 2)

    def test_unparseable_stdin_blocked(self):
        rc, _ = _run_hook(["bug-report.json"], stdin="not json")
        self.assertEqual(rc, 2)

    def test_missing_path_blocked(self):
        rc, _ = _run_hook(["bug-report.json"], stdin=json.dumps(
            {"tool_name": "Write", "tool_input": {}}))
        self.assertEqual(rc, 2)

    def test_hook_script_exists_and_is_executable_python(self):
        self.assertTrue(_HOOK.is_file())
        first = _HOOK.read_text(encoding="utf-8").splitlines()[0]
        self.assertIn("python", first)


if __name__ == "__main__":
    unittest.main()
