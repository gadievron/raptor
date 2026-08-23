"""Robustness tests for the per-agent WebFetch domain-allowlist hook.

`.claude/hooks/webfetch-domain-allowlist.py` is the mechanical
narrowing behind the WebFetch-capable agents' network posture. Three
modes are pinned here:

  * static hostname allowlist (b4: oss github / wayback agents)
  * ``--https-any`` (b4: ioc-extractor)
  * ``--anchor-file`` (crash-report-fetcher): https + same registrable
    domain as the operator-supplied URL, extra hosts as logged
    operator-visible additions, fail-closed on a missing/invalid
    anchor.

The hook is exercised as a subprocess with the real PreToolUse stdin
contract (JSON with tool_input.url; exit 0 allow / exit 2 block).
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

_REPO = Path(__file__).resolve().parents[3]
_HOOK = _REPO / ".claude" / "hooks" / "webfetch-domain-allowlist.py"


def _run_hook(args, url=None, stdin=None):
    """Run the hook. Returns (rc, stderr)."""
    if stdin is None:
        stdin = json.dumps(
            {"tool_name": "WebFetch", "tool_input": {"url": url}})
    proc = subprocess.run(
        [sys.executable, str(_HOOK), *args],
        input=stdin, capture_output=True, text=True, check=False,
    )
    return proc.returncode, proc.stderr


class TestStaticAllowlistMode(unittest.TestCase):

    def test_listed_host_allowed(self):
        rc, _ = _run_hook(["github.com"], "https://github.com/o/r")
        self.assertEqual(rc, 0)

    def test_unlisted_host_blocked(self):
        rc, err = _run_hook(["github.com"], "https://evil.example/x")
        self.assertEqual(rc, 2)
        self.assertIn("not in this agent's allowlist", err)

    def test_http_blocked_even_for_listed_host(self):
        rc, err = _run_hook(["github.com"], "http://github.com/o/r")
        self.assertEqual(rc, 2)
        self.assertIn("https", err)

    def test_unparseable_stdin_blocked(self):
        rc, _ = _run_hook(["github.com"], stdin="not json")
        self.assertEqual(rc, 2)

    def test_missing_url_blocked(self):
        rc, _ = _run_hook(
            ["github.com"],
            stdin=json.dumps({"tool_name": "WebFetch", "tool_input": {}}))
        self.assertEqual(rc, 2)

    def test_unknown_flag_blocked_fail_closed(self):
        rc, err = _run_hook(
            ["--frobnicate", "github.com"], "https://github.com/o/r")
        self.assertEqual(rc, 2)
        self.assertIn("unknown flag", err)


class TestHttpsAnyMode(unittest.TestCase):

    def test_any_https_host_allowed(self):
        rc, _ = _run_hook(["--https-any"], "https://vendor.example/report")
        self.assertEqual(rc, 0)

    def test_http_blocked(self):
        rc, _ = _run_hook(["--https-any"], "http://vendor.example/report")
        self.assertEqual(rc, 2)


class TestAnchorFileMode(unittest.TestCase):

    def _anchor(self, tmp, *lines):
        path = Path(tmp) / "fetcher.anchor"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_anchor_host_allowed(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "https://trac.ffmpeg.org/ticket/1")
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "https://trac.ffmpeg.org/ticket/1")
            self.assertEqual(rc, 0)

    def test_same_registrable_domain_sibling_allowed(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "https://trac.ffmpeg.org/ticket/1")
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "https://attachments.ffmpeg.org/file/2")
            self.assertEqual(rc, 0)

    def test_other_registrable_domain_blocked(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "https://trac.ffmpeg.org/ticket/1")
            rc, err = _run_hook(["--anchor-file", str(anchor)],
                                "https://evil.example/exfil")
            self.assertEqual(rc, 2)
            self.assertIn("registrable domain", err)

    def test_suffix_squat_blocked(self):
        # evil-ffmpeg.org shares a suffix string but not the
        # registrable domain.
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "https://trac.ffmpeg.org/ticket/1")
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "https://evil-ffmpeg.org/x")
            self.assertEqual(rc, 2)

    def test_multi_label_public_suffix_not_treated_as_one_domain(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "https://bugs.foo.co.uk/1")
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "https://www.foo.co.uk/2")
            self.assertEqual(rc, 0)
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "https://bar.co.uk/x")
            self.assertEqual(rc, 2)

    def test_extra_host_line_allowed_and_logged(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(
                tmp,
                "https://trac.ffmpeg.org/ticket/1",
                "cdn.attachments.example",
            )
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "https://cdn.attachments.example/poc.bin")
            self.assertEqual(rc, 0)
            log = Path(str(anchor) + ".log").read_text(encoding="utf-8")
            self.assertIn("allow\tcdn.attachments.example", log)

    def test_denied_fetch_is_logged(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "https://trac.ffmpeg.org/ticket/1")
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "https://evil.example/x")
            self.assertEqual(rc, 2)
            log = Path(str(anchor) + ".log").read_text(encoding="utf-8")
            self.assertIn("deny\tevil.example", log)

    def test_http_blocked_regardless_of_anchor(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "https://trac.ffmpeg.org/ticket/1")
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "http://trac.ffmpeg.org/ticket/1")
            self.assertEqual(rc, 2)

    def test_missing_anchor_file_blocked_fail_closed(self):
        with TemporaryDirectory() as tmp:
            rc, err = _run_hook(
                ["--anchor-file", str(Path(tmp) / "absent.anchor")],
                "https://trac.ffmpeg.org/ticket/1")
            self.assertEqual(rc, 2)
            self.assertIn("missing or unreadable", err)

    def test_empty_anchor_file_blocked_fail_closed(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "# comment only")
            rc, err = _run_hook(["--anchor-file", str(anchor)],
                                "https://trac.ffmpeg.org/ticket/1")
            self.assertEqual(rc, 2)
            self.assertIn("no anchor URL", err)

    def test_non_https_anchor_blocked_fail_closed(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "http://trac.ffmpeg.org/ticket/1")
            rc, err = _run_hook(["--anchor-file", str(anchor)],
                                "https://trac.ffmpeg.org/ticket/1")
            self.assertEqual(rc, 2)
            self.assertIn("valid https URL", err)

    def test_bare_hostname_anchor_accepted(self):
        with TemporaryDirectory() as tmp:
            anchor = self._anchor(tmp, "trac.ffmpeg.org")
            rc, _ = _run_hook(["--anchor-file", str(anchor)],
                              "https://trac.ffmpeg.org/ticket/1")
            self.assertEqual(rc, 0)

    def test_anchor_file_flag_without_value_blocked(self):
        rc, err = _run_hook(["--anchor-file"], "https://a.example/x")
        self.assertEqual(rc, 2)
        self.assertIn("requires a path", err)


class TestFetcherAgentWiring(unittest.TestCase):
    """The crash-report-fetcher frontmatter must wire this hook in
    anchor-file mode — the enforcement lives there, not in prose."""

    def test_fetcher_frontmatter_wires_anchor_mode(self):
        agent = (_REPO / ".claude" / "agents"
                 / "crash-report-fetcher-agent.md").read_text(
                     encoding="utf-8")
        self.assertIn("webfetch-domain-allowlist.py", agent)
        self.assertIn("--anchor-file", agent)
        self.assertIn(".claude/run/crash-report-fetcher.anchor", agent)


if __name__ == "__main__":
    unittest.main()
