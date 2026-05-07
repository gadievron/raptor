"""Regression tests for the proxy-events.jsonl target-pollution fix.

Some callers (notably packages/codeql/build_detector.py) intentionally
pass output=target so Landlock engages on a writable repo for compile/
build steps. The post-sandbox proxy-events.jsonl writer must NOT drop
its file into the user's scanned source tree in that scenario, but it
MUST keep writing when output is genuinely outside target. The
in-memory proxy_events on result.sandbox_info are unaffected either
way.

These run a real sandbox + egress proxy (same shape as the existing
TestE2EEgressProxy / TestPostSandboxParentTOCTOU tests).
"""

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals",
)


import os
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.sandbox import check_net_available, run as sandbox_run


class TestProxyEventsTargetPollution(unittest.TestCase):
    """proxy-events.jsonl must not be written into `target` when
    output==target (or output lives under target). In-memory events
    must still be populated regardless."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        from core.sandbox.proxy import _reset_for_tests
        _reset_for_tests()

    def tearDown(self):
        from core.sandbox.proxy import _reset_for_tests
        _reset_for_tests()

    def test_target_equals_output_does_not_write_jsonl(self):
        """sandbox(target=X, output=X) MUST NOT create X/proxy-events.jsonl.

        Mirrors the codeql build_detector pattern. The denied CONNECT
        produces an in-memory event (asserted below) but the on-disk
        write is suppressed because the path would land inside the
        scanned tree.
        """
        with TemporaryDirectory() as d:
            r = sandbox_run(
                ["curl", "-sI", "--max-time", "3",
                 "https://evil.invalid"],
                target=d, output=d,
                use_egress_proxy=True, proxy_hosts=["example.com"],
                capture_output=True, text=True, timeout=10,
            )

            jsonl = Path(d) / "proxy-events.jsonl"
            self.assertFalse(
                jsonl.exists(),
                f"target={d} output={d} polluted the scanned tree with "
                f"{jsonl} (contents: "
                f"{jsonl.read_text() if jsonl.exists() else ''!r})"
            )

            # In-memory events MUST still be populated — the fix only
            # suppresses on-disk persistence, not the proxy_events
            # buffer surfaced on result.sandbox_info.
            events = r.sandbox_info.get("proxy_events", [])
            denied = [e for e in events if e["result"] == "denied_host"]
            self.assertEqual(
                len(denied), 1,
                f"expected 1 denied_host in-memory event, got {events}"
            )
            self.assertEqual(denied[0]["host"], "evil.invalid")

    def test_output_outside_target_still_writes_jsonl(self):
        """Regression guard: when output is OUTSIDE target, the JSONL
        write MUST still happen (sandbox observability for callers that
        pass distinct paths)."""
        with TemporaryDirectory() as tgt, TemporaryDirectory() as out:
            # Belt-and-braces: ensure the two paths really are disjoint
            # after realpath() (TemporaryDirectory honours TMPDIR but
            # we don't want any symlink games).
            assert not os.path.realpath(out).startswith(
                os.path.realpath(tgt) + os.sep)
            assert os.path.realpath(out) != os.path.realpath(tgt)

            sandbox_run(
                ["curl", "-sI", "--max-time", "3",
                 "https://evil.invalid"],
                target=tgt, output=out,
                use_egress_proxy=True, proxy_hosts=["example.com"],
                capture_output=True, text=True, timeout=10,
            )

            tgt_jsonl = Path(tgt) / "proxy-events.jsonl"
            out_jsonl = Path(out) / "proxy-events.jsonl"
            self.assertFalse(
                tgt_jsonl.exists(),
                f"target dir polluted with {tgt_jsonl}"
            )
            self.assertTrue(
                out_jsonl.exists(),
                f"output dir missing expected {out_jsonl} — the "
                f"target-pollution fix should not affect this path"
            )

    def test_output_under_target_does_not_write_jsonl(self):
        """sandbox(target=X, output=X/sub) is also pollution — output is
        a subdir of the scanned tree."""
        with TemporaryDirectory() as d:
            sub = Path(d) / "sub"
            sub.mkdir()
            r = sandbox_run(
                ["curl", "-sI", "--max-time", "3",
                 "https://evil.invalid"],
                target=d, output=str(sub),
                use_egress_proxy=True, proxy_hosts=["example.com"],
                capture_output=True, text=True, timeout=10,
            )

            self.assertFalse(
                (sub / "proxy-events.jsonl").exists(),
                "output under target still wrote proxy-events.jsonl"
            )
            self.assertFalse(
                (Path(d) / "proxy-events.jsonl").exists(),
                "target itself was polluted"
            )

            # In-memory events still populated.
            events = r.sandbox_info.get("proxy_events", [])
            self.assertGreaterEqual(
                len(events), 1,
                f"in-memory events lost when on-disk write is "
                f"suppressed: {events}"
            )


if __name__ == "__main__":
    unittest.main()
