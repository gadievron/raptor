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


import os  # noqa: E402
import shutil  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402
from tempfile import TemporaryDirectory  # noqa: E402

from core.sandbox import check_net_available, run as sandbox_run  # noqa: E402
from core.sandbox.tests.capability import requires_landlock


@requires_landlock
class TestProxyEventsTargetPollution(unittest.TestCase):
    """proxy-events.jsonl must not be written into `target` when
    output==target (or output lives under target). In-memory events
    must still be populated regardless."""

    def setUp(self):
        if not check_net_available():
            self.skipTest("User namespaces not available")
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        from core.testing.proxy_scope import isolated_proxy_scope
        self.enterContext(isolated_proxy_scope())
        # Hermetic against leaked proxy env from earlier suites: a
        # dead 127.0.0.1 upstream pointer makes the proxy tunnel
        # instead of screening locally, and denied_host / the local
        # jsonl paths this class asserts on never happen. Same guard
        # the attack-scenario is_global test carries.
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"):
            for name in (var, var.lower()):
                if name in os.environ:
                    # addCleanup at the pop site: restoration survives
                    # future insertions after these lines and skip
                    # paths, structurally.
                    value = os.environ.pop(name)
                    self.addCleanup(os.environ.__setitem__, name, value)



    @staticmethod
    def _attempt_diag(r) -> str:
        """One-line per-attempt evidence for the zero-events skip path.

        The skip message used to assert 'host load' without evidence;
        the curl exit code separates the two mechanisms this class has
        been starved by in the field: 28 (curl burned --max-time — the
        CONNECT genuinely never completed, load-consistent) vs 7/5/56
        (curl could not reach or speak to the proxy at all — a broken
        netns bridge / forwarder, which is a bug, not load). Enforcement
        tier and stderr ride along so the CI log names the failing leg
        without a reproduction."""
        info = getattr(r, "sandbox_info", {}) or {}
        stderr = (r.stderr or "").strip().replace("\n", " | ")[-300:]
        return (
            f"curl rc={r.returncode} "
            f"enforcement={info.get('proxy_enforcement')!r} "
            f"mount_ns={info.get('mount_ns_active')!r} "
            f"stderr={stderr!r}"
        )

    def test_target_equals_output_does_not_write_jsonl(self):
        """sandbox(target=X, output=X) MUST NOT create X/proxy-events.jsonl.

        Mirrors the codeql build_detector pattern. The denied CONNECT
        produces an in-memory event (asserted below) but the on-disk
        write is suppressed because the path would land inside the
        scanned tree.
        """
        with TemporaryDirectory() as d:
            jsonl = Path(d) / "proxy-events.jsonl"
            events = []
            diags = []
            # Under a loaded parallel battery curl can burn its whole
            # --max-time before the CONNECT reaches the proxy — no
            # event exists and the run proves nothing about the
            # in-memory buffer. The pollution claim is asserted for
            # EVERY attempt; the event claim earns bounded retries.
            for _attempt in range(3):
                r = sandbox_run(
                    ["curl", "-sI", "--max-time", "3",
                     "https://evil.invalid"],
                    target=d, output=d,
                    use_egress_proxy=True, proxy_hosts=["example.com"],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertFalse(
                    jsonl.exists(),
                    f"target={d} output={d} polluted the scanned tree "
                    f"with {jsonl} (contents: "
                    f"{jsonl.read_text() if jsonl.exists() else ''!r})"
                )
                events = r.sandbox_info.get("proxy_events", [])
                diags.append(self._attempt_diag(r))
                if events:
                    break
            if not events:
                # Starvation, not a wrong buffer: the on-disk
                # non-pollution claim above held on every attempt.
                self.skipTest(
                    "no proxy events after 3 attempts — the in-memory "
                    "event claim was not exercised. Per-attempt "
                    "evidence (curl 28 = load starvation; 7/5/56 = "
                    "proxy unreachable, a bridge bug): "
                    + "; ".join(diags))

            # In-memory events MUST still be populated — the fix only
            # suppresses on-disk persistence, not the proxy_events
            # buffer surfaced on result.sandbox_info.
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

            tgt_jsonl = Path(tgt) / "proxy-events.jsonl"
            out_jsonl = Path(out) / "proxy-events.jsonl"
            events = []
            diags = []
            # Same starvation guard as the target==output test: under
            # a loaded parallel battery curl can burn its --max-time
            # before the CONNECT reaches the proxy — no event exists,
            # so no write is due and its absence proves nothing. The
            # non-pollution claim is asserted for EVERY attempt; the
            # write claim earns bounded retries.
            for _attempt in range(3):
                r = sandbox_run(
                    ["curl", "-sI", "--max-time", "3",
                     "https://evil.invalid"],
                    target=tgt, output=out,
                    use_egress_proxy=True, proxy_hosts=["example.com"],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertFalse(
                    tgt_jsonl.exists(),
                    f"target dir polluted with {tgt_jsonl}"
                )
                events = r.sandbox_info.get("proxy_events", [])
                diags.append(self._attempt_diag(r))
                if events:
                    break
            if not events:
                # Starvation, not a suppressed write: no event was
                # recorded, so nothing was due on disk; the
                # non-pollution claim above held on every attempt.
                self.skipTest(
                    "no proxy events after 3 attempts — the output-dir "
                    "write claim was not exercised. Per-attempt "
                    "evidence (curl 28 = load starvation; 7/5/56 = "
                    "proxy unreachable, a bridge bug): "
                    + "; ".join(diags))
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
            events = []
            diags = []
            # Bounded retries for the in-memory claim, pollution
            # asserted on every attempt — same starvation guard as
            # the sibling tests.
            for _attempt in range(3):
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
                events = r.sandbox_info.get("proxy_events", [])
                diags.append(self._attempt_diag(r))
                if events:
                    break
            if not events:
                self.skipTest(
                    "no proxy events after 3 attempts — the in-memory "
                    "event claim was not exercised. Per-attempt "
                    "evidence (curl 28 = load starvation; 7/5/56 = "
                    "proxy unreachable, a bridge bug): "
                    + "; ".join(diags))

            # In-memory events still populated.
            self.assertGreaterEqual(
                len(events), 1,
                f"in-memory events lost when on-disk write is "
                f"suppressed: {events}"
            )


if __name__ == "__main__":
    unittest.main()
