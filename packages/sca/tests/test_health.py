"""Tests for the registry health probe (packages/sca/health.py)."""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from packages.sca import health as health_mod


class _StubClient:
    """list_versions stub matching the registry-client swallow
    contract: logs a WARNING and returns [] on failure."""

    def __init__(self, versions, warn=None):
        self._versions = versions
        self._warn = warn

    def list_versions(self, name):
        if self._warn:
            logging.getLogger(
                health_mod.PyPIClient.__module__.rsplit(".", 1)[0]
                + ".stub").warning(self._warn)
        return self._versions


class TestProbeErrorAttribution:
    def _probe_with_capture(self, client):
        capture = health_mod._ThreadLogCapture()
        reg = logging.getLogger(
            health_mod.PyPIClient.__module__.rsplit(".", 1)[0])
        reg.addHandler(capture)
        try:
            return health_mod._run_probe(client, "stub", "pkg", capture)
        finally:
            reg.removeHandler(capture)

    def test_swallowed_error_surfaces_in_row(self):
        r = self._probe_with_capture(_StubClient(
            [], warn="Upstream proxy could not tunnel to 'x' (CONNECT)"))
        assert r.ok is False
        assert "could not tunnel" in (r.error or "")

    def test_genuinely_empty_keeps_generic_message(self):
        r = self._probe_with_capture(_StubClient([], warn=None))
        assert r.error == "registry returned 0 versions"

    def test_success_has_no_error(self):
        r = self._probe_with_capture(_StubClient(["1.0", "1.1"]))
        assert r.ok is True and r.error is None

    def test_exception_path_reports_exception(self):
        class _Boom:
            def list_versions(self, name):
                raise RuntimeError("kaput")
        r = health_mod._run_probe(_Boom(), "stub", "pkg", None)
        assert r.ok is False and "kaput" in (r.error or "")

    def test_parallel_probes_attribute_to_own_thread(self):
        # Two concurrent probes, each logging a distinct cause: each
        # row must carry ITS thread's message, never the sibling's.
        capture = health_mod._ThreadLogCapture()
        reg = logging.getLogger(
            health_mod.PyPIClient.__module__.rsplit(".", 1)[0])
        reg.addHandler(capture)
        barrier = threading.Barrier(2)

        class _SyncStub(_StubClient):
            def list_versions(self, name):
                barrier.wait(timeout=10)
                return super().list_versions(name)

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                fa = pool.submit(health_mod._run_probe,
                                 _SyncStub([], warn="cause-alpha"),
                                 "a", "pkg", capture)
                fb = pool.submit(health_mod._run_probe,
                                 _SyncStub([], warn="cause-beta"),
                                 "b", "pkg", capture)
                ra, rb = fa.result(), fb.result()
        finally:
            reg.removeHandler(capture)
        assert ra.error == "cause-alpha"
        assert rb.error == "cause-beta"


class TestTrimCause:
    def test_first_line_only(self):
        assert health_mod._trim_cause("one\ntwo") == "one"

    def test_bounded(self):
        out = health_mod._trim_cause("x" * 500)
        assert len(out) <= 220 and out.endswith("…")
