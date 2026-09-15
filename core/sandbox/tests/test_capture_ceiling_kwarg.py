"""Per-call capture ceiling (``max_capture_bytes``) on the run surface.

Callers that only consume bounded tails of hostile output (the
sandbox-tier exec handle) must be able to bound the capture at the
sandbox boundary instead of buffering an arbitrary flood through the
trusted parent. The fork spawn backend enforces the cap during its
pipe drain (transient bound, covered by the gated flood test in
test_run_surface_hardening); these tests pin the surface contract —
the kwarg is accepted, popped before any subprocess lane sees it, and
the result is clamped with the truncation marker on every lane.
"""

from __future__ import annotations

import subprocess
import sys

from core.sandbox import sandbox
from core.sandbox.context import _apply_capture_ceiling


class TestApplyCaptureCeiling:
    def _cp(self, stdout, stderr):
        return subprocess.CompletedProcess(
            ["x"], 0, stdout=stdout, stderr=stderr)

    def test_text_streams_clamped_with_marker(self):
        r = self._cp("a" * 100, "b" * 100)
        _apply_capture_ceiling(r, 10)
        assert r.stdout.startswith("a" * 10)
        assert "stdout capture truncated at 10 bytes" in r.stdout
        assert "stderr capture truncated at 10 bytes" in r.stderr

    def test_bytes_streams_clamped_with_marker(self):
        r = self._cp(b"a" * 100, b"b" * 100)
        _apply_capture_ceiling(r, 10)
        assert isinstance(r.stdout, bytes)
        assert r.stdout.startswith(b"a" * 10)
        assert b"capture truncated" in r.stdout

    def test_under_cap_untouched(self):
        r = self._cp("short", None)
        _apply_capture_ceiling(r, 10)
        assert r.stdout == "short"
        assert r.stderr is None


class TestRunSurfaceKwarg:
    def test_result_clamped_on_the_disabled_lane(self, tmp_path):
        # disabled=True gives the plain-subprocess lane on every host
        # — hermetic, and exactly a lane whose own buffering is NOT
        # drained through the spawn backend, so the chokepoint clamp
        # must bound what flows downstream.
        out = tmp_path / "out"
        out.mkdir()
        with sandbox(target=str(tmp_path), output=str(out),
                     disabled=True) as run:
            r = run(
                [sys.executable, "-c",
                 "import sys; sys.stdout.write('x' * 100000)"],
                capture_output=True, text=True, timeout=60,
                max_capture_bytes=4096,
            )
        assert r.returncode == 0
        assert "capture truncated at 4096 bytes" in r.stdout
        # Cap plus marker slack only.
        assert len(r.stdout) <= 4096 + 128

    def test_without_kwarg_untruncated(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        with sandbox(target=str(tmp_path), output=str(out),
                     disabled=True) as run:
            r = run(
                [sys.executable, "-c",
                 "import sys; sys.stdout.write('x' * 100000)"],
                capture_output=True, text=True, timeout=60,
            )
        assert r.returncode == 0
        assert len(r.stdout) == 100000
