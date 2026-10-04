"""Tests for the setgroups-stub build helper.

Pins two fixes:
  * gcc's exit status is checked — a failed compile that still left
    partial output at ``-o`` must not be promoted into the cache
    (pre-fix the returncode was discarded and any tmp file present
    was renamed over the cache entry).
  * the temp path is per-process (mkstemp), so concurrent cold
    builders cannot rename each other's partially written .so.
"""

import subprocess
import sys
from unittest.mock import patch

import pytest

from core.sandbox import shims

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="stub build is Linux-only",
)


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "shims-cache"
    monkeypatch.setattr(shims, "_CACHE_DIR", d)
    return d


def _argv_output_path(argv):
    return argv[argv.index("-o") + 1]


def test_compile_failure_with_partial_output_not_cached(cache_dir):
    """gcc rc!=0 with a partial .so left at -o must yield None and an
    empty cache — not a corrupt cached stub."""

    def fake_gcc(argv, **kwargs):
        with open(_argv_output_path(argv), "wb") as f:
            f.write(b"\x7fELF-partial-garbage")
        return subprocess.CompletedProcess(
            argv, returncode=1, stdout="", stderr="ld: error: boom",
        )

    with patch("core.sandbox.shims.subprocess.run", side_effect=fake_gcc):
        result = shims.build_setgroups_stub()
    assert result is None
    assert not list(cache_dir.glob("libsetgroups_stub-*.so")), (
        "partial compiler output was promoted into the cache"
    )


def test_compile_failure_no_output_not_cached(cache_dir):
    def fake_gcc(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv, returncode=1, stdout="", stderr="gcc: fatal error",
        )

    with patch("core.sandbox.shims.subprocess.run", side_effect=fake_gcc):
        result = shims.build_setgroups_stub()
    assert result is None
    assert not list(cache_dir.glob("*.so"))


def test_successful_build_cached_and_temp_removed(cache_dir):
    payload = b"\x7fELF fake shared object"

    def fake_gcc(argv, **kwargs):
        with open(_argv_output_path(argv), "wb") as f:
            f.write(payload)
        return subprocess.CompletedProcess(
            argv, returncode=0, stdout="", stderr="",
        )

    with patch("core.sandbox.shims.subprocess.run", side_effect=fake_gcc):
        result = shims.build_setgroups_stub()
    assert result is not None
    assert result.read_bytes() == payload
    assert result.parent == cache_dir
    # World-readable like the pre-mkstemp default-umask output.
    assert result.stat().st_mode & 0o044
    # No temp litter left behind.
    assert not list(cache_dir.glob("*.tmp.so"))

    # Second call is a cache hit — the compiler must not run again.
    with patch(
        "core.sandbox.shims.subprocess.run",
        side_effect=AssertionError("cache miss re-ran gcc"),
    ):
        again = shims.build_setgroups_stub()
    assert again == result
