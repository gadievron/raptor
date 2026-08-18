"""Tests for packages.codeql.tunables — resource-flag resolution."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.codeql.tunables import CodeQLTunables


def _tuning(threads=0, ram=0, cache=0):
    class _T:
        codeql_threads = threads
        codeql_ram_mb = ram
        codeql_max_disk_cache_mb = cache
    return _T()


class TestAppendTo:
    def test_flags_appended_in_order(self):
        cmd = ["codeql", "database", "create"]
        CodeQLTunables(threads=4, ram_mb=2048, max_disk_cache_mb=100).append_to(
            cmd, include_disk_cache=True)
        assert cmd[-4:] == ["-j", "4", "-M", "2048"] or "-j" in cmd
        assert "--max-disk-cache=100" in cmd

    def test_analyze_path_omits_disk_cache(self):
        cmd = []
        CodeQLTunables(threads=0, max_disk_cache_mb=100).append_to(
            cmd, include_disk_cache=False)
        assert not any(a.startswith("--max-disk-cache") for a in cmd)

    def test_none_ram_skips_flag(self):
        cmd = []
        CodeQLTunables(threads=0, ram_mb=None).append_to(cmd)
        assert "-M" not in cmd


class TestConcurrentWorkerShare:
    """N concurrent -j0 invocations must not each claim every core."""

    def test_auto_threads_divided_between_workers(self):
        with patch("core.tuning.get_tuning", return_value=_tuning(threads=0)):
            t = CodeQLTunables.from_tuning(concurrent_workers=4)
        assert t.threads == max(1, (os.cpu_count() or 4) // 4)

    def test_single_worker_keeps_full_auto(self):
        with patch("core.tuning.get_tuning", return_value=_tuning(threads=0)):
            t = CodeQLTunables.from_tuning(concurrent_workers=1)
        assert t.threads == 0

    def test_pinned_threads_never_divided(self):
        """An explicit numeric codeql_threads is the operator's call —
        concurrency must not second-guess it."""
        with patch("core.tuning.get_tuning", return_value=_tuning(threads=6)):
            t = CodeQLTunables.from_tuning(concurrent_workers=4)
        assert t.threads == 6

    def test_override_threads_never_divided(self):
        with patch("core.tuning.get_tuning", return_value=_tuning(threads=0)):
            t = CodeQLTunables.from_tuning(
                overrides={"threads": 12}, concurrent_workers=4)
        assert t.threads == 12

    def test_division_floors_at_one(self):
        with patch("core.tuning.get_tuning", return_value=_tuning(threads=0)):
            t = CodeQLTunables.from_tuning(concurrent_workers=10_000)
        assert t.threads == 1
