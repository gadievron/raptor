"""Disk-budget guard tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from cve_diff.infra import disk_budget


class _Usage:
    def __init__(self, used: int, total: int) -> None:
        self.used = used
        self.total = total
        self.free = total - used


def test_check_returns_used_pct():
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=_Usage(50, 100)):
        status = disk_budget.check("/")
    assert status.used_pct == 50.0
    assert status.limit_pct == disk_budget.DEFAULT_LIMIT_PCT
    assert status.ok


def test_explicit_limit_rejects_equal_usage():
    gib = 1024**3
    usage = _Usage(used=80 * gib, total=100 * gib)
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=usage):
        status = disk_budget.check("/", limit_pct=80.0)
    assert status.free_bytes == disk_budget.DEFAULT_MIN_FREE_BYTES
    assert not status.ok


def test_check_not_ok_above_limit():
    gib = 1024**3
    with patch(
        "cve_diff.infra.disk_budget.shutil.disk_usage",
        return_value=_Usage(180 * gib, 200 * gib),
    ):
        status = disk_budget.check("/", limit_pct=50.0)
    assert status.free_bytes == disk_budget.DEFAULT_MIN_FREE_BYTES
    assert not status.ok


def test_assert_ok_raises_when_full():
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=_Usage(95, 100)):
        with pytest.raises(disk_budget.DiskBudgetExceeded) as excinfo:
            disk_budget.assert_ok("/", limit_pct=80.0)
    assert "95.0%" in str(excinfo.value)
    assert "80%" in str(excinfo.value)


def test_assert_ok_passes_when_under():
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=_Usage(10, 100)):
        disk_budget.assert_ok("/", limit_pct=80.0)


def test_assert_ok_passes_default_limit_with_ample_free_space():
    gib = 1024**3
    usage = _Usage(used=762 * gib, total=926 * gib)  # 82% used, 164 GiB free
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=usage):
        disk_budget.assert_ok("/")


def test_default_policy_accepts_exact_minimum_free_space():
    gib = 1024**3
    usage = _Usage(used=80 * gib, total=100 * gib)
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=usage):
        status = disk_budget.check("/")
    assert status.used_pct == disk_budget.DEFAULT_LIMIT_PCT
    assert status.free_bytes == disk_budget.DEFAULT_MIN_FREE_BYTES
    assert status.ok


def test_default_policy_rejects_equal_usage_below_minimum_free_space():
    gib = 1024**3
    usage = _Usage(used=40 * gib, total=50 * gib)
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=usage):
        status = disk_budget.check("/")
    assert status.used_pct == disk_budget.DEFAULT_LIMIT_PCT
    assert status.free_bytes < disk_budget.DEFAULT_MIN_FREE_BYTES
    assert not status.ok


def test_default_policy_rejects_above_limit_just_below_minimum_free_space():
    gib = 1024**3
    usage = _Usage(used=180 * gib, total=200 * gib - 1)
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=usage):
        status = disk_budget.check("/")
    assert status.used_pct > disk_budget.DEFAULT_LIMIT_PCT
    assert status.free_bytes == disk_budget.DEFAULT_MIN_FREE_BYTES - 1
    assert not status.ok


def test_default_policy_accepts_usage_below_limit_with_low_free_space():
    gib = 1024**3
    usage = _Usage(used=39 * gib, total=50 * gib)
    with patch("cve_diff.infra.disk_budget.shutil.disk_usage", return_value=usage):
        status = disk_budget.check("/")
    assert status.used_pct < disk_budget.DEFAULT_LIMIT_PCT
    assert status.free_bytes < disk_budget.DEFAULT_MIN_FREE_BYTES
    assert status.ok
