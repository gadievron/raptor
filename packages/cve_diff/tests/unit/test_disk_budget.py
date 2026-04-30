"""Disk-budget guard tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from cve_diff.infra import disk_budget


class _Usage:
    def __init__(self, used: int, total: int) -> None:
        self.used = used
        self.total = total


def test_check_returns_used_pct():
    with patch("cve_diff.infra.disk_budget.psutil.disk_usage", return_value=_Usage(50, 100)):
        status = disk_budget.check("/")
    assert status.used_pct == 50.0
    assert status.limit_pct == disk_budget.DEFAULT_LIMIT_PCT
    assert status.ok


def test_check_ok_at_threshold():
    with patch("cve_diff.infra.disk_budget.psutil.disk_usage", return_value=_Usage(79, 100)):
        status = disk_budget.check("/", limit_pct=80.0)
    assert status.ok


def test_check_not_ok_above_limit():
    with patch("cve_diff.infra.disk_budget.psutil.disk_usage", return_value=_Usage(81, 100)):
        status = disk_budget.check("/", limit_pct=80.0)
    assert not status.ok


def test_assert_ok_raises_when_full():
    with patch("cve_diff.infra.disk_budget.psutil.disk_usage", return_value=_Usage(95, 100)):
        with pytest.raises(disk_budget.DiskBudgetExceeded) as excinfo:
            disk_budget.assert_ok("/", limit_pct=80.0)
    assert "95.0%" in str(excinfo.value)
    assert "80%" in str(excinfo.value)


def test_assert_ok_passes_when_under():
    with patch("cve_diff.infra.disk_budget.psutil.disk_usage", return_value=_Usage(10, 100)):
        disk_budget.assert_ok("/", limit_pct=80.0)
