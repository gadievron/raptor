"""Only numeric gcov execution counts may establish runtime coverage."""
import pytest

from core.coverage.parsers.gcov import parse_gcov


def report(path, count):
    path.write_text(f"-:0:Source:owned.c\n1:1:covered\n{count}:2:candidate\n7:3:covered\n")
    return path


@pytest.mark.parametrize("count", [
    "garbage", "NaN", "inf", "1e3", "1.2", "k", "1K", "1m", "*", "1**",
    "-2k", "+2k", "1.2.3k", "1kk", "", "١", "#", "$$$$$", "%%%%%",
])
def test_malformed_count_does_not_mark_line_executed(tmp_path, count):
    path = report(tmp_path / "owned.gcov", count)
    assert parse_gcov(path) == {"owned.c": {1, 3}}


@pytest.mark.parametrize("count", [
    "1", "1234", "1*", "24k", "24k*", "24.6k", "24.6k*", "1.0M",
    "2G", "3T", "4P", "5E", "6Z", "7Y", "0001",
    "\x1b[45;37m        1\x1b[0m",
])
def test_documented_numeric_and_partial_counts_remain_executed(tmp_path, count):
    assert parse_gcov(report(tmp_path / "owned.gcov", count)) == {"owned.c": {1, 2, 3}}


@pytest.mark.parametrize("count", [
    "0", "0*", "0k", "0.0M", "000", "-1", "-", "#####", "=====",
    "\x1b[41;37m        0\x1b[0m",
])
def test_zero_and_unexecuted_markers_stay_uncovered(tmp_path, count):
    assert parse_gcov(report(tmp_path / "owned.gcov", count)) == {"owned.c": {1, 3}}


def test_invalid_count_cannot_enter_runtime_store(tmp_path):
    from core.coverage.importer import import_runtime
    from core.coverage.store import CoverageStore

    path = report(tmp_path / "owned.gcov", "garbage")
    checklist = {"files": [{"path": "owned.c", "lines": 3, "items": []}]}
    store = CoverageStore(tmp_path / "coverage.json", target="owned-report")
    store.import_inventory_meta(checklist)
    import_runtime(store, path, checklist)
    assert store.who_checked("owned.c", 1) == ["gcov"]
    assert store.who_checked("owned.c", 2) == []
    assert store.who_checked("owned.c", 3) == ["gcov"]


def test_count_validation_preserves_report_byte_cap(tmp_path, monkeypatch):
    from core.coverage.parsers import gcov

    path = report(tmp_path / "owned.gcov", "24.6k")
    monkeypatch.setattr(gcov, "_MAX_REPORT_BYTES", 16)
    assert parse_gcov(path) == {}
