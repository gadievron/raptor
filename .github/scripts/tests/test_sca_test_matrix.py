"""SCA sizing may change parallelism, never which files pytest receives."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "sca_test_matrix", Path(__file__).resolve().parents[1] / "sca_test_matrix.py",
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
sca_matrix = _module.sca_matrix


def _timings(tmp_path, rows):
    path = tmp_path / "durations.json"
    path.write_text(json.dumps(rows))
    return path


def _groups(count):
    return [{"group": i, "groups": count} for i in range(1, count + 1)]


@pytest.mark.parametrize("seconds,count", [(1, 1), (30, 1), (31, 2), (61, 3), (91, 4), (999, 4)])
def test_measured_runtime_sizes_groups(tmp_path, seconds, count):
    assert sca_matrix(["a.py"], _timings(tmp_path, {"a.py::test_a": seconds})) == _groups(count)


def test_many_cheap_cases_still_split(tmp_path):
    rows = {f"a.py::test_a[{i}]": 0.001 for i in range(2001)}
    assert sca_matrix(["a.py"], _timings(tmp_path, rows)) == _groups(3)


def test_unselected_slow_records_do_not_inflate_selection(tmp_path):
    path = _timings(tmp_path, {"a.py::test_a": 1, "b.py::test_b": 1000, "b.py::test_huge": 10 ** 400})
    assert sca_matrix(["a.py", "a.py"], path) == _groups(1)


@pytest.mark.parametrize("rows", [None, [], {}, {"a.py": 1}, {"a.py::test_a": 0},
    {"a.py::test_a": -1}, {"a.py::test_a": True}, {"a.py::test_a": "1"},
    {"a.py::test_a": float("nan")}, {"a.py::test_a": float("inf")},
    {"a.py::test_a": 1e308, "a.py::test_b": 1e308}, {"b.py::test_b": 1},
    pytest.param({"a.py::test_a": 10 ** 400}, id="oversized-positive-integer"),
    pytest.param({"a.py::test_a": -(10 ** 400)}, id="oversized-negative-integer"),
    pytest.param({"a.py::": 1}, id="missing-test-name")])
def test_unknown_or_invalid_timings_keep_four_groups(tmp_path, rows):
    assert sca_matrix(["a.py"], _timings(tmp_path, rows)) == _groups(4)


def test_partially_covered_selection_keeps_four_groups(tmp_path):
    assert sca_matrix(["a.py", "new.py"], _timings(tmp_path, {"a.py::test_a": 1})) == _groups(4)


def test_missing_or_corrupt_file_keeps_four_groups(tmp_path):
    path = tmp_path / "missing.json"
    assert sca_matrix(["a.py"], path) == _groups(4)
    path.write_text("{bad")
    assert sca_matrix(["a.py"], path) == _groups(4)


def test_no_selection_needs_no_runners(tmp_path):
    assert sca_matrix([], tmp_path / "missing.json") == []


@pytest.mark.parametrize('duration,groups', [(1, 1), (10 ** 400, 4)], ids=['valid-timings', 'oversized-integer'])
def test_cli_emits_matrix(tmp_path, monkeypatch, duration, groups):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "packages/sca").mkdir(parents=True)
    (tmp_path / "packages/sca/test-durations.json").write_text(json.dumps({"a.py::test_a": duration}))
    output = tmp_path / "output"
    monkeypatch.setenv("SCA_FILES", "a.py")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    _module.main()
    assert json.loads(output.read_text().split("=", 1)[1]) == _groups(groups)
