"""Tests for .github/scripts/junit_durations.py — junit XML →
duration-map converter feeding duration-aware CI batching."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from junit_durations import (
    collect_run,
    main,
    mean_across_runs,
    resolve_classname,
)


def _write_junit(path: Path, cases: list[tuple[str, str, str]]) -> Path:
    """cases: (classname, name, time) triples in this repo's junit
    shape (xunit2: one <testcase> per test, dotted classname)."""
    rows = "".join(
        f'<testcase classname="{cn}" name="{nm}" time="{t}" />'
        for cn, nm, t in cases
    )
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<testsuites><testsuite name="pytest">{rows}</testsuite>'
        "</testsuites>",
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def mini_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "core/pkga/tests").mkdir(parents=True)
    (repo / "core/pkga/tests/test_mod.py").write_text("")
    (repo / "core/pkga/tests/test_other.py").write_text("")
    return repo


class TestResolveClassname:
    def test_plain_module(self, mini_repo):
        assert resolve_classname("core.pkga.tests.test_mod", mini_repo) == (
            "core/pkga/tests/test_mod.py", []
        )

    def test_class_components_fall_away(self, mini_repo):
        assert resolve_classname(
            "core.pkga.tests.test_mod.TestOuter.TestInner", mini_repo
        ) == ("core/pkga/tests/test_mod.py", ["TestOuter", "TestInner"])

    def test_unresolvable_returns_none(self, mini_repo):
        assert resolve_classname("core.gone.test_x", mini_repo) is None


class TestCollectRun:
    def test_per_file_sums_and_class_strip(self, mini_repo, tmp_path):
        xml = _write_junit(tmp_path / "run.xml", [
            ("core.pkga.tests.test_mod", "test_a", "1.5"),
            ("core.pkga.tests.test_mod.TestC", "test_b", "2.0"),
            ("core.pkga.tests.test_other", "test_c[x.y:1]", "0.25"),
        ])
        per_file, per_nodeid, dropped = collect_run(xml, mini_repo)
        assert per_file == {
            "core/pkga/tests/test_mod.py": 3.5,
            "core/pkga/tests/test_other.py": 0.25,
        }
        # Nodeids keep class components and the raw (dotted,
        # bracketed) parametrized name.
        assert per_nodeid == {
            "core/pkga/tests/test_mod.py::test_a": 1.5,
            "core/pkga/tests/test_mod.py::TestC::test_b": 2.0,
            "core/pkga/tests/test_other.py::test_c[x.y:1]": 0.25,
        }
        assert dropped == 0

    def test_collection_skip_rows_use_name(self, mini_repo, tmp_path):
        # Rows skipped at collection carry the dotted module path in
        # name and an empty classname (observed junit shape).
        xml = _write_junit(tmp_path / "run.xml", [
            ("", "core.pkga.tests.test_other", "0.000"),
        ])
        per_file, per_nodeid, dropped = collect_run(xml, mini_repo)
        assert per_file == {"core/pkga/tests/test_other.py": 0.0}
        assert per_nodeid == {}  # no test name → no nodeid to form
        assert dropped == 0

    def test_unresolvable_rows_dropped_and_counted(self, mini_repo, tmp_path):
        xml = _write_junit(tmp_path / "run.xml", [
            ("core.deleted.tests.test_gone", "test_a", "9.0"),
            ("core.pkga.tests.test_mod", "test_a", "1.0"),
        ])
        per_file, _, dropped = collect_run(xml, mini_repo)
        assert per_file == {"core/pkga/tests/test_mod.py": 1.0}
        assert dropped == 1


class TestMeanAcrossRuns:
    def test_mean_over_runs_where_key_appears(self):
        merged = mean_across_runs([
            {"a.py": 2.0, "b.py": 1.0},
            {"a.py": 4.0},  # b.py absent: not diluted by this run
        ])
        assert merged == {"a.py": 3.0, "b.py": 1.0}


class TestCli:
    def test_end_to_end_per_file(self, mini_repo, tmp_path):
        xml = _write_junit(tmp_path / "run.xml", [
            ("core.pkga.tests.test_mod", "test_a", "1.5"),
            ("core.pkga.tests.test_mod.TestC", "test_b", "2.0"),
        ])
        out = tmp_path / "out.json"
        rc = main([str(out), str(xml), "--repo", str(mini_repo)])
        assert rc == 0
        assert json.loads(out.read_text(encoding="utf-8")) == {
            "core/pkga/tests/test_mod.py": 3.5,
        }

    def test_end_to_end_nodeids_with_prefix(self, mini_repo, tmp_path):
        (mini_repo / "packages/sca/tests").mkdir(parents=True)
        (mini_repo / "packages/sca/tests/test_p.py").write_text("")
        xml = _write_junit(tmp_path / "run.xml", [
            ("packages.sca.tests.test_p", "test_a", "0.5"),
            ("core.pkga.tests.test_mod", "test_b", "1.0"),
        ])
        out = tmp_path / "out.json"
        rc = main([
            "--nodeids", "--prefix", "packages/sca",
            str(out), str(xml), "--repo", str(mini_repo),
        ])
        assert rc == 0
        assert json.loads(out.read_text(encoding="utf-8")) == {
            "packages/sca/tests/test_p.py::test_a": 0.5,
        }

    def test_zero_entries_refuses_to_write(self, mini_repo, tmp_path):
        # Fail-closed: an empty map silently degrades every consumer
        # (pytest-split random-splits, batch_matrix falls to default
        # weights) — better to fail the generating step loudly.
        xml = _write_junit(tmp_path / "run.xml", [
            ("core.deleted.tests.test_gone", "test_a", "9.0"),
        ])
        out = tmp_path / "out.json"
        rc = main([str(out), str(xml), "--repo", str(mini_repo)])
        assert rc == 1
        assert not out.exists()
