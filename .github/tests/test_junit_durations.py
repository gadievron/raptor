"""Tests for .github/scripts/junit_durations.py — junit XML →
duration-map converter feeding duration-aware CI batching."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from contextlib import nullcontext as _path_nullcontext
from unittest.mock import patch as _path_patch
import pytest as _path_pytest

with (_path_patch.object(sys, "path", sys.path.copy())
      if __name__ != "__main__" else _path_nullcontext()):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

    from junit_durations import (
        collect_run,
        main,
        mean_across_runs,
        resolve_classname,
    )




@_path_pytest.fixture(autouse=True)
def _scoped_helper_import_path(monkeypatch):
    """Keep lazy helper imports available without modifying borrowed path lists."""
    monkeypatch.setattr(sys, "path", sys.path.copy())
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))


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
    def test_file_only_keeps_totals_and_dropped_rows(self, mini_repo, tmp_path):
        xml = _write_junit(tmp_path / "file-only.xml", [
            ("core.pkga.tests.test_mod.TestC", "test_a[case]", "1.5"),
            ("core.pkga.tests.test_mod.TestC", "test_a[case]", "2.0"),
            ("", "core.pkga.tests.test_other", "0"),
            ("core.deleted.test_gone", "test_missing", "9"),
            ("core.pkga.tests.test_mod", "test_invalid", "NaN"),
        ])
        files, nodeids, dropped = collect_run(xml, mini_repo)
        assert nodeids == {"core/pkga/tests/test_mod.py::TestC::test_a[case]": 3.5}
        assert dropped == 2
        assert collect_run(xml, mini_repo, include_nodeids=False) == (files, {}, dropped)

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
    @pytest.mark.parametrize("nodeids", [False, True], ids=["files", "nodeids"])
    def test_multiple_reports_keep_per_present_run_means(self, mini_repo, tmp_path, nodeids):
        first = _write_junit(tmp_path / "first.xml", [
            ("core.pkga.tests.test_mod.TestC", "test_a", "1"),
            ("core.pkga.tests.test_mod.TestC", "test_b", "3"),
        ])
        second = _write_junit(tmp_path / "second.xml", [
            ("core.pkga.tests.test_mod.TestC", "test_a", "5"),
            ("core.pkga.tests.test_other", "test_new", "2"),
        ])
        out = tmp_path / "mean.json"
        flags = ["--nodeids"] if nodeids else []
        assert main([*flags, str(out), str(first), str(second), "--repo", str(mini_repo)]) == 0
        expected = {
            "core/pkga/tests/test_mod.py::TestC::test_a": 3.0,
            "core/pkga/tests/test_mod.py::TestC::test_b": 3.0,
            "core/pkga/tests/test_other.py::test_new": 2.0,
        } if nodeids else {
            "core/pkga/tests/test_mod.py": 4.5,
            "core/pkga/tests/test_other.py": 2.0,
        }
        assert json.loads(out.read_text()) == expected

    def test_end_to_end_per_file(self, mini_repo, tmp_path, monkeypatch):
        xml = _write_junit(tmp_path / "run.xml", [
            ("core.pkga.tests.test_mod", "test_a", "1.5"),
            ("core.pkga.tests.test_mod.TestC", "test_b", "2.0"),
        ])
        out = tmp_path / "out.json"

        def file_only(*args, **kwargs):
            result = collect_run(*args, **kwargs)
            assert result[1] == {}, "file-only CLI allocated per-test timings"
            return result

        monkeypatch.setitem(main.__globals__, "collect_run", file_only)
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


@pytest.mark.parametrize('duration', ['NaN', 'inf', '-inf', '-1', 'not-a-number'])
def test_invalid_durations_do_not_poison_valid_measurements(mini_repo, tmp_path, duration):
    xml = _write_junit(tmp_path / 'run.xml', [
        ('core.pkga.tests.test_mod', 'test_bad', duration),
        ('core.pkga.tests.test_mod', 'test_good', '1.5'),
    ])
    per_file, per_nodeid, dropped = collect_run(xml, mini_repo)
    assert per_file == {'core/pkga/tests/test_mod.py': 1.5}
    assert per_nodeid == {'core/pkga/tests/test_mod.py::test_good': 1.5}
    assert dropped == 1


@pytest.mark.parametrize('root_name', ['.github', '.hidden'])
def test_hidden_root_classname_stays_repo_relative(mini_repo, root_name):
    path = mini_repo / root_name / 'tests/test_hidden.py'
    path.parent.mkdir(parents=True)
    path.write_text('')
    assert resolve_classname(f'{root_name}.tests.test_hidden.Outer.Inner', mini_repo) == (
        f'{root_name}/tests/test_hidden.py', ['Outer', 'Inner'])


def test_absolute_classname_does_not_resolve_outside_repo(mini_repo, tmp_path):
    outside = tmp_path / 'outside.py'
    outside.write_text('')
    probes = []
    class Repo:
        def __truediv__(self, candidate):
            probes.append(candidate)
            return mini_repo / candidate
    assert resolve_classname(str(outside.with_suffix('')), Repo()) is None
    assert probes == []


@pytest.mark.parametrize('nodeids', [False, True], ids=['file-totals', 'nodeids'])
def test_cli_keeps_hidden_script_timings_and_collection_skips(mini_repo, tmp_path, nodeids):
    path = mini_repo / '.github/scripts/tests/test_helper.py'
    path.parent.mkdir(parents=True)
    path.write_text('')
    xml = _write_junit(tmp_path / 'run.xml', [
        ('.github.scripts.tests.test_helper.Outer.Inner', 'test_value[a.b]', '2.5'),
        ('', '.github.scripts.tests.test_helper', '0'),
        ('core.pkga.tests.test_mod', 'test_other', '1'),
    ])
    out = tmp_path / 'durations.json'
    args = ['--repo', str(mini_repo), '--prefix', '.github', str(out), str(xml)]
    if nodeids:
        args.insert(0, '--nodeids')
    assert main(args) == 0
    expected_key = '.github/scripts/tests/test_helper.py'
    if nodeids:
        expected_key += '::Outer::Inner::test_value[a.b]'
    assert json.loads(out.read_text()) == {expected_key: 2.5}


def test_repeated_classnames_and_misses_resolve_once(mini_repo, tmp_path, monkeypatch):
    from collections import Counter

    import junit_durations as converter

    calls = Counter()
    original = converter.resolve_classname
    def resolve(dotted, repo):
        calls[dotted] += 1
        return original(dotted, repo)
    monkeypatch.setattr(converter, 'resolve_classname', resolve)
    known = 'core.pkga.tests.test_mod.TestC'
    missing = 'core.missing.tests.test_gone'
    module = 'core.pkga.tests.test_mod'
    rows = ([(known, f'test_{i}', '1') for i in range(10)]
            + [(missing, f'test_{i}', '1') for i in range(5)]
            + [('', module, '0')] * 2)
    xml = _write_junit(tmp_path / 'run.xml', rows)
    per_file, per_nodeid, dropped = collect_run(xml, mini_repo)
    assert per_file == {'core/pkga/tests/test_mod.py': 10.0}
    assert len(per_nodeid) == 10
    assert dropped == 5
    assert calls == {known: 1, missing: 1, module: 1}


def test_resolution_cache_does_not_survive_report_collection(mini_repo, tmp_path):
    xml = _write_junit(tmp_path / 'run.xml', [('core.pkga.tests.test_new', 'test_new', '1')])
    assert collect_run(xml, mini_repo) == ({}, {}, 1)
    path = mini_repo / 'core/pkga/tests/test_new.py'
    path.write_text('')
    assert collect_run(xml, mini_repo) == (
        {'core/pkga/tests/test_new.py': 1.0}, {'core/pkga/tests/test_new.py::test_new': 1.0}, 0)
    path.unlink()
    assert collect_run(xml, mini_repo) == ({}, {}, 1)


@pytest.mark.parametrize("nodeids", [False, True], ids=["files", "nodeids"])
@pytest.mark.parametrize("across_runs", [False, True], ids=["within-report", "across-reports"])
@pytest.mark.parametrize("existing", [False, True], ids=["absent-output", "existing-output"])
def test_aggregate_overflow_refuses_output(
    mini_repo, tmp_path, capsys, nodeids, across_runs, existing,
):
    row = ("core.pkga.tests.test_mod", "test_a", "1e308")
    if across_runs:
        reports = [_write_junit(tmp_path / f"run-{i}.xml", [row]) for i in range(2)]
    else:
        reports = [_write_junit(tmp_path / "run.xml", [row, row])]
    output = tmp_path / "durations.json"
    previous = b'{"preserved": 2.5}\n'
    if existing:
        output.write_bytes(previous)
    args = [str(output), *(str(report) for report in reports), "--repo", str(mini_repo)]
    if nodeids:
        args.append("--nodeids")
    assert main(args) == 1
    assert capsys.readouterr().err == (
        "junit_durations: non-finite aggregated duration; refusing to write map\n"
    )
    if existing:
        assert output.read_bytes() == previous
    else:
        assert not output.exists()


def test_finite_nodeids_survive_unused_file_overflow(mini_repo, tmp_path):
    report = _write_junit(tmp_path / "run.xml", [
        ("core.pkga.tests.test_mod", "test_a", "1e308"),
        ("core.pkga.tests.test_mod", "test_b", "1e308"),
    ])
    output = tmp_path / "durations.json"
    assert main([str(output), str(report), "--repo", str(mini_repo), "--nodeids"]) == 0
    assert json.loads(output.read_text()) == {
        "core/pkga/tests/test_mod.py::test_a": 1e308,
        "core/pkga/tests/test_mod.py::test_b": 1e308,
    }


def test_prefix_excludes_overflow_before_output_validation(mini_repo, tmp_path):
    report = _write_junit(tmp_path / "run.xml", [
        ("core.pkga.tests.test_mod", "test_a", "1e308"),
        ("core.pkga.tests.test_mod", "test_a", "1e308"),
        ("core.pkga.tests.test_other", "test_valid", "2.5"),
    ])
    output = tmp_path / "durations.json"
    assert main([
        str(output), str(report), "--repo", str(mini_repo),
        "--prefix", "core/pkga/tests/test_other.py",
    ]) == 0
    assert output.read_text() == '{\n    "core/pkga/tests/test_other.py": 2.5\n}\n'


def test_nested_testcase_preorder_preserves_float_accumulation(mini_repo, tmp_path):
    report = tmp_path / "nested.xml"
    report.write_text(
        '<testcase classname="core.pkga.tests.test_mod" name="test_a" time="1e16">'
        '<testcase classname="core.pkga.tests.test_mod" name="test_a" time="1"/>'
        '<testcase classname="core.pkga.tests.test_mod" name="test_a" time="1"/>'
        '</testcase>'
    )
    files, nodeids, dropped = collect_run(report, mini_repo)
    assert files == {"core/pkga/tests/test_mod.py": 1e16}
    assert nodeids == {"core/pkga/tests/test_mod.py::test_a": 1e16}
    assert dropped == 0


def test_malformed_suffix_does_not_resolve_or_overwrite(
    mini_repo, tmp_path, monkeypatch,
):
    import xml.etree.ElementTree as ET
    report = tmp_path / "broken.xml"
    report.write_text(
        '<testsuite><testcase classname="core.pkga.tests.test_mod" '
        'name="test_a" time="1"/></broken>'
    )
    output = tmp_path / "durations.json"
    prior = b'{"preserved": 1}\n'
    output.write_bytes(prior)
    def unexpected_resolution(*args):
        pytest.fail("resolver ran before XML validation completed")
    monkeypatch.setitem(collect_run.__globals__, "resolve_classname", unexpected_resolution)
    with pytest.raises(ET.ParseError, match="mismatched tag"):
        main([str(output), str(report), "--repo", str(mini_repo)])
    assert output.read_bytes() == prior


@pytest.mark.parametrize("failure", [None, OSError, KeyboardInterrupt],
                         ids=["success", "read-error", "interrupted"])
def test_owned_incremental_input_closes(mini_repo, tmp_path, monkeypatch, failure):
    import io
    class OwnedInput(io.BytesIO):
        def read(self, *args):
            if failure is not None:
                raise failure("owned input failure")
            return super().read(*args)
    owned = OwnedInput(
        b'<testcase classname="core.pkga.tests.test_mod" name="test_a" time="1"/>'
    )
    path = tmp_path / "owned.xml"
    def open_owned(actual_path, mode):
        assert actual_path == path
        assert mode == "rb"
        return owned
    monkeypatch.setitem(collect_run.__globals__, "open", open_owned)
    if failure is None:
        files, _, dropped = collect_run(path, mini_repo)
        assert files == {"core/pkga/tests/test_mod.py": 1.0}
        assert dropped == 0
    else:
        with pytest.raises(failure, match="owned input failure"):
            collect_run(path, mini_repo)
    assert owned.closed


@pytest.mark.parametrize("malformed", [False, True], ids=["valid", "malformed"])
def test_incremental_input_preserves_borrowed_stream_ownership(mini_repo, malformed):
    import io
    import xml.etree.ElementTree as ET
    data = b'<testcase classname="core.pkga.tests.test_mod" name="test_a" time="1"/>'
    if malformed:
        data += b'</broken>'
    with io.BytesIO(data) as borrowed:
        if malformed:
            with pytest.raises(ET.ParseError):
                collect_run(borrowed, mini_repo)
        else:
            files, _, dropped = collect_run(borrowed, mini_repo)
            assert files == {"core/pkga/tests/test_mod.py": 1.0}
            assert dropped == 0
        assert not borrowed.closed


def test_owned_malformed_xml_closes_before_error(mini_repo, tmp_path, monkeypatch):
    import io
    import xml.etree.ElementTree as ET
    owned = io.BytesIO(b"<testsuite><testcase/></broken>")
    monkeypatch.setitem(collect_run.__globals__, "open", lambda path, mode: owned)
    with pytest.raises(ET.ParseError, match="mismatched tag"):
        collect_run(tmp_path / "broken.xml", mini_repo)
    assert owned.closed


def test_borrowed_read_interruption_keeps_stream_open(mini_repo):
    import io
    interruption = KeyboardInterrupt("borrowed read interrupted")
    class BorrowedInput(io.BytesIO):
        def read(self, *args):
            raise interruption
    with BorrowedInput(b"<testsuite/>") as borrowed:
        with pytest.raises(KeyboardInterrupt) as caught:
            collect_run(borrowed, mini_repo)
        assert caught.value is interruption
        assert not borrowed.closed


@pytest.mark.parametrize("borrowed", [False, True], ids=["owned", "borrowed"])
def test_resolution_error_keeps_primary_exception_and_input_ownership(
    mini_repo, tmp_path, monkeypatch, borrowed,
):
    import io
    failure = RuntimeError("resolution failed")
    with io.BytesIO(
        b'<testcase classname="core.pkga.tests.test_mod" name="test_a" time="1"/>'
    ) as source:
        def fail_resolution(*args):
            assert source.closed is (not borrowed)
            raise failure
        monkeypatch.setitem(collect_run.__globals__, "resolve_classname", fail_resolution)
        if borrowed:
            supplied = source
        else:
            supplied = tmp_path / "owned.xml"
            monkeypatch.setitem(collect_run.__globals__, "open", lambda path, mode: source)
        with pytest.raises(RuntimeError) as caught:
            collect_run(supplied, mini_repo)
        assert caught.value is failure
        assert source.closed is (not borrowed)


def test_namespaced_cases_and_irrelevant_children_do_not_change_totals(mini_repo, tmp_path):
    report = tmp_path / "namespaced.xml"
    report.write_text(
        '<testsuite xmlns:n="urn:owned">'
        '<n:testcase classname="core.pkga.tests.test_mod" name="test_ignored" time="100"/>'
        '<testcase classname="core.pkga.tests.test_mod" name="test_a" time="2.5">'
        '<ignored>owned text</ignored></testcase></testsuite>'
    )
    files, nodeids, dropped = collect_run(report, mini_repo)
    assert files == {"core/pkga/tests/test_mod.py": 2.5}
    assert nodeids == {"core/pkga/tests/test_mod.py::test_a": 2.5}
    assert dropped == 0
