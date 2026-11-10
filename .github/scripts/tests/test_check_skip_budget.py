"""Detector-correctness tests for the skip-count budget gate."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_skip_budget.py"


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location("check_skip_budget", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _junit(tmp_path: Path, name: str, skipped: int, tests: int = 50,
           suites: int = 1) -> Path:
    """A junit file shaped like pytest's --junitxml output."""
    body = "".join(
        f'<testsuite name="pytest{i}" errors="0" failures="0" '
        f'skipped="{skipped}" tests="{tests}" time="1.0"></testsuite>'
        for i in range(suites)
    )
    p = tmp_path / name
    p.write_text(f"<?xml version='1.0'?><testsuites>{body}</testsuites>",
                 encoding="utf-8")
    return p


def _baseline(tmp_path: Path, entries: dict) -> Path:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(entries), encoding="utf-8")
    return p


def _run(gate, monkeypatch, capsys, argv: list[str]) -> tuple[int, str]:
    monkeypatch.setattr("sys.argv", ["check_skip_budget.py", *argv])
    rc = gate.main()
    return rc, capsys.readouterr().out


class TestJunitParsing:
    def test_counts_skips(self, gate, tmp_path):
        xml = _junit(tmp_path, "a.xml", skipped=7)
        assert gate.count_skips(xml) == 7

    def test_sums_multiple_suites(self, gate, tmp_path):
        xml = _junit(tmp_path, "a.xml", skipped=3, suites=2)
        assert gate.count_skips(xml) == 6

    def test_missing_file_raises(self, gate, tmp_path):
        with pytest.raises(ValueError, match="cannot read"):
            gate.count_skips(tmp_path / "nope.xml")

    def test_xml_without_testsuite_raises(self, gate, tmp_path):
        p = tmp_path / "bad.xml"
        p.write_text("<notjunit/>", encoding="utf-8")
        with pytest.raises(ValueError, match="no <testsuite>"):
            gate.count_skips(p)


class TestGateSemantics:
    def test_growth_over_recorded_count_fails(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=9)
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 1
        assert "skip count changed vs baseline" in out
        assert "9 > recorded 5" in out

    def test_at_recorded_count_passes(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=5)
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, _ = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 0

    def test_shrink_is_silent_on_filtered_runs(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        # A path-filtered run collects a subset — a lower count is
        # expected, not stale headroom.
        xml = _junit(tmp_path, "a.xml", skipped=1)
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 0
        assert "WARN" not in out

    def test_shrink_warns_on_full_runs(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=1)
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base), "--full",
        ])
        assert rc == 0
        assert "WARN" in out
        assert "skip count changed vs baseline" in out

    def test_unrecorded_lane_notices_without_failing(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        # Adoption path: counts are runner-environment facts, seeded
        # from a CI run's own output — an unrecorded lane must report,
        # never block.
        xml = _junit(tmp_path, "a.xml", skipped=4)
        base = _baseline(tmp_path, {})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "new-lane", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 0
        assert "NOTICE" in out
        assert "--write-baseline" in out

    def test_multiple_junit_files_sum(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        a = _junit(tmp_path, "a.xml", skipped=3)
        b = _junit(tmp_path, "b.xml", skipped=4)
        base = _baseline(tmp_path, {"lane-x": {"skips": 6}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(a),
            "--junit-xml", str(b), "--baseline", str(base),
        ])
        assert rc == 1
        assert "7 > recorded 6" in out

    def test_unreadable_junit_is_a_usage_error_not_a_pass(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        base = _baseline(tmp_path, {"lane-x": {"skips": 5}})
        rc, _ = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(tmp_path / "gone.xml"),
            "--baseline", str(base),
        ])
        assert rc == 2

    def test_absent_baseline_is_the_adoption_path(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=4)
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(tmp_path / "never-written.json"),
        ])
        assert rc == 0
        assert "NOTICE" in out

    def test_corrupt_baseline_fails_closed_in_read_mode(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        # A present-but-unparseable baseline must be exit 2, not the
        # NOTICE path: falling open would demote EVERY recorded lane
        # to non-enforcing behind one corrupt commit.
        xml = _junit(tmp_path, "a.xml", skipped=4)
        base = tmp_path / "baseline.json"
        base.write_text("{not json", encoding="utf-8")
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 2
        assert "NOTICE" not in out

    def test_misshapen_baseline_fails_closed_in_read_mode(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=4)
        base = tmp_path / "baseline.json"
        base.write_text('["not", "an", "object"]', encoding="utf-8")
        rc, _ = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 2

    def test_non_integer_skips_row_is_an_error_not_a_notice(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=4)
        base = _baseline(tmp_path, {"lane-x": {"skips": "5"}})
        rc, out = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base),
        ])
        assert rc == 2
        assert "NOTICE" not in out


class TestWriteBaseline:
    def test_records_lane_and_preserves_other_rows_and_notes(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=8)
        base = _baseline(tmp_path, {
            "lane-x": {"skips": 5, "note": "reviewed"},
            "lane-y": {"skips": 2, "note": "other lane"},
        })
        rc, _ = _run(gate, monkeypatch, capsys, [
            "--lane", "lane-x", "--junit-xml", str(xml),
            "--baseline", str(base), "--write-baseline",
        ])
        assert rc == 0
        data = json.loads(base.read_text(encoding="utf-8"))
        assert data["lane-x"] == {"skips": 8, "note": "reviewed"}
        assert data["lane-y"] == {"skips": 2, "note": "other lane"}

    def test_unreadable_baseline_refuses_the_rewrite(
        self, gate, tmp_path, monkeypatch, capsys,
    ):
        xml = _junit(tmp_path, "a.xml", skipped=8)
        base = tmp_path / "baseline.json"
        base.write_text("{not json", encoding="utf-8")
        monkeypatch.setattr("sys.argv", [
            "check_skip_budget.py", "--lane", "lane-x",
            "--junit-xml", str(xml), "--baseline", str(base),
            "--write-baseline",
        ])
        with pytest.raises(SystemExit):
            gate.main()
        assert base.read_text(encoding="utf-8") == "{not json"


@pytest.mark.parametrize('count', [-1, -100])
def test_negative_xml_skip_counts_are_rejected(gate, tmp_path, count):
    xml = _junit(tmp_path, 'bad.xml', skipped=count)
    with pytest.raises(ValueError, match='non-negative integer'):
        gate.count_skips(xml)


@pytest.mark.parametrize('count', [True, False, -1])
def test_boolean_or_negative_baseline_count_is_invalid(
    gate, tmp_path, monkeypatch, capsys, count,
):
    xml = _junit(tmp_path, 'a.xml', skipped=0)
    base = _baseline(tmp_path, {'lane-x': {'skips': count}})
    rc, _ = _run(gate, monkeypatch, capsys, [
        '--lane', 'lane-x', '--junit-xml', str(xml), '--baseline', str(base),
    ])
    assert rc == 2


@pytest.mark.parametrize('data', [[], {'lane-x': {'skips': 2}, 'lane-y': 3}])
def test_refresh_refuses_to_erase_misshapen_baseline(gate, tmp_path, data):
    base = _baseline(tmp_path, data)
    original = base.read_bytes()
    with pytest.raises(SystemExit):
        gate.write_baseline(base, 'lane-x', 5)
    assert base.read_bytes() == original


@pytest.mark.parametrize('reported', [0, 2], ids=['underreported', 'overreported'])
def test_detailed_skip_counter_mismatch_is_an_error(gate, tmp_path, reported):
    xml = tmp_path / 'report.xml'
    xml.write_text(f'<testsuite skipped="{reported}"><testcase name="test_x"><skipped/></testcase></testsuite>')
    with pytest.raises(ValueError, match='does not match testcase records'):
        gate.count_skips(xml)


@pytest.mark.parametrize('wrapper', [False, True], ids=['suite-root', 'suites-root'])
def test_nested_rollups_count_skipped_records_once(gate, tmp_path, wrapper):
    body = ('<testsuite skipped="2">'
            '<testsuite skipped="1"><testcase name="a"><skipped/></testcase></testsuite>'
            '<testsuite skipped="1"><testcase name="b"><skipped/></testcase></testsuite>'
            '</testsuite>')
    if wrapper:
        body = '<testsuites>' + body + '</testsuites>'
    xml = tmp_path / 'report.xml'
    xml.write_text(body)
    assert gate.count_skips(xml) == 2


def test_multiple_skip_phase_records_keep_their_count(gate, tmp_path):
    xml = tmp_path / 'report.xml'
    xml.write_text('<testsuite skipped="2"><testcase name="a"><skipped/><skipped/></testcase></testsuite>')
    assert gate.count_skips(xml) == 2


@pytest.mark.parametrize('write', [False, True], ids=['check', 'record-baseline'])
def test_invalid_report_cannot_pass_or_refresh_baseline(gate, tmp_path, monkeypatch, capsys, write):
    xml = tmp_path / 'report.xml'
    xml.write_text('<testsuite skipped="0"><testcase name="a"><skipped/></testcase></testsuite>')
    baseline = _baseline(tmp_path, {'lane-x': {'skips': 5, 'note': 'keep'}})
    before = baseline.read_bytes()
    argv = ['check_skip_budget.py', '--lane', 'lane-x', '--junit-xml', str(xml), '--baseline', str(baseline)]
    if write:
        argv.append('--write-baseline')
    monkeypatch.setattr('sys.argv', argv)
    assert gate.main() == 2
    assert 'does not match testcase records' in capsys.readouterr().err
    assert baseline.read_bytes() == before


@pytest.mark.parametrize('wrapper,expected', [(False, 7), (True, 11)],
                         ids=['suite-root', 'suites-root'])
def test_summary_only_nested_counters_keep_historical_behavior(gate, tmp_path, wrapper, expected):
    body = '<testsuite skipped="7"><testsuite skipped="4"/></testsuite>'
    if wrapper:
        body = '<testsuites>' + body + '</testsuites>'
    xml = tmp_path / 'summary.xml'
    xml.write_text(body)
    assert gate.count_skips(xml) == expected


def test_xml_parse_error_precedes_counter_validation(gate, tmp_path):
    xml = tmp_path / 'truncated.xml'
    xml.write_text('<testsuite skipped="bad"><testcase></testsuite>')
    with pytest.raises(ValueError, match='cannot read junit XML') as error:
        gate.count_skips(xml)
    assert isinstance(error.value.__cause__, gate.ET.ParseError)


@pytest.mark.parametrize('kind', ['parse', 'read', 'interrupt', 'exit'])
def test_reader_closes_owned_stream_on_parser_failure(gate, tmp_path, monkeypatch, kind):
    xml = tmp_path / 'report.xml'
    xml.write_text('<testsuite skipped="0"/>')
    opened = []
    primary = {'parse': gate.ET.ParseError('owned parse error'),
               'read': OSError('owned read error'),
               'interrupt': KeyboardInterrupt('owned interrupt'),
               'exit': SystemExit(9)}[kind]

    native_open = open

    def recording_open(path, mode):
        stream = native_open(path, mode)
        opened.append(stream)
        return stream

    def fail_parse(stream, *, events):
        assert not stream.closed
        assert events == ('start', 'end')
        raise primary

    parser = SimpleNamespace(**(vars(gate.ET) | {'iterparse': fail_parse}))
    monkeypatch.setattr(gate, 'ET', parser)
    monkeypatch.setattr(gate, 'open', recording_open, raising=False)
    expected = ValueError if kind in {'parse', 'read'} else type(primary)
    with pytest.raises(expected) as observed:
        gate.count_skips(xml)
    assert len(opened) == 1 and opened[0].closed
    if expected is ValueError:
        assert observed.value.__cause__ is primary
    else:
        assert observed.value is primary


@pytest.mark.parametrize('malformed', [False, True], ids=['valid', 'malformed'])
def test_borrowed_stream_is_not_closed(gate, malformed):
    body = b'<testsuite><testcase>' if malformed else b'<testsuite skipped="3"/>'
    with io.BytesIO(body) as stream:
        if malformed:
            with pytest.raises(ValueError, match='cannot read junit XML'):
                gate.count_skips(stream)
        else:
            assert gate.count_skips(stream) == 3
        assert not stream.closed


def test_string_filename_remains_supported(gate, tmp_path):
    xml = _junit(tmp_path, 'string-path.xml', skipped=3)
    assert gate.count_skips(str(xml)) == 3
