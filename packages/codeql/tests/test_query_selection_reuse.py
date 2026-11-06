"""Compatibility selection owns its metadata and probe reuse for one call."""

import json
import subprocess
from collections import Counter
from pathlib import Path
from unittest.mock import Mock

import pytest

from packages.codeql import query_runner


@pytest.fixture
def selection(tmp_path, monkeypatch):
    pack = tmp_path / "pack"
    pack.mkdir()
    runner = query_runner.QueryRunner(codeql_cli=str(tmp_path / "codeql"))
    monkeypatch.setattr(runner, "_sandbox_tool_paths", lambda: [])
    monkeypatch.setattr(query_runner, "temporary_command", lambda command: command)
    selected: list[str] = []
    resolutions = []

    def resolve(command, **kwargs):
        assert "resolve" in command and "queries" in command
        resolutions.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(selected), stderr="")

    monkeypatch.setattr("core.sandbox.run", resolve)
    reads: Counter[Path] = Counter()
    read = query_runner.read_capped_text

    def tracked_read(path, *args, **kwargs):
        reads[Path(path).resolve()] += 1
        return read(path, *args, **kwargs)

    monkeypatch.setattr(query_runner, "read_capped_text", tracked_read)
    return runner, pack, selected, reads, resolutions


def test_declared_rules_share_unknown_answer_and_retry_next_selection(selection, monkeypatch):
    runner, pack, selected, reads, resolutions = selection
    plain = pack / "plain.ql"
    plain.write_text("select 1\n")
    declared = [pack / f"requires-{index}.ql" for index in range(12)]
    for path in declared:
        path.write_text("// raptor-min-version: 2.20.0\nselect 1\n")
    selected.extend(map(str, [plain, *declared]))
    version = Mock(side_effect=[None, "2.23.8"])
    monkeypatch.setattr(runner, "_codeql_version", version)

    args, skipped = runner._compatible_query_args(pack)
    assert args == [f"path:{plain}"]
    assert len(skipped) == len(declared)
    assert all("installed version unknown" in reason for reason in skipped)
    assert version.call_count == 1
    assert reads == Counter({path.resolve(): 1 for path in [plain, *declared]})

    args, skipped = runner._compatible_query_args(pack)
    assert args == [str(pack)] and not skipped  # Preserve native suite selection.
    assert version.call_count == 2
    assert reads == Counter({path.resolve(): 2 for path in [plain, *declared]})
    assert len(resolutions) == 1


def test_suite_reads_only_selected_members_and_rechecks_changed_metadata(selection, monkeypatch):
    runner, pack, selected, reads, _ = selection
    suite = pack / "selection.qls"
    suite.write_text("- query: chosen.ql\n")
    chosen = pack / "chosen.ql"
    chosen.write_text("// raptor-min-version: 2.20.0\nselect 1\n")
    ignored = pack / "ignored.ql"
    ignored.write_text("// raptor-min-version: 999.0.0\nselect 2\n")
    selected.extend([str(chosen), str(chosen)])
    version = Mock(return_value="2.23.8")
    monkeypatch.setattr(runner, "_codeql_version", version)

    args, skipped = runner._compatible_query_args(suite)
    assert args == [f"path:{chosen}"] and not skipped
    assert reads == Counter({chosen.resolve(): 1})
    assert version.call_count == 1

    chosen.write_text("// raptor-min-version: 999.0.0\nselect 1\n")
    args, skipped = runner._compatible_query_args(suite)
    assert not args and len(skipped) == 1
    assert "requires tool >= 999.0.0" in skipped[0]
    assert reads == Counter({chosen.resolve(): 2})
    assert version.call_count == 2


def test_undeclared_queries_never_probe_or_force_resolution(selection, monkeypatch):
    runner, pack, _, reads, resolutions = selection
    query = pack / "plain.ql"
    query.write_text("select 1\n")
    version = Mock(side_effect=AssertionError("undeclared query probed the CLI"))
    monkeypatch.setattr(runner, "_codeql_version", version)
    assert runner._compatible_query_args(pack) == ([str(pack)], [])
    assert reads == Counter({query.resolve(): 1})
    assert not resolutions
    version.assert_not_called()
