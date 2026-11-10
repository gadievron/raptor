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



def test_utility_exclusion_preserves_other_native_suite_members(selection, monkeypatch):
    runner, pack, selected, reads, resolutions = selection
    security = pack / "Security" / "security.ql"
    security.parent.mkdir()
    security.write_text("select 1\n")
    outside = pack / "custom.ql"
    outside.write_text("select 2\n")
    probe = pack / "Raptor" / "CallableInventory.ql"
    probe.parent.mkdir()
    probe.write_text("// raptor-min-version: 999.0.0\nselect 3\n")
    selected.extend(map(str, [security, probe, outside]))
    version = Mock(side_effect=AssertionError("excluded utility probed the CLI"))
    monkeypatch.setattr(runner, "_codeql_version", version)
    args, skipped = runner._compatible_query_args(pack, excluded_queries=(probe,))
    assert args == [f"path:{security}", f"path:{outside}"]
    assert not skipped
    assert reads == Counter({security.resolve(): 1, outside.resolve(): 1})
    assert len(resolutions) == 1
    version.assert_not_called()


def test_absent_utility_does_not_force_resolution(selection):
    runner, pack, _, _, resolutions = selection
    (pack / "security.ql").write_text("select 1\n")
    assert runner._compatible_query_args(
        pack, excluded_queries=(pack / "Raptor/CallableInventory.ql",)) == ([str(pack)], [])
    assert not resolutions


def test_iris_pass_excludes_probe_but_custom_probe_remains_available(selection, monkeypatch, tmp_path):
    runner, pack, selected, _, _ = selection
    security = pack / "security.ql"
    security.write_text("select 1\n")
    probe = pack / "Raptor/CallableInventory.ql"
    probe.parent.mkdir()
    probe.write_text("select 2\n")
    selected.extend(map(str, [security, probe]))
    monkeypatch.setattr(runner, "_local_dependency_roots", lambda *args: [])
    calls = []

    def analyze(lang, db, pack_dir, out_dir, **kwargs):
        calls.append((pack_dir, kwargs["query_args"]))
        return query_runner.QueryResult(True, lang, db, None, 0, 0, [], kwargs["suite_name"])

    monkeypatch.setattr(runner, "_run_selected_local_pack", analyze)
    result = runner._run_iris_pack("python", tmp_path / "db", pack, tmp_path / "out")
    assert result.success
    assert calls == [(pack, [f"path:{security}"])]
    assert runner._compatible_query_args(probe) == ([str(probe)], [])


def test_utility_exclusion_preserves_compatibility_refusals(selection, monkeypatch):
    runner, pack, selected, _, _ = selection
    unsupported = pack / "unsupported.ql"
    unsupported.write_text("// raptor-min-version: 999.0.0\nselect 1\n")
    plain = pack / "plain.ql"
    plain.write_text("select 2\n")
    probe = pack / "Raptor/CallableInventory.ql"
    probe.parent.mkdir()
    probe.write_text("select 3\n")
    selected.extend(map(str, [unsupported, probe, plain]))
    monkeypatch.setattr(runner, "_codeql_version", lambda: "2.23.8")
    args, skipped = runner._compatible_query_args(pack, excluded_queries=(probe,))
    assert args == [f"path:{plain}"]
    assert len(skipped) == 1
    assert str(unsupported) in skipped[0]
    assert "requires tool >= 999.0.0" in skipped[0]


@pytest.mark.slow
def test_native_iris_security_selection_retains_direct_probe(tmp_path, monkeypatch):
    import shutil

    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig
    from packages.codeql import _resolve_cli

    cli = _resolve_cli()
    if cli is None:
        pytest.skip("CodeQL CLI not installed")
    source = Path(__file__).resolve().parents[3] / "packages/llm_analysis/codeql_packs/python-queries"
    pack = tmp_path / "pack"
    shutil.copytree(source, pack, ignore=shutil.ignore_patterns(".codeql", "*.qlx", "*.qlo"))
    runner = query_runner.QueryRunner(codeql_cli=cli)
    monkeypatch.setattr(runner, "_sandbox_tool_paths", lambda: [])
    monkeypatch.setattr(query_runner, "temporary_command", lambda command: command)

    def native_resolve(command, **kwargs):
        assert list(command[:3]) == [runner.codeql_cli, "resolve", "queries"]
        return run_pinned_subprocess(
            command, timeout=30, context="CodeQL owned native security query selection",
            env=RaptorConfig.get_safe_env(), skip_signals=(9,),
        )

    # This proves real CLI selection, not the independently tested sandbox boundary.
    monkeypatch.setattr("core.sandbox.run", native_resolve)
    probe = pack / "Raptor/CallableInventory.ql"
    args, skipped = runner._compatible_query_args(pack, excluded_queries=(probe,))
    assert not skipped
    resolved = native_resolve([runner.codeql_cli, "resolve", "queries", *args, "--format=json"])
    assert resolved.returncode == 0, resolved.stderr
    actual = {Path(path).resolve() for path in json.loads(resolved.stdout)}
    expected = {path.resolve() for path in (pack / "Security").rglob("*.ql")}
    assert expected
    assert actual == expected
    direct, _ = runner._compatible_query_args(probe)
    resolved_probe = native_resolve(
        [runner.codeql_cli, "resolve", "queries", *direct, "--format=json"])
    assert resolved_probe.returncode == 0, resolved_probe.stderr
    assert json.loads(resolved_probe.stdout) == [str(probe)]
