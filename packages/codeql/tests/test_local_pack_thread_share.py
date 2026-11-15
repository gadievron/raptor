"""Parallel local packs share automatic threads at the command boundary."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from packages.codeql import query_runner


@pytest.mark.parametrize("kind,count,workers,pinned,share", [
    ("iris", 2, 2, 0, 2),
    ("curated", 2, 2, 0, 2),
    ("curated", 1, 4, 0, 1),
    ("curated", 3, 2, 0, 2),
    ("curated", 2, 2, 6, 2),
], ids=["iris-two", "curated-two", "one-selected", "worker-cap", "pinned"])
def test_local_pack_commands_share_auto_threads(
    tmp_path, monkeypatch, kind, count, workers, pinned, share,
):
    runner = query_runner.QueryRunner(codeql_cli="/owned/codeql")
    root = tmp_path / "packs"
    root.mkdir()
    languages = ["python", "java", "javascript"][:count]
    for lang in languages:
        pack = root / (f"{lang}-queries" if kind == "iris" else lang)
        pack.mkdir()
        (pack / "qlpack.yml").write_text(f"name: owned/{lang}\nversion: 0.0.1\n")
        (pack / "owned.ql").write_text("select 1\n")
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", True)
    monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
    monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
    monkeypatch.setattr(RaptorConfig, "CODEQL_OFFLINE", True)
    monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [root])
    monkeypatch.setattr(RaptorConfig, "CODEQL_QUERIES_DIR", root)
    monkeypatch.setattr(runner, "_local_dependency_roots", lambda *args: [])
    monkeypatch.setattr(runner, "_compatible_query_args", lambda pack, **kw: ([str(pack)], []))
    monkeypatch.setattr(runner, "_analysis_scope", lambda *args: {})
    monkeypatch.setattr(query_runner, "_iris_pack_deps_already_resolved", lambda *args: False)
    monkeypatch.setattr(query_runner, "temporary_command", lambda command, **kw: command)
    import core.tuning
    monkeypatch.setattr(core.tuning, "get_tuning", lambda: SimpleNamespace(
        codeql_threads=pinned, codeql_ram_mb=0, codeql_max_disk_cache_mb=0,
    ))
    commands = []

    def dispatch(command, **kwargs):
        commands.append(command)
        assert command[1:3] == ["database", "analyze"]
        assert kwargs["block_network"] is True
        output = next(arg.split("=", 1)[1] for arg in command if arg.startswith("--output="))
        Path(output).write_text(json.dumps({"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "CodeQL"}}, "results": [],
        }]}))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    import core.sandbox
    monkeypatch.setattr(core.sandbox, "run", dispatch)
    databases = {lang: tmp_path / f"db-{lang}" for lang in languages}
    databases["absent-pack"] = tmp_path / "db-absent"
    analyze = runner.analyze_iris_packs if kind == "iris" else runner.analyze_curated_packs
    results = analyze(databases, out, max_workers=workers)
    assert set(results) == set(languages)
    assert all(result.success for result in results.values())
    assert len(commands) == count
    expected = pinned or (0 if share == 1 else max(1, (os.cpu_count() or 4) // share))
    assert {command[command.index("-j") + 1] for command in commands} == {str(expected)}
