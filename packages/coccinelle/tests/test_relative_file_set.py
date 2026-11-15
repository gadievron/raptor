"""File-set operands and member keys share the caller coordinate system."""

import json
import re
import subprocess
from pathlib import Path

import pytest

from packages.coccinelle import runner


@pytest.mark.parametrize("spelling", ["absolute", "parent_relative"])
@pytest.mark.parametrize("unassigned", [False, True])
def test_member_operands_and_demux_preserve_authentic_matches(
    tmp_path, monkeypatch, spelling, unassigned,
):
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "nested" / "source"
    root.mkdir(parents=True)
    files = [root / name for name in ("owned.c", "quiet.c")]
    for path in files:
        path.write_text("void owned(void) {}\n")
    members = files if spelling == "absolute" else [path.relative_to(tmp_path) for path in files]
    original_members = list(members)
    rule = tmp_path / "owned.cocci"
    rule.write_text("@owned@\nposition p;\n@@\nowned@p(...)\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "_spatch_path", lambda: "/unused/spatch")
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        operands = command[3:5]
        assert [(Path(kwargs["cwd"]) / operand).resolve() for operand in operands] == files
        text = Path(command[command.index("--sp-file") + 1]).read_text()
        prefix = re.search(r"COCCIRESULT-[0-9a-f]+:", text).group()
        records = [{"rule": "owned", "file": str(files[0]), "line": 1, "message": "owned"}]
        if unassigned:
            records.append({"rule": "owned", "file": "./quiet.c", "line": 2, "message": "unassigned"})
        output = "".join(prefix + json.dumps(record) + "\n" for record in records)
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    result = runner.run_rule(
        root.relative_to(tmp_path), rule, file_set=members,
        subprocess_runner=execute, _installed_version=lambda: "1.3.0",
    )
    assert result.ok and len(calls) == 1
    out = runner.demux_result_by_file(result, members, root)
    assert set(out) == {"owned.c", "quiet.c"}
    assert len(out["owned.c"].matches) == 1
    assert out["quiet.c"].matches == []
    assert members == original_members
    for name, per_file in out.items():
        assert per_file.ok is not unassigned
        assert per_file.files_examined == ([] if unassigned else [name])
        assert bool(per_file.errors) is unassigned
    assert result.ok


@pytest.mark.parametrize("case", ["empty", "missing", "directory"])
def test_file_set_refusals_do_not_invoke_engine(tmp_path, monkeypatch, case):
    root = tmp_path / "root"
    root.mkdir()
    rule = tmp_path / "owned.cocci"
    rule.write_text("@owned@\nposition p;\n@@\nowned@p(...)\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "_spatch_path", lambda: "/unused/spatch")
    members = [] if case == "empty" else [root / "missing.c" if case == "missing" else root]

    def execute(*args, **kwargs):
        pytest.fail("a refused or empty member set invoked the engine")

    result = runner.run_rule(root, rule, file_set=members, subprocess_runner=execute,
                             _installed_version=lambda: "1.3.0")
    assert result.ok is (case == "empty")
    assert result.files_examined == []
    assert bool(result.errors) is (case != "empty")


def test_explicit_outside_root_member_keeps_absolute_key(tmp_path):
    from packages.coccinelle.models import SpatchMatch, SpatchResult

    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("/* inert owned file */\n")
    result = SpatchResult(rule="owned", matches=[SpatchMatch(file=str(outside), line=1)])
    out = runner.demux_result_by_file(result, [outside], root)
    assert list(out) == [str(outside)]
    assert out[str(outside)].ok
    assert out[str(outside)].files_examined == [str(outside)]
    assert out[str(outside)].matches == result.matches
