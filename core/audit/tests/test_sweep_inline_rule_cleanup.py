"""Inline --rule tempfiles are removed on every sweep exit path.

`sweep --rule '...'` materialises the rule as a `.sweep-rule-*`
dotfile in the run directory. It must be unlinked on error returns and
tool exceptions as well as on success — otherwise repeated inline
sweeps litter the output directory with orphaned dotfiles.
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_ruletmp", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("raptor_audit_cli_ruletmp", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _sweep_args(out_dir: Path, target: Path, *, tool: str, file_path: str,
                rule: str = "fake-rule-body") -> SimpleNamespace:
    return SimpleNamespace(
        out=str(out_dir),
        target=str(target),
        file=file_path,
        function="foo",
        tool=tool,
        rule=rule,
        rule_file=None,
        query=None,
        result_file=None,
        outcome=None,
        cwe=None,
        line_start=None,
        line_end=None,
        smt_verb=None,
        smt_args=None,
        codeql_db=None,
    )


def _rule_tmpfiles(out_dir: Path) -> list[Path]:
    return list(out_dir.glob(".sweep-rule-*"))


@pytest.fixture()
def run_env(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text("int foo(void) { return 0; }\n")
    return out_dir, target


def test_needs_source_error_path_cleans_up(run_env, capsys):
    """coccinelle on a binary item errors out before any tool run."""
    mod = _load_cli()
    out_dir, target = run_env
    from core.inventory.binary_builder import BINARY_PATH_PREFIX
    args = _sweep_args(out_dir, target, tool="coccinelle",
                       file_path=f"{BINARY_PATH_PREFIX}foo")
    rc = mod.cmd_sweep(args)
    captured = capsys.readouterr()
    assert rc == 1
    assert "needs source" in captured.err
    assert _rule_tmpfiles(out_dir) == []


def test_missing_decompilation_error_path_cleans_up(
        run_env, capsys, monkeypatch):
    mod = _load_cli()
    out_dir, target = run_env
    import core.audit.binary_context as binary_context
    monkeypatch.setattr(binary_context, "find_redb", lambda out, tgt: None)
    from core.inventory.binary_builder import BINARY_PATH_PREFIX
    args = _sweep_args(out_dir, target, tool="semgrep",
                       file_path=f"{BINARY_PATH_PREFIX}foo")
    rc = mod.cmd_sweep(args)
    captured = capsys.readouterr()
    assert rc == 1
    assert "no decompilation" in captured.err
    assert _rule_tmpfiles(out_dir) == []


def test_tool_exception_path_cleans_up(run_env, monkeypatch):
    mod = _load_cli()
    out_dir, target = run_env

    def boom(**kwargs):
        raise RuntimeError("tool crashed")

    import core.audit.sweep as sweep_mod
    monkeypatch.setattr(sweep_mod, "run_semgrep_sweep", boom)
    args = _sweep_args(out_dir, target, tool="semgrep", file_path="a.c")
    with pytest.raises(RuntimeError):
        mod.cmd_sweep(args)
    assert _rule_tmpfiles(out_dir) == []


def test_success_path_still_works_and_cleans_up(run_env, monkeypatch):
    mod = _load_cli()
    out_dir, target = run_env
    seen: dict[str, str] = {}

    def fake_semgrep(*, target_path, file_path, function_name,
                     rule_config, line_start, line_end):
        # The rule tempfile must still exist while the tool runs.
        seen["rule_exists"] = str(Path(rule_config).exists())
        return SimpleNamespace(
            outcome="confirmed", matches=["a.c:1"], errors=[],
            to_log_entry=lambda: {
                "action": "sweep", "key": f"{file_path}:{function_name}",
                "file": file_path, "function": function_name,
                "tool": "semgrep", "outcome": "confirmed",
            },
        )

    import core.audit.sweep as sweep_mod
    monkeypatch.setattr(sweep_mod, "run_semgrep_sweep", fake_semgrep)
    args = _sweep_args(out_dir, target, tool="semgrep", file_path="a.c")
    rc = mod.cmd_sweep(args)
    assert rc == 0
    assert seen["rule_exists"] == "True"
    assert _rule_tmpfiles(out_dir) == []
    # The sweep receipt was still logged.
    from core.audit.record import load_audit_log
    log = load_audit_log(out_dir)
    assert any(
        e.get("action") == "sweep" and e.get("outcome") == "confirmed"
        for e in log
    )
