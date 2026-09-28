"""raptor-audit gaps — project-index verdict folding parity.

The standalone ``gaps`` subcommand must resolve the project directory
exactly like the run path's forecast (parent-of-out-dir holding the
review-journal index) and pass it to compute_gaps, so prior-run
verdicts fold out of the printed queue. Hermetic: the CLI is loaded
in-process through its real argument parser; the fixture journal is
written through the real append/merge machinery.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    merge_into_index,
    now_iso,
)
from core.staleness import hash_span

_RAPTOR_DIR = Path(__file__).resolve().parents[3]

_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""


def _load_cli():
    cli_path = str(_RAPTOR_DIR / "libexec" / "raptor-audit")
    loader = SourceFileLoader("raptor_audit_gaps_cli_test", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_audit_gaps_cli_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _checklist(target: Path) -> dict:
    return {
        "target_path": str(target),
        "files": [{
            "path": "auth.c",
            "language": "c",
            "items": [{
                "name": "check_pw",
                "kind": "function",
                "line_start": 1,
                "line_end": 5,
            }],
        }],
    }


@pytest.fixture()
def gaps_env(tmp_path, monkeypatch):
    """Target + a project whose run1 journal covers check_pw, plus a
    fresh run2 out dir carrying a pre-built checklist."""
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    (target / "auth.c").write_text(_SOURCE, encoding="utf-8")

    project = tmp_path / "project"
    run1 = project / "run1"
    run1.mkdir(parents=True)
    append_entry(run1, ReviewJournalEntry(
        ts=now_iso(),
        run_id="run1",
        file="auth.c",
        function="check_pw",
        verdict="clean",
        source_hash=hash_span(target / "auth.c", 1, 5),
        line_start=1,
        line_end=5,
    ))
    merge_into_index(project, run1)

    out_dir = project / "run2"
    out_dir.mkdir()
    (out_dir / "checklist.json").write_text(json.dumps(_checklist(target)))

    def run_cli(argv: list[str]) -> int:
        # Through the real parser, exactly as a live invocation.
        monkeypatch.setattr(sys, "argv", ["raptor-audit", *argv])
        return mod.main()

    class Env:
        pass

    env = Env()
    env.target = target
    env.project = project
    env.out_dir = out_dir
    env.run_cli = run_cli
    return env


def _gap_keys(out_dir: Path) -> set[str]:
    doc = json.loads((out_dir / "gaps.json").read_text())
    return {f"{g['file']}:{g['name']}" for g in doc["gaps"]}


def test_cli_folds_prior_run_verdicts(gaps_env, capsys):
    # run1 reviewed check_pw (hash-verified, clean): the CLI queue for
    # run2 must fold it exactly as the run path does — pre-fix the CLI
    # never passed project_dir and reprinted the whole checklist as
    # uncovered.
    rc = gaps_env.run_cli(["gaps", "--out", str(gaps_env.out_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "auth.c:check_pw" not in _gap_keys(gaps_env.out_dir)
    assert "gaps: 0 unreviewed functions" in out


def test_cli_without_project_index_keeps_full_queue(gaps_env, tmp_path,
                                                    capsys):
    # Same checklist in an out dir whose parent has no journal index:
    # nothing to fold, the function stays a gap (the resolution rule is
    # parent-index-exists, not unconditional parent).
    lone = tmp_path / "lone-out"
    lone.mkdir()
    (lone / "checklist.json").write_text(
        json.dumps(_checklist(gaps_env.target)))
    rc = gaps_env.run_cli(["gaps", "--out", str(lone)])
    capsys.readouterr()
    assert rc == 0
    assert "auth.c:check_pw" in _gap_keys(lone)


def test_cli_changed_source_resurfaces(gaps_env, capsys):
    # Drift parity: the fold is hash-aware through the same
    # compute_gaps machinery, so a function whose source changed since
    # its journaled review resurfaces in the CLI queue too.
    (gaps_env.target / "auth.c").write_text(
        "int check_pw(const char *pw) {\n"
        "    /* validation removed */\n"
        "    return strcmp(pw, stored) == 0;\n"
        "    (void)0;\n"
        "}\n",
        encoding="utf-8",
    )
    rc = gaps_env.run_cli(["gaps", "--out", str(gaps_env.out_dir)])
    capsys.readouterr()
    assert rc == 0
    assert "auth.c:check_pw" in _gap_keys(gaps_env.out_dir)
