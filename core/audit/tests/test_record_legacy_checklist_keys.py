"""`record` line auto-resolution handles legacy checklist shapes.

Older checklists keep per-file entries under a 'functions' key instead
of 'items'; the other checklist readers in the CLI apply the fallback.
Without it, line_start silently stayed 0 on legacy checklists — and a
zero line makes the reachability caller lookup miss every definitive
caller (callers_of matches by exact function identity including line).
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_legacyck", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("raptor_audit_cli_legacyck", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _prepare(tmp_path: Path, items_key: str):
    from core.audit.record import append_audit_log

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.c").write_text(
        "\n" * 41 + "int foo(char *p) { return p[0]; }\n"
    )
    (out_dir / "checklist.json").write_text(json.dumps({
        "target_path": str(target),
        "files": [{
            "path": "src/a.c",
            items_key: [
                {"name": "foo", "line_start": 42, "line_end": 42},
            ],
        }],
    }))
    append_audit_log(out_dir, {
        "action": "context", "key": "src/a.c:foo",
        "file": "src/a.c", "function": "foo",
    })
    return out_dir, target


def _record_clean(mod, out_dir: Path, target: Path) -> int:
    return mod.cmd_record(SimpleNamespace(
        out=str(out_dir),
        target=str(target),
        file="src/a.c",
        function="foo",
        status="clean",
        body="reviewed",
        line_start=None,
        line_end=None,
        cwe=None,
        strategies=None,
        evidence_tool=None,
        hypothesis=None,
        vuln_type=None,
        related_to=None,
        reach_via=None,
    ))


@pytest.mark.parametrize("items_key", ["items", "functions"])
def test_line_autoresolve_supports_both_checklist_shapes(
        tmp_path, items_key):
    mod = _load_cli()
    out_dir, target = _prepare(tmp_path, items_key)
    rc = _record_clean(mod, out_dir, target)
    assert rc == 0
    from core.coverage.journal import load_entries
    entries = load_entries(out_dir)
    assert entries, "journal entry expected"
    assert entries[-1].line_start == 42
