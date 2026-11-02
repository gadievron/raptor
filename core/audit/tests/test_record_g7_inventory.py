"""`record` G7 reachability gate reads its callers inventory from
checklist.json.

The gate used to load a separate ``out_dir/inventory.json`` that no
pipeline stage ever writes, so ``has_callers`` was always None and
neither G7 arm (zero-caller --reach-via requirement, binary-oracle
absent → dormant downgrade) could ever fire on the ``record`` path.
The checklist IS the callers inventory: raptor-build-checklist embeds
per-file call_graph data there and every other ``callers_of`` consumer
feeds it the checklist directly.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_g7inv", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("raptor_audit_cli_g7inv", loader)
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(mod)
    return mod


def _record_args(out_dir: Path, target: Path, **overrides) -> SimpleNamespace:
    base = dict(
        out=str(out_dir),
        target=str(target),
        file="src/a.py",
        function="orphan",
        status="finding",
        body="sweep output",
        line_start=None,
        line_end=None,
        cwe=None,
        strategies=None,
        evidence_tool="semgrep",
        hypothesis="if input reaches sink unchecked, CWE-787",
        vuln_type="buffer_overflow",
        related_to=None,
        reach_via=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _seed_run(
    tmp_path: Path,
    checklist: dict,
    *,
    function: str = "orphan",
    file: str = "src/a.py",
):
    """Run dir with the G5 context breadcrumb + a confirmed sweep
    receipt so only the G7 gate is under test."""
    from core.audit.record import append_audit_log

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.py").write_text(
        "def orphan(p):\n"
        "    return p[0]\n"
        "\n"
        "\n"
        "def called(p):\n"
        "    return p[0]\n"
        "\n"
        "\n"
        "def main(p):\n"
        "    return called(p)\n"
    )
    (out_dir / "checklist.json").write_text(json.dumps(checklist))
    key = f"{file}:{function}"
    append_audit_log(out_dir, {
        "action": "context", "key": key,
        "file": file, "function": function,
    })
    append_audit_log(out_dir, {
        "action": "sweep", "key": key,
        "file": file, "function": function,
        "tool": "semgrep", "outcome": "confirmed",
    })
    return out_dir, target


def _checklist(items, call_graph=None, items_key="items"):
    file_entry = {"path": "src/a.py", "language": "python",
                  items_key: items}
    if call_graph is not None:
        file_entry["call_graph"] = call_graph
    return {"files": [file_entry]}


_ITEMS = [
    {"name": "orphan", "line_start": 1, "line_end": 2},
    {"name": "called", "line_start": 5, "line_end": 6},
    {"name": "main", "line_start": 9, "line_end": 10},
]

_CALLS = {"imports": {}, "calls": [
    {"caller": "main", "chain": ["called"], "line": 10},
]}


class TestG7ChecklistInventory:
    def test_zero_callers_requires_reach_via(self, tmp_path, capsys):
        mod = _load_cli()
        out_dir, target = _seed_run(
            tmp_path, _checklist(_ITEMS, _CALLS),
        )
        rc = mod.cmd_record(_record_args(out_dir, target))
        captured = capsys.readouterr()
        assert rc == 1
        assert "G7 REACHABILITY" in captured.err
        assert "--reach-via" in captured.err

    def test_zero_callers_with_reach_via_records(self, tmp_path, capsys):
        mod = _load_cli()
        out_dir, target = _seed_run(
            tmp_path, _checklist(_ITEMS, _CALLS),
        )
        rc = mod.cmd_record(
            _record_args(out_dir, target, reach_via="exported API"),
        )
        captured = capsys.readouterr()
        assert rc == 0, captured.err
        assert "recorded: src/a.py:orphan" in captured.out

    def test_function_with_caller_passes(self, tmp_path, capsys):
        mod = _load_cli()
        out_dir, target = _seed_run(
            tmp_path, _checklist(_ITEMS, _CALLS), function="called",
        )
        rc = mod.cmd_record(
            _record_args(out_dir, target, function="called"),
        )
        captured = capsys.readouterr()
        assert rc == 0, captured.err

    def test_oracle_absent_downgraded_on_record(self, tmp_path, capsys):
        # End-to-end two-signal arm: zero static callers AND a
        # full-tier binary-oracle absent verdict on the checklist
        # item → the finding is refused with the dormant downgrade
        # instruction, even when --reach-via is supplied.
        mod = _load_cli()
        items = json.loads(json.dumps(_ITEMS))
        items[0]["metadata"] = {"binary_oracle": {
            "classification": "absent",
            "binaries": [{"tier": "full"}],
        }}
        out_dir, target = _seed_run(
            tmp_path, _checklist(items, _CALLS),
        )
        rc = mod.cmd_record(
            _record_args(out_dir, target, reach_via="exported API"),
        )
        captured = capsys.readouterr()
        assert rc == 1
        assert "G7 REACHABILITY" in captured.err
        assert "binary oracle says absent" in captured.err
        assert "--status dormant" in captured.err
        # Nothing reached the journal or findings store.
        assert not (out_dir / "findings.json").exists()

    def test_symbol_only_oracle_does_not_hard_downgrade(
            self, tmp_path, capsys):
        # Two-direction: a symbol-only tier can't distinguish inlined
        # from absent, so the hard-downgrade arm must NOT fire — the
        # soft --reach-via arm still applies to the zero-caller signal.
        mod = _load_cli()
        items = json.loads(json.dumps(_ITEMS))
        items[0]["metadata"] = {"binary_oracle": {
            "classification": "absent",
            "binaries": [{"tier": "symbol_only"}],
        }}
        out_dir, target = _seed_run(
            tmp_path, _checklist(items, _CALLS),
        )
        rc = mod.cmd_record(
            _record_args(out_dir, target, reach_via="exported API"),
        )
        captured = capsys.readouterr()
        assert rc == 0, captured.err

    def test_legacy_functions_checklist_bypasses_gate(
            self, tmp_path, capsys):
        # Legacy checklists keep items under 'functions' — invisible
        # to the reachability index, so zero callers there means "no
        # data", not "dead code". The gate must stay bypassed.
        mod = _load_cli()
        out_dir, target = _seed_run(
            tmp_path, _checklist(_ITEMS, _CALLS, items_key="functions"),
        )
        rc = mod.cmd_record(_record_args(out_dir, target))
        captured = capsys.readouterr()
        assert rc == 0, captured.err

    def test_stray_inventory_json_is_ignored(self, tmp_path, capsys):
        # The old artifact must carry no authority: a planted
        # inventory.json claiming callers exist cannot bypass the
        # checklist-derived zero-caller signal.
        mod = _load_cli()
        out_dir, target = _seed_run(
            tmp_path, _checklist(_ITEMS, _CALLS),
        )
        (out_dir / "inventory.json").write_text(json.dumps(
            _checklist(_ITEMS, {"imports": {}, "calls": [
                {"caller": "main", "chain": ["orphan"], "line": 10},
            ]}),
        ))
        rc = mod.cmd_record(_record_args(out_dir, target))
        captured = capsys.readouterr()
        assert rc == 1
        assert "G7 REACHABILITY" in captured.err
