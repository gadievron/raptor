"""Coccinelle substrate gates: all three refutation variants.

Two-direction pairs per variant (skip on unmodeled substrate, refute
preserved on C-family substrate with a receipt), the whole-tree
tree-scope contract, the dispatcher's pre-dispatch gate (including
the cross-file conjunct rule), and skipped-outcome memo replay.
Hermetic — spatch is stubbed at the runner boundary.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import core.audit.orchestrator as orch
import packages.coccinelle.runner as cocci_runner
from core.audit.cocci_flow import run_flow_cocci_sweep
from core.audit.orchestrator import _make_tier_counters, _run_tool_chain
from core.audit.substrate import _reset_substrate_caches
from core.audit.sweep import run_coccinelle_sweep, run_consistency_check
from core.audit.sweep_memo import SweepMemo

_UAF_HYPOTHESIS = (
    "use-after-free of conn->buf: kfree(conn->buf) then deref"
)


@pytest.fixture(autouse=True)
def _fresh_caches():
    _reset_substrate_caches()
    yield
    _reset_substrate_caches()


def _stub_spatch(monkeypatch, calls: list | None = None):
    """spatch double: available, runs clean, matches nothing."""
    monkeypatch.setattr(cocci_runner, "is_available", lambda: True)

    def _run_rule(target, rule, **kw):
        if calls is not None:
            calls.append(str(target))
        return SimpleNamespace(matches=[], errors=[], returncode=0)

    monkeypatch.setattr(cocci_runner, "run_rule", _run_rule)


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "a.c").write_text(
        "int f(void){ return 0; }\n",
    )
    (tmp_path / "src" / "index.php").write_text(
        "<?php function f() { return 0; }\n",
    )
    rule = tmp_path / "check.cocci"
    rule.write_text("@@ @@\n")
    return rule


class TestSingleFileSweep:
    def test_php_file_skips_without_spawning_spatch(
        self, tmp_path, monkeypatch,
    ):
        rule = _tree(tmp_path)
        calls: list = []
        _stub_spatch(monkeypatch, calls)
        res = run_coccinelle_sweep(
            target_path=tmp_path, file_path="src/index.php",
            function_name="f", cocci_rule=str(rule),
        )
        assert res.outcome == "skipped"
        assert "php" in res.details["reason"]
        assert res.details["substrate"]["covered"] is False
        assert not calls

    def test_c_file_keeps_genuine_refutation_with_receipt(
        self, tmp_path, monkeypatch,
    ):
        # The over-skipping tripwire: a clean spatch run on real C
        # still refutes, now carrying its substrate receipt.
        rule = _tree(tmp_path)
        calls: list = []
        _stub_spatch(monkeypatch, calls)
        res = run_coccinelle_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", cocci_rule=str(rule),
        )
        assert res.outcome == "refuted"
        assert calls, "spatch must run on a C-family file"
        assert res.details["substrate"]["covered"] is True
        assert res.details["substrate"]["evidence"] == {"language": "c"}

    def test_stamped_language_overrides_extension(
        self, tmp_path, monkeypatch,
    ):
        # An inventory-stamped 'php' wins over a .c suffix
        # (content-probed foreign-extension source).
        rule = _tree(tmp_path)
        _stub_spatch(monkeypatch)
        res = run_coccinelle_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", cocci_rule=str(rule), language="php",
        )
        assert res.outcome == "skipped"


class TestFlowSweep:
    def test_php_file_skips(self, tmp_path, monkeypatch):
        _tree(tmp_path)
        calls: list = []
        _stub_spatch(monkeypatch, calls)
        res = run_flow_cocci_sweep(
            target_path=tmp_path, file_path="src/index.php",
            function_name="f", hypothesis=_UAF_HYPOTHESIS,
            template="use_after_free",
        )
        assert res.outcome == "skipped"
        assert res.details["substrate"]["covered"] is False
        assert not calls

    def test_c_file_refutes_with_receipt(self, tmp_path, monkeypatch):
        _tree(tmp_path)
        _stub_spatch(monkeypatch)
        res = run_flow_cocci_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", hypothesis=_UAF_HYPOTHESIS,
            template="use_after_free",
        )
        assert res.outcome == "refuted"
        assert res.details["substrate"]["covered"] is True
        # The flow channel's own details survive the license.
        assert res.details["binding"]["victim"] == "conn->buf"


class TestWholeTreeSweep:
    def test_no_c_substrate_in_tree_skips(self, tmp_path, monkeypatch):
        rule = _tree(tmp_path)
        calls: list = []
        _stub_spatch(monkeypatch, calls)
        res = run_consistency_check(
            target_path=tmp_path, function_name="f",
            cocci_rule=str(rule),
            tree_languages=frozenset({"php", "javascript"}),
        )
        assert res.outcome == "skipped"
        assert res.file_path == "<codebase>"
        assert "no C substrate in tree" in res.details["reason"]
        assert not calls

    def test_c_family_tree_refutes_with_tree_scoped_receipt(
        self, tmp_path, monkeypatch,
    ):
        rule = _tree(tmp_path)
        _stub_spatch(monkeypatch)
        res = run_consistency_check(
            target_path=tmp_path, function_name="f",
            cocci_rule=str(rule),
            tree_languages=frozenset({"php", "c"}),
        )
        assert res.outcome == "refuted"
        assert res.details["substrate"]["tier"] == "tree-language"
        assert res.details["substrate"]["covered"] is True

    def test_no_inventory_fails_open_to_historic_refuted(
        self, tmp_path, monkeypatch,
    ):
        # Direct callers without an inventory keep the historic
        # behavior; the receipt records the unknown.
        rule = _tree(tmp_path)
        _stub_spatch(monkeypatch)
        res = run_consistency_check(
            target_path=tmp_path, function_name="f",
            cocci_rule=str(rule), tree_languages=None,
        )
        assert res.outcome == "refuted"
        assert res.details["substrate"]["covered"] == "unknown"


class _Cfg:
    def __init__(self, target: Path, out_dir: Path | None = None):
        self.target_path = target
        self.out_dir = out_dir
        self.codeql_db_path = None
        self.project_sinks = None
        self.tool_chain_early_exit = True


def _dispatch(cfg, entry, file_path, *, tiers, skipped, memo=None):
    if memo is not None:
        cfg.sweep_memo = memo
    return _run_tool_chain(
        [entry],
        config=cfg,
        file_path=file_path,
        function_name="f",
        source="int f(void){ return 0; }",
        hypothesis=_UAF_HYPOTHESIS,
        line_start=1,
        tier_counters=tiers,
        skipped_types=skipped,
    )


class TestDispatcherGate:
    def test_php_subject_skips_before_the_sweep_runs(
        self, tmp_path, monkeypatch,
    ):
        rule = _tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        sweep_calls: list = []
        monkeypatch.setattr(
            orch, "run_coccinelle_sweep",
            lambda **kw: sweep_calls.append(kw),
        )
        cfg = _Cfg(tmp_path, out_dir=out)
        tiers = _make_tier_counters()
        skipped: set = set()
        _dispatch(
            cfg, {"type": "coccinelle", "config": {"rule": str(rule)}},
            "src/index.php", tiers=tiers, skipped=skipped,
        )
        assert not sweep_calls
        assert "coccinelle" in skipped
        tc = tiers["coccinelle"]
        assert tc.skipped == 1
        assert tc.skipped_substrate == 1
        assert tc.substrate_skip_languages == {"php": 1}
        assert tc.refuted == 0
        rows = [
            json.loads(line)
            for line in (out / ".audit-log.jsonl").read_text().splitlines()
        ]
        skip_rows = [r for r in rows if r.get("action") == "substrate_skip"]
        assert len(skip_rows) == 1
        assert skip_rows[0]["tool"] == "coccinelle"
        assert skip_rows[0]["file"] == "src/index.php"
        assert "php" in skip_rows[0]["reason"]

    def test_c_subject_dispatches(self, tmp_path, monkeypatch):
        rule = _tree(tmp_path)
        monkeypatch.setattr(
            orch, "run_coccinelle_sweep",
            lambda **kw: SimpleNamespace(
                outcome="refuted", details=None, errors=[],
                rule_id=str(rule), matches=[],
            ),
        )
        cfg = _Cfg(tmp_path)
        tiers = _make_tier_counters()
        skipped: set = set()
        _dispatch(
            cfg, {"type": "coccinelle", "config": {"rule": str(rule)}},
            "src/a.c", tiers=tiers, skipped=skipped,
        )
        assert "coccinelle" not in skipped
        assert tiers["coccinelle"].refuted == 1
        assert tiers["coccinelle"].skipped_substrate == 0

    def test_cross_file_entry_keeps_the_subject_file_gate(
        self, tmp_path, monkeypatch,
    ):
        # Conjunct, not replacement: a stray C file in the tree must
        # not let a whole-tree sweep refute a PHP-function hypothesis
        # — the subject-file predicate gates the dispatch even though
        # the result would be tree-scoped.
        rule = _tree(tmp_path)
        import core.audit.sweep as sweep_mod
        tree_calls: list = []
        monkeypatch.setattr(
            sweep_mod, "run_consistency_check",
            lambda **kw: tree_calls.append(kw),
        )
        cfg = _Cfg(tmp_path)
        # Inventory carries a C file — the tree fact alone would
        # license the "<codebase>" result.
        cfg.inventory = {"files": [
            {"path": "src/a.c", "language": "c"},
            {"path": "src/index.php", "language": "php"},
        ]}
        tiers = _make_tier_counters()
        skipped: set = set()
        _dispatch(
            cfg,
            {"type": "coccinelle",
             "config": {"rule": str(rule), "cross_file": True}},
            "src/index.php", tiers=tiers, skipped=skipped,
        )
        assert not tree_calls
        assert "coccinelle" in skipped
        assert tiers["coccinelle"].skipped_substrate == 1

    def test_cross_file_entry_dispatches_with_tree_context(
        self, tmp_path, monkeypatch,
    ):
        rule = _tree(tmp_path)
        import core.audit.sweep as sweep_mod
        seen: dict[str, Any] = {}

        def _fake_tree_sweep(**kw):
            seen.update(kw)
            return SimpleNamespace(
                outcome="refuted", details=None, errors=[],
                rule_id=str(rule), matches=[],
            )

        monkeypatch.setattr(
            sweep_mod, "run_consistency_check", _fake_tree_sweep,
        )
        cfg = _Cfg(tmp_path)
        cfg.inventory = {"files": [
            {"path": "src/a.c", "language": "c"},
            {"path": "src/index.php", "language": "php"},
        ]}
        tiers = _make_tier_counters()
        _dispatch(
            cfg,
            {"type": "coccinelle",
             "config": {"rule": str(rule), "cross_file": True}},
            "src/a.c", tiers=tiers, skipped=set(),
        )
        assert seen["tree_languages"] == frozenset({"c", "php"})
        assert tiers["coccinelle"].refuted == 1


class TestSkippedMemoReplay:
    def test_skipped_is_stored_and_replayed(self, tmp_path, monkeypatch):
        # Run-scoped, file-keyed, semantically stable: the second
        # dispatch serves the skip from the memo without re-running
        # the sweep, with identical accounting.
        from core.audit.sweep import SweepResult

        rule = _tree(tmp_path)
        runs: list = []

        def _skipping_sweep(**kw):
            runs.append(kw)
            return SweepResult(
                tool="coccinelle", file_path=kw["file_path"],
                function_name=kw["function_name"], outcome="skipped",
                rule_id=str(rule),
                details={"reason": "r", "substrate": {"covered": False}},
            )

        monkeypatch.setattr(
            orch, "run_coccinelle_sweep", _skipping_sweep,
        )
        cfg = _Cfg(tmp_path)
        memo = SweepMemo()
        tiers = _make_tier_counters()
        entry = {"type": "coccinelle", "config": {"rule": str(rule)}}
        _dispatch(cfg, entry, "src/a.c", tiers=tiers,
                  skipped=set(), memo=memo)
        _dispatch(cfg, entry, "src/a.c", tiers=tiers,
                  skipped=set(), memo=memo)
        assert len(runs) == 1, "second dispatch must be a memo hit"
        assert tiers["coccinelle"].skipped == 2
        assert tiers["coccinelle"].refuted == 0
