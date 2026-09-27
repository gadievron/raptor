"""Tool-chain early exit: skip subprocess-tier steps after a
promotion-grade confirmation.

Two-direction coverage: the exit fires (subprocess-tier steps skipped,
skip recorded and journaled) AND the full chain runs with the flag
off, with no predicate, and when the only confirmation is
detection-role (aggregation still needs the later channels).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import core.audit.orchestrator as orch
from core.audit.orchestrator import (
    _EARLY_EXIT_SKIPPABLE_TYPES,
    _promotion_grade_receipt,
    _run_tool_chain,
)
from core.audit.sweep import SweepResult


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path, out_dir: Path | None = None):
        self.target_path = target
        self.out_dir = out_dir
        self.codeql_db_path = None
        self.project_sinks = None
        self.tool_chain_early_exit = True
        # No memo: every dispatch must reach the stubs.


def _sg_result(outcome: str = "confirmed") -> SweepResult:
    return SweepResult(
        tool="semgrep", file_path="src/a.c", function_name="f",
        outcome=outcome, rule_id="rules/r.yaml",
        matches=[{"line": 4}] if outcome == "confirmed" else [],
    )


def _write_tree(tmp_path: Path) -> tuple[Path, Path]:
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "a.c").write_text("int f(void){}\n")
    rule = tmp_path / "rules" / "r.yaml"
    rule.parent.mkdir(exist_ok=True)
    rule.write_text("rules: []\n")
    cocci = tmp_path / "rules" / "check.cocci"
    cocci.write_text("@@ @@\n")
    return rule, cocci


def _chain(rule: Path, cocci: Path) -> list[dict[str, Any]]:
    return [
        {"type": "semgrep", "config": {"rule": str(rule)}},
        {"type": "coccinelle", "config": {"rule": str(cocci)}},
    ]


def _run(cfg, chain, *, check=None, skipped=None):
    return _run_tool_chain(
        chain,
        config=cfg,
        file_path="src/a.c",
        function_name="f",
        source="int f(void){}",
        hypothesis="missing bounds check on `len`",
        line_start=1,
        early_exit_check=check,
        skipped_types=skipped,
    )


class TestEarlyExitFires:
    def test_subprocess_steps_skipped_after_qualifying_confirm(
        self, tmp_path, monkeypatch,
    ):
        rule, cocci = _write_tree(tmp_path)
        cfg = _Cfg(tmp_path)
        cocci_calls = []
        monkeypatch.setattr(
            orch, "run_semgrep_sweep", lambda **kw: _sg_result(),
        )
        monkeypatch.setattr(
            orch, "run_coccinelle_file_sweep",
            lambda **kw: cocci_calls.append(kw),
        )
        skipped: set = set()
        confirmed = _run(
            cfg, _chain(rule, cocci),
            check=_promotion_grade_receipt, skipped=skipped,
        )
        assert confirmed == ["semgrep:rules/r.yaml"]
        assert not cocci_calls
        assert skipped == {"coccinelle"}

    def test_in_process_channel_still_runs_after_exit(
        self, tmp_path, monkeypatch,
    ):
        rule, cocci = _write_tree(tmp_path)
        cfg = _Cfg(tmp_path)
        inv_calls = []
        cocci_calls = []

        class _InvRes:
            outcome = "violable"
            invariant = "a <= b"
            reason = "model found"

        import core.audit.invariant_smt as inv_mod
        monkeypatch.setattr(
            orch, "run_semgrep_sweep", lambda **kw: _sg_result(),
        )
        monkeypatch.setattr(
            inv_mod, "check_invariant_preservation",
            lambda *a, **kw: (inv_calls.append(1), _InvRes())[1],
        )
        monkeypatch.setattr(
            orch, "run_coccinelle_file_sweep",
            lambda **kw: cocci_calls.append(kw),
        )
        chain = [
            {"type": "semgrep", "config": {"rule": str(rule)}},
            {"type": "smt_invariant", "config": {"invariant": "a <= b"}},
            {"type": "coccinelle", "config": {"rule": str(cocci)}},
        ]
        skipped: set = set()
        confirmed = _run(
            cfg, chain, check=_promotion_grade_receipt, skipped=skipped,
        )
        assert inv_calls, "in-process channel must run after the exit"
        assert not cocci_calls
        assert "semgrep:rules/r.yaml" in confirmed
        assert skipped == {"coccinelle"}

    def test_exit_journaled(self, tmp_path, monkeypatch):
        rule, cocci = _write_tree(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        cfg = _Cfg(tmp_path, out_dir=out_dir)
        monkeypatch.setattr(
            orch, "run_semgrep_sweep", lambda **kw: _sg_result(),
        )
        monkeypatch.setattr(
            orch, "run_coccinelle_file_sweep", lambda **kw: None,
        )
        _run(cfg, _chain(rule, cocci), check=_promotion_grade_receipt)
        rows = [
            json.loads(line)
            for line in (out_dir / ".audit-log.jsonl")
            .read_text().splitlines()
        ]
        exit_rows = [
            r for r in rows if r.get("action") == "tool_chain_early_exit"
        ]
        assert len(exit_rows) == 1
        assert exit_rows[0]["tools_skipped"] == ["coccinelle"]
        assert exit_rows[0]["confirming_receipt"] == "semgrep:rules/r.yaml"

    def test_executed_type_not_reported_skipped(
        self, tmp_path, monkeypatch,
    ):
        # A chain may carry several entries of one type (binary
        # decompiler rules append extra semgrep entries). The type ran
        # once before the exit armed, so reporting it skipped would
        # drop it from tools_dispatched and demote the confirming
        # receipt's verification tier.
        rule, cocci = _write_tree(tmp_path)
        rule_b = tmp_path / "rules" / "r2.yaml"
        rule_b.write_text("rules: [b]\n")
        cfg = _Cfg(tmp_path)
        sg_calls = []

        def sg_stub(**kw):
            sg_calls.append(kw)
            return _sg_result()

        monkeypatch.setattr(orch, "run_semgrep_sweep", sg_stub)
        monkeypatch.setattr(
            orch, "run_coccinelle_file_sweep", lambda **kw: None,
        )
        chain = [
            {"type": "semgrep", "config": {"rule": str(rule)}},
            {"type": "semgrep", "config": {"rule": str(rule_b)}},
            {"type": "coccinelle", "config": {"rule": str(cocci)}},
        ]
        skipped: set = set()
        _run(cfg, chain, check=_promotion_grade_receipt, skipped=skipped)
        assert len(sg_calls) == 1
        assert skipped == {"coccinelle"}

    def test_confirming_step_itself_never_skipped(
        self, tmp_path, monkeypatch,
    ):
        rule, cocci = _write_tree(tmp_path)
        cfg = _Cfg(tmp_path)
        sg_calls = []

        def sg_stub(**kw):
            sg_calls.append(kw)
            return _sg_result()

        monkeypatch.setattr(orch, "run_semgrep_sweep", sg_stub)
        _run(cfg, _chain(rule, cocci), check=_promotion_grade_receipt)
        assert len(sg_calls) == 1


class TestFullChainRuns:
    def test_flag_off_runs_full_chain(self, tmp_path, monkeypatch):
        rule, cocci = _write_tree(tmp_path)
        cfg = _Cfg(tmp_path)
        cfg.tool_chain_early_exit = False
        cocci_calls = []
        monkeypatch.setattr(
            orch, "run_semgrep_sweep", lambda **kw: _sg_result(),
        )
        monkeypatch.setattr(
            orch, "run_coccinelle_file_sweep",
            lambda **kw: (cocci_calls.append(kw), _sg_result("refuted"))[1],
        )
        skipped: set = set()
        _run(
            cfg, _chain(rule, cocci),
            check=_promotion_grade_receipt, skipped=skipped,
        )
        assert cocci_calls
        assert not skipped

    def test_no_predicate_runs_full_chain(self, tmp_path, monkeypatch):
        rule, cocci = _write_tree(tmp_path)
        cfg = _Cfg(tmp_path)
        cocci_calls = []
        monkeypatch.setattr(
            orch, "run_semgrep_sweep", lambda **kw: _sg_result(),
        )
        monkeypatch.setattr(
            orch, "run_coccinelle_file_sweep",
            lambda **kw: (cocci_calls.append(kw), _sg_result("refuted"))[1],
        )
        _run(cfg, _chain(rule, cocci), check=None)
        assert cocci_calls

    def test_detection_role_confirm_does_not_exit(
        self, tmp_path, monkeypatch,
    ):
        rule, cocci = _write_tree(tmp_path)
        cfg = _Cfg(tmp_path)
        sg_calls = []
        monkeypatch.setattr(
            orch, "run_smt_verb_direct",
            lambda **kw: SweepResult(
                tool="smt", file_path="src/a.c", function_name="f",
                outcome="confirmed", rule_id="smt:check-auth-bypass",
            ),
        )
        monkeypatch.setattr(
            orch, "run_semgrep_sweep",
            lambda **kw: (sg_calls.append(kw), _sg_result("refuted"))[1],
        )
        chain = [
            {"type": "smt", "config": {"verb": "check-auth-bypass"}},
            {"type": "semgrep", "config": {"rule": str(rule)}},
        ]
        confirmed = _run(cfg, chain, check=_promotion_grade_receipt)
        # Detection-role receipt collected but the chain keeps going —
        # aggregation needs the later channels.
        assert confirmed == ["smt:check-auth-bypass"]
        assert sg_calls

    def test_refuted_steps_never_arm_the_exit(self, tmp_path, monkeypatch):
        rule, cocci = _write_tree(tmp_path)
        cfg = _Cfg(tmp_path)
        cocci_calls = []
        monkeypatch.setattr(
            orch, "run_semgrep_sweep", lambda **kw: _sg_result("refuted"),
        )
        monkeypatch.setattr(
            orch, "run_coccinelle_file_sweep",
            lambda **kw: (cocci_calls.append(kw), _sg_result("refuted"))[1],
        )
        confirmed = _run(
            cfg, _chain(rule, cocci), check=_promotion_grade_receipt,
        )
        assert confirmed == []
        assert cocci_calls


class TestPromotionGradePredicate:
    def test_verification_receipts_qualify(self):
        assert _promotion_grade_receipt("semgrep:rules/r.yaml")
        assert _promotion_grade_receipt("smt:check-oob")
        assert _promotion_grade_receipt("api_boundary:caller-contract")

    def test_detection_role_receipts_do_not_qualify(self):
        assert not _promotion_grade_receipt("smt:check-auth-bypass")
        assert not _promotion_grade_receipt("joern:live")

    def test_llm_claims_do_not_qualify(self):
        assert not _promotion_grade_receipt("llm-claimed:semgrep")
        assert not _promotion_grade_receipt("")


def test_skippable_set_is_subprocess_tier_only():
    in_process = {
        "smt", "smt_invariant", "api_boundary", "fail_open",
        "consistency", "ptr_lifecycle", "lock_region",
        "resource_bounds", "release_order", "protocol_state",
        "integer_truncation", "proto_length", "struct_field",
    }
    assert not (_EARLY_EXIT_SKIPPABLE_TYPES & in_process)
