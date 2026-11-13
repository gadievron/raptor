"""Owned retained-buffer ordering diagnostic; no signal or process execution."""
from core.audit import orchestrator as orch
from core.audit.collector import Collector
from core.audit.final_log_flush import FinalAuditLogFlush
from core.audit.record import append_audit_log, load_verified_audit_log
from core.testing.module_views import module_function_view


def test_retained_pre_final_row_cannot_follow_final_correction(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("int f(void) { return 0; }\n")
    row = {"action": "orchestrator_review", "key": "unit.c:f:1", "status": "suspicious"}
    append_audit_log(out, row)
    collector = Collector(out_dir=out, target_path=target, _log_entries=[dict(row)])
    log = out / ".audit-log.jsonl"
    saved = out / "owned-prior.jsonl"
    log.rename(saved)
    log.symlink_to(saved.name)
    try:
        collector.flush()
        assert len(collector._log_entries) == 1
    finally:
        log.unlink()
        saved.rename(log)
    final = orch.ReviewOutcome("unit.c", "f", "clean", "Declared final status", line=1)
    owner = FinalAuditLogFlush(collector, orch.OrchestratorConfig(target_path=target, out_dir=out))
    assert owner.finish(orch.OrchestratorResult(outcomes=[final])) == 1
    assert owner._config._verdicts_finalized is False
    assert load_verified_audit_log(out)[-1]["status"] == "clean"
    private = module_function_view(orch, bindings={"_sigterm_flush_hooks": [owner]})
    private._run_sigterm_flush_hooks()
    assert collector._log_entries == []
    assert load_verified_audit_log(out)[-1]["status"] == "clean"


def _owned_case(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.c").write_text("int f(void) { return 0; }\n")
    row = {"action": "orchestrator_review", "key": "unit.c:f:1", "status": "suspicious"}
    append_audit_log(out, row)
    collector = Collector(out_dir=out, target_path=target)
    config = orch.OrchestratorConfig(target_path=target, out_dir=out)
    owner = FinalAuditLogFlush(collector, config)
    return out, row, collector, owner


def test_prefinal_hook_only_flushes_without_correction(tmp_path, monkeypatch):
    out, row, collector, owner = _owned_case(tmp_path, monkeypatch)
    collector._log_entries.append(dict(row))
    owner()
    rows = load_verified_audit_log(out)
    assert len(rows) == 2 and all(r["status"] == "suspicious" for r in rows)
    assert collector._log_entries == [] and owner._snapshot is None


def test_fixed_snapshot_survives_outcome_mutation_and_repeated_hook(tmp_path, monkeypatch):
    out, row, collector, owner = _owned_case(tmp_path, monkeypatch)
    final = orch.ReviewOutcome("unit.c", "f", "clean", "Declared final", line=1,
                              cost_usd=0.25, model="owned-model")
    result = orch.OrchestratorResult(outcomes=[final])
    assert owner.finish(result) == 1
    final.status = "finding"
    final.cost_usd = 999
    result.outcomes.clear()
    collector._log_entries.append(dict(row))
    owner()
    rows = load_verified_audit_log(out)
    assert rows[-1]["status"] == "clean" and rows[-1]["cost_usd"] == 0.25
    assert rows[-1]["model"] == "owned-model" and "strategies" not in rows[-1]
    owner()
    assert load_verified_audit_log(out) == rows


def test_nested_hook_during_first_correction_preserves_final_status(tmp_path, monkeypatch):
    out, row, collector, owner = _owned_case(tmp_path, monkeypatch)
    collector._log_entries.append(dict(row))
    actual = orch.append_audit_log
    reentered = []

    def append_then_reenter(directory, entry):
        actual(directory, entry)
        if entry.get("final_status_correction") and not reentered:
            reentered.append(True)
            assert owner._config._verdicts_finalized is False
            owner()

    private = module_function_view(orch, bindings={"append_audit_log": append_then_reenter})
    monkeypatch.setattr(orch, "_relog_final_statuses", private._relog_final_statuses)
    final = orch.ReviewOutcome("unit.c", "f", "clean", "Declared final", line=1)
    assert owner.finish(orch.OrchestratorResult(outcomes=[final])) == 1
    assert reentered == [True] and collector._log_entries == []
    assert load_verified_audit_log(out)[-1]["status"] == "clean"


def test_failed_correction_is_retried_after_retained_flush(tmp_path, monkeypatch):
    out, row, collector, owner = _owned_case(tmp_path, monkeypatch)
    log, saved = out / ".audit-log.jsonl", out / "owned-prior.jsonl"
    actual = orch.append_audit_log
    attempts = []

    def refuse_first_correction(directory, entry):
        if entry.get("final_status_correction") and not attempts:
            attempts.append(True)
            log.rename(saved)
            log.symlink_to(saved.name)
            try:
                return actual(directory, entry)
            finally:
                log.unlink()
                saved.rename(log)
        return actual(directory, entry)

    private = module_function_view(orch, bindings={"append_audit_log": refuse_first_correction})
    monkeypatch.setattr(orch, "_relog_final_statuses", private._relog_final_statuses)
    final = orch.ReviewOutcome("unit.c", "f", "clean", "Declared final", line=1)
    assert owner.finish(orch.OrchestratorResult(outcomes=[final])) == 0
    assert attempts == [True] and load_verified_audit_log(out)[-1]["status"] == "suspicious"
    collector._log_entries.append(dict(row))
    owner()
    assert collector._log_entries == [] and load_verified_audit_log(out)[-1]["status"] == "clean"


def test_reconciliation_failure_preserves_primary_cancellation(tmp_path, monkeypatch):
    import pytest

    _, _, collector, owner = _owned_case(tmp_path, monkeypatch)
    primary = KeyboardInterrupt("owned flush interruption")
    reached = []

    def interrupt_flush():
        raise primary

    def fail_reconciliation():
        reached.append(True)
        raise ValueError("owned reconciliation fault")

    monkeypatch.setattr(collector, "flush", interrupt_flush)
    monkeypatch.setattr(owner, "_reconcile", fail_reconciliation)
    with pytest.raises(KeyboardInterrupt) as caught:
        owner()
    assert caught.value is primary and reached == [True]
    assert any("ValueError" in note for note in primary.__notes__)


def test_snapshot_includes_error_sibling_in_legacy_ambiguity(tmp_path, monkeypatch):
    out, _, _, owner = _owned_case(tmp_path, monkeypatch)
    append_audit_log(out, {"action": "orchestrator_review", "key": "unit.c:g", "status": "suspicious"})
    final = orch.ReviewOutcome("unit.c", "g", "clean", "Declared final", line=2)
    sibling = orch.ReviewOutcome("unit.c", "g", "error", "Owned unavailable sibling", line=4)
    assert owner.finish(orch.OrchestratorResult(outcomes=[final, sibling])) == 0
    assert len(load_verified_audit_log(out)) == 2


def test_actual_normal_and_salvage_sites_share_registered_owner():
    import ast
    from pathlib import Path

    tree = ast.parse(Path(orch.__file__).read_text())
    registrations = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                     and ast.unparse(n.func) == "_sigterm_flush_hooks.append"
                     and n.args and ast.unparse(n.args[0]) == "final_log_flush"]
    assert len(registrations) == 1
    finishes = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and ast.unparse(n.func) == "final_log_flush.finish"]
    assert len(finishes) == 2
    salvage = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
               and ast.unparse(n.func) == "_sigterm_salvage"]
    assert len(salvage) == 1
    assert any(k.arg == "final_log_flush" and ast.unparse(k.value) == "final_log_flush"
               for k in salvage[0].keywords)


def test_post_snapshot_failed_flush_retains_rows_until_retry(tmp_path, monkeypatch):
    out, row, collector, owner = _owned_case(tmp_path, monkeypatch)
    final = orch.ReviewOutcome("unit.c", "f", "clean", "Declared final", line=1)
    assert owner.finish(orch.OrchestratorResult(outcomes=[final])) == 1
    collector._log_entries.append(dict(row))
    log, saved = out / ".audit-log.jsonl", out / "owned-prior.jsonl"
    log.rename(saved)
    log.symlink_to(saved.name)
    try:
        owner()
        assert collector._log_entries == [row]
    finally:
        log.unlink()
        saved.rename(log)
    assert load_verified_audit_log(out)[-1]["status"] == "clean"
    owner()
    assert collector._log_entries == []
    rows = load_verified_audit_log(out)
    assert rows[-1]["status"] == "clean" and rows[-2]["status"] == "suspicious"
