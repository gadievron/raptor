"""Study exit contract: a run that ends without ``domain-model.json``
fails loudly at the root cause — nonzero exit plus a machine-readable
``study-failure.json`` record naming why (``core.concepts.study_failure``).

Failing-first taxonomy (this file copied verbatim onto the BASE tree):

- ``TestStudyFailureRecord``: RED — ``ModuleNotFoundError`` (the
  record module is new).
- ``TestStudyRunExitContract``: RED (mechanism) — study-run lets the
  ``run_study`` exception escape (the test sees a raise instead of
  rc 1) and writes no record; the success case leaves the stale
  record in place. The traceback-preservation pin
  (``test_generic_failure_log_carries_traceback_budget_does_not``)
  is RED for the same escaping-raise mechanism.
- ``TestPhase2ZeroYieldBudget`` budget cases: RED (mechanism) — the
  zero-yield guard raises the generic all-failed message without the
  ``budget_exhausted`` stamp. ``test_serial_generic_zero_yield_*``
  and ``test_serial_budget_stop_with_salvage_*`` are green-by-design
  pins: they guard the OTHER direction (non-budget failures keep the
  generic message; a salvaged partial never raises).
- ``TestBinaryStudyExitContract``: rc-0-no-model and budget-floor
  cases RED (mechanism: BASE exits 0 with no model, no record);
  ``test_failed_pass_records_fallback_cause`` RED on the record
  assertion (the rc propagation half pre-exists);
  ``test_model_written_run_stays_green_and_clears_stale_record`` RED
  on the stale-record assertion (BASE never clears it);
  ``test_partial_yield_budget_stop_with_model_stays_green`` is a
  green-by-design pin — a budget stop AFTER a model exists already
  stayed rc 0 on BASE, and the exit contract must keep it that way.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_script(path: Path, name: str, monkeypatch) -> ModuleType:
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_file_location(
        name, str(path), loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _record(output_dir: Path) -> "dict[str, Any] | None":
    """Read the record with plain json — the tests must observe the
    on-disk contract, not the helper module under test."""
    path = output_dir / "study-failure.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# ── the record module itself ─────────────────────────────────────────

class TestStudyFailureRecord:
    def _mod(self):
        import core.concepts.study_failure as sf
        return sf

    def test_write_and_load_roundtrip(self, tmp_path: Path) -> None:
        sf = self._mod()
        sf.write_study_failure(
            tmp_path, "llm_budget_exhausted", detail="cap tripped")
        rec = sf.load_study_failure(tmp_path)
        assert rec is not None
        assert rec["schema"] == "study-failure/1"
        assert rec["reason"] == "llm_budget_exhausted"
        assert rec["detail"] == "cap tripped"
        assert rec["at"]  # UTC stamp present

    def test_detail_bounded_with_elision_marker(
            self, tmp_path: Path) -> None:
        sf = self._mod()
        sf.write_study_failure(tmp_path, "study_error",
                               detail="x" * 5000)
        rec = sf.load_study_failure(tmp_path)
        assert rec is not None
        assert len(rec["detail"]) < 600
        assert rec["detail"].endswith("…[truncated]")

    def test_clear_is_missing_tolerant_and_removes(
            self, tmp_path: Path) -> None:
        sf = self._mod()
        sf.clear_study_failure(tmp_path)  # nothing there — no raise
        sf.write_study_failure(tmp_path, "no_domain_model")
        sf.clear_study_failure(tmp_path)
        assert sf.load_study_failure(tmp_path) is None

    def test_load_absent_returns_none(self, tmp_path: Path) -> None:
        assert self._mod().load_study_failure(tmp_path) is None

    @pytest.mark.parametrize("raw", [
        "not json at all",
        "[1, 2]",                       # wrong shape
        '{"detail": "no reason key"}',  # missing reason
        '{"reason": 42}',               # non-string reason
    ])
    def test_load_unusable_record_returns_none(
            self, tmp_path: Path, raw: str) -> None:
        (tmp_path / "study-failure.json").write_text(
            raw, encoding="utf-8")
        assert self._mod().load_study_failure(tmp_path) is None

    def test_load_normalises_non_string_detail(
            self, tmp_path: Path) -> None:
        (tmp_path / "study-failure.json").write_text(
            '{"reason": "study_error", "detail": [1]}',
            encoding="utf-8")
        rec = self._mod().load_study_failure(tmp_path)
        assert rec is not None
        assert rec["detail"] == ""

    def test_write_never_raises(self, tmp_path: Path) -> None:
        # Diagnosis riding a failure path: a write failure must not
        # mask the nonzero exit it accompanies.
        target = tmp_path / "gone"  # parent auto-created by save_json
        self._mod().write_study_failure(target, "study_error")
        # And an unwritable destination degrades silently too.
        blocker = tmp_path / "blocked"
        blocker.write_text("a file where a directory must go")
        self._mod().write_study_failure(
            blocker / "sub", "study_error")


# ── raptor-study-run: catch → record → rc 1 ─────────────────────────

def _fake_llm_module(client) -> ModuleType:
    mod = ModuleType("packages.llm_analysis")
    mod.get_client = lambda config=None: client
    return mod


class _LogSpy:
    """Records ``logger.error`` calls — message and the exc_info
    kwarg — at the module seam, immune to whatever handler layout
    ``configure_cli_logging`` installs inside ``main()``."""

    def __init__(self) -> None:
        self.errors: list[tuple[str, Any]] = []

    def error(self, msg: str, *args: Any, **kw: Any) -> None:
        rendered = msg % args if args else msg
        self.errors.append((rendered, kw.get("exc_info")))

    def __getattr__(self, name: str) -> Any:  # info/debug/warning
        return lambda *a, **k: None


class TestStudyRunExitContract:
    def _run(self, tmp_path: Path, monkeypatch, run_study,
             log_spy: "_LogSpy | None" = None) -> int:
        mod = _load_script(
            REPO_ROOT / "libexec" / "raptor-study-run",
            "raptor_study_run_exit_contract", monkeypatch,
        )
        (tmp_path / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        client = SimpleNamespace(
            config=SimpleNamespace(max_cost_per_scan=10.0))
        monkeypatch.setitem(
            sys.modules, "packages.llm_analysis",
            _fake_llm_module(client))
        monkeypatch.setattr(mod, "_ensure_llm_dispatcher",
                            lambda c, label, run_dir=None: None)
        monkeypatch.setattr(mod, "run_study", run_study)
        if log_spy is not None:
            monkeypatch.setattr(mod, "logger", log_spy)
        monkeypatch.setattr(
            sys, "argv", ["raptor-study-run", str(tmp_path)])
        return mod.main()

    def test_budget_flagged_error_exits_1_with_budget_record(
            self, tmp_path: Path, monkeypatch) -> None:
        def _boom(*a, **k):
            err = RuntimeError(
                "LLM budget exhausted with 0 completed Phase 2 "
                "batch(es)")
            err.budget_exhausted = True
            raise err
        assert self._run(tmp_path, monkeypatch, _boom) == 1
        rec = _record(tmp_path)
        assert rec is not None
        assert rec["reason"] == "llm_budget_exhausted"
        assert "0 completed" in rec["detail"]

    def test_typed_budget_error_classified_as_budget(
            self, tmp_path: Path, monkeypatch) -> None:
        # The structural classifier covers raises that never went
        # through the phase-2 guard (e.g. Phase 3 synthesis).
        from core.llm.client import LLMBudgetExceededError

        def _boom(*a, **k):
            raise LLMBudgetExceededError("spend cap tripped")
        assert self._run(tmp_path, monkeypatch, _boom) == 1
        rec = _record(tmp_path)
        assert rec is not None
        assert rec["reason"] == "llm_budget_exhausted"

    def test_generic_error_exits_1_with_study_error_record(
            self, tmp_path: Path, monkeypatch) -> None:
        def _boom(*a, **k):
            msg = "all 3 attempted Phase 2 batch(es) failed"
            raise RuntimeError(msg)
        assert self._run(tmp_path, monkeypatch, _boom) == 1
        rec = _record(tmp_path)
        assert rec is not None
        assert rec["reason"] == "study_error"
        assert "batch(es) failed" in rec["detail"]

    def test_generic_failure_log_carries_traceback_budget_does_not(
            self, tmp_path: Path, monkeypatch) -> None:
        # Both directions of the traceback contract: a genuine bug
        # keeps its crash site (exc_info on the error log — BASE let
        # the raise escape with a full traceback, and the bounded
        # record detail alone cannot recover it); a budget stop is a
        # chosen limit, not a bug, and stays one line.
        spy = _LogSpy()

        def _generic(*a, **k):
            msg = "unexpected synthesis crash"
            raise KeyError(msg)
        assert self._run(tmp_path, monkeypatch, _generic,
                         log_spy=spy) == 1
        generic = [e for e in spy.errors if "study failed" in e[0]]
        assert generic and generic[-1][1] is True

        spy2 = _LogSpy()

        def _budget(*a, **k):
            err = RuntimeError("cap tripped")
            err.budget_exhausted = True
            raise err
        assert self._run(tmp_path, monkeypatch, _budget,
                         log_spy=spy2) == 1
        budgetish = [e for e in spy2.errors if "study failed" in e[0]]
        assert budgetish and not budgetish[-1][1]

    def test_success_clears_stale_record(
            self, tmp_path: Path, monkeypatch) -> None:
        (tmp_path / "study-failure.json").write_text(
            '{"reason": "study_error", "detail": "old run"}',
            encoding="utf-8")
        ok = lambda *a, **k: SimpleNamespace(  # noqa: E731
            concepts=[], invariants=[], contracts=[])
        assert self._run(tmp_path, monkeypatch, ok) == 0
        assert _record(tmp_path) is None


# ── phase-2 zero-yield guard names the budget ────────────────────────

class TestPhase2ZeroYieldBudget:
    def _study(self):
        import core.concepts.study as study
        return study

    def test_serial_budget_zero_yield_names_budget(
            self, monkeypatch) -> None:
        study = self._study()

        def _boom(*a, **k):
            raise study._PhaseBudgetExhausted(
                "batch 1/25: LLM budget exceeded: cap reached")
        monkeypatch.setattr(
            study, "_run_batch_splitting_on_truncation", _boom)
        with pytest.raises(study._BatchLLMError) as ei:
            study._run_phase2_serial(
                [(["item"], [])], "target", "/src", object(),
                None, None)
        err = ei.value
        assert getattr(err, "budget_exhausted", False) is True
        assert "LLM budget exhausted with 0 completed" in str(err)
        # The original cap message rides along for the operator.
        assert "cap reached" in str(err)

    def test_serial_generic_zero_yield_keeps_generic_message(
            self, monkeypatch) -> None:
        study = self._study()

        def _boom(*a, **k):
            raise study._BatchLLMError("provider fell over")
        monkeypatch.setattr(
            study, "_run_batch_splitting_on_truncation", _boom)
        with pytest.raises(study._BatchLLMError) as ei:
            study._run_phase2_serial(
                [(["item"], [])], "target", "/src", object(),
                None, None)
        err = ei.value
        assert getattr(err, "budget_exhausted", False) is False
        assert "all 1 attempted Phase 2 batch(es) failed" in str(err)

    def test_serial_budget_stop_with_salvage_never_raises(
            self, monkeypatch) -> None:
        # Paid partial coverage inside the tripping batch counts as
        # yield — the guard must NOT convert it into a failure.
        study = self._study()
        sentinel = object()

        def _boom(*a, **k):
            raise study._PhaseBudgetExhausted(
                "batch 1/25: LLM budget exceeded",
                partial=([sentinel], [], [], [], []))
        monkeypatch.setattr(
            study, "_run_batch_splitting_on_truncation", _boom)
        concepts, *_rest = study._run_phase2_serial(
            [(["item"], [])], "target", "/src", object(),
            None, None)
        assert concepts == [sentinel]

    def test_parallel_budget_zero_yield_names_budget(
            self, monkeypatch) -> None:
        study = self._study()

        def _boom(*a, **k):
            raise study._PhaseBudgetExhausted(
                "batch 2/25: LLM budget exceeded: cap reached")
        monkeypatch.setattr(
            study, "_run_batch_splitting_on_truncation", _boom)
        with pytest.raises(study._BatchLLMError) as ei:
            study._run_phase2_parallel(
                [(["a"], []), (["b"], [])], "target", "/src",
                object(), None, None, 2)
        err = ei.value
        assert getattr(err, "budget_exhausted", False) is True
        assert "LLM budget exhausted with 0 completed" in str(err)
        assert "cap reached" in str(err)


# ── raptor-binary-study: no model ⇒ nonzero + record ────────────────

class TestBinaryStudyExitContract:
    def _run_main(self, tmp_path: Path, monkeypatch, *,
                  run_rc: int = 0, write_model: bool = False,
                  extra_argv: "list[str] | None" = None,
                  ) -> "tuple[int, Path]":
        mod = _load_script(
            REPO_ROOT / "libexec" / "raptor-binary-study",
            "raptor_binary_study_exit_contract", monkeypatch,
        )
        out = tmp_path / "out"
        out.mkdir(parents=True, exist_ok=True)
        redb = tmp_path / "re-database.json"
        redb.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(mod, "_resolve_redb_path",
                            lambda arg: redb)
        monkeypatch.setattr(mod, "_load_db", lambda p: object())
        monkeypatch.setattr(mod, "_clamp_domain_model",
                            lambda *a, **k: None)
        monkeypatch.setattr(mod, "_pending_reading_names",
                            lambda d: [])

        fake_tree = ModuleType("packages.ghidra.decomp_tree")

        def _write_decomp_tree(db, tree_root):
            Path(tree_root).mkdir(parents=True, exist_ok=True)
            return SimpleNamespace(
                coverage_line=lambda: "1/1 functions decompiled",
                functions_decompiled=1,
                sidecar_path=Path(tree_root) / "decomp-map.json",
            )
        fake_tree.write_decomp_tree = _write_decomp_tree
        monkeypatch.setitem(sys.modules, "packages.ghidra.decomp_tree",
                            fake_tree)

        def _fake_run(cmd, verbose, gap_dir=None):
            if write_model:
                (out / "domain-model.json").write_text(
                    json.dumps({"concepts": [], "invariants": [],
                                "contracts": []}),
                    encoding="utf-8")
            return run_rc
        monkeypatch.setattr(mod, "_run", _fake_run)

        argv = ["raptor-binary-study", str(redb), str(out),
                "--no-bridge-seeds", "--max-passes", "1"]
        argv.extend(extra_argv or [])
        monkeypatch.setattr(sys, "argv", argv)
        return mod.main(), out

    def test_rc_zero_without_model_exits_1_and_records_cause(
            self, tmp_path: Path, monkeypatch) -> None:
        rc, out = self._run_main(tmp_path, monkeypatch)
        assert rc == 1
        rec = _record(out)
        assert rec is not None
        assert rec["reason"] == "no_domain_model"
        assert "without producing domain-model.json" in rec["detail"]

    def test_budget_floor_stop_exits_1_and_records_budget(
            self, tmp_path: Path, monkeypatch) -> None:
        # A budget below the per-pass floor stops before pass 1 —
        # zero-yield budget stop, the live defect's shape.
        rc, out = self._run_main(
            tmp_path, monkeypatch,
            extra_argv=["--max-cost", "0.20"])
        assert rc == 1
        rec = _record(out)
        assert rec is not None
        assert rec["reason"] == "llm_budget_exhausted"
        assert "before any domain model" in rec["detail"]

    def test_failed_pass_records_fallback_cause(
            self, tmp_path: Path, monkeypatch) -> None:
        rc, out = self._run_main(tmp_path, monkeypatch, run_rc=7)
        assert rc == 7  # the pass's own rc still propagates
        rec = _record(out)
        assert rec is not None
        assert rec["reason"] == "study_error"
        assert "exit 7" in rec["detail"]

    def test_model_written_run_stays_green_and_clears_stale_record(
            self, tmp_path: Path, monkeypatch) -> None:
        out = tmp_path / "out"
        out.mkdir(parents=True)
        (out / "study-failure.json").write_text(
            '{"reason": "study_error", "detail": "old run"}',
            encoding="utf-8")
        rc, out = self._run_main(tmp_path, monkeypatch,
                                 write_model=True)
        assert rc == 0
        assert _record(out) is None

    def test_partial_yield_budget_stop_with_model_stays_green(
            self, tmp_path: Path, monkeypatch) -> None:
        # Pass 1 produced a model; the budget floor then stops pass 2.
        # A partial-yield budget stop is a SUCCESS — rc 0, no record.
        mod = _load_script(
            REPO_ROOT / "libexec" / "raptor-binary-study",
            "raptor_binary_study_partial_yield", monkeypatch,
        )
        out = tmp_path / "out"
        out.mkdir(parents=True, exist_ok=True)
        redb = tmp_path / "re-database.json"
        redb.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(mod, "_resolve_redb_path",
                            lambda arg: redb)
        monkeypatch.setattr(mod, "_load_db", lambda p: object())
        monkeypatch.setattr(mod, "_clamp_domain_model",
                            lambda *a, **k: None)
        # Pass 1 leaves work pending, so the loop WANTS a pass 2 and
        # only the budget floor stops it.
        monkeypatch.setattr(mod, "_pending_reading_names",
                            lambda d: ["unresolved_fn"])

        fake_tree = ModuleType("packages.ghidra.decomp_tree")

        def _write_decomp_tree(db, tree_root):
            Path(tree_root).mkdir(parents=True, exist_ok=True)
            return SimpleNamespace(
                coverage_line=lambda: "1/1 functions decompiled",
                functions_decompiled=1,
                sidecar_path=Path(tree_root) / "decomp-map.json",
            )
        fake_tree.write_decomp_tree = _write_decomp_tree
        monkeypatch.setitem(sys.modules, "packages.ghidra.decomp_tree",
                            fake_tree)

        def _fake_run(cmd, verbose, gap_dir=None):
            (out / "domain-model.json").write_text(
                json.dumps({"concepts": [], "invariants": [],
                            "contracts": []}),
                encoding="utf-8")
            # Pass 1 spends almost the whole budget.
            (out / "study-cost.json").write_text(
                '{"cost_usd": 0.90}', encoding="utf-8")
            return 0
        monkeypatch.setattr(mod, "_run", _fake_run)
        monkeypatch.setattr(sys, "argv", [
            "raptor-binary-study", str(redb), str(out),
            "--no-bridge-seeds", "--max-passes", "3",
            "--max-cost", "1.00"])
        assert mod.main() == 0
        assert _record(out) is None
