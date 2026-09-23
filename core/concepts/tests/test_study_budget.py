"""--max-cost plumbing through the study CLIs and the per-pass
spend accounting the multi-pass driver reads back."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

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


def _fake_llm_module(client) -> ModuleType:
    mod = ModuleType("packages.llm_analysis")
    mod.get_client = lambda config=None: client
    return mod


class TestStudyRunMaxCost:
    def _run(self, tmp_path, monkeypatch, argv, client):
        mod = _load_script(
            REPO_ROOT / "libexec" / "raptor-study-run",
            "raptor_study_run_budget", monkeypatch,
        )
        (tmp_path / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        monkeypatch.setitem(
            sys.modules, "packages.llm_analysis",
            _fake_llm_module(client))
        monkeypatch.setattr(mod, "_ensure_llm_dispatcher",
                            lambda c, label: None)
        monkeypatch.setattr(
            mod, "run_study",
            lambda *a, **k: SimpleNamespace(
                concepts=[], invariants=[], contracts=[]))
        monkeypatch.setattr(
            sys, "argv", ["raptor-study-run", str(tmp_path)] + argv)
        return mod.main()

    def test_max_cost_reaches_client_config(self, tmp_path, monkeypatch):
        client = SimpleNamespace(
            config=SimpleNamespace(max_cost_per_scan=10.0))
        rc = self._run(tmp_path, monkeypatch, ["--max-cost", "2.5"],
                       client)
        assert rc == 0
        assert client.config.max_cost_per_scan == 2.5

    def test_no_flag_leaves_config_default(self, tmp_path, monkeypatch):
        client = SimpleNamespace(
            config=SimpleNamespace(max_cost_per_scan=10.0))
        assert self._run(tmp_path, monkeypatch, [], client) == 0
        assert client.config.max_cost_per_scan == 10.0

    def test_non_positive_max_cost_rejected(self, tmp_path, monkeypatch):
        client = SimpleNamespace(
            config=SimpleNamespace(max_cost_per_scan=10.0))
        assert self._run(tmp_path, monkeypatch,
                         ["--max-cost", "0"], client) == 1
        assert self._run(tmp_path, monkeypatch,
                         ["--max-cost", "-3"], client) == 1

    def test_non_finite_max_cost_rejected(self, tmp_path, monkeypatch):
        # argparse's float() accepts these spellings; NaN passes a
        # naive `<= 0` gate and the cap then never trips — silently
        # unlimited spend.
        client = SimpleNamespace(
            config=SimpleNamespace(max_cost_per_scan=10.0))
        for bad in ("nan", "inf"):
            assert self._run(tmp_path, monkeypatch,
                             ["--max-cost", bad], client) == 1
        # "-inf" needs the = spelling (argparse reads a bare "-inf"
        # token as an option string).
        assert self._run(tmp_path, monkeypatch,
                         ["--max-cost=-inf"], client) == 1
        assert client.config.max_cost_per_scan == 10.0

    def test_spend_record_written_with_ledger_max(
        self, tmp_path, monkeypatch,
    ):
        # The provider ledger is the honest floor for money actually
        # gone; the record must carry the max of the two figures.
        client = SimpleNamespace(
            config=SimpleNamespace(max_cost_per_scan=10.0),
            total_cost=1.5, provider_spend_usd=2.25)
        assert self._run(tmp_path, monkeypatch, [], client) == 0
        data = json.loads(
            (tmp_path / "study-cost.json").read_text())
        assert data["cost_usd"] == 2.25

    def test_spend_record_written_when_run_study_raises(
        self, tmp_path, monkeypatch,
    ):
        import pytest

        mod = _load_script(
            REPO_ROOT / "libexec" / "raptor-study-run",
            "raptor_study_run_budget_fail", monkeypatch,
        )
        (tmp_path / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        client = SimpleNamespace(
            config=SimpleNamespace(max_cost_per_scan=10.0),
            total_cost=0.75, provider_spend_usd=0.5)
        monkeypatch.setitem(
            sys.modules, "packages.llm_analysis",
            _fake_llm_module(client))
        monkeypatch.setattr(mod, "_ensure_llm_dispatcher",
                            lambda c, label: None)

        def _boom(*a, **k):
            msg = "all batches failed"
            raise RuntimeError(msg)
        monkeypatch.setattr(mod, "run_study", _boom)
        monkeypatch.setattr(
            sys, "argv", ["raptor-study-run", str(tmp_path)])
        with pytest.raises(RuntimeError):
            mod.main()
        # A failed leg's spend is still money gone — the multi-pass
        # driver must see it.
        data = json.loads((tmp_path / "study-cost.json").read_text())
        assert data["cost_usd"] == 0.75


class TestStudyLoopMaxCost:
    def test_non_positive_max_cost_rejected(self, tmp_path, monkeypatch):
        mod = _load_script(
            REPO_ROOT / "libexec" / "raptor-study-loop",
            "raptor_study_loop_budget", monkeypatch,
        )
        for bad in ("-1", "0", "nan", "inf"):
            monkeypatch.setattr(sys, "argv", [
                "raptor-study-loop", str(tmp_path), str(tmp_path),
                "--max-cost", bad])
            assert mod.main() == 1, bad


class TestBinaryStudyBudget:
    def _mod(self, monkeypatch):
        return _load_script(
            REPO_ROOT / "libexec" / "raptor-binary-study",
            "raptor_binary_study_budget", monkeypatch,
        )

    def test_non_positive_max_cost_rejected(self, tmp_path, monkeypatch):
        mod = self._mod(monkeypatch)
        for bad in ("0", "-2", "nan", "inf"):
            monkeypatch.setattr(sys, "argv", [
                "raptor-binary-study", str(tmp_path / "in"),
                str(tmp_path / "out"), "--max-cost", bad])
            assert mod.main() == 1, bad

    def test_pass_budget_floor_stops_the_loop(self, tmp_path,
                                              monkeypatch):
        mod = self._mod(monkeypatch)
        # Remainder below the floor: stop (None), and the stale
        # record survives untouched (nothing will consume it).
        (tmp_path / "study-cost.json").write_text('{"cost_usd": 1}')
        assert mod._pass_budget(10.0, 9.80, tmp_path, 2) is None
        assert (tmp_path / "study-cost.json").is_file()

    def test_pass_budget_returns_remainder_and_unlinks(
        self, tmp_path, monkeypatch,
    ):
        mod = self._mod(monkeypatch)
        (tmp_path / "study-cost.json").write_text('{"cost_usd": 1}')
        remaining = mod._pass_budget(10.0, 4.0, tmp_path, 2)
        # Sign matters: remaining is max_cost MINUS spend, positive.
        assert remaining == 6.0
        # Pre-pass unlink: a pass dying before study-run must not
        # re-count the previous pass's record.
        assert not (tmp_path / "study-cost.json").exists()

    def test_pass_budget_floor_boundary(self, tmp_path, monkeypatch):
        mod = self._mod(monkeypatch)
        floor = mod._MIN_PASS_BUDGET_USD
        assert mod._pass_budget(10.0, 10.0 - floor, tmp_path, 3) == (
            pytest.approx(floor))
        assert mod._pass_budget(
            10.0, 10.0 - floor + 0.01, tmp_path, 3) is None

    def test_read_pass_cost_missing_and_malformed_read_zero(
        self, tmp_path, monkeypatch,
    ):
        mod = self._mod(monkeypatch)
        assert mod._read_pass_cost(tmp_path) == 0.0
        (tmp_path / "study-cost.json").write_text("[1, 2]")
        assert mod._read_pass_cost(tmp_path) == 0.0
        (tmp_path / "study-cost.json").write_text(
            '{"cost_usd": "lots"}')
        assert mod._read_pass_cost(tmp_path) == 0.0
        (tmp_path / "study-cost.json").write_text(
            '{"cost_usd": -4}')
        assert mod._read_pass_cost(tmp_path) == 0.0

    def test_read_pass_cost_reads_spend(self, tmp_path, monkeypatch):
        mod = self._mod(monkeypatch)
        (tmp_path / "study-cost.json").write_text(
            '{"cost_usd": 1.75}')
        assert mod._read_pass_cost(tmp_path) == 1.75
