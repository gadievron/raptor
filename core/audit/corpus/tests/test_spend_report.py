"""End-of-run spend block: one authoritative number.

A v5 corpus run printed four mutually inconsistent totals and its
prominent final "Cost:" banner under-stated total spend by 3.2x (it
summed only per-label review cost). The spend block aggregates the
per-group telemetry ledgers — the only source that saw every
completed call — and folds the telemetry-vs-summary divergence
warnings into one reconciliation section.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.corpus.run_corpus import (
    _aggregate_spend,
    _format_spend_block,
    _format_summary,
)


def _group(base: Path, name: str, records, ledger_total=None) -> Path:
    gdir = base / name
    gdir.mkdir(parents=True, exist_ok=True)
    (gdir / "llm-telemetry.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8",
    )
    if ledger_total is not None:
        (gdir / "cost-breakdown.json").write_text(json.dumps({
            "phases": {},
            "totals": {"cost_usd": ledger_total,
                       "total_spend_usd": ledger_total},
        }), encoding="utf-8")
    return gdir


class TestAggregateSpend:
    def test_totals_classes_and_groups(self, tmp_path):
        _group(tmp_path / "run-sec", "linux", [
            {"call_class": "review", "cost_usd": 1.5},
            {"call_class": "review", "cost_usd": 0.5},
            {"call_class": "checker_synthesis", "cost_usd": 2.0},
        ], ledger_total=4.0)
        _group(tmp_path / "run-bf", "linux", [
            {"call_class": "review", "cost_usd": 1.0},
        ], ledger_total=1.0)
        spend = _aggregate_spend([tmp_path / "run-sec", tmp_path / "run-bf"])
        assert spend is not None
        assert abs(spend["total_usd"] - 5.0) < 1e-9
        assert spend["calls"] == 4
        assert spend["per_class"]["review"] == (3, 3.0)
        assert spend["per_class"]["checker_synthesis"] == (1, 2.0)
        assert {g["group"] for g in spend["groups"]} == {
            "run-sec/linux", "run-bf/linux",
        }

    def test_failed_attempts_cost_counts_money_not_calls(self, tmp_path):
        _group(tmp_path / "run", "g", [
            {"call_class": "review", "cost_usd": 1.0},
            {"call_class": "review", "cost_usd": 0.25,
             "event": "attempt_failed"},
            {"call_class": "review", "cost_usd": 0.0,
             "disposition": "cache_hit"},
        ])
        spend = _aggregate_spend([tmp_path / "run"])
        assert spend["calls"] == 1
        assert abs(spend["total_usd"] - 1.25) < 1e-9

    def test_no_telemetry_returns_none(self, tmp_path):
        (tmp_path / "empty").mkdir()
        assert _aggregate_spend([tmp_path / "empty"]) is None
        assert _aggregate_spend([tmp_path / "absent"]) is None

    def test_duplicate_dirs_counted_once(self, tmp_path):
        base = tmp_path / "run"
        _group(base, "g", [{"call_class": "review", "cost_usd": 1.0}])
        spend = _aggregate_spend([base, base, base / "g"])
        assert abs(spend["total_usd"] - 1.0) < 1e-9


class TestSpendBlock:
    def _spend(self, tmp_path, tel=2.0, ledger=2.0):
        _group(tmp_path / "run", "g", [
            {"call_class": "review", "cost_usd": tel},
        ], ledger_total=ledger)
        return _aggregate_spend([tmp_path / "run"])

    def test_block_carries_total_and_reconciliation(self, tmp_path):
        block = _format_spend_block(self._spend(tmp_path), label_cost=0.5)
        assert "Total: $2.0000" in block
        assert "labels $0.5000" in block
        assert "infra $1.5000" in block
        assert "ledgers agree" in block

    def test_divergent_group_is_called_out(self, tmp_path):
        block = _format_spend_block(
            self._spend(tmp_path, tel=2.0, ledger=1.5), label_cost=0.0,
        )
        assert "diverged >1%" in block
        assert "authoritative" in block

    def test_summary_prefers_total_spend(self, tmp_path):
        rows = [{
            "function_id": "a.c:f", "bug_class": "auth",
            "expected": "clean", "actual": "clean", "match": True,
            "hypothesis": "", "evidence_tool": "", "cost_usd": 0.5,
            "duration_s": 1.0,
        }]
        text, _gates = _format_summary(
            rows, 10.0, "m", spend=self._spend(tmp_path),
        )
        assert "Total spend: $2.0000" in text
        assert "Spend (telemetry ledger — authoritative):" in text
        # The bare, misleading "Cost:" banner is gone.
        assert "\n  Cost:" not in text

    def test_summary_without_spend_names_the_number(self):
        rows = [{
            "function_id": "a.c:f", "bug_class": "auth",
            "expected": "clean", "actual": "clean", "match": True,
            "hypothesis": "", "evidence_tool": "", "cost_usd": 0.5,
            "duration_s": 1.0,
        }]
        text, _gates = _format_summary(rows, 10.0, "m")
        assert "Label-attributed cost: $0.5000" in text
        assert "per-label review spend only" in text


class TestRunHeader:
    def test_header_states_config_and_tree(self, capsys):
        from types import SimpleNamespace

        from core.audit.corpus.run_corpus import _print_run_header

        labels = [
            SimpleNamespace(source=SimpleNamespace(repo="linux-kernel")),
            SimpleNamespace(source=SimpleNamespace(repo="openssl")),
        ]
        args = SimpleNamespace(
            profile="cold", mode="ensemble", triage="off",
            prefilter="off", scope="excerpt",
        )
        _print_run_header(labels, args, [""])
        out = capsys.readouterr().out
        assert "Corpus run starting" in out
        assert "profile=cold" in out
        assert "mode=ensemble" in out
        assert "model=default" in out
        assert "pipeline-tree=" in out
        assert "labels=2" in out and "groups=2" in out
        # Timestamped banner.
        import re
        assert re.search(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\]", out)
