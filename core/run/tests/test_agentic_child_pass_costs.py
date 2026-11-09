"""Headline-cost aggregation of the opt-in pass subprocesses.

--understand / --validate settle credential-proxy spend into
``cc-proxy-spend.json`` in their own run dirs; --gap-audit writes
``cost-breakdown.json`` with the authoritative
``totals.total_spend_usd``. The run's headline Cost joins them; these
tests pin the join against stubbed child outputs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_agentic():
    from unittest.mock import patch

    with patch.object(sys, "path", list(sys.path)):
        if str(_RAPTOR_ROOT) not in sys.path:
            sys.path.insert(0, str(_RAPTOR_ROOT))
        import raptor_agentic
        return raptor_agentic


def _proxy_spend_dir(tmp_path: Path, name: str, usd: float) -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / "cc-proxy-spend.json").write_text(json.dumps({
        "token_id": "t-1", "budget_usd": 10.0,
        "reconciled_usd": usd, "requests_made": 3,
    }), encoding="utf-8")
    return d


def _audit_dir(tmp_path: Path, usd: float) -> Path:
    d = tmp_path / "audit_run"
    d.mkdir()
    (d / "cost-breakdown.json").write_text(json.dumps({
        "phases": {}, "totals": {"total_spend_usd": usd},
    }), encoding="utf-8")
    return d


class TestCollectChildPassCosts:
    def test_all_three_passes_join(self, tmp_path):
        agentic = _import_agentic()
        pre = SimpleNamespace(
            ran=True,
            understand_dir=_proxy_spend_dir(tmp_path, "und", 4.25))
        post = SimpleNamespace(
            ran=True,
            validate_dir=_proxy_spend_dir(tmp_path, "val", 7.50))
        audit = {"audit_dir": str(_audit_dir(tmp_path, 12.34))}
        costs = agentic._collect_child_pass_costs(pre, post, audit)
        assert ("understand pre-pass", 4.25) in costs
        assert ("validate post-pass", 7.50) in costs
        assert ("gap-audit", 12.34) in costs
        assert round(sum(c for _, c in costs), 2) == 24.09

    def test_missing_records_contribute_nothing(self, tmp_path):
        # Non-proxy claude passes write no spend ledger; a skipped
        # audit has no dir. The join must stay silent, not invent $0
        # line items or crash.
        agentic = _import_agentic()
        empty_dir = tmp_path / "no-record"
        empty_dir.mkdir()
        pre = SimpleNamespace(ran=True, understand_dir=empty_dir)
        post = SimpleNamespace(ran=False, validate_dir=None)
        assert agentic._collect_child_pass_costs(pre, post, {}) == []
        assert agentic._collect_child_pass_costs(None, None, None) == []

    def test_not_ran_pass_is_ignored_even_with_a_record(self, tmp_path):
        agentic = _import_agentic()
        d = _proxy_spend_dir(tmp_path, "und", 3.0)
        pre = SimpleNamespace(ran=False, understand_dir=d)
        assert agentic._collect_child_pass_costs(pre, None, {}) == []

    def test_malformed_records_read_as_zero(self, tmp_path):
        agentic = _import_agentic()
        d = tmp_path / "und"
        d.mkdir()
        (d / "cc-proxy-spend.json").write_text(
            '{"reconciled_usd": "not-a-number"}', encoding="utf-8")
        a = tmp_path / "audit_run"
        a.mkdir()
        (a / "cost-breakdown.json").write_text(
            '{"totals": "corrupt"}', encoding="utf-8")
        pre = SimpleNamespace(ran=True, understand_dir=d)
        costs = agentic._collect_child_pass_costs(
            pre, None, {"audit_dir": str(a)})
        assert costs == []

    def test_headline_sums_child_costs(self):
        # The console and report cost blocks must aggregate the child
        # total, not print the orchestration figure alone.
        src = (_RAPTOR_ROOT / "raptor_agentic.py").read_text(
            encoding="utf-8")
        assert 'f"   Cost: ${cost + child_total:.2f}"' in src
        assert "if report_cost + child_total > 0:" in src
