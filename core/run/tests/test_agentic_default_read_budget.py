"""The agentic cost join pays the shared default read budget.

``_collect_child_pass_costs`` reads each child pass's
cc-proxy-spend.json through ``core.json.load_json`` with no
site-specific budget, so it must inherit the loader's
capped-by-default contract: an oversized ledger is refused and the
pass contributes nothing (the site's own best-effort join), a normal
ledger still joins. The budget is tightened via the module constant
(resolved per call) so the probe costs kilobytes, not the real cap.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_agentic():
    if str(_RAPTOR_ROOT) not in sys.path:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor_agentic
    return raptor_agentic


def _tighten(monkeypatch, agentic, budget: int = 1024) -> None:
    # Patch the constant in the loader module raptor_agentic actually
    # bound (via the function's own globals): suites that reset
    # core.json in sys.modules can leave this test's static import
    # pointing at a different module object than the one the entry
    # module re-imported.
    monkeypatch.setitem(
        agentic.load_json.__globals__, "DEFAULT_JSON_MAX_BYTES", budget,
    )


def _spend_dir(tmp_path: Path, name: str, usd: float, pad: str = "") -> Path:
    d = tmp_path / name
    d.mkdir()
    record = {"token_id": "t-1", "reconciled_usd": usd}
    if pad:
        record["pad"] = pad
    (d / "cc-proxy-spend.json").write_text(
        json.dumps(record), encoding="utf-8",
    )
    return d


class TestDefaultReadBudget:
    def test_oversized_ledger_contributes_nothing(self, tmp_path, monkeypatch):
        agentic = _import_agentic()
        _tighten(monkeypatch, agentic)
        pre = SimpleNamespace(
            ran=True,
            understand_dir=_spend_dir(tmp_path, "und", 4.25, pad="x" * 4096),
        )
        post = SimpleNamespace(ran=False, validate_dir=None)
        assert agentic._collect_child_pass_costs(pre, post, None) == []

    def test_normal_ledger_still_joins(self, tmp_path, monkeypatch):
        agentic = _import_agentic()
        _tighten(monkeypatch, agentic)
        pre = SimpleNamespace(
            ran=True, understand_dir=_spend_dir(tmp_path, "und", 4.25),
        )
        post = SimpleNamespace(ran=False, validate_dir=None)
        costs = agentic._collect_child_pass_costs(pre, post, None)
        assert ("understand pre-pass", 4.25) in costs
