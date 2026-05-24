"""Deterministic selection eval for cwe_strategies.

Runs the picker over a labeled set of signal cases and checks the right
strategy is routed (and the wrong ones are not). No LLM — fast, repeatable,
CI-able. This measures the ROUTING layer only: it proves the right lens is
chosen for a given function shape, NOT that the lens helps the model (that
is the efficacy eval).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from core.llm.cwe_strategies import load_all, pick_strategies

from .models import SelectionCase, SelectionOutcome


def default_cases_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "selection_cases.yml"


def load_cases(path: Optional[Path] = None) -> List[SelectionCase]:
    path = Path(path) if path is not None else default_cases_path()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cases: List[SelectionCase] = []
    for raw in data.get("cases", []):
        cases.append(
            SelectionCase(
                name=raw["name"],
                signals=dict(raw.get("signals", {})),
                expect_selected=tuple(raw.get("expect_selected", ())),
                expect_not_selected=tuple(raw.get("expect_not_selected", ())),
            )
        )
    return cases


def run_case(case: SelectionCase) -> SelectionOutcome:
    picked = tuple(s.name for s in pick_strategies(**case.signals))
    missing = tuple(n for n in case.expect_selected if n not in picked)
    overfired = tuple(n for n in case.expect_not_selected if n in picked)
    return SelectionOutcome(
        case=case, picked=picked, missing=missing, overfired=overfired,
    )


def run_selection_eval(
    cases: Optional[List[SelectionCase]] = None,
) -> List[SelectionOutcome]:
    cases = cases if cases is not None else load_cases()
    return [run_case(c) for c in cases]


def per_strategy_recall(outcomes: List[SelectionOutcome]) -> Dict[str, float]:
    """For each strategy named in any ``expect_selected``, the fraction of
    its positive cases where it was actually selected."""
    hits: Dict[str, int] = defaultdict(int)
    total: Dict[str, int] = defaultdict(int)
    for o in outcomes:
        for name in o.case.expect_selected:
            total[name] += 1
            if name not in o.missing:
                hits[name] += 1
    return {name: hits[name] / total[name] for name in sorted(total)}


def format_report(outcomes: List[SelectionOutcome]) -> str:
    passed = [o for o in outcomes if o.passed]
    failed = [o for o in outcomes if not o.passed]
    lines = [
        "Selection eval (routing) — deterministic, no LLM",
        f"  cases: {len(outcomes)}   passed: {len(passed)}   failed: {len(failed)}",
        "",
        "Per-strategy routing recall:",
    ]
    for name, recall in per_strategy_recall(outcomes).items():
        lines.append(f"  {name:18s} {recall * 100:5.1f}%")
    if failed:
        lines.append("")
        lines.append("Failures:")
        for o in failed:
            lines.append(
                f"  {o.case.name}\n"
                f"    picked      = {list(o.picked)}\n"
                f"    missing     = {list(o.missing)}\n"
                f"    overfired   = {list(o.overfired)}"
            )
    return "\n".join(lines)


def uncovered_strategies(outcomes: List[SelectionOutcome]) -> List[str]:
    """Bundled strategies with no positive selection case — the eval would
    silently stop covering them."""
    covered = set()
    for o in outcomes:
        covered.update(o.case.expect_selected)
    return sorted({s.name for s in load_all()} - covered)
