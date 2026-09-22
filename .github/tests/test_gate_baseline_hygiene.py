"""Gate-baseline hygiene: duplicate JSON keys are refused.

The three review-gate baselines (vocab, miswiring, report-writer
closure) are hand-edited JSON objects keyed by finding. ``json.loads``
is last-wins on duplicate keys, so a second row with the same key
silently SHADOWS the first — a branch can replace a reviewed baseline
row (note, count, review stamp) with an unreviewed one and the diff
shows only an easily-missed extra key. Nothing in the gate scripts
detects this; this oracle does, over every baseline the gate scripts
consume.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"

GATE_BASELINES = (
    "vocab_baseline.json",
    "miswiring_baseline.json",
    "report_writer_closure_baseline.json",
)


class DuplicateKeyError(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            msg = f"duplicate JSON key: {key!r}"
            raise DuplicateKeyError(msg)
        seen[key] = value
    return seen


def load_rejecting_duplicates(text: str) -> object:
    """Parse JSON, raising DuplicateKeyError on any duplicated object key.

    ``object_pairs_hook`` runs for every object at every nesting level,
    so nested duplicates are caught too.
    """
    return json.loads(text, object_pairs_hook=_reject_duplicates)


@pytest.mark.parametrize("name", GATE_BASELINES)
def test_gate_baseline_has_no_duplicate_keys(name: str) -> None:
    path = SCRIPTS_DIR / name
    assert path.exists(), f"gate baseline missing: {path}"
    load_rejecting_duplicates(path.read_text(encoding="utf-8"))


def test_oracle_fires_on_duplicate_key() -> None:
    """The oracle itself can fail: a shadowing duplicate is detected."""
    shadowing = '{"a::LIST": {"count": 1, "reviewed": "x"}, "a::LIST": {"count": 1}}'
    with pytest.raises(DuplicateKeyError):
        load_rejecting_duplicates(shadowing)


def test_oracle_fires_on_nested_duplicate_key() -> None:
    nested = '{"row": {"note": "n", "note": "shadow"}}'
    with pytest.raises(DuplicateKeyError):
        load_rejecting_duplicates(nested)
