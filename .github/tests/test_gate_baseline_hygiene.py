"""Gate-baseline hygiene: duplicate JSON keys are refused.

The review-gate baselines are hand-edited JSON objects keyed by
finding. ``json.loads`` is last-wins on duplicate keys, so a second
row with the same key silently SHADOWS the first — a branch can
replace a reviewed baseline row (note, count, review stamp) with an
unreviewed one and the diff shows only an easily-missed extra key.
Nothing in the gate scripts detects this; this oracle does, over
every baseline the gate scripts consume.

The baseline universe is DERIVED, never enumerated: every
``*baseline*.json`` filename mentioned by any top-level gate script
in ``.github/scripts/`` is oracle-covered automatically, so a new
gate's baseline joins the oracle the moment its script names it.
(A hand-typed enumeration covered three of six baselines, and a
shadowing duplicate planted in an unenumerated one passed both this
oracle and its gate.)  Three pins keep the derivation honest: a
vacuousness floor on the extraction regex, existence of every
derived name, and no on-disk data file left underived.

The name-shape assumption is guarded mechanically, not just
documented: EVERY ``.json`` file in ``.github/scripts/`` is
duplicate-key checked regardless of name, and every one must be
mentioned by a gate script — a gate data file named outside the
``*baseline*.json`` shape is still policed, and an unmentioned one
fails loudly by name instead of rotting unchecked.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"

#: Filename shape of a gate baseline as gate scripts spell it
#: (docstrings, DEFAULT_BASELINE constants, and error hints all use
#: the literal filename).
_BASELINE_NAME_RE = re.compile(r"\b\w*baseline\w*\.json\b")

#: The derivation must never silently shrink below the universe size
#: at introduction time; raise this floor when a new gate baseline
#: lands, lower it only with the removal of a gate and its baseline
#: (which the on-disk pin below still balances).
_UNIVERSE_FLOOR = 9


def gate_baseline_names() -> tuple[str, ...]:
    """Every baseline filename any top-level gate script mentions.

    Top-level ``*.py`` only: the scripts' own unit tests under
    ``tests/`` synthesize scratch baselines that are not gate inputs.
    """
    names: set[str] = set()
    for script in sorted(SCRIPTS_DIR.glob("*.py")):
        names.update(
            _BASELINE_NAME_RE.findall(script.read_text(encoding="utf-8")),
        )
    return tuple(sorted(names))


GATE_BASELINES = gate_baseline_names()

#: Mechanical guard for the ``*baseline*.json`` shape assumption:
#: every on-disk .json beside the gate scripts joins the duplicate-key
#: check regardless of its name.
ALL_SCRIPT_JSON = tuple(sorted(p.name for p in SCRIPTS_DIR.glob("*.json")))

#: Union universe the per-file checks run over: derived baseline
#: mentions (a mentioned-but-missing name fails existence) plus every
#: on-disk .json (a differently-named data file cannot escape).
CHECKED_JSON = tuple(sorted(set(GATE_BASELINES) | set(ALL_SCRIPT_JSON)))


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


def test_universe_is_derived_and_complete() -> None:
    """Derivation health: floor + no on-disk baseline left underived.

    (The other direction — every derived name exists on disk — is
    asserted per-baseline by the parametrized hygiene test.)
    """
    assert len(GATE_BASELINES) >= _UNIVERSE_FLOOR, (
        f"derived baseline universe shrank to {GATE_BASELINES} — the "
        "filename extraction went vacuous, or a gate baseline was "
        "removed without lowering _UNIVERSE_FLOOR deliberately"
    )
    mentioned_somewhere = "".join(
        script.read_text(encoding="utf-8")
        for script in sorted(SCRIPTS_DIR.glob("*.py"))
    )
    orphans = sorted(
        name for name in ALL_SCRIPT_JSON if name not in mentioned_somewhere
    )
    assert not orphans, (
        f"data file(s) {orphans} exist in .github/scripts/ but no "
        "gate script mentions them — dead data files rot unreviewed; "
        "wire them to their gate or delete them"
    )


@pytest.mark.parametrize("name", CHECKED_JSON)
def test_gate_baseline_has_no_duplicate_keys(name: str) -> None:
    path = SCRIPTS_DIR / name
    assert path.exists(), f"gate baseline missing: {path}"
    load_rejecting_duplicates(path.read_text(encoding="utf-8"))


def _first_populated_object(node: object) -> dict | None:
    """Depth-first: the first non-empty dict inside *node*."""
    if isinstance(node, dict):
        if node:
            return node
        return None
    if isinstance(node, list):
        for item in node:
            found = _first_populated_object(item)
            if found is not None:
                return found
    return None


@pytest.mark.parametrize("name", CHECKED_JSON)
def test_oracle_fires_on_a_shadowed_row(name: str) -> None:
    """Self-check against each REAL baseline: re-serialising its own
    row object with one key duplicated must fire — proves every
    member of the derived universe flows through a shape the
    duplicate-rejecting loader actually polices, not one it ignores
    (e.g. rows kept in a list)."""
    path = SCRIPTS_DIR / name
    data = json.loads(path.read_text(encoding="utf-8"))
    obj = _first_populated_object(data)
    if obj is None:
        # Nothing to shadow yet (an empty baseline) — but it must at
        # least BE a keyed object so future rows are policed.
        assert isinstance(data, dict), f"{name}: not a keyed object"
        return
    key = next(iter(obj))
    shadowed = (
        "{"
        + ", ".join(f"{json.dumps(k)}: {json.dumps(v)}"
                    for k, v in obj.items())
        + f", {json.dumps(key)}: {json.dumps(obj[key])}"
        + "}"
    )
    with pytest.raises(DuplicateKeyError):
        load_rejecting_duplicates(shadowed)


def test_oracle_fires_on_duplicate_key() -> None:
    """The oracle itself can fail: a shadowing duplicate is detected."""
    shadowing = '{"a::LIST": {"count": 1, "reviewed": "x"}, "a::LIST": {"count": 1}}'
    with pytest.raises(DuplicateKeyError):
        load_rejecting_duplicates(shadowing)


def test_oracle_fires_on_nested_duplicate_key() -> None:
    nested = '{"row": {"note": "n", "note": "shadow"}}'
    with pytest.raises(DuplicateKeyError):
        load_rejecting_duplicates(nested)
