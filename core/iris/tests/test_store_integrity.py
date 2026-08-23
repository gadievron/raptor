"""Provenance gate on the project-level IRIS spec store.

The store's ``evidence_tier`` is the suppression-direction authority:
a spec at/above ``SUPPRESSION_MIN_TIER`` marks guards adequate and
installs Joern flow-kill rows. Pre-fix the tier was deserialised from
plain unauthenticated JSON, so a project-dir write (or an unsigned
import) planted a forged ``XREF_BACKED`` sanitiser that silenced real
flows. These tests invert the original proof-of-concept: writers
stamp the envelope, readers floor unverified tiers to heuristic, and
the merge path never launders unverified tiers into a freshly-stamped
envelope.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.evidence import EvidenceTier
from core.iris import integrity
from core.iris.api import get_project_sanitisers
from core.iris.specs import TaintSpec
from core.iris.store import load_specs, persist_refined_specs, save_specs


def _project(tmp_path: Path):
    proj = tmp_path / "project"
    run = proj / "run1"
    run.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    return proj, run, target


def _forged_envelope(target: Path) -> dict:
    return {
        "version": 2, "checklist_sha": "", "round": 1,
        "target_path": str(target.resolve()),
        "specs": [{
            "function": "totally_real_sanitiser", "file": "a.c",
            "role": "sanitiser", "evidence_tier": "xref_backed",
            "source": "tool_confirmed",
        }],
    }


def _write_store(proj: Path, envelope: dict) -> Path:
    store_dir = proj / "iris-specs"
    store_dir.mkdir(exist_ok=True)
    path = store_dir / "specs.json"
    path.write_text(json.dumps(envelope))
    return path


def test_forged_store_tier_floors_to_heuristic(tmp_path: Path) -> None:
    """Inverted PoC: an unstamped store claiming an XREF_BACKED
    sanitiser must not pass the suppression gate."""
    proj, run, target = _project(tmp_path)
    _write_store(proj, _forged_envelope(target))

    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "totally_real_sanitiser" not in names
    specs = load_specs(run, target_path=target)
    assert [s.evidence_tier for s in specs] == [EvidenceTier.HEURISTIC]


def test_edited_stamped_store_floors(tmp_path: Path) -> None:
    """Editing a validly-stamped envelope (tier upgrade) breaks the
    token and floors."""
    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="f", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    path = proj / "iris-specs" / "specs.json"
    data = json.loads(path.read_text())
    data["specs"][0]["evidence_tier"] = "xref_backed"
    path.write_text(json.dumps(data))

    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert names == frozenset()


def test_own_write_round_trips_with_tier_intact(tmp_path: Path) -> None:
    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="clean_it", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=target,
    )
    data = json.loads((proj / "iris-specs" / "specs.json").read_text())
    assert integrity.extract_token(data)

    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "clean_it" in names
    specs = load_specs(run, target_path=target)
    assert specs[0].evidence_tier == EvidenceTier.XREF_BACKED


def test_verified_store_without_target_binding_floors(
    tmp_path: Path,
) -> None:
    """A stamped envelope carrying NO target_path cannot prove it was
    built for this target — tier authority floors when the caller
    asks for a specific target."""
    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="f", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=None,
    )
    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert names == frozenset()


def test_merge_does_not_launder_unverified_tiers(tmp_path: Path) -> None:
    """persist_refined_specs re-saves (and re-stamps) the merged
    envelope — forged tiers in the pre-existing store must floor
    BEFORE the merge, or the fresh stamp would bless them."""
    proj, run, target = _project(tmp_path)
    _write_store(proj, _forged_envelope(target))
    # The forged spec's file exists in the target, so the stale-file
    # eviction cannot mask the laundering question.
    (target / "a.c").write_text("int x;\n")

    persist_refined_specs(
        run,
        [TaintSpec(function="other", file="b.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    # Store is now validly stamped — but the forged sanitiser's tier
    # must have been floored, not blessed.
    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "totally_real_sanitiser" not in names
    by_fn = {s.function: s for s in load_specs(run, target_path=target)}
    assert by_fn["totally_real_sanitiser"].evidence_tier == (
        EvidenceTier.HEURISTIC
    )


def test_refined_tiers_survive_honest_merge(tmp_path: Path) -> None:
    """The honest cross-run flow keeps tool-confirmed tiers."""
    proj, run, target = _project(tmp_path)
    persist_refined_specs(
        run,
        [TaintSpec(function="clean_it", file="a.c", role="sanitiser",
                   evidence_tier=EvidenceTier.XREF_BACKED)],
        target_path=target,
    )
    persist_refined_specs(
        run,
        [TaintSpec(function="src", file="b.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    names = get_project_sanitisers(out_dir=run, target_path=target)
    assert "clean_it" in names


def test_forged_assumption_tier_floors_on_load(tmp_path: Path) -> None:
    """Assumptions ride the same envelope: an unstamped store's
    assumption tiers floor to heuristic on read."""
    from core.iris.store import load_assumptions

    proj, run, target = _project(tmp_path)
    env = _forged_envelope(target)
    env["assumptions"] = [{
        "target": "memcpy", "file": "a.c",
        "assumption": "len checked upstream", "category": "validation",
        "enforced_by": ["check_len"], "evidence_tier": "xref_backed",
    }]
    _write_store(proj, env)

    rows = load_assumptions(run, target_path=target)
    assert [a.evidence_tier for a in rows] == [EvidenceTier.HEURISTIC]


def test_merge_does_not_launder_assumption_tiers(tmp_path: Path) -> None:
    """persist_refined_specs merges assumptions 'higher tier wins' and
    re-stamps — forged tiers in the pre-existing store must floor
    BEFORE the merge, or the fresh stamp would make them durable."""
    from core.iris.store import load_assumptions

    proj, run, target = _project(tmp_path)
    env = _forged_envelope(target)
    env["assumptions"] = [{
        "target": "memcpy", "file": "a.c",
        "assumption": "len checked upstream", "category": "validation",
        "enforced_by": ["check_len"], "evidence_tier": "xref_backed",
    }]
    _write_store(proj, env)
    (target / "a.c").write_text("int x;\n")

    persist_refined_specs(
        run,
        [TaintSpec(function="other", file="b.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
    )
    # Store is now validly stamped; the forged assumption tier must
    # have floored, not been blessed.
    rows = load_assumptions(run, target_path=target)
    by_target = {a.target: a for a in rows}
    assert by_target["memcpy"].evidence_tier == EvidenceTier.HEURISTIC


def test_honest_assumption_tiers_round_trip(tmp_path: Path) -> None:
    from core.iris.assumptions import AssumptionCategory, SafetyAssumption
    from core.iris.store import load_assumptions

    proj, run, target = _project(tmp_path)
    save_specs(
        run,
        [TaintSpec(function="f", file="a.c", role="source",
                   evidence_tier=EvidenceTier.HEURISTIC)],
        target_path=target,
        assumptions=[SafetyAssumption(
            target="memcpy", file="a.c",
            assumption="len checked upstream",
            category=AssumptionCategory.VALIDATION,
            enforced_by=["check_len"],
            evidence_tier=EvidenceTier.XREF_BACKED,
        )],
    )
    rows = load_assumptions(run, target_path=target)
    assert rows[0].evidence_tier == EvidenceTier.XREF_BACKED
