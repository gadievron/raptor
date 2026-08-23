"""Provenance gates on /audit feedback's mechanical-claim channels.

Cross-run consumers used to accept unauthenticated mechanical claims
outside the witness-mac channel: a bare ``ruling.disqualifier ==
"witness_refuted"`` string survived the sanitise chokepoint, and the
sibling files (``disproven.json`` IRIS rows, ``attack-paths.json``
``smt_feasibility`` records) were loaded with no verification at all
— any of the three forged a mechanical refutation that demoted a real
audit finding. These tests pin the fix: sibling rows only count when
their witness-mac stamp verifies for the report's own directory, and
the sanitiser rolls back bare refutation strings.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.feedback import _mechanical_disqualifier, _ValidationSiblings
from core.witness import provenance as prov


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path, monkeypatch):
    """Every test gets its own key under a private XDG_DATA_HOME."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _write_siblings(base: Path, disproven_rows, attack_paths) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    report = base / "findings.json"
    report.write_text("{}")
    (base / "disproven.json").write_text(
        json.dumps({"disproven": disproven_rows}))
    (base / "attack-paths.json").write_text(json.dumps(attack_paths))
    return report


# ---------------------------------------------------------------------------
# disproven.json — IRIS Tier-1 refutations
# ---------------------------------------------------------------------------


def test_forged_iris_row_is_ignored(tmp_path: Path) -> None:
    """Inverted PoC: an unstamped iris_tier1_refuted
    row must not become a mechanical disqualifier."""
    report = _write_siblings(
        tmp_path / "run",
        [{"finding": "F2", "lesson": "iris_tier1_refuted"}],
        [],
    )
    sib = _ValidationSiblings(report)
    assert sib.iris_refuted_ids == set()
    assert sib.unverified_rows == 1
    finding = {"id": "F2", "file": "a.c", "function": "g", "ruling": {}}
    assert _mechanical_disqualifier(finding, sib) is None


def test_stamped_iris_row_counts(tmp_path: Path) -> None:
    base = tmp_path / "run"
    row = {"finding": "F2", "lesson": "iris_tier1_refuted"}
    base.mkdir(parents=True)
    prov.stamp_iris_refutation(row, base)
    report = _write_siblings(base, [row], [])
    sib = _ValidationSiblings(report)
    assert sib.iris_refuted_ids == {"F2"}
    finding = {"id": "F2", "file": "a.c", "function": "g", "ruling": {}}
    assert _mechanical_disqualifier(finding, sib) == "iris_tier1_refuted"


def test_iris_row_replayed_from_another_run_fails(tmp_path: Path) -> None:
    """Run binding: a validly-stamped row copied from another run dir
    carries that run's binding and is ignored here."""
    other = tmp_path / "other-run"
    other.mkdir(parents=True)
    row = {"finding": "F2", "lesson": "iris_tier1_refuted"}
    prov.stamp_iris_refutation(row, other)
    report = _write_siblings(tmp_path / "run", [row], [])
    sib = _ValidationSiblings(report)
    assert sib.iris_refuted_ids == set()
    assert sib.unverified_rows == 1


# ---------------------------------------------------------------------------
# attack-paths.json — SMT sweep verdicts
# ---------------------------------------------------------------------------


def test_forged_smt_record_is_ignored(tmp_path: Path) -> None:
    report = _write_siblings(
        tmp_path / "run", [],
        [{"finding_id": "F3", "smt_feasibility": {"feasible": False}}],
    )
    sib = _ValidationSiblings(report)
    assert sib.smt_all_paths_infeasible("F3") is False
    finding = {"id": "F3", "file": "a.c", "function": "h", "ruling": {}}
    assert _mechanical_disqualifier(finding, sib) is None


def test_stamped_smt_record_counts(tmp_path: Path) -> None:
    base = tmp_path / "run"
    base.mkdir(parents=True)
    path = {"finding_id": "F3", "path_conditions": ["x > 0"]}
    # conditions_hash must be the canonical hash of the path's OWN
    # conditions — the verifier recomputes it as the path binding.
    record = {
        "feasible": False,
        "conditions_hash": prov.smt_conditions_hash(
            path["path_conditions"]),
    }
    prov.stamp_smt_feasibility(path, record, base)
    path["smt_feasibility"] = record
    report = _write_siblings(base, [], [path])
    sib = _ValidationSiblings(report)
    assert sib.smt_all_paths_infeasible("F3") is True
    finding = {"id": "F3", "file": "a.c", "function": "h", "ruling": {}}
    assert _mechanical_disqualifier(finding, sib) == "smt_paths_infeasible"


def test_one_forged_path_blocks_the_refutation(tmp_path: Path) -> None:
    """A finding with one verified-unsat path and one forged one is
    NOT mechanically refuted — every path must verify."""
    base = tmp_path / "run"
    base.mkdir(parents=True)
    p1 = {"finding_id": "F3", "path_conditions": ["x > 0"]}
    r1 = {
        "feasible": False,
        "conditions_hash": prov.smt_conditions_hash(["x > 0"]),
    }
    prov.stamp_smt_feasibility(p1, r1, base)
    p1["smt_feasibility"] = r1
    p2 = {"finding_id": "F3",
          "smt_feasibility": {"feasible": False, "conditions_hash": "bb"}}
    report = _write_siblings(base, [], [p1, p2])
    sib = _ValidationSiblings(report)
    assert sib.smt_all_paths_infeasible("F3") is False


# ---------------------------------------------------------------------------
# Sanitiser: bare ruling strings
# ---------------------------------------------------------------------------


def test_bare_witness_refuted_disqualifier_rolls_back(tmp_path: Path) -> None:
    """A ruling carrying ONLY ``disqualifier: witness_refuted`` (no
    marker, no witness_execution record) is the forged-refutation
    shape spelled differently — the chokepoint must roll it back so
    no consumer counts it as mechanical."""
    finding = {
        "id": "F1", "file": "a.c", "function": "f",
        "ruling": {"disqualifier": "witness_refuted",
                   "status": "ruled_out"},
        "final_status": "ruled_out",
    }
    stats = prov.sanitise_findings_evidence(
        {"findings": [finding]}, tmp_path)
    assert stats["witness_stripped"] == 1
    assert "ruling" not in finding
    assert finding["status"] == "pending"
    assert _mechanical_disqualifier(finding, None) is None


def test_disqualifier_grafted_onto_verified_record_rolls_back(
    tmp_path: Path,
) -> None:
    """A verified witness record with verdict != refuted must not
    lend its stamp to a grafted witness_refuted disqualifier."""
    finding = {"id": "F1", "file": "a.c", "function": "f"}
    record = {"verdict": "confirmed"}
    prov.stamp_witness_execution(finding, record, tmp_path)
    finding["witness_execution"] = record
    finding["ruling"] = {"disqualifier": "witness_refuted",
                         "status": "ruled_out"}
    stats = prov.sanitise_findings_evidence(
        {"findings": [finding]}, tmp_path)
    assert stats["witness_stripped"] == 1
    assert _mechanical_disqualifier(finding, None) is None


def test_verified_refutation_still_counts(tmp_path: Path) -> None:
    """The honest path: a verified refuted record with the matching
    ruling survives sanitisation and counts as mechanical."""
    finding = {"id": "F1", "file": "a.c", "function": "f"}
    record = {"verdict": "refuted"}
    prov.stamp_witness_execution(finding, record, tmp_path)
    finding["witness_execution"] = record
    finding["ruling"] = {"disqualifier": "witness_refuted",
                         "witness": "dark_verify:refuted",
                         "status": "ruled_out"}
    stats = prov.sanitise_findings_evidence(
        {"findings": [finding]}, tmp_path)
    assert stats["witness_stripped"] == 0
    assert _mechanical_disqualifier(finding, None) == "witness_refuted"


def test_stamped_record_copied_onto_sibling_path_is_refused(
    tmp_path: Path,
) -> None:
    """Path binding (inverted proof-of-concept): a genuinely-stamped
    feasible:false record copied onto a sibling SAT path of the SAME
    finding must not verify there — the record's conditions_hash is
    recomputed from the path's own path_conditions."""
    from packages.exploitability_validation.smt_paths import (
        sweep_attack_paths,
    )

    base = tmp_path / "run"
    base.mkdir(parents=True)
    p_unsat = {"finding_id": "F3", "path_conditions": ["x > 10", "x < 5"]}
    p_sat = {"finding_id": "F3", "path_conditions": ["y == 1"]}

    def fake_validate(conds, profile):
        if len(conds) == 2:
            return {"feasible": False, "unsatisfied": conds}
        return {"feasible": True, "model": {"y": 1}}

    sweep_attack_paths(
        [p_unsat, p_sat], validate_fn=fake_validate, run_dir=base,
    )
    assert p_unsat["smt_feasibility"]["feasible"] is False
    assert p_sat["smt_feasibility"]["feasible"] is True

    # The forgery: overwrite the SAT path's record with the unsat
    # path's genuinely-stamped one.
    p_sat["smt_feasibility"] = dict(p_unsat["smt_feasibility"])
    report = _write_siblings(base, [], [p_unsat, p_sat])

    sib = _ValidationSiblings(report)
    assert sib.smt_all_paths_infeasible("F3") is False
    finding = {"id": "F3", "file": "a.c", "function": "h", "ruling": {}}
    assert _mechanical_disqualifier(finding, sib) is None


def test_record_on_conditionless_path_is_refused(tmp_path: Path) -> None:
    """A stamped record grafted onto a path with NO path_conditions is
    foreign by construction (the sweep only rules on condition-carrying
    paths) and must not count."""
    from core.witness.provenance import stamp_smt_feasibility

    base = tmp_path / "run"
    base.mkdir(parents=True)
    donor = {"finding_id": "F4", "path_conditions": ["a > 1", "a < 0"]}
    record = {
        "feasible": False,
        "conditions_hash": prov.smt_conditions_hash(
            donor["path_conditions"]),
    }
    stamp_smt_feasibility(donor, record, base)
    bare = {"finding_id": "F4", "smt_feasibility": dict(record)}
    report = _write_siblings(base, [], [bare])
    sib = _ValidationSiblings(report)
    assert sib.smt_all_paths_infeasible("F4") is False
