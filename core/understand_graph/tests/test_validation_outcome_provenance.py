"""Run-bound provenance on the VALIDATES suppression lane.

validation-outcomes.json lives in the target-writable run dir
(hostile target code executes during validation stages) and is
replayed by ``/project graph rebuild`` long after the run, yet each
row with a resolvable ``finding_id`` used to mint a VALIDATES edge
unconditionally — retiring the joined entry→sink path from
``coverage_residual`` with no provenance at all. One planted row
naming a flow id silenced a never-validated attack path.

The writer now stamps every row with a run-bound MAC
(``journal_mac.mint_validation_outcome_row``); the ingest grades each
row and withholds the VALIDATES edge from anything that does not
verify (unstamped, tampered, or replayed from another run), recording
the row as examination telemetry only; and ``coverage_residual``
additionally refuses outcome nodes the ingest did not grade
``verified`` (legacy/foreign graphs). Zero LLM calls.
"""

from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path

from core.coverage import journal_mac
from core.json import save_json
from core.understand_graph import coverage_residual, ingest_validation_outcomes
from core.understand_graph.store import graph_write_txn, open_graph
from core.understand_graph.tests.test_validates_join import (
    _validates_targets,
    _write_two_flow_run,
    save_outcomes,
)

_ROW = {"finding_id": "FLOW-1", "status": "exploitable"}


def _residual_sinks(graph_path: Path, target: Path) -> set[str]:
    return {p["sink"]["id"]
            for p in coverage_residual(graph_path, str(target))}


def _node_provenances(graph_path: Path) -> set[str | None]:
    with closing(open_graph(graph_path)) as conn, conn:
        rows = conn.execute(
            "SELECT props_json FROM nodes WHERE kind='verified_outcome'"
        ).fetchall()
    return {json.loads(r["props_json"]).get("provenance") for r in rows}


def test_unstamped_row_is_telemetry_only(tmp_path: Path) -> None:
    """The planted-row PoC inverted: a raw hand-written outcome row
    mints its node (examination telemetry, graded unstamped) but no
    VALIDATES edge — the path stays in the residual."""
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)
    save_json(run / "validation-outcomes.json", [dict(_ROW)])
    assert ingest_validation_outcomes(run, str(target)) is not None

    assert _node_provenances(graph) == {journal_mac.ROW_UNSTAMPED}
    assert _validates_targets(graph) == []
    assert _residual_sinks(graph, target) == {"SINK-1", "SINK-2"}


def test_stamped_row_earns_suppression(tmp_path: Path) -> None:
    """Control direction: the real writer's run-bound stamp verifies,
    the edge mints, and the validated path leaves the residual."""
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)
    save_outcomes(run, [dict(_ROW)])
    assert ingest_validation_outcomes(run, str(target)) is not None

    assert _node_provenances(graph) == {journal_mac.ROW_VERIFIED}
    assert _validates_targets(graph) == ["unchecked_flow://FLOW-1"]
    assert _residual_sinks(graph, target) == {"SINK-2"}


def test_edited_stamped_row_never_suppresses(tmp_path: Path) -> None:
    """A validly-stamped row edited in the file-writable artifact
    (here: verdict rewritten) demotes to tampered — telemetry only."""
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)
    save_outcomes(run, [{"finding_id": "FLOW-1", "status": "inconclusive"}])
    outcomes_path = run / "validation-outcomes.json"
    rows = json.loads(outcomes_path.read_text(encoding="utf-8"))
    rows[0]["status"] = "exploitable"  # covered byte flip
    outcomes_path.write_text(json.dumps(rows), encoding="utf-8")
    assert ingest_validation_outcomes(run, str(target)) is not None

    assert _node_provenances(graph) == {journal_mac.ROW_TAMPERED}
    assert _validates_targets(graph) == []
    assert _residual_sinks(graph, target) == {"SINK-1", "SINK-2"}


def test_replayed_row_from_another_run_never_suppresses(
    tmp_path: Path,
) -> None:
    """Run-bound: a genuine stamped outcomes file copied from another
    run dir does not verify here — display finding ids repeat across
    targets, so a cross-run replay could join a different target's
    finding by id and falsely retire its path."""
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)

    other_run = tmp_path / "other-run"
    other_run.mkdir()
    row = dict(_ROW)
    token = journal_mac.mint_validation_outcome_row(
        row, journal_mac.audit_log_run_binding(other_run))
    assert token
    row[journal_mac.TOKEN_KEY] = token
    save_json(run / "validation-outcomes.json", [row])
    assert ingest_validation_outcomes(run, str(target)) is not None

    assert _node_provenances(graph) == {journal_mac.ROW_TAMPERED}
    assert _validates_targets(graph) == []
    assert _residual_sinks(graph, target) == {"SINK-1", "SINK-2"}


def test_planted_provenance_key_is_overwritten(tmp_path: Path) -> None:
    """The row is attacker-shaped: a planted ``"provenance":
    "verified"`` field must not survive into the graded props the
    query-side filter trusts."""
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)
    planted = dict(_ROW)
    planted["provenance"] = journal_mac.ROW_VERIFIED
    save_json(run / "validation-outcomes.json", [planted])
    assert ingest_validation_outcomes(run, str(target)) is not None

    assert _node_provenances(graph) == {journal_mac.ROW_UNSTAMPED}
    assert _validates_targets(graph) == []
    assert _residual_sinks(graph, target) == {"SINK-1", "SINK-2"}


def test_residual_refuses_ungraded_outcome_nodes(tmp_path: Path) -> None:
    """Query-side belt: a graph whose VALIDATES edges already exist
    but whose outcome nodes carry no ``verified`` grade (built by an
    older ingest, or merged from elsewhere) does not suppress — the
    path stays reported, the safe direction."""
    target, run = tmp_path / "target", tmp_path / "run"
    graph = _write_two_flow_run(run, target)
    save_outcomes(run, [dict(_ROW)])
    assert ingest_validation_outcomes(run, str(target)) is not None
    assert _residual_sinks(graph, target) == {"SINK-2"}

    # Model the legacy graph: strip the grade, keep the edge.
    with graph_write_txn(graph) as conn:
        conn.execute(
            "UPDATE nodes SET props_json = json_remove(props_json,"
            " '$.provenance') WHERE kind='verified_outcome'")
    assert _validates_targets(graph) == ["unchecked_flow://FLOW-1"]
    assert _residual_sinks(graph, target) == {"SINK-1", "SINK-2"}
