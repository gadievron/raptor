"""Tests for the analyzed-units coverage projection
(packages/openant/coverage.py).

The scan dir is written by the sandboxed child processing a hostile
target, so beside the matching-rule tests every intake is exercised
with drifted/hostile shapes: the projection must degrade (skip, count,
truncate) — never crash, never force-match, and never write a record
that could read as review coverage (the grade itself is consumer-traced
in core/coverage/tests/test_scanner_grade.py).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.openant import coverage as oac  # noqa: E402

_CHECKLIST = {
    "files": [
        {"path": "src/app.py", "lines": 200, "items": [
            {"name": "handler", "line_start": 10, "line_end": 40,
             "kind": "function"},
            {"name": "helper", "line_start": 50, "line_end": 80,
             "kind": "function"},
            {"name": "Config", "line_start": 90, "line_end": 120,
             "kind": "class"},
        ]},
        {"path": "src/util.py", "lines": 60, "items": [
            {"name": "misc", "line_start": 5, "line_end": 20,
             "kind": "function"},
        ]},
    ],
}


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _scan_dir(tmp_path: Path, results_rows, dataset_units=None) -> Path:
    scan = tmp_path / "openant_scan"
    scan.mkdir(parents=True, exist_ok=True)
    _write(scan / "results.json", {
        "model": "model-x", "provider": "prov-y",
        "analyze_fingerprint": "fp123",
        "results": results_rows,
    })
    if dataset_units is not None:
        _write(scan / "dataset.json", {"units": dataset_units})
    return scan


def _unit(uid, file, func, lo, hi):
    return {"id": uid, "code": {"primary_origin": {
        "file_path": file, "start_line": lo, "end_line": hi,
        "function_name": func}}}


# ---------------------------------------------------------------- intake


def test_results_lane_collects_dedupes_and_screens_errors(tmp_path):
    scan = _scan_dir(tmp_path, [
        {"unit_id": "src/app.py:handler", "finding": "safe"},
        {"unit_id": "src/app.py:handler", "finding": "vulnerable"},  # dup
        {"unit_id": "src/app.py:broken", "finding": "error"},
        {"unit_id": "src/app.py:legacy", "verdict": "ERROR"},
        # The pinned analyze_result_is_error arms beyond the explicit
        # spellings (contract-pinned in
        # test_error_predicate_pinned_contract.py): null/ineffective
        # verdicts, unrecognized verdicts, and malformed rows are all
        # attempted-not-analysed.
        {"unit_id": "src/app.py:refused", "verdict": None},
        {"unit_id": "src/app.py:drifted", "verdict": "SAY WHAT"},
        "not-a-dict",
        None,
    ])
    units, acct = oac.collect_analyzed_units(scan)
    assert [u["id"] for u in units] == ["src/app.py:handler"]
    assert acct["source"] == "results.json"
    assert acct["units_analyzed"] == 1
    assert acct["units_error"] == 6
    assert acct["model"] == "model-x"
    assert acct["provider"] == "prov-y"
    assert acct["analyze_fingerprint"] == "fp123"


def test_pinned_vocab_verdicts_count_as_analysed(tmp_path):
    scan = _scan_dir(tmp_path, [
        {"unit_id": "u1", "verdict": "INSUFFICIENT_CONTEXT"},
        {"unit_id": "u2", "verdict": "inconclusive"},   # case-folded vocab
        {"unit_id": "u3", "finding": "protected"},      # effective finding
    ])
    units, acct = oac.collect_analyzed_units(scan)
    assert len(units) == 3
    assert acct["units_error"] == 0


def test_checkpoint_fallback_when_no_results_document(tmp_path):
    scan = tmp_path / "openant_scan"
    ckpt = scan / "analyze_checkpoints"
    _write(ckpt / "u1.json", {"id": "src/app.py:handler",
                              "result": {"finding": "safe"}})
    _write(ckpt / "u2.json", {"id": "src/app.py:broken",
                              "result": {"finding": "error"}})
    # Sidecars are counters' poison in the pinned core too — skipped.
    _write(ckpt / "_summary.json", {"id": "forged"})
    _write(ckpt / "_fingerprint.json", {"id": "forged2"})
    units, acct = oac.collect_analyzed_units(scan)
    assert [u["id"] for u in units] == ["src/app.py:handler"]
    assert acct["source"] == "analyze_checkpoints"
    assert acct["units_error"] == 1


def test_empty_scan_dir_yields_source_none(tmp_path):
    units, acct = oac.collect_analyzed_units(tmp_path / "nowhere")
    assert units == []
    assert acct["source"] == "none"


def test_results_row_cap_truncates_loudly(tmp_path, monkeypatch):
    monkeypatch.setattr(oac, "MAX_UNITS", 3)
    rows = [{"unit_id": f"f.py:u{i}", "finding": "safe"} for i in range(10)]
    scan = _scan_dir(tmp_path, rows)
    units, acct = oac.collect_analyzed_units(scan)
    assert len(units) == 3
    assert acct["truncated"] is True


def test_hostile_results_shapes_degrade_to_nothing(tmp_path):
    scan = tmp_path / "openant_scan"
    scan.mkdir()
    (scan / "results.json").write_text('["not", "a", "dict... wait"]',
                                       encoding="utf-8")
    units, acct = oac.collect_analyzed_units(scan)
    # Non-dict document -> not the results lane; no checkpoints either.
    assert units == []
    assert acct["source"] == "none"


# ------------------------------------------------------------ matching


def test_exact_name_match(tmp_path):
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:handler", "finding": "safe"}],
        [_unit("src/app.py:handler", "src/app.py", "handler", 10, 40)],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert record["functions_analysed"] == [
        {"file": "src/app.py", "function": "handler"}]
    sc = record["scanner_coverage"]
    assert sc["join"] == "inventory"
    assert sc["units_matched"] == 1
    assert sc["units_unmatched"] == 0
    assert "unmatched_sample" not in sc


def test_line_overlap_matches_every_spanned_function(tmp_path):
    # A unit spanning handler AND helper credits both (unit != function
    # granularity), but never the overlapped CLASS item (reviewable
    # kinds only).
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:route", "finding": "safe"}],
        [_unit("src/app.py:route", "src/app.py", "route_span", 30, 100)],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert record["functions_analysed"] == [
        {"file": "src/app.py", "function": "handler"},
        {"file": "src/app.py", "function": "helper"},
    ]


def test_name_mismatch_resolved_by_overlap(tmp_path):
    # Method units carry a name the inventory spells differently — the
    # span decides.
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:App.handler", "finding": "safe"}],
        [_unit("src/app.py:App.handler", "src/app.py", "App.handler",
               12, 38)],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert record["functions_analysed"] == [
        {"file": "src/app.py", "function": "handler"}]


def test_route_ids_and_foreign_files_stay_unmatched(tmp_path):
    scan = _scan_dir(
        tmp_path,
        [
            {"unit_id": "GET:/admin", "finding": "vulnerable"},
            {"unit_id": "vendor/x.py:f", "finding": "safe"},
            # Traversal-shaped origin: never resolves to inventory.
            {"unit_id": "esc", "finding": "safe"},
        ],
        [
            _unit("GET:/admin", "", "", None, None),
            _unit("vendor/x.py:f", "vendor/x.py", "f", 1, 5),
            _unit("esc", "../../etc/passwd", "root", 1, 2),
        ],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert record["functions_analysed"] == []
    sc = record["scanner_coverage"]
    assert sc["units_unmatched"] == 3
    assert sc["units_matched"] == 0
    assert len(sc["unmatched_sample"]) == 3


def test_unmatched_sample_is_capped_in_count_and_length(tmp_path,
                                                        monkeypatch):
    monkeypatch.setattr(oac, "UNMATCHED_SAMPLE_CAP", 2)
    rows = [{"unit_id": "nowhere.zz:" + "A" * 5000 + str(i),
             "finding": "safe"} for i in range(5)]
    scan = _scan_dir(tmp_path, rows)
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    sample = record["scanner_coverage"]["unmatched_sample"]
    assert len(sample) == 2
    assert all(len(s) <= 200 for s in sample)
    assert record["scanner_coverage"]["units_unmatched"] == 5


def test_id_parse_fallback_without_dataset(tmp_path):
    # No dataset.json: the file:function id convention still joins by
    # exact name (overlap needs the span the dataset would carry).
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:handler", "finding": "safe"},
         {"unit_id": "src/app.py:renamed_since", "finding": "safe"}],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert record["functions_analysed"] == [
        {"file": "src/app.py", "function": "handler"}]
    assert record["scanner_coverage"]["units_unmatched"] == 1


def test_absolute_origin_path_normalises_to_inventory_key(tmp_path):
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "u1", "finding": "safe"}],
        [_unit("u1", "/build/root/src/util.py", "misc", 5, 20)],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert record["functions_analysed"] == [
        {"file": "src/util.py", "function": "misc"}]


def test_forged_line_numbers_never_enter_overlap(tmp_path):
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "u1", "finding": "safe"}],
        [_unit("u1", "src/app.py", "no_such_name", "10", True)],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert record["functions_analysed"] == []
    assert record["scanner_coverage"]["units_unmatched"] == 1


# -------------------------------------------------- module-shaped units

# Inventory with a top_level item beside functions — the module-unit
# fixtures join against this.
_TL_CHECKLIST = {
    "files": [
        {"path": "src/mod.py", "lines": 100, "items": [
            {"name": "fn_a", "line_start": 10, "line_end": 30,
             "kind": "function"},
            {"name": "fn_b", "line_start": 40, "line_end": 60,
             "kind": "function"},
            {"name": "(module setup)", "line_start": 1, "line_end": 8,
             "kind": "top_level"},
        ]},
    ],
}


def test_module_unit_span_never_credits_function_items(tmp_path):
    # THE level-filtered-dataset shape: the synthetic module unit spans
    # first->last top-level statement (here: the whole file) while its
    # code holds only top-level statements; the function units were
    # pruned by the level filter. The functions must stay unanalysed
    # (in the residual) — only the top_level item is credited.
    unit = _unit("src/mod.py:__module__", "src/mod.py", "__module__",
                 1, 95)
    unit["unit_type"] = "module_level"
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/mod.py:__module__", "finding": "safe"}],
        [unit],
    )
    record = oac.build_openant_coverage_record(scan, _TL_CHECKLIST)
    assert record["functions_analysed"] == [
        {"file": "src/mod.py", "function": "(module setup)"}]


def test_module_shape_detected_by_name_alone(tmp_path):
    # Belt: some parsers stamp the synthetic name without the
    # unit_type — the __module__ spelling alone restricts the overlap.
    unit = _unit("src/mod.py:__module__", "src/mod.py", "__module__",
                 1, 95)
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/mod.py:__module__", "finding": "safe"}],
        [unit],
    )
    record = oac.build_openant_coverage_record(scan, _TL_CHECKLIST)
    assert record["functions_analysed"] == [
        {"file": "src/mod.py", "function": "(module setup)"}]


def test_function_units_with_own_units_still_credit(tmp_path):
    # Control: ordinary function units keep crediting the functions
    # they span. NOTE the documented trade in the other direction: a
    # function whose ONLY span coverage was the module unit (no unit
    # of its own, even on a full dataset) is conservatively
    # under-credited — it stays in the residual (safe direction),
    # never silently retired.
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/mod.py:fn_a", "finding": "safe"},
         {"unit_id": "src/mod.py:__module__", "finding": "safe"}],
        [_unit("src/mod.py:fn_a", "src/mod.py", "fn_a", 10, 30),
         {**_unit("src/mod.py:__module__", "src/mod.py", "__module__",
                  1, 95), "unit_type": "module_level"}],
    )
    record = oac.build_openant_coverage_record(scan, _TL_CHECKLIST)
    assert record["functions_analysed"] == [
        {"file": "src/mod.py", "function": "(module setup)"},
        {"file": "src/mod.py", "function": "fn_a"},
    ]


# --------------------------------------------------- intake byte budget


def test_checkpoint_walk_pays_a_running_byte_budget(tmp_path,
                                                    monkeypatch):
    scan = tmp_path / "openant_scan"
    ckpt = scan / "analyze_checkpoints"
    for i in range(6):
        _write(ckpt / f"u{i}.json",
               {"id": f"f.py:u{i}", "result": {"finding": "safe"},
                "pad": "x" * 100})
    # Budget admits roughly half the files, then the walk stops loudly.
    monkeypatch.setattr(oac, "CHECKPOINT_WALK_MAX_BYTES", 450)
    units, acct = oac.collect_analyzed_units(scan)
    assert acct["source"] == "analyze_checkpoints"
    assert acct["truncated"] is True
    assert 0 < len(units) < 6


# ------------------------------------------------ overlap explosion flag


def test_overlap_explosion_flagged_above_threshold(tmp_path):
    items = [{"name": f"fn{i}", "line_start": i * 10 + 1,
              "line_end": i * 10 + 9, "kind": "function"}
             for i in range(30)]
    checklist = {"files": [
        {"path": "src/big.py", "lines": 400, "items": items}]}
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "u1", "finding": "safe"}],
        [_unit("u1", "src/big.py", "nosuch", 1, 400)],
    )
    record = oac.build_openant_coverage_record(scan, checklist)
    sc = record["scanner_coverage"]
    assert sc["functions_matched"] == 30
    assert sc["overlap_explosion"] is True
    assert "span blowup" in oac.summary_line(record)


def test_honest_span_units_never_flag(tmp_path):
    # Refusal direction: a route unit spanning two functions (the
    # honest span shape) stays unflagged.
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:route", "finding": "safe"}],
        [_unit("src/app.py:route", "src/app.py", "route_span", 30, 100)],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert "overlap_explosion" not in record["scanner_coverage"]
    assert "span blowup" not in oac.summary_line(record)


# ----------------------------------------------------- target provenance


def test_record_stamps_target_path(tmp_path):
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:handler", "finding": "safe"}],
        [_unit("src/app.py:handler", "src/app.py", "handler", 10, 40)],
    )
    record = oac.build_openant_coverage_record(
        scan, _CHECKLIST, repo_path="/scanned/tree")
    assert record["scanner_coverage"]["target_path"] == "/scanned/tree"


def test_project_scan_coverage_backfills_target_from_run_metadata(
        tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write(run_dir / ".raptor-run.json",
           {"target_path": "/scanned/tree", "command": "openant"})
    scan = _scan_dir(
        run_dir,
        [{"unit_id": "src/app.py:handler", "finding": "safe"}],
        [_unit("src/app.py:handler", "src/app.py", "handler", 10, 40)],
    )
    assert oac.project_scan_coverage(run_dir, scan) is not None
    on_disk = json.loads(
        (run_dir / "coverage-openant.json").read_text(encoding="utf-8"))
    assert on_disk["scanner_coverage"]["target_path"] == "/scanned/tree"
    # Deferred lane (no checklist anywhere): the target rides so the
    # later import can bind the raw rows to THIS tree.
    assert on_disk["scanner_coverage"]["join"] == "deferred"


# -------------------------------------------------------------- record


def test_no_units_yields_no_record(tmp_path):
    scan = tmp_path / "openant_scan"
    scan.mkdir()
    assert oac.build_openant_coverage_record(scan, _CHECKLIST) is None


def test_record_never_carries_files_examined(tmp_path):
    # files_examined imports WHOLE-FILE — a scanner analysed UNITS, and
    # a file-level mark would push never-analysed siblings out of the
    # no-lane residual.
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:handler", "finding": "safe"}],
        [_unit("src/app.py:handler", "src/app.py", "handler", 10, 40)],
    )
    record = oac.build_openant_coverage_record(scan, _CHECKLIST)
    assert "files_examined" not in record
    assert record["tool"] == "openant"


def test_deferred_join_without_inventory(tmp_path):
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:handler", "finding": "safe"},
         {"unit_id": "GET:/admin", "finding": "safe"}],
        [_unit("src/app.py:handler", "src/app.py", "handler", 10, 40),
         _unit("GET:/admin", "", "", None, None)],
    )
    record = oac.build_openant_coverage_record(scan, None)
    assert record["scanner_coverage"]["join"] == "deferred"
    # Raw origin rows ride for a later inventory join; locationless
    # units contribute nothing.
    assert record["functions_analysed"] == [
        {"file": "src/app.py", "function": "handler"}]


def test_level_and_provenance_ride_the_record(tmp_path):
    scan = _scan_dir(
        tmp_path,
        [{"unit_id": "src/app.py:handler", "finding": "safe"}],
        [_unit("src/app.py:handler", "src/app.py", "handler", 10, 40)],
    )
    record = oac.build_openant_coverage_record(
        scan, _CHECKLIST, level="reachable")
    sc = record["scanner_coverage"]
    assert sc["level"] == "reachable"
    assert sc["scan_subdir"] == "openant_scan"
    assert sc["source"] == "results.json"
    assert sc["model"] == "model-x"


# ------------------------------------------------------- entry point


def test_project_scan_coverage_writes_record_and_summarises(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write(run_dir / "checklist.json", _CHECKLIST)
    scan = _scan_dir(
        run_dir,
        [{"unit_id": "src/app.py:handler", "finding": "safe"},
         {"unit_id": "GET:/admin", "finding": "vulnerable"},
         {"unit_id": "src/app.py:broken", "finding": "error"}],
        [_unit("src/app.py:handler", "src/app.py", "handler", 10, 40),
         _unit("GET:/admin", "", "", None, None)],
    )
    line = oac.project_scan_coverage(run_dir, scan, level="reachable")
    assert "2 unit(s) analyzed" in line
    assert "1 inventory function(s)" in line
    assert "1 unit(s) unmatched" in line
    assert "1 unit(s) errored" in line
    on_disk = json.loads(
        (run_dir / "coverage-openant.json").read_text(encoding="utf-8"))
    assert on_disk["tool"] == "openant"
    assert on_disk["functions_analysed"] == [
        {"file": "src/app.py", "function": "handler"}]


def test_project_scan_coverage_finds_project_parent_checklist(tmp_path):
    project = tmp_path / "proj"
    run_dir = project / "run1"
    run_dir.mkdir(parents=True)
    _write(project / "checklist.json", _CHECKLIST)
    scan = _scan_dir(
        run_dir,
        [{"unit_id": "src/app.py:handler", "finding": "safe"}],
        [_unit("src/app.py:handler", "src/app.py", "handler", 10, 40)],
    )
    line = oac.project_scan_coverage(run_dir, scan)
    assert "join deferred" not in line
    on_disk = json.loads(
        (run_dir / "coverage-openant.json").read_text(encoding="utf-8"))
    assert on_disk["scanner_coverage"]["join"] == "inventory"


def test_project_scan_coverage_nothing_to_project(tmp_path):
    run_dir = tmp_path / "run"
    scan = run_dir / "openant_scan"
    scan.mkdir(parents=True)
    assert oac.project_scan_coverage(run_dir, scan) is None
    assert not (run_dir / "coverage-openant.json").exists()
