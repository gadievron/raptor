"""Tests for checkpoint-verdict recovery (packages/openant/recovery.py).

Synthetic fixtures only — no live scans, no LLM calls. Both directions
are covered for every gate: recovered when the scanner's report dropped
a vulnerable-class verdict, NOT recovered when the verdict is present,
negative, or the artifacts drifted.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from packages.openant.recovery import (
    RECOVERED_TIER,
    _removal_keys,
    recover_dropped_verdicts,
)
from packages.openant.translator import deduplicate_with_sarif


def _row(route_key: str, verdict: str = "vulnerable", cwe: int = 89,
         **extra) -> dict:
    base = {
        "unit_id": route_key,
        "route_key": route_key,
        "finding": verdict,
        "verdict": verdict.upper(),
        "cwe_id": cwe,
        "cwe_name": "SQL Injection",
        "reasoning": "user input reaches the raw query string",
        "confidence": 0.9,
    }
    base.update(extra)
    return base


def _results_doc(rows: list[dict], code_by_route: dict | None = None) -> dict:
    return {
        "results": rows,
        "code_by_route": code_by_route or {},
        "metrics": {"total": len(rows)},
    }


def _finding_for(route_key: str) -> dict:
    file_ = route_key.split(":")[0] if ":" in route_key else "unknown"
    func = route_key.split(":", 1)[1] if ":" in route_key else route_key
    return {"id": "VULN-001", "location": {"file": file_, "function": func}}


def _pipeline(findings: list[dict], deduplicated: int = 0) -> dict:
    return {
        "findings": findings,
        "results": {"deduplicated": deduplicated},
    }


class _ScanDirCase(unittest.TestCase):
    """Base: a temp scan dir per test with fixture writers."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.scan_dir = Path(self._td.name)

    def write_json(self, name: str, data) -> Path:
        path = self.scan_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def write_call_graph(self, reverse: dict) -> None:
        self.write_json("call_graph.json", {"reverse_call_graph": reverse})

    def write_checkpoint(self, name: str, unit_id: str, verdict: str,
                         route_key: str | None = None,
                         code: str = "") -> None:
        self.write_json(f"analyze_checkpoints/{name}", {
            "id": unit_id,
            "route_key": route_key or unit_id,
            "code_for_route": code,
            "result": _row(route_key or unit_id, verdict),
        })


CALLER = "app/api.py:handle_request"
CALLEE = "app/db.py:run_query"
LEAF = "app/db.py:exec_raw"


class TestDedupRederivationLane(_ScanDirCase):

    def _collapsed_pair(self):
        """Caller kept, callee dedup-collapsed — the canonical shape."""
        self.write_json("results.json", _results_doc(
            [_row(CALLER), _row(CALLEE)],
            code_by_route={CALLEE: "cur.execute(q)"},
        ))
        self.write_call_graph({CALLEE: [CALLER]})
        return _pipeline([_finding_for(CALLER)], deduplicated=1)

    def test_collapsed_callee_recovered_with_marker(self):
        recovered = recover_dropped_verdicts(
            self.scan_dir, self._collapsed_pair())
        self.assertEqual(len(recovered), 1)
        rec = recovered[0]
        self.assertEqual(rec["level"], "note")
        self.assertEqual(rec["tool"], "openant")
        self.assertEqual(rec["file"], "app/db.py")
        self.assertEqual(rec["cwe_id"], "CWE-89")
        self.assertEqual(rec["snippet"], "cur.execute(q)")
        self.assertIn("raw query string", rec["message"])
        meta = rec["metadata"]
        self.assertEqual(meta["provenance_tier"], RECOVERED_TIER)
        self.assertEqual(meta["recovery_source"], "dedup_rederivation")
        self.assertEqual(meta["deduplicated_into"], CALLER)
        self.assertEqual(meta["function"], "run_query")
        self.assertEqual(meta["stage1_verdict"], "vulnerable")
        self.assertEqual(meta["confidence"], 0.9)
        self.assertEqual(rec["finding_id"], f"openant-recovered:{CALLEE}")

    def test_vulnerable_with_finding_not_duplicated(self):
        # Same artifacts, but the report kept BOTH records: nothing to
        # recover (and the honest dedup count is 0).
        self.write_json("results.json", _results_doc(
            [_row(CALLER), _row(CALLEE)]))
        self.write_call_graph({})
        recovered = recover_dropped_verdicts(
            self.scan_dir,
            _pipeline([_finding_for(CALLER), _finding_for(CALLEE)],
                      deduplicated=0))
        self.assertEqual(recovered, [])

    def test_safe_and_protected_never_recovered(self):
        # Negative verdicts are the scanner's own suppression — absence
        # from the report is correct, never a drop.
        self.write_json("results.json", _results_doc([
            _row(CALLER, verdict="safe"),
            _row(CALLEE, verdict="protected"),
            _row(LEAF, verdict="inconclusive"),
        ]))
        self.write_call_graph({CALLEE: [CALLER]})
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([], deduplicated=0))
        self.assertEqual(recovered, [])

    def test_transitive_chain_recovers_all_resolving_survivor(self):
        # A 3-deep same-CWE chain collapses to the topmost caller; both
        # removed links come back, each naming the SURVIVING ancestor.
        self.write_json("results.json", _results_doc(
            [_row(CALLER), _row(CALLEE), _row(LEAF)]))
        self.write_call_graph({CALLEE: [CALLER], LEAF: [CALLEE]})
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([_finding_for(CALLER)], deduplicated=2))
        self.assertEqual(
            sorted(r["metadata"]["route_key"] for r in recovered),
            sorted([CALLEE, LEAF]))
        for rec in recovered:
            self.assertEqual(rec["metadata"]["deduplicated_into"], CALLER)

    def test_multi_caller_and_zero_cwe_do_not_enter_removal(self):
        # The upstream rule removes only single-caller, same-NONZERO-CWE
        # callees — mirror both exclusions.
        confirmed = [_row(CALLER), _row(CALLEE), _row(LEAF, cwe=0),
                     _row("app/db.py:other", cwe=0)]
        remove = _removal_keys(confirmed, confirmed, {
            CALLEE: [CALLER, "app/cli.py:main"],       # two callers
            LEAF: ["app/db.py:other"],                 # cwe 0 == cwe 0
        })
        self.assertEqual(remove, set())

    def test_count_mismatch_degrades_loudly_to_nothing(self):
        pipeline = self._collapsed_pair()
        pipeline["results"]["deduplicated"] = 5  # re-derivation says 1
        with self.assertLogs("raptor", level="WARNING") as logs:
            recovered = recover_dropped_verdicts(self.scan_dir, pipeline)
        self.assertEqual(recovered, [])
        self.assertTrue(any("mismatch" in m for m in logs.output))

    def test_missing_deduplicated_field_degrades_loudly(self):
        # The pinned reporter always writes results.deduplicated; its
        # absence is schema drift — recover nothing, loudly.
        pipeline = self._collapsed_pair()
        del pipeline["results"]["deduplicated"]
        with self.assertLogs("raptor", level="WARNING") as logs:
            recovered = recover_dropped_verdicts(self.scan_dir, pipeline)
        self.assertEqual(recovered, [])
        self.assertTrue(any("schema drift" in m for m in logs.output))

    def test_bool_deduplicated_is_not_an_integer_count(self):
        pipeline = self._collapsed_pair()
        pipeline["results"]["deduplicated"] = True
        with self.assertLogs("raptor", level="WARNING"):
            self.assertEqual(
                recover_dropped_verdicts(self.scan_dir, pipeline), [])

    def test_verified_results_preferred_with_confirmed_findings(self):
        # When the verify stage ran, the reporter consumed
        # results_verified.json and its confirmed_findings — mirror that
        # population choice.
        self.write_json("results.json", _results_doc([]))  # stale twin
        self.write_json("results_verified.json", {
            "results": [_row(CALLER), _row(CALLEE)],
            "confirmed_findings": [_row(CALLER), _row(CALLEE)],
            "code_by_route": {},
        })
        self.write_call_graph({CALLEE: [CALLER]})
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([_finding_for(CALLER)], deduplicated=1))
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["metadata"]["route_key"], CALLEE)

    def test_hostile_call_graph_shapes_degrade_not_crash(self):
        self.write_json("results.json", _results_doc(
            [_row(CALLER), _row(CALLEE)]))
        self.write_json("call_graph.json", {"reverse_call_graph": {
            CALLEE: "not-a-list",
            "x": [{"nested": "dict"}],
            "y": [],
        }})
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([_finding_for(CALLER)], deduplicated=0))
        self.assertEqual(recovered, [])

    def test_duplicate_confirmed_rows_emit_one_record_tripwire_matches(self):
        # The pinned reporter's deduplicated counter counts each
        # duplicate ROW (two same-key rows removed = 2), but one unit
        # must never emit two same-finding_id records into one
        # artifact: tripwire on the row count, records deduped by key.
        self.write_json("results.json", _results_doc(
            [_row(CALLER), _row(CALLEE), _row(CALLEE)]))
        self.write_call_graph({CALLEE: [CALLER]})
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([_finding_for(CALLER)], deduplicated=2))
        self.assertEqual([r["metadata"]["route_key"] for r in recovered],
                         [CALLEE])

    def test_torn_verified_doc_falls_through_to_results(self):
        # A 2-byte torn results_verified.json (the child owns the scan
        # dir) must not demote recovery to the checkpoint-diff lane
        # while a readable results.json sits beside it — planted
        # checkpoint files for never-analyzed units would recover.
        (self.scan_dir / "results_verified.json").write_text(
            "{n", encoding="utf-8")
        self.write_json("results.json", _results_doc(
            [_row(CALLER), _row(CALLEE)]))
        self.write_call_graph({CALLEE: [CALLER]})
        self.write_checkpoint("ghost.json", "ghost.py:g", "vulnerable")
        with self.assertLogs("raptor", level="WARNING") as logs:
            recovered = recover_dropped_verdicts(
                self.scan_dir,
                _pipeline([_finding_for(CALLER)], deduplicated=1))
        self.assertEqual([r["metadata"]["route_key"] for r in recovered],
                         [CALLEE])
        self.assertEqual(recovered[0]["metadata"]["recovery_source"],
                         "dedup_rederivation")
        self.assertTrue(any("results_verified.json" in m
                            for m in logs.output))

    def test_lane_a_cap_truncates_loudly_and_under_cap_is_silent(self):
        from unittest.mock import patch
        rows = [_row(CALLER)] + [_row(f"m{i}.py:f", cwe=89)
                                 for i in range(4)]
        self.write_json("results.json", _results_doc(rows))
        self.write_call_graph(
            {f"m{i}.py:f": [CALLER] for i in range(4)})
        pipeline = _pipeline([_finding_for(CALLER)], deduplicated=4)
        with patch("packages.openant.recovery.RECOVERED_RECORD_CAP", 2):
            with self.assertLogs("raptor", level="WARNING") as logs:
                recovered = recover_dropped_verdicts(self.scan_dir,
                                                     pipeline)
        self.assertEqual(len(recovered), 2)
        self.assertTrue(any("recovery record cap" in m
                            for m in logs.output))
        # Under the cap: everything recovers, no truncation warning.
        recovered = recover_dropped_verdicts(self.scan_dir, pipeline)
        self.assertEqual(len(recovered), 4)

    def test_nonfinite_confidence_dropped_record_stays_serializable(self):
        # stdlib json parses 1e999 to inf even though the non-finite
        # LITERALS are rejected — a copied inf poisoned the shared
        # findings-artifact write. Forced through the stdlib parser so
        # the test is hermetic across orjson-present/absent hosts
        # (orjson refuses the doc outright, which is the other lane).
        import core.json.utils as cju
        from unittest.mock import patch
        rows_text = json.dumps(_results_doc(
            [_row(CALLER), _row(CALLEE)])).replace(
                '"confidence": 0.9', '"confidence": 1e999')
        (self.scan_dir / "results.json").write_text(rows_text,
                                                    encoding="utf-8")
        self.write_call_graph({CALLEE: [CALLER]})
        with patch.object(cju, "_orjson", None):
            recovered = recover_dropped_verdicts(
                self.scan_dir,
                _pipeline([_finding_for(CALLER)], deduplicated=1))
        self.assertEqual(len(recovered), 1)
        self.assertNotIn("confidence", recovered[0]["metadata"])
        json.dumps(recovered, allow_nan=False)  # must not raise

    def test_cyclic_call_graph_survivor_walk_terminates(self):
        # A crafted cycle in the (target-derived) graph must not hang
        # the survivor resolution; the record still recovers, with no
        # survivor attribution.
        a, b = "m.py:a", "m.py:b"
        self.write_json("results.json", _results_doc([_row(a), _row(b)]))
        self.write_call_graph({a: [b], b: [a]})
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([], deduplicated=2))
        self.assertEqual(len(recovered), 2)
        for rec in recovered:
            self.assertNotIn("deduplicated_into", rec["metadata"])


class TestCheckpointFallbackLane(_ScanDirCase):

    def test_falls_back_when_results_unreadable(self):
        (self.scan_dir / "results.json").write_text("{not json",
                                                    encoding="utf-8")
        self.write_checkpoint("u1.json", CALLEE, "vulnerable",
                              code="cur.execute(q)")
        with self.assertLogs("raptor", level="WARNING") as logs:
            recovered = recover_dropped_verdicts(
                self.scan_dir, _pipeline([], deduplicated=0))
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["metadata"]["recovery_source"],
                         "analyze_checkpoint")
        self.assertEqual(recovered[0]["snippet"], "cur.execute(q)")
        self.assertTrue(any("falling back" in m for m in logs.output))

    def test_checkpoint_two_directions_and_negative_verdicts(self):
        # No results file at all: pure checkpoint-diff lane.
        self.write_checkpoint("kept.json", CALLER, "vulnerable")
        self.write_checkpoint("dropped.json", CALLEE, "bypassable")
        self.write_checkpoint("safe.json", LEAF, "safe")
        self.write_checkpoint("err.json", "m.py:oops", "error")
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([_finding_for(CALLER)]))
        self.assertEqual([r["metadata"]["route_key"] for r in recovered],
                         [CALLEE])
        self.assertEqual(recovered[0]["metadata"]["stage1_verdict"],
                         "bypassable")

    def test_corrupt_checkpoint_skipped_loudly_others_recovered(self):
        self.write_checkpoint("good.json", CALLEE, "vulnerable")
        (self.scan_dir / "analyze_checkpoints" / "bad.json").write_text(
            "\x00garbage", encoding="utf-8")
        with self.assertLogs("raptor", level="WARNING") as logs:
            recovered = recover_dropped_verdicts(
                self.scan_dir, _pipeline([]))
        self.assertEqual(len(recovered), 1)
        self.assertTrue(any("unreadable" in m for m in logs.output))

    def test_reserved_sidecars_never_recover(self):
        # _summary.json / _fingerprint.json are step sidecars, not unit
        # checkpoints (upstream's reserved-file convention).
        self.write_json("analyze_checkpoints/_summary.json",
                        {"step": "Analyze", "completed": 1})
        self.write_json("analyze_checkpoints/_fingerprint.json",
                        {"key_digest": "k"})
        recovered = recover_dropped_verdicts(self.scan_dir, _pipeline([]))
        self.assertEqual(recovered, [])

    def test_schema_drift_checkpoint_without_result_is_skipped(self):
        self.write_json("analyze_checkpoints/drift.json",
                        {"id": CALLEE, "verdict": "vulnerable"})
        recovered = recover_dropped_verdicts(self.scan_dir, _pipeline([]))
        self.assertEqual(recovered, [])

    def test_lane_b_cap_bounds_planted_checkpoint_volume(self):
        # This lane has no consistency cross-check (planted checkpoint
        # files recover directly) — the record cap is its only volume
        # bound, and files past it are left unread, not just unbuilt.
        from unittest.mock import patch
        for i in range(4):
            self.write_checkpoint(f"u{i}.json", f"g{i}.py:f", "vulnerable")
        with patch("packages.openant.recovery.RECOVERED_RECORD_CAP", 2):
            with self.assertLogs("raptor", level="WARNING") as logs:
                recovered = recover_dropped_verdicts(
                    self.scan_dir, _pipeline([]))
        self.assertEqual(len(recovered), 2)
        self.assertTrue(any("recovery record cap" in m
                            for m in logs.output))


class TestFailOpenAndIdentity(_ScanDirCase):

    def test_missing_scan_dir_returns_nothing(self):
        self.assertEqual(
            recover_dropped_verdicts(self.scan_dir / "absent",
                                     _pipeline([])), [])

    def test_non_dict_pipeline_output_returns_nothing(self):
        self.assertEqual(recover_dropped_verdicts(self.scan_dir, None), [])
        self.assertEqual(
            recover_dropped_verdicts(self.scan_dir, ["not", "dict"]), [])

    def test_recovery_is_deterministic_across_invocations(self):
        # Resume interaction: a resumed run re-reads the SAME per-run
        # artifacts (the seeding copies prior checkpoints into the new
        # run's scan dir; upstream regenerates results/pipeline_output
        # over the union), so each dropped unit recovers exactly once
        # per run — and the identity-keyed finding_id makes cross-run
        # merged views collapse a re-recovered unit instead of
        # double-counting it.
        self.write_json("results.json", _results_doc(
            [_row(CALLER), _row(CALLEE)]))
        self.write_call_graph({CALLEE: [CALLER]})
        pipeline = _pipeline([_finding_for(CALLER)], deduplicated=1)
        first = recover_dropped_verdicts(self.scan_dir, pipeline)
        second = recover_dropped_verdicts(self.scan_dir, pipeline)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        self.assertNotIn(":index", first[0]["finding_id"])

    def test_seeded_checkpoints_with_findings_do_not_double_recover(self):
        # The resume seeder copies the prior run's analyze checkpoints
        # into the new scan dir; once the resumed scan's report carries
        # the unit, the checkpoint's presence must not resurrect it.
        self.write_checkpoint("seeded.json", CALLER, "vulnerable")
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([_finding_for(CALLER)]))
        self.assertEqual(recovered, [])

    def test_same_function_name_in_other_file_does_not_mask_recovery(self):
        # Identity is the FULL route_key: a kept finding for a
        # same-named function in a DIFFERENT file must not read as
        # "this unit is present" and silently withhold the recovery.
        twin = "app/other.py:run_query"  # same function part as CALLEE
        self.write_json("results.json", _results_doc(
            [_row(CALLER), _row(CALLEE), _row(twin, cwe=78)]))
        self.write_call_graph({CALLEE: [CALLER]})
        recovered = recover_dropped_verdicts(
            self.scan_dir,
            _pipeline([_finding_for(CALLER), _finding_for(twin)],
                      deduplicated=1))
        self.assertEqual([r["metadata"]["route_key"] for r in recovered],
                         [CALLEE])

    def test_over_cap_route_key_id_carries_hash_suffix(self):
        long_key = "p.py:" + "f" * 400
        self.write_checkpoint("long.json", long_key, "vulnerable")
        recovered = recover_dropped_verdicts(self.scan_dir, _pipeline([]))
        self.assertEqual(len(recovered), 1)
        fid = recovered[0]["finding_id"]
        self.assertTrue(fid.startswith("openant-recovered:"))
        # capped + injective: 12-hex disambiguator on truncation
        self.assertRegex(fid, r":[0-9a-f]{12}$")

    def test_hostile_route_key_yields_printable_injective_id(self):
        # finding_id is an identifier (logs, jsonl, report headings) —
        # control/format characters from a hostile-repo symbol name are
        # neutralised, with a hash of the full key restoring
        # injectivity so two keys differing only in a control run
        # cannot collide.
        k1 = "ev\x1bil.py:fn"
        k2 = "ev\x07il.py:fn"
        self.write_checkpoint("a.json", k1, "vulnerable")
        self.write_checkpoint("b.json", k2, "vulnerable")
        recovered = recover_dropped_verdicts(self.scan_dir, _pipeline([]))
        ids = [r["finding_id"] for r in recovered]
        self.assertEqual(len(set(ids)), 2)
        for fid in ids:
            self.assertTrue(all(ch.isprintable() for ch in fid))
            self.assertRegex(fid, r":[0-9a-f]{12}$")

    def test_stored_file_field_is_capped(self):
        long_key = ("F" * 3000) + ":func"
        self.write_checkpoint("long.json", long_key, "vulnerable")
        recovered = recover_dropped_verdicts(self.scan_dir, _pipeline([]))
        self.assertEqual(len(recovered), 1)
        self.assertLessEqual(len(recovered[0]["file"]), 500)

    def test_internal_failure_degrades_to_nothing_loudly(self):
        # The fail-open wrapper is the contract: ANY internal raise
        # (including the serializability self-check) becomes zero
        # records + a warning, never an escaped exception that could
        # void the translator's findings at the shared artifact write.
        from unittest.mock import patch
        with patch("packages.openant.recovery._recover",
                   side_effect=ValueError("boom")):
            with self.assertLogs("raptor", level="WARNING") as logs:
                recovered = recover_dropped_verdicts(
                    self.scan_dir, _pipeline([]))
        self.assertEqual(recovered, [])
        self.assertTrue(any("recovering" in m.lower() for m in logs.output))

    def test_recovered_record_joins_sarif_dedup(self):
        # A SARIF finding covering the same (file, CWE) makes the
        # recovered candidate redundant through the SAME dedup gate as
        # any OpenAnt finding — no special-casing, no double report.
        self.write_checkpoint("u.json", CALLEE, "vulnerable")
        recovered = recover_dropped_verdicts(self.scan_dir, _pipeline([]))
        sarif = [{"file": "app/db.py", "cwe_id": "CWE-89", "tool": "codeql"}]
        merged, dropped = deduplicate_with_sarif(recovered, sarif)
        self.assertEqual(dropped, 1)
        self.assertEqual([f["tool"] for f in merged], ["codeql"])

    def test_untrusted_field_shapes_are_coerced_and_capped(self):
        row = _row(CALLEE)
        row["reasoning"] = "A" * 100_000
        row["cwe_name"] = {"not": "a string"}
        row["confidence"] = True  # bool is not a confidence
        self.write_json("results.json", _results_doc([_row(CALLER), row]))
        self.write_call_graph({CALLEE: [CALLER]})
        recovered = recover_dropped_verdicts(
            self.scan_dir, _pipeline([_finding_for(CALLER)], deduplicated=1))
        self.assertEqual(len(recovered), 1)
        rec = recovered[0]
        self.assertLessEqual(len(rec["message"]), 4000)
        self.assertEqual(rec["metadata"]["vuln_name"], "")
        self.assertNotIn("confidence", rec["metadata"])


if __name__ == "__main__":
    unittest.main()
