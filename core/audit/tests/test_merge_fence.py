"""Merge-lane receipt fence: receipt loading, lookup, hold semantics.

The fence's engagement through the ensemble Phase-2 quality
suppression (and the rxkad merge-clean regression) is tested where
that consumer lives, in
``core/audit/corpus/tests/test_run_corpus.py``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from core.audit import merge_fence
from core.audit.refutation import DOMINANCE_VERDICT

RXKAD_KEY = "net/rxrpc/rxkad.c:rxkad_verify_packet_2"

RECEIPT_HIT = {
    "file": "net/rxrpc/rxkad.c",
    "function": "rxkad_verify_packet_2",
    "detector": "cocci:scatterlist_frag_undersize",
    "line": 510,
    "description": (
        "scatterlist sized from bare fragment count at line 510 but "
        "mapped via skb_to_sgvec at line 520"
    ),
}

LEAK_HIT = {
    "file": "net/rxrpc/rxkad.c",
    "function": "rxkad_verify_packet_2",
    "detector": "cocci:resource_leak_err",
    "line": 516,
    "description": "'sg' allocated at line 514 not freed on error path",
}


def _lane(
    tmp_path: Path,
    name: str,
    mech: dict[str, Any],
    suppressions: list[dict[str, Any]] | None = None,
) -> Path:
    lane = tmp_path / name
    grp = lane / "repo"
    grp.mkdir(parents=True)
    (grp / "mechanical-findings.json").write_text(json.dumps(mech))
    if suppressions:
        with (grp / "suppressions.jsonl").open("w") as fh:
            for rec in suppressions:
                fh.write(json.dumps(rec) + "\n")
    return lane


def _dominance_row(receipt: str = "cocci:scatterlist_frag_undersize"):
    return {
        "finding_id": f"audit-refutation:{RXKAD_KEY}:487",
        "rule_id": "audit:receipt-floor-dominance",
        "file_path": "net/rxrpc/rxkad.c",
        "function": "rxkad_verify_packet_2",
        "line": 487,
        "verdict": DOMINANCE_VERDICT,
        "reason": "proof-grade refuter dominates the receipt",
        "dropped": False,
        "stage": "refutation-floor",
        "floor_gate": "anti_self_refutation",
        "refuter_gate": "input_bound_t0",
        "refuter_grade": "proof",
        "receipt": receipt,
    }


class TestLoadStandingReceipts:
    def test_floor_family_receipt_indexed(self, tmp_path):
        lane = _lane(tmp_path, "sec", {RXKAD_KEY: [RECEIPT_HIT]})
        index = merge_fence.load_standing_receipts([lane])
        assert list(index) == ["repo"]
        assert list(index["repo"]) == [RXKAD_KEY]
        assert index["repo"][RXKAD_KEY][0]["detector"] == (
            "cocci:scatterlist_frag_undersize"
        )
        assert index["repo"][RXKAD_KEY][0]["line"] == 510

    def test_non_floor_detectors_ignored(self, tmp_path):
        lane = _lane(tmp_path, "sec", {
            RXKAD_KEY: [LEAK_HIT],
            "net/rxrpc/rxkad.c:rxkad_secure_packet": [
                {"file": "net/rxrpc/rxkad.c",
                 "function": "rxkad_secure_packet",
                 "detector": "ops_struct", "line": 340},
                {"file": "net/rxrpc/rxkad.c",
                 "function": "rxkad_secure_packet",
                 "detector": "callsite_deviation", "line": 382},
            ],
        })
        assert merge_fence.load_standing_receipts([lane]) == {}

    def test_family_agnostic_across_floor_classes(self, tmp_path):
        # Any family the anti-self-refutation floor consumes counts,
        # not just the OOB scatterlist class.
        lane = _lane(tmp_path, "sec", {
            "fs/super.c:sget": [{
                "file": "fs/super.c", "function": "sget",
                "detector": "cocci:uninitialized_return", "line": 840,
            }],
        })
        index = merge_fence.load_standing_receipts([lane])
        assert "fs/super.c:sget" in index["repo"]

    def test_dominance_row_refutes_receipt(self, tmp_path):
        lane = _lane(
            tmp_path, "sec", {RXKAD_KEY: [RECEIPT_HIT]},
            suppressions=[_dominance_row()],
        )
        assert merge_fence.load_standing_receipts([lane]) == {}

    def test_dominance_for_other_receipt_leaves_standing(self, tmp_path):
        lane = _lane(
            tmp_path, "sec", {RXKAD_KEY: [RECEIPT_HIT]},
            suppressions=[_dominance_row("cocci:uninitialized_return")],
        )
        index = merge_fence.load_standing_receipts([lane])
        assert RXKAD_KEY in index["repo"]

    def test_cross_lane_dominance_refutes(self, tmp_path):
        # Receipt standing in one lane, refuted (with record) in the
        # other: the refutation is mechanical and lifts the fence.
        sec = _lane(tmp_path, "sec", {RXKAD_KEY: [RECEIPT_HIT]})
        bf = _lane(tmp_path, "bf", {}, suppressions=[_dominance_row()])
        assert merge_fence.load_standing_receipts([sec, bf]) == {}

    def test_receipts_deduped_across_lanes(self, tmp_path):
        sec = _lane(tmp_path, "sec", {RXKAD_KEY: [RECEIPT_HIT]})
        bf = _lane(tmp_path, "bf", {RXKAD_KEY: [RECEIPT_HIT]})
        index = merge_fence.load_standing_receipts([sec, bf])
        assert len(index["repo"][RXKAD_KEY]) == 1

    def test_malformed_line_value_degrades(self, tmp_path):
        # Best-effort contract: an unhashable line value in a hit
        # must not abort the run post-spend.
        hit = dict(RECEIPT_HIT)
        hit["line"] = [1, 2]
        lane = _lane(tmp_path, "sec", {RXKAD_KEY: [hit]})
        index = merge_fence.load_standing_receipts([lane])
        assert index["repo"][RXKAD_KEY][0]["line"] == 0

    def test_per_group_dir_scopes_to_dirname(self, tmp_path):
        # A caller handing the per-group audit dir itself (instead of
        # the lane root): the artifact sits directly under the root,
        # and the root's dirname IS the repo key — receipts must stay
        # matchable for repo-carrying rows.
        grp = tmp_path / "linux-kernel"
        grp.mkdir()
        (grp / "mechanical-findings.json").write_text(
            json.dumps({RXKAD_KEY: [RECEIPT_HIT]}),
        )
        index = merge_fence.load_standing_receipts([grp])
        assert list(index) == ["linux-kernel"]
        assert merge_fence.standing_receipts_for(
            index, RXKAD_KEY, repo="linux-kernel",
        )
        assert merge_fence.standing_receipts_for(
            index, RXKAD_KEY, repo="moby",
        ) == []

    def test_missing_dirs_and_artifacts_are_empty(self, tmp_path):
        assert merge_fence.load_standing_receipts(
            [tmp_path / "nope"],
        ) == {}
        empty = tmp_path / "empty"
        empty.mkdir()
        assert merge_fence.load_standing_receipts([empty]) == {}


class TestStandingReceiptsFor:
    def _index(self):
        return {"linux-kernel": {
            RXKAD_KEY: [dict(RECEIPT_HIT)],
            "src/database/sql/sql.go:Scan": [{
                "file": "src/database/sql/sql.go", "function": "Scan",
                "detector": "cocci:uninitialized_return", "line": 1,
            }],
        }}

    def test_exact_key(self):
        assert merge_fence.standing_receipts_for(self._index(), RXKAD_KEY)

    def test_line_suffixed_key(self):
        assert merge_fence.standing_receipts_for(
            self._index(), RXKAD_KEY + ":487",
        )

    def test_receiver_qualified_key(self):
        assert merge_fence.standing_receipts_for(
            self._index(), "src/database/sql/sql.go:Rows.Scan",
        )

    def test_no_match(self):
        assert merge_fence.standing_receipts_for(
            self._index(), "net/ipv4/esp4.c:esp_output_tail",
        ) == []

    def test_empty_index(self):
        assert merge_fence.standing_receipts_for(None, RXKAD_KEY) == []
        assert merge_fence.standing_receipts_for({}, RXKAD_KEY) == []

    def test_repo_scoping(self):
        # A receipt from one fixture repo must not hold a same-keyed
        # function of another repo in the same multi-repo run.
        index = self._index()
        assert merge_fence.standing_receipts_for(
            index, RXKAD_KEY, repo="linux-kernel",
        )
        assert merge_fence.standing_receipts_for(
            index, RXKAD_KEY, repo="moby",
        ) == []

    def test_repoless_row_unique_group_matches(self):
        # Legacy checkpoint rows carry no repo: match only when
        # exactly one group resolves the key.
        index = self._index()
        assert merge_fence.standing_receipts_for(index, RXKAD_KEY)
        index["moby"] = {RXKAD_KEY: [dict(RECEIPT_HIT)]}
        assert merge_fence.standing_receipts_for(index, RXKAD_KEY) == []

    def test_line_suffix_twins_ambiguous(self):
        # Two same-name line-suffixed rows reduce to one stripped
        # key; a single receipt on it cannot be attributed to either.
        index = {"g": {"a.c:foo": [dict(RECEIPT_HIT)]}}
        amb = frozenset({"a.c:foo"})
        assert merge_fence.standing_receipts_for(
            index, "a.c:foo:12", repo="g", ambiguous_bare_keys=amb,
        ) == []
        assert merge_fence.standing_receipts_for(
            index, "a.c:foo:99", repo="g", ambiguous_bare_keys=amb,
        ) == []
        # The exact (unsuffixed) id still matches — attribution is
        # exact there.
        assert merge_fence.standing_receipts_for(
            index, "a.c:foo", repo="g", ambiguous_bare_keys=amb,
        )

    def test_ambiguous_bare_key_fallback_skipped(self):
        # The artifact keys receipts by bare method name; when two
        # reviewed functions share it, the receipt cannot be
        # attributed to one receiver — no fallback, no hold.
        index = self._index()
        amb = frozenset({"src/database/sql/sql.go:Scan"})
        assert merge_fence.standing_receipts_for(
            index, "src/database/sql/sql.go:Rows.Scan",
            ambiguous_bare_keys=amb,
        ) == []
        assert merge_fence.standing_receipts_for(
            index, "src/database/sql/sql.go:NullString.Scan",
            ambiguous_bare_keys=amb,
        ) == []
        # Exact (unqualified) keys are unaffected by the guard.
        assert merge_fence.standing_receipts_for(
            index, "src/database/sql/sql.go:Scan",
            ambiguous_bare_keys=amb,
        )

    def test_bare_key_forms(self):
        assert merge_fence.bare_key("a.go:Rows.Scan:12") == "a.go:Scan"
        assert merge_fence.bare_key("a.go:Rows.Scan") == "a.go:Scan"
        assert merge_fence.bare_key("a.c:fn:7") == "a.c:fn"
        assert merge_fence.bare_key("a.c:fn") == "a.c:fn"


class TestHoldCleanMint:
    def _row(self, **over):
        row = {
            "function_id": RXKAD_KEY,
            "actual": "suspicious",
            "phase2_classification": "quality_finding",
        }
        row.update(over)
        return row

    def test_hold_keeps_grade_and_records(self, tmp_path):
        row = self._row()
        merge_fence.hold_clean_mint(row, [dict(RECEIPT_HIT)], tmp_path)
        assert row["actual"] == "suspicious"
        assert row["merge_fence"] == "receipt_stands"
        assert row["merge_fence_receipts"] == [
            "cocci:scatterlist_frag_undersize",
        ]
        sink = tmp_path / "suppressions.jsonl"
        recs = [json.loads(ln) for ln in sink.read_text().splitlines()]
        assert len(recs) == 1
        rec = recs[0]
        assert rec["verdict"] == merge_fence.MERGE_FENCE_VERDICT
        assert rec["dropped"] is False
        assert rec["function"] == "rxkad_verify_packet_2"
        assert rec["file_path"] == "net/rxrpc/rxkad.c"
        assert rec["line"] == 510
        assert rec["stage"] == "ensemble-merge"
        assert rec["held_status"] == "suspicious"
        assert rec["receipts"] == ["cocci:scatterlist_frag_undersize"]

    def test_hold_never_lowers_a_finding(self, tmp_path):
        row = self._row(actual="finding")
        merge_fence.hold_clean_mint(row, [dict(RECEIPT_HIT)], tmp_path)
        assert row["actual"] == "finding"

    def test_non_ascii_function_id_verifies(self, tmp_path, caplog):
        # append_jsonl writes non-ASCII ids as \uXXXX escapes; the
        # verification must parse, not substring-probe, or every
        # successful non-ASCII hold logs a lost-record warning.
        row = self._row(function_id="net/a.c:обработчик")
        with caplog.at_level(logging.WARNING, "core.audit.merge_fence"):
            merge_fence.hold_clean_mint(row, [dict(RECEIPT_HIT)], tmp_path)
        assert not any(
            "fence still holds" in r.message for r in caplog.records
        )

    def test_stale_same_id_row_does_not_verify(self, tmp_path, caplog):
        # A fence row from an earlier resume segment carries the same
        # finding_id; only THIS invocation's nonce satisfies
        # verification, so a genuinely lost write is still reported.
        import json as _json

        stale = {
            "finding_id": f"audit-merge-fence:{RXKAD_KEY}",
            "verdict": merge_fence.MERGE_FENCE_VERDICT,
            "record_nonce": "0" * 16,
            "dropped": False,
        }
        sink = tmp_path / "suppressions.jsonl"
        sink.write_text(_json.dumps(stale) + "\n")
        row = self._row()
        with caplog.at_level(logging.WARNING, "core.audit.merge_fence"):
            # Force the chokepoint write itself to be lost.
            import core.analysis.reach_chokepoint as rc
            orig = rc.record_suppression
            try:
                rc.record_suppression = lambda *a, **k: None
                merge_fence.hold_clean_mint(
                    row, [dict(RECEIPT_HIT)], tmp_path,
                )
            finally:
                rc.record_suppression = orig
        assert row["actual"] == "suspicious"
        assert any(
            "fence still holds" in r.message for r in caplog.records
        )

    def test_record_failure_holds_and_logs(self, tmp_path, caplog):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        row = self._row()
        with caplog.at_level(logging.WARNING, "core.audit.merge_fence"):
            merge_fence.hold_clean_mint(
                row, [dict(RECEIPT_HIT)], blocker,
            )
        assert row["actual"] == "suspicious"
        assert row["merge_fence"] == "receipt_stands"
        assert any(
            "fence still holds" in r.message for r in caplog.records
        )

    def test_no_record_dir_holds_and_logs(self, caplog):
        row = self._row()
        with caplog.at_level(logging.WARNING, "core.audit.merge_fence"):
            merge_fence.hold_clean_mint(row, [dict(RECEIPT_HIT)], None)
        assert row["actual"] == "suspicious"
        assert any(
            "fence still holds" in r.message for r in caplog.records
        )
