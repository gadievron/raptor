"""Tests for AFL crash → SMT-seed exact-lineage attribution."""

from __future__ import annotations

import json
from pathlib import Path

from packages.fuzzing.crash_attribution import (
    AttributionSummary,
    CrashAttribution,
    _instance_for_crash,
    _parse_orig,
    _parse_srcs,
    _root_orig_seeds,
    attribute_crashes,
    load_seed_provenance,
    manifest_path_for_run,
)
from packages.fuzzing.crash_collector import Crash
from packages.fuzzing.smt_seed import MANIFEST_NAME, SEED_DIR_NAME


def _mk_afl_tree(tmp_path: Path, queue_names: list[str], crash_names: list[str]):
    """Materialise an AFL output layout: <afl>/main/{queue,crashes}."""
    afl = tmp_path / "afl_out"
    queue = afl / "main" / "queue"
    crashes = afl / "main" / "crashes"
    queue.mkdir(parents=True)
    crashes.mkdir(parents=True)
    for name in queue_names:
        (queue / name).write_bytes(b"q")
    crash_files = []
    for name in crash_names:
        p = crashes / name
        p.write_bytes(b"c")
        crash_files.append(p)
    return afl, crash_files


def _mk_manifest(tmp_path: Path, seeds: list[dict]) -> Path:
    seed_dir = tmp_path / SEED_DIR_NAME
    seed_dir.mkdir(parents=True, exist_ok=True)
    manifest = seed_dir / MANIFEST_NAME
    manifest.write_text(json.dumps({"seeds": seeds}), encoding="utf-8")
    return manifest


def _crash(path: Path) -> Crash:
    return Crash(crash_id=path.name.split(",")[0].split(":")[1],
                 input_file=path, signal="06")


# Filename shapes verified live on afl-fuzz++4.33c.
_ORIG_A = "id:000000,time:0,execs:0,orig:smt_000_buf_len_len16"
_ORIG_B = "id:000001,time:0,execs:0,orig:plain_seed"


class TestNameParsing:
    def test_srcs_single(self):
        assert _parse_srcs("id:000003,sig:06,src:000002,op:havoc,rep:2") == ["000002"]

    def test_srcs_splice(self):
        assert _parse_srcs("id:000009,src:000002+000005,op:splice") == [
            "000002", "000005",
        ]

    def test_srcs_absent(self):
        assert _parse_srcs(_ORIG_A) == []

    def test_orig(self):
        assert _parse_orig(_ORIG_A) == "smt_000_buf_len_len16"
        assert _parse_orig("id:000002,src:000000,op:havoc,rep:2") is None


def _local_only(index):
    """Adapt a single-instance queue index to the per-instance lookup."""
    return lambda inst: index if inst == "main" else {}


class TestChainWalk:
    def test_direct_child_of_seed(self):
        index = {"000000": _ORIG_A}
        roots = _root_orig_seeds(
            "id:000000,sig:06,src:000000,op:havoc", "main",
            _local_only(index))
        assert roots == {"smt_000_buf_len_len16"}

    def test_multi_hop_chain(self):
        index = {
            "000000": _ORIG_A,
            "000002": "id:000002,src:000000,time:2,execs:26,op:havoc,rep:2",
            "000005": "id:000005,src:000002,op:havoc,rep:1",
        }
        roots = _root_orig_seeds(
            "id:000001,sig:11,src:000005,op:havoc", "main",
            _local_only(index))
        assert roots == {"smt_000_buf_len_len16"}

    def test_splice_converging_to_one_seed(self):
        index = {
            "000000": _ORIG_A,
            "000002": "id:000002,src:000000,op:havoc,rep:2",
            "000003": "id:000003,src:000000,op:havoc,rep:1",
        }
        roots = _root_orig_seeds(
            "id:000004,sig:06,src:000002+000003,op:splice", "main",
            _local_only(index))
        assert roots == {"smt_000_buf_len_len16"}

    def test_splice_across_two_seeds_yields_both_roots(self):
        index = {
            "000000": _ORIG_A,
            "000001": _ORIG_B,
            "000002": "id:000002,src:000000,op:havoc,rep:2",
            "000003": "id:000003,src:000001,op:havoc,rep:1",
        }
        roots = _root_orig_seeds(
            "id:000004,sig:06,src:000002+000003,op:splice", "main",
            _local_only(index))
        assert roots == {"smt_000_buf_len_len16", "plain_seed"}

    def test_missing_queue_entry_breaks_chain(self):
        assert _root_orig_seeds(
            "id:000000,sig:06,src:000042,op:havoc", "main",
            _local_only({})) is None

    def test_no_src_on_crash_is_unattributable(self):
        assert _root_orig_seeds(
            _ORIG_A, "main", _local_only({"000000": _ORIG_A})) is None

    def test_cycle_terminates_unattributed(self):
        index = {
            "000001": "id:000001,src:000002,op:havoc",
            "000002": "id:000002,src:000001,op:havoc",
        }
        assert _root_orig_seeds(
            "id:000000,sig:06,src:000001", "main",
            _local_only(index)) is None

    def test_sync_entry_resolves_in_source_instance_queue(self):
        # An imported queue entry's src id belongs to the NAMED source
        # instance. The local queue also holds a same-numbered entry
        # rooted at a different seed — resolving locally would stamp
        # that wrong root.
        indexes = {
            "main": {"000000": _ORIG_A},
            "secondary1": {
                "000000": _ORIG_B,
                "000001": "id:000001,sync:main,src:000000",
            },
        }
        roots = _root_orig_seeds(
            "id:000002,sig:11,src:000001", "secondary1",
            lambda inst: indexes.get(inst, {}))
        assert roots == {"smt_000_buf_len_len16"}

    def test_sync_to_unknown_instance_is_unattributable(self):
        # Prefer unattributed over wrong: an import from an instance
        # whose queue we cannot see breaks the chain.
        indexes = {
            "secondary1": {
                "000000": _ORIG_B,
                "000001": "id:000001,sync:ghost,src:000000",
            },
        }
        roots = _root_orig_seeds(
            "id:000002,sig:11,src:000001", "secondary1",
            lambda inst: indexes.get(inst, {}))
        assert roots is None


class TestInstanceResolution:
    def test_normal_layout(self, tmp_path):
        afl, files = _mk_afl_tree(tmp_path, [], ["id:000000,sig:06,src:000000"])
        instance, out = _instance_for_crash(files[0])
        assert instance == "main"
        assert out == afl

    def test_merged_layout_suffix(self, tmp_path):
        merged = tmp_path / "afl_out" / "merged_crashes"
        merged.mkdir(parents=True)
        p = merged / "id:000000,sig:06,src:000000,instance:sec1"
        p.write_bytes(b"c")
        instance, out = _instance_for_crash(p)
        assert instance == "sec1"
        assert out == tmp_path / "afl_out"

    def test_unrecognised_layout_is_none(self, tmp_path):
        p = tmp_path / "id:000000,sig:06"
        p.write_bytes(b"c")
        assert _instance_for_crash(p) is None


class TestAttributeCrashes:
    _SEED_ENTRY = {
        "seed": "smt_000_buf_len_len16",
        "origin_id": "F-001",
        "source_file": "attack-paths.json",
        "variable": "buf_len",
        "value": 16,
    }

    def test_end_to_end_attribution(self, tmp_path):
        afl, files = _mk_afl_tree(
            tmp_path,
            [_ORIG_A, "id:000002,src:000000,op:havoc,rep:2"],
            ["id:000000,sig:06,src:000002,op:havoc,rep:1"],
        )
        manifest = _mk_manifest(tmp_path, [self._SEED_ENTRY])
        summary = attribute_crashes([_crash(files[0])], manifest)
        assert summary.total_crashes == 1
        assert summary.unattributed == 0
        att = summary.attributed["000000"]
        assert att.origin_id == "F-001"
        assert att.seed_name == "smt_000_buf_len_len16"
        assert summary.by_finding() == {"F-001": ["000000"]}

    def test_non_smt_seed_root_is_unattributed(self, tmp_path):
        afl, files = _mk_afl_tree(
            tmp_path, [_ORIG_B], ["id:000000,sig:06,src:000001,op:havoc"],
        )
        manifest = _mk_manifest(tmp_path, [self._SEED_ENTRY])
        summary = attribute_crashes([_crash(files[0])], manifest)
        assert not summary.attributed
        assert summary.unattributed == 1

    def test_two_seed_splice_is_unattributed(self, tmp_path):
        afl, files = _mk_afl_tree(
            tmp_path,
            [_ORIG_A, _ORIG_B],
            ["id:000000,sig:06,src:000000+000001,op:splice"],
        )
        manifest = _mk_manifest(tmp_path, [self._SEED_ENTRY])
        summary = attribute_crashes([_crash(files[0])], manifest)
        assert not summary.attributed
        assert summary.unattributed == 1

    def test_missing_manifest_leaves_all_unattributed(self, tmp_path):
        afl, files = _mk_afl_tree(
            tmp_path, [_ORIG_A], ["id:000000,sig:06,src:000000"],
        )
        summary = attribute_crashes(
            [_crash(files[0])], tmp_path / "nope" / MANIFEST_NAME,
        )
        assert not summary.attributed
        assert summary.unattributed == 1

    def test_malformed_manifest_is_soft(self, tmp_path):
        afl, files = _mk_afl_tree(
            tmp_path, [_ORIG_A], ["id:000000,sig:06,src:000000"],
        )
        seed_dir = tmp_path / SEED_DIR_NAME
        seed_dir.mkdir()
        (seed_dir / MANIFEST_NAME).write_text("{not json", encoding="utf-8")
        summary = attribute_crashes(
            [_crash(files[0])], seed_dir / MANIFEST_NAME,
        )
        assert not summary.attributed
        assert summary.unattributed == 1


class TestProvenanceLoading:
    def test_manifest_path_for_run(self, tmp_path):
        assert manifest_path_for_run(tmp_path) == (
            tmp_path / SEED_DIR_NAME / MANIFEST_NAME
        )

    def test_load_ignores_entries_without_seed(self, tmp_path):
        manifest = _mk_manifest(
            tmp_path,
            [{"origin_id": "F-9"}, {"seed": "s1", "origin_id": "F-1"}],
        )
        prov = load_seed_provenance(manifest)
        assert list(prov) == ["s1"]


class TestWitnessStamping:
    def test_attribution_rides_outcome_detail(self, tmp_path):
        from packages.fuzzing.witness_adapter import witness_from_crash

        crash_file = tmp_path / "id:000000,sig:06,src:000002"
        crash_file.write_bytes(b"\xff\xff")
        crash = _crash(crash_file)
        att = CrashAttribution(
            crash_id="000000",
            seed_name="smt_000_buf_len_len16",
            origin_id="F-001",
            source_file="attack-paths.json",
        )
        witness, data = witness_from_crash(crash, smt_attribution=att)
        assert witness.outcome_detail["finding_id"] == "F-001"
        assert witness.outcome_detail["smt_seed"] == "smt_000_buf_len_len16"
        assert witness.outcome_detail["smt_attribution"] == "exact-lineage"

    def test_no_attribution_keeps_legacy_detail(self, tmp_path):
        from packages.fuzzing.witness_adapter import witness_from_crash

        crash_file = tmp_path / "id:000001,sig:11,src:000003"
        crash_file.write_bytes(b"\x00")
        witness, _ = witness_from_crash(_crash(crash_file))
        assert "finding_id" not in witness.outcome_detail
        assert "smt_seed" not in witness.outcome_detail

    def test_verified_outcome_projection_carries_finding(self, tmp_path):
        from core.labeled_attempts.view import from_witness
        from packages.fuzzing.witness_adapter import witness_from_crash

        crash_file = tmp_path / "id:000000,sig:06,src:000002"
        crash_file.write_bytes(b"\xff")
        att = CrashAttribution(
            crash_id="000000", seed_name="s", origin_id="F-777",
            source_file="autonomous_analysis_report.json",
        )
        witness, _ = witness_from_crash(_crash(crash_file), smt_attribution=att)
        outcome = from_witness(witness)
        assert outcome.finding_id == "F-777"
        assert outcome.oracle.value == "fuzzer"
        assert outcome.status.value == "verified"


class TestSummaryShape:
    def test_by_finding_groups_and_sorts(self):
        summary = AttributionSummary(total_crashes=3)
        for cid, origin in (("2", "F-B"), ("1", "F-A"), ("3", "F-A")):
            summary.attributed[cid] = CrashAttribution(
                crash_id=cid, seed_name="s", origin_id=origin, source_file="f",
            )
        assert summary.by_finding() == {"F-A": ["1", "3"], "F-B": ["2"]}


class TestDuplicateCrashIds:
    """Consumers key attribution lookups by crash_id — when two
    attributable crashes arrive sharing one id, every attribution for
    that id is dropped (a wrong finding-confirmation is worse than
    none). Unique ids are unaffected."""

    _SEED_ENTRY = TestAttributeCrashes._SEED_ENTRY

    def _two_crashes_same_id(self, tmp_path: Path):
        afl, files = _mk_afl_tree(
            tmp_path,
            [_ORIG_A],
            [
                "id:000000,sig:06,src:000000,op:havoc",
                "id:000000,sig:11,src:000000,op:arith8",
            ],
        )
        manifest = _mk_manifest(tmp_path, [self._SEED_ENTRY])
        crashes = []
        for f in files:
            crash = _crash(f)
            crash.crash_id = "000000"  # degenerate: no instance suffix
            crashes.append(crash)
        return crashes, manifest

    def test_colliding_ids_drop_all_attributions(self, tmp_path):
        # The second crash filename must differ, but AFL never writes
        # two id:000000 crashes in ONE instance dir — this simulates a
        # foreign merge without instance suffixes.
        crashes, manifest = self._two_crashes_same_id(tmp_path)
        summary = attribute_crashes(crashes, manifest)
        assert summary.attributed == {}
        assert summary.unattributed == 2

    def test_three_way_collision_stays_dropped(self, tmp_path):
        crashes, manifest = self._two_crashes_same_id(tmp_path)
        third = crashes[0].input_file.parent / (
            "id:000000,sig:04,src:000000,op:flip1")
        third.write_bytes(b"c")
        crash3 = _crash(third)
        crash3.crash_id = "000000"
        summary = attribute_crashes([*crashes, crash3], manifest)
        assert summary.attributed == {}
        assert summary.unattributed == 3

    def test_unique_ids_both_attributed(self, tmp_path):
        afl, files = _mk_afl_tree(
            tmp_path,
            [_ORIG_A],
            [
                "id:000000,sig:06,src:000000,op:havoc",
                "id:000001,sig:11,src:000000,op:arith8",
            ],
        )
        manifest = _mk_manifest(tmp_path, [self._SEED_ENTRY])
        summary = attribute_crashes([_crash(f) for f in files], manifest)
        assert sorted(summary.attributed) == ["000000", "000001"]
        assert summary.unattributed == 0
