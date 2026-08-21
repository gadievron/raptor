"""Tests for SMT-witness → AFL seed/dictionary synthesis."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from packages.fuzzing.smt_seed import (
    MANIFEST_NAME,
    MAX_WITNESSES,
    SEED_LEN_CAP,
    WitnessRecord,
    collect_witnesses,
    merge_witness_dict,
    synthesize_from_run_dir,
    synthesize_seeds,
)


def _record(model, anon=None, origin="F-001", source="attack-paths.json"):
    return WitnessRecord(
        source_file=source, origin_id=origin, model=model,
        anon_var_map=anon or {},
    )


class TestLengthRule:
    def test_length_like_name_produces_exact_size_seed(self, tmp_path):
        manifest = synthesize_seeds([_record({"buf_len": 32})], tmp_path)
        entries = [s for s in manifest["seeds"] if s["rule"] == "length"]
        assert len(entries) == 1
        seed = tmp_path / entries[0]["seed"]
        assert seed.stat().st_size == 32
        assert entries[0]["clamped"] is False

    def test_decoded_strlen_label_is_length_like(self, tmp_path):
        manifest = synthesize_seeds(
            [_record({"_anon_0": 16}, anon={"_anon_0": "strlen(argv[1])"})],
            tmp_path,
        )
        entries = [s for s in manifest["seeds"] if s["rule"] == "length"]
        assert len(entries) == 1
        assert (tmp_path / entries[0]["seed"]).stat().st_size == 16

    def test_clamp_recorded_never_silent(self, tmp_path):
        manifest = synthesize_seeds(
            [_record({"size": SEED_LEN_CAP + 5})], tmp_path,
        )
        entries = [s for s in manifest["seeds"] if s["rule"] == "length"]
        assert entries[0]["clamped"] is True
        assert (tmp_path / entries[0]["seed"]).stat().st_size == SEED_LEN_CAP

    def test_non_positive_length_skipped_with_reason(self, tmp_path):
        manifest = synthesize_seeds([_record({"count": 0})], tmp_path)
        assert not [s for s in manifest["seeds"] if s["rule"] == "length"]
        assert any("non-positive" in s["reason"] for s in manifest["skipped"])

    def test_plain_variable_is_not_length_like(self, tmp_path):
        manifest = synthesize_seeds([_record({"offset": 64})], tmp_path)
        assert not [s for s in manifest["seeds"] if s["rule"] == "length"]


class TestMagicValueRule:
    def test_small_value_encodes_4_byte_le(self, tmp_path):
        manifest = synthesize_seeds([_record({"magic": 0xDEAD})], tmp_path)
        raw = [s for s in manifest["seeds"] if s["rule"] == "magic-value"]
        assert (tmp_path / raw[0]["seed"]).read_bytes() == struct.pack("<i", 0xDEAD)

    def test_large_value_encodes_8_byte_le(self, tmp_path):
        value = 2**40
        manifest = synthesize_seeds([_record({"big": value})], tmp_path)
        raw = [s for s in manifest["seeds"] if s["rule"] == "magic-value"]
        assert (tmp_path / raw[0]["seed"]).read_bytes() == struct.pack("<q", value)

    def test_negative_value_twos_complement(self, tmp_path):
        manifest = synthesize_seeds([_record({"delta": -1})], tmp_path)
        raw = [s for s in manifest["seeds"] if s["rule"] == "magic-value"]
        assert (tmp_path / raw[0]["seed"]).read_bytes() == struct.pack("<i", -1)

    def test_out_of_range_value_skipped(self, tmp_path):
        manifest = synthesize_seeds([_record({"huge": 2**70})], tmp_path)
        assert manifest["seed_count"] == 0
        assert any("64-bit" in s["reason"] for s in manifest["skipped"])

    def test_non_integer_value_skipped(self, tmp_path):
        manifest = synthesize_seeds([_record({"weird": "abc"})], tmp_path)
        assert manifest["seed_count"] == 0
        assert any("non-integer" in s["reason"] for s in manifest["skipped"])


class TestDictionary:
    def test_dict_file_format_and_escaping(self, tmp_path):
        synthesize_seeds([_record({"magic": 0xDEAD})], tmp_path)
        content = (tmp_path / "smt-witness.dict").read_text()
        line = content.strip()
        name, _, value = line.partition("=")
        assert name.startswith("smt_magic_")
        assert value == '"\\xad\\xde\\x00\\x00"'

    def test_no_dict_file_when_no_entries(self, tmp_path):
        manifest = synthesize_seeds([_record({"huge": 2**70})], tmp_path)
        assert manifest["dict_entries"] == 0
        assert not (tmp_path / "smt-witness.dict").exists()


class TestManifestProvenance:
    def test_every_seed_names_its_finding_and_variable(self, tmp_path):
        manifest = synthesize_seeds(
            [_record({"buf_len": 8}, origin="AP-007")], tmp_path,
        )
        for entry in manifest["seeds"]:
            assert entry["origin_id"] == "AP-007"
            assert entry["variable"] == "buf_len"
            assert entry["value"] == 8
            assert entry["source_file"] == "attack-paths.json"
        on_disk = json.loads((tmp_path / MANIFEST_NAME).read_text())
        assert on_disk["seed_count"] == manifest["seed_count"]


class TestCollectWitnesses:
    def test_reads_both_producer_shapes(self, tmp_path):
        (tmp_path / "attack-paths.json").write_text(json.dumps([
            {"id": "AP-001", "smt_model": {"len": 4}},
            {"id": "AP-002"},  # no witness — ignored
        ]))
        (tmp_path / "autonomous_analysis_report.json").write_text(json.dumps({
            "results": [
                {"finding_id": "F-9",
                 "smt_witness": {"model": {"_anon_0": 32},
                                 "anon_var_map": {"_anon_0": "strlen(s)"}}},
                {"finding_id": "F-10"},  # no witness — ignored
            ],
        }))
        records, skipped = collect_witnesses(tmp_path)
        assert {r.origin_id for r in records} == {"AP-001", "F-9"}
        assert not skipped
        anon = next(r for r in records if r.origin_id == "F-9")
        assert anon.anon_var_map == {"_anon_0": "strlen(s)"}

    def test_malformed_file_counted_not_crashed(self, tmp_path):
        (tmp_path / "attack-paths.json").write_text("{not json")
        records, skipped = collect_witnesses(tmp_path)
        assert not records
        assert any("unreadable" in s["reason"] for s in skipped)

    def test_empty_dir_reports_reason(self, tmp_path):
        records, skipped = collect_witnesses(tmp_path)
        assert not records
        assert any("found" in s["reason"] for s in skipped)

    def test_witness_cap_recorded(self, tmp_path):
        paths = [{"id": f"AP-{i}", "smt_model": {"len": 4}}
                 for i in range(MAX_WITNESSES + 10)]
        (tmp_path / "attack-paths.json").write_text(json.dumps(paths))
        records, skipped = collect_witnesses(tmp_path)
        assert len(records) == MAX_WITNESSES
        assert any("witness cap" in s["reason"] for s in skipped)


class TestMergeWitnessDict:
    def test_appends_and_dedups(self, tmp_path):
        seed_dir = tmp_path / "smt-seeds"
        seed_dir.mkdir()
        (seed_dir / "smt-witness.dict").write_text(
            'smt_a="\\x01"\nsmt_b="\\x02"\n')
        (tmp_path / "fuzz.dict").write_text('audit_tok="X"\nsmt_a="\\x01"\n')
        target = merge_witness_dict(seed_dir, tmp_path)
        lines = target.read_text().splitlines()
        assert lines.count('smt_a="\\x01"') == 1
        assert 'audit_tok="X"' in lines
        assert 'smt_b="\\x02"' in lines

    def test_no_witness_dict_is_noop(self, tmp_path):
        seed_dir = tmp_path / "smt-seeds"
        seed_dir.mkdir()
        assert merge_witness_dict(seed_dir, tmp_path) is None
        assert not (tmp_path / "fuzz.dict").exists()


class TestEndToEnd:
    def test_dir_scan_to_artifacts(self, tmp_path):
        source = tmp_path / "validate_run"
        source.mkdir()
        (source / "attack-paths.json").write_text(json.dumps([
            {"id": "AP-001", "smt_model": {"buf_len": 24, "magic": 0x41}},
        ]))
        run_out = tmp_path / "fuzz_run"
        run_out.mkdir()
        manifest = synthesize_from_run_dir(source, run_out)
        seed_dir = run_out / "smt-seeds"
        assert manifest["seed_count"] >= 2  # length seed + raw seeds
        assert (seed_dir / MANIFEST_NAME).is_file()
        assert manifest["merged_dict"] == str(run_out / "fuzz.dict")
        assert (run_out / "fuzz.dict").is_file()

    def test_flag_is_plumbed(self):
        repo_root = Path(__file__).resolve().parents[3]
        source = (repo_root / "raptor_fuzzing.py").read_text(encoding="utf-8")
        assert '"--from-smt-witness"' in source
        assert "synthesize_from_run_dir" in source
