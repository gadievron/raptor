"""Tests for SMT-witness → AFL seed/dictionary synthesis."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from packages.fuzzing.smt_seed import (
    MANIFEST_NAME,
    MAX_WITNESSES,
    SEED_DIR_NAME,
    SEED_LEN_CAP,
    WitnessRecord,
    collect_witnesses,
    ensure_real_seed_dir,
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

    def test_filename_collision_recorded_not_silent(self, tmp_path):
        # Two variables in one record sanitizing to the same token
        # collide on the raw-seed filename; the drop must appear in
        # the manifest (no-silent-truncation contract). '$x' and '#x'
        # both sanitize to the same token.
        manifest = synthesize_seeds(
            [_record({"$x": 7, "#x": 9})], tmp_path)
        collisions = [
            s for s in manifest["skipped"]
            if s["reason"] == "seed filename collision"
        ]
        assert len(collisions) == 1
        assert collisions[0]["seed"]
        # Direction two: the first write itself is recorded as a seed.
        raws = [s for s in manifest["seeds"] if s["rule"] == "magic-value"]
        assert len(raws) == 1

    def test_non_integer_value_skipped(self, tmp_path):
        manifest = synthesize_seeds([_record({"weird": "abc"})], tmp_path)
        assert manifest["seed_count"] == 0
        assert any("non-integer" in s["reason"] for s in manifest["skipped"])


class TestPlantedSymlinkDefense:
    """The seed dir sits in the reused, target-writable run dir: a
    planted DANGLING symlink passes ``exists() == False``, so the old
    exists()-gated ``write_bytes`` created the attacker-chosen target.
    The exclusive create refuses and records the drop instead."""

    def test_dangling_symlink_at_seed_name_refused_and_recorded(
        self, tmp_path,
    ):
        victim = tmp_path / "victim"
        (tmp_path / "smt_000_magic_raw").symlink_to(victim)

        manifest = synthesize_seeds([_record({"magic": 0xDEAD})], tmp_path)

        assert not victim.exists()
        assert all(s["seed"] != "smt_000_magic_raw"
                   for s in manifest["seeds"])
        assert any(s.get("seed") == "smt_000_magic_raw"
                   for s in manifest["skipped"])

    def test_dict_write_replaces_planted_symlink(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_text("do not touch")
        (tmp_path / "smt-witness.dict").symlink_to(victim)

        synthesize_seeds([_record({"magic": 0xDEAD})], tmp_path)

        dict_path = tmp_path / "smt-witness.dict"
        assert victim.read_text() == "do not touch"
        assert not dict_path.is_symlink()
        assert "smt_magic" in dict_path.read_text()

    def test_planted_witness_dict_directory_contained(
        self, tmp_path, caplog,
    ):
        """A directory planted at the predictable smt-witness.dict
        name is the one non-regular shape ``os.replace`` cannot swap —
        the dictionary write raised ``IsADirectoryError`` up through
        the bare /fuzz CLI handler. Contained: one warning, seeds and
        manifest still produced, no dictionary file recorded, plant
        left in place (never removed)."""
        plant = tmp_path / "smt-witness.dict"
        plant.mkdir()
        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            manifest = synthesize_seeds([_record({"magic": 0x41})], tmp_path)
        assert manifest["dict_file"] is None
        assert manifest["seed_count"] >= 1
        assert plant.is_dir()  # never removed
        assert any("witness dictionary not written" in r.getMessage()
                   for r in caplog.records)

    def test_merge_replaces_planted_dangling_symlink(self, tmp_path):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "smt-witness.dict").write_text('k="v"\n')
        victim = tmp_path / "victim"
        (tmp_path / "fuzz.dict").symlink_to(victim)

        target = merge_witness_dict(seed_dir, tmp_path)

        assert target == tmp_path / "fuzz.dict"
        assert not victim.exists()
        assert not target.is_symlink()
        assert target.read_text() == 'k="v"\n'


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

    def test_planted_fuzz_dict_symlink_never_read(self, tmp_path, caplog):
        """The merge runs in the unsandboxed parent over a run dir the
        previous campaign's sandboxed target could write. A planted
        symlink at the predictable fuzz.dict name must be refused
        loudly, never read through — Path.read_text followed it and
        copied operator-readable file content into the merged dict
        the NEXT campaign's sandboxed target can read."""
        seed_dir = tmp_path / "smt-seeds"
        seed_dir.mkdir()
        (seed_dir / "smt-witness.dict").write_text('smt_a="\\x01"\n')
        secret = tmp_path / "operator-secret"
        secret.write_text("SECRET-LINE\n")
        (tmp_path / "fuzz.dict").symlink_to(secret)

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            target = merge_witness_dict(seed_dir, tmp_path)

        merged = target.read_text()
        assert "SECRET" not in merged
        assert 'smt_a="\\x01"' in merged
        assert not target.is_symlink()  # plant replaced, not followed
        assert secret.read_text() == "SECRET-LINE\n"  # untouched
        assert any("not a readable regular file" in r.message
                   for r in caplog.records)

    def test_planted_witness_dict_symlink_refuses_merge(self, tmp_path, caplog):
        seed_dir = tmp_path / "smt-seeds"
        seed_dir.mkdir()
        secret = tmp_path / "operator-secret"
        secret.write_text("SECRET-LINE\n")
        (seed_dir / "smt-witness.dict").symlink_to(secret)
        (tmp_path / "fuzz.dict").write_text('audit_tok="X"\n')

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            assert merge_witness_dict(seed_dir, tmp_path) is None

        # No merge happened and nothing leaked.
        assert (tmp_path / "fuzz.dict").read_text() == 'audit_tok="X"\n'
        assert any("refusing witness-dict merge" in r.message
                   for r in caplog.records)

    def test_oversize_fuzz_dict_refused_untouched(self, tmp_path, caplog):
        from packages.fuzzing.smt_seed import MAX_DICT_FILE_CHARS

        seed_dir = tmp_path / "smt-seeds"
        seed_dir.mkdir()
        (seed_dir / "smt-witness.dict").write_text('smt_a="\\x01"\n')
        blob = "a" * (MAX_DICT_FILE_CHARS + 1)
        (tmp_path / "fuzz.dict").write_text(blob)

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            assert merge_witness_dict(seed_dir, tmp_path) is None

        assert (tmp_path / "fuzz.dict").read_text() == blob  # untouched
        assert any("dictionary bound" in r.message for r in caplog.records)

    def test_oversize_witness_dict_refused(self, tmp_path, caplog):
        from packages.fuzzing.smt_seed import MAX_DICT_FILE_CHARS

        seed_dir = tmp_path / "smt-seeds"
        seed_dir.mkdir()
        (seed_dir / "smt-witness.dict").write_text(
            "a" * (MAX_DICT_FILE_CHARS + 1))

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            assert merge_witness_dict(seed_dir, tmp_path) is None

        assert not (tmp_path / "fuzz.dict").exists()
        assert any("dictionary bound" in r.message for r in caplog.records)

    def test_planted_fuzz_dict_directory_refused_not_crashed(
        self, tmp_path, caplog,
    ):
        """A planted DIRECTORY at the predictable fuzz.dict name is the
        one non-regular shape ``os.replace`` cannot swap — the write
        raised ``IsADirectoryError`` up through the CLI. The merge must
        refuse with one warning and skip the write: the directory is a
        target-planted object and removing a whole tree from the
        unsandboxed parent is a destructive step the merge never
        takes."""
        seed_dir = tmp_path / "smt-seeds"
        seed_dir.mkdir()
        (seed_dir / "smt-witness.dict").write_text('smt_a="\\x01"\n')
        plant = tmp_path / "fuzz.dict"
        plant.mkdir()
        (plant / "occupant").write_text("inside\n")

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            assert merge_witness_dict(seed_dir, tmp_path) is None

        # Plant left in place — never removed, never written through.
        assert plant.is_dir()
        assert (plant / "occupant").read_text() == "inside\n"
        # Exactly one loud refusal, and no stray atomic tempfiles.
        refusals = [
            r for r in caplog.records
            if "refusing witness-dict merge" in r.message
        ]
        assert len(refusals) == 1
        assert "directory" in refusals[0].getMessage()
        assert not list(tmp_path.glob(".atomic-*"))

    def test_write_failure_contained_not_crashed(
        self, tmp_path, caplog, monkeypatch,
    ):
        """Re-plant race containment: a directory that appears at
        fuzz.dict between the shape check and the atomic write makes
        ``os.replace`` raise — the merge must warn and skip, never
        propagate out of ``merge_witness_dict``."""
        import packages.fuzzing.smt_seed as smt_seed

        seed_dir = tmp_path / "smt-seeds"
        seed_dir.mkdir()
        (seed_dir / "smt-witness.dict").write_text('smt_a="\\x01"\n')

        def _boom(path, content):
            raise IsADirectoryError(21, "Is a directory", str(path))

        monkeypatch.setattr(smt_seed, "write_text_atomically", _boom)
        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            assert merge_witness_dict(seed_dir, tmp_path) is None
        assert any("merge skipped" in r.getMessage()
                   for r in caplog.records)


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

    def test_planted_fuzz_dict_directory_run_completes(self, tmp_path):
        """CLI-path regression: ``synthesize_from_run_dir`` (bare call
        at raptor_fuzzing's --from-smt-witness handler) must complete —
        seeds and manifest still produced, merge recorded as skipped —
        when a directory squats the fuzz.dict name in the reused run
        dir."""
        source = tmp_path / "validate_run"
        source.mkdir()
        (source / "attack-paths.json").write_text(json.dumps([
            {"id": "AP-001", "smt_model": {"buf_len": 24, "magic": 0x41}},
        ]))
        run_out = tmp_path / "fuzz_run"
        run_out.mkdir()
        (run_out / "fuzz.dict").mkdir()
        manifest = synthesize_from_run_dir(source, run_out)
        assert manifest["seed_count"] >= 2
        assert (run_out / "smt-seeds" / MANIFEST_NAME).is_file()
        assert manifest["merged_dict"] is None
        assert (run_out / "fuzz.dict").is_dir()  # plant left in place

    def test_flag_is_plumbed(self):
        repo_root = Path(__file__).resolve().parents[3]
        source = (repo_root / "raptor_fuzzing.py").read_text(encoding="utf-8")
        assert '"--from-smt-witness"' in source
        assert "synthesize_from_run_dir" in source


class TestLengthPathOverwriteGuard:
    def test_preexisting_length_seed_not_silently_overwritten(
        self, tmp_path,
    ):
        """The magic-value path records a skip when its filename
        already exists; the length path lacked the guard — a
        pre-existing file was overwritten with fill bytes AND listed
        in the manifest, refuting the manifest's no-silent-drop
        promise."""
        victim = tmp_path / "smt_000_buf_len_len16"
        victim.write_text("OPERATOR-CONTENT", encoding="utf-8")
        manifest = synthesize_seeds([_record({"buf_len": 16})], tmp_path)
        assert victim.read_text(encoding="utf-8") == "OPERATOR-CONTENT", (
            "pre-existing file overwritten by the length rule"
        )
        length_seeds = [
            s for s in manifest["seeds"] if s["rule"] == "length"
        ]
        assert length_seeds == []
        assert any(
            sk.get("reason") == "seed filename collision"
            for sk in manifest["skipped"]
        ), "the drop must be recorded, never silent"


def _witness_source(tmp_path):
    source = tmp_path / "validate_run"
    source.mkdir()
    (source / "attack-paths.json").write_text(json.dumps([
        {"id": "AP-001", "smt_model": {"buf_len": 24, "magic": 0x41}},
    ]))
    return source


class TestPlantedSeedDirDefense:
    """Class closure at the flow entry: the smt-seeds NAME itself is
    exactly as predictable as the seed / dict / manifest names inside
    it, and a plant there kills or redirects EVERY artifact at once.
    The old ``mkdir(exist_ok=True)`` crashed on a file or dangling
    symlink (``FileExistsError``) and silently FOLLOWED a symlink to a
    directory (CPython's exist_ok re-check is ``is_dir()``), letting
    the unsandboxed parent write all seeds, the dictionary, and the
    manifest into an attacker-chosen directory — and read the campaign
    corpus back through it."""

    def test_file_at_seed_dir_name_refused_not_crashed(
        self, tmp_path, caplog,
    ):
        source = _witness_source(tmp_path)
        run_out = tmp_path / "fuzz_run"
        run_out.mkdir()
        plant = run_out / SEED_DIR_NAME
        plant.write_text("occupied")

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            manifest = synthesize_from_run_dir(source, run_out)

        assert manifest["seed_dir_refused"]
        assert manifest["seed_count"] == 0
        assert manifest["merged_dict"] is None
        assert plant.read_text() == "occupied"  # left in place
        assert not (run_out / "fuzz.dict").exists()  # merge skipped
        assert any("refusing SMT witness synthesis" in r.getMessage()
                   for r in caplog.records)
        # No-silent-drop contract: the refusal is in the audit trail.
        assert any(s["reason"].startswith("seed dir refused")
                   for s in manifest["skipped"])

    def test_dangling_symlink_at_seed_dir_name_refused(
        self, tmp_path, caplog,
    ):
        """A dangling symlink passes ``exists() == False`` but makes
        ``mkdir(exist_ok=True)`` raise ``FileExistsError`` — the whole
        /fuzz run died on a traceback before any campaign."""
        source = _witness_source(tmp_path)
        run_out = tmp_path / "fuzz_run"
        run_out.mkdir()
        target = run_out / "never-created"
        (run_out / SEED_DIR_NAME).symlink_to(target)

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            manifest = synthesize_from_run_dir(source, run_out)

        assert manifest["seed_dir_refused"]
        assert manifest["seed_count"] == 0
        assert manifest["merged_dict"] is None
        assert (run_out / SEED_DIR_NAME).is_symlink()  # left in place
        assert not target.exists()  # never created through the link
        assert any("refusing SMT witness synthesis" in r.getMessage()
                   for r in caplog.records)

    def test_symlink_to_attacker_dir_refused_nothing_redirected(
        self, tmp_path, caplog,
    ):
        """The strongest member: a symlink to an attacker-chosen
        directory passed the old gate silently, and the unsandboxed
        parent wrote every artifact through it — with ``os.replace``
        CLOBBERING anything named like the manifest in the victim
        directory — then read the campaign corpus back through it.
        The attacker directory must stay untouched."""
        source = _witness_source(tmp_path)
        run_out = tmp_path / "fuzz_run"
        run_out.mkdir()
        attacker = tmp_path / "attacker"
        attacker.mkdir()
        victim = attacker / MANIFEST_NAME
        victim.write_text("victim manifest\n")
        (run_out / SEED_DIR_NAME).symlink_to(attacker)

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            manifest = synthesize_from_run_dir(source, run_out)

        # Attacker dir holds ONLY what the attacker put there — the
        # write-redirect assertion comes first: pre-fix it held the
        # manifest, the dictionary, and every seed.
        assert sorted(p.name for p in attacker.iterdir()) == [MANIFEST_NAME]
        assert victim.read_text() == "victim manifest\n"  # not clobbered
        assert manifest["seed_dir_refused"]
        assert manifest["seed_count"] == 0
        assert manifest["merged_dict"] is None
        assert (run_out / SEED_DIR_NAME).is_symlink()  # left in place
        assert not (run_out / "fuzz.dict").exists()  # no poisoned merge
        assert any("refusing SMT witness synthesis" in r.getMessage()
                   for r in caplog.records)

    def test_guard_direct_route_refuses_all_three_shapes(self, tmp_path):
        """The CLI calls ``ensure_real_seed_dir`` directly BEFORE the
        built-in corpus materialisation — replay the shapes through
        that route too."""
        file_plant = tmp_path / "a" / SEED_DIR_NAME
        file_plant.parent.mkdir()
        file_plant.write_text("x")
        assert ensure_real_seed_dir(file_plant) is not None

        dangling = tmp_path / "b" / SEED_DIR_NAME
        dangling.parent.mkdir()
        dangling.symlink_to(tmp_path / "b" / "gone")
        assert ensure_real_seed_dir(dangling) is not None

        attacker = tmp_path / "attacker"
        attacker.mkdir()
        link = tmp_path / "c" / SEED_DIR_NAME
        link.parent.mkdir()
        link.symlink_to(attacker)
        assert ensure_real_seed_dir(link) is not None
        assert list(attacker.iterdir()) == []

        # Both directions: a fresh name and a pre-existing real
        # directory are accepted.
        clean = tmp_path / "d" / SEED_DIR_NAME
        clean.parent.mkdir()
        assert ensure_real_seed_dir(clean) is None
        assert clean.is_dir() and not clean.is_symlink()
        assert ensure_real_seed_dir(clean) is None  # idempotent

    def test_cli_flow_guards_before_first_write_and_gates_corpus(self):
        """The CLI's --from-smt-witness block writes into seed_dir
        BEFORE synthesize_from_run_dir (built-in corpus), and reads
        the campaign corpus back from it afterwards — both must sit
        behind the same containment verdict."""
        repo_root = Path(__file__).resolve().parents[3]
        source = (repo_root / "raptor_fuzzing.py").read_text(encoding="utf-8")
        guard_at = source.index("ensure_real_seed_dir(seed_dir)")
        builtin_at = source.index("prepare_builtin_seed_corpus(seed_dir")
        assert guard_at < builtin_at, (
            "the seed-dir guard must run before the built-in corpus "
            "materialisation — the first seed-dir write on the flow"
        )
        assert 'manifest.get("seed_dir_refused")' in source, (
            "corpus read-back must gate on the containment verdict"
        )

    def test_clean_and_reused_seed_dir_still_work(self, tmp_path):
        """Direction two of the refusal: a clean run and a re-run over
        the same (real) seed dir must keep producing artifacts."""
        source = _witness_source(tmp_path)
        run_out = tmp_path / "fuzz_run"
        run_out.mkdir()

        manifest = synthesize_from_run_dir(source, run_out)
        assert manifest["seed_dir_refused"] is None
        assert manifest["seed_count"] >= 2
        assert manifest["merged_dict"] == str(run_out / "fuzz.dict")
        assert (run_out / SEED_DIR_NAME / MANIFEST_NAME).is_file()

        # Re-run over the now-existing real dir: accepted, no refusal.
        manifest2 = synthesize_from_run_dir(source, run_out)
        assert manifest2["seed_dir_refused"] is None


class TestPlantedManifestDefense:
    def test_dir_at_manifest_name_contained_run_continues(
        self, tmp_path, caplog,
    ):
        """A directory planted at the predictable manifest name is the
        one shape ``save_json``'s ``os.replace`` cannot swap — the
        ``IsADirectoryError`` used to propagate up through the bare
        /fuzz CLI handler and kill the run (the prior containment
        commit's claim that seeds AND the manifest always survive a
        plant was wrong for exactly this shape). Contained: one
        warning, seeds and dictionary still produced, plant left in
        place, the in-memory manifest still returned."""
        plant = tmp_path / MANIFEST_NAME
        plant.mkdir()
        (plant / "occupant").write_text("inside\n")

        with caplog.at_level("WARNING", logger="packages.fuzzing.smt_seed"):
            manifest = synthesize_seeds([_record({"magic": 0x41})], tmp_path)

        assert manifest["seed_count"] >= 1
        assert (tmp_path / "smt-witness.dict").is_file()  # unaffected
        assert plant.is_dir()  # never removed
        assert (plant / "occupant").read_text() == "inside\n"
        refusals = [r for r in caplog.records
                    if "witness manifest not written" in r.getMessage()]
        assert len(refusals) == 1
        assert not list(tmp_path.glob(".~savejson-*"))  # no stray tmp

    def test_dir_at_manifest_name_e2e_merge_still_happens(self, tmp_path):
        """End-to-end over the CLI's bare-call route: the run must
        complete AND the dictionary merge must still happen — the
        manifest plant costs only the manifest file."""
        source = _witness_source(tmp_path)
        run_out = tmp_path / "fuzz_run"
        run_out.mkdir()
        seed_dir = run_out / SEED_DIR_NAME
        seed_dir.mkdir()
        (seed_dir / MANIFEST_NAME).mkdir()

        manifest = synthesize_from_run_dir(source, run_out)

        assert manifest["seed_count"] >= 2
        assert manifest["seed_dir_refused"] is None
        assert manifest["merged_dict"] == str(run_out / "fuzz.dict")
        assert (run_out / "fuzz.dict").is_file()
        assert (seed_dir / MANIFEST_NAME).is_dir()  # plant left in place


class TestCollectWitnessesShapes:
    def test_list_shaped_analysis_report_recorded_as_skipped(
        self, tmp_path,
    ):
        """A list-shaped autonomous_analysis_report.json must degrade
        to a skip record, not AttributeError out of the .get() walk."""
        (tmp_path / "autonomous_analysis_report.json").write_text(
            '["junk"]', encoding="utf-8",
        )
        records, skipped = collect_witnesses(tmp_path)
        assert records == []
        assert any(
            sk["file"] == "autonomous_analysis_report.json"
            for sk in skipped
        )
