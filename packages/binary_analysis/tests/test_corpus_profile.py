"""Tests for the sample-corpus format profiler.

All corpora are synthetic with known layouts — the assertions check
that the statistics recover the planted structure, that every cap
holds under pathological input, and that hostile filenames stay inert
end-to-end.
"""

from __future__ import annotations

import os
import random
import struct
from pathlib import Path

import pytest

import json

from packages.binary_analysis.corpus_profile import (
    CorpusProfileOptions,
    PROFILE_JSON_NAME,
    PROFILE_REPORT_NAME,
    SEED_DIR_NAME,
    SEED_MANIFEST_SOURCE,
    _Sample,
    _write_seed_bytes,
    _write_seed_minset,
    profile_corpus,
)
from packages.fuzzing.audit_dict import MAX_DICT_BYTES


def _write_layout_corpus(
    corpus: Path,
    count: int = 12,
    *,
    size_delta: int = 0,
    body_base: int = 100,
    body_len_step: int = 16,
    body_random: bool = False,
    name_pattern: str = "C-{i:08d}.sys",
) -> None:
    """Known layout: magic ``SAMP``, u32le size field at offset 4
    (``file_size - size_delta``), enum byte at offset 8 (three
    values), reserved zeros to offset 16, structured or random body.
    """
    corpus.mkdir(parents=True, exist_ok=True)
    rng = random.Random(1234)
    for i in range(count):
        body_len = body_base + i * body_len_step
        if body_random:
            body = rng.randbytes(body_len)
        else:
            body = bytes(rng.randrange(0, 40) for _ in range(body_len))
        total = 16 + body_len
        payload = (
            b"SAMP"
            + struct.pack("<I", total - size_delta)
            + bytes([1 + i % 3])
            + b"\x00" * 7
            + body
        )
        (corpus / name_pattern.format(i=i)).write_bytes(payload)


def _profile(corpus: Path, out: Path, **kwargs) -> dict:
    return profile_corpus(
        CorpusProfileOptions(samples_dir=corpus, out_dir=out, **kwargs),
    )


def _single_family(profile: dict) -> dict:
    assert profile["summary"]["family_count"] == 1, profile["summary"]
    return profile["families"][0]


class TestLayoutRecovery:
    def test_recovers_magic_size_field_and_enum(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus)
        family = _single_family(_profile(corpus, tmp_path / "out"))

        magic = family["fields"][0]
        assert magic["kind"] == "constant"
        assert magic["offset"] == 0
        assert magic["length"] >= 4
        assert magic["value_hex"].startswith(b"SAMP".hex())
        assert magic["classification"] == "magic"
        # Corpus-tier ceiling: full coverage still never reads 1.0.
        assert magic["confidence"] == 0.95

        enum_fields = [f for f in family["fields"] if f["kind"] == "enum_candidate"]
        enum_at_8 = [f for f in enum_fields if f["offset"] == 8]
        assert enum_at_8, enum_fields
        assert enum_at_8[0]["cardinality"] == 3
        assert {v["value_hex"] for v in enum_at_8[0]["values"]} == {"01", "02", "03"}

        best = family["size_field_candidates"][0]
        assert best["offset"] == 4
        assert best["endianness"] == "le"
        assert best["delta_k"] == 0
        assert best["agreement"] == 1.0
        assert best["value_varies"] is True
        assert family["endianness_vote"] == "le"
        # u16/u32 at the same (offset, endianness, delta) deduped —
        # a u32 with a zero high half also matches as u16 and would
        # double-count one piece of evidence.
        keys = [
            (c["offset"], c["endianness"], c["delta_k"])
            for c in family["size_field_candidates"]
        ]
        assert len(keys) == len(set(keys))

    def test_size_field_tolerance_recovers_header_delta(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, size_delta=16)
        family = _single_family(_profile(corpus, tmp_path / "out"))
        deltas = {
            (c["offset"], c["delta_k"]) for c in family["size_field_candidates"]
        }
        assert (4, 16) in deltas

    def test_uniform_sizes_flagged_vacuous(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, body_len_step=0)
        family = _single_family(_profile(corpus, tmp_path / "out"))
        candidates = [
            c for c in family["size_field_candidates"] if c["offset"] == 4
        ]
        assert candidates
        best = candidates[0]
        assert best["value_varies"] is False
        # Agreement is perfect but the cross-check is vacuous — the
        # confidence must say so, not launder it.
        assert best["confidence"] < best["agreement"]
        assert "vacuous" in best["evidence"]
        # Vacuous candidates must not fabricate an endianness vote.
        assert family["endianness_vote"] == "unknown"

    def test_high_entropy_body_flagged_envelope_only(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        # Shannon entropy of an n-byte sample is bounded by log2(n):
        # a "random" body needs roughly 300+ bytes before it can clear
        # the 7.2 bits/byte threshold (the bound bites below ~150 B).
        _write_layout_corpus(corpus, body_random=True, body_base=4096, body_len_step=512)
        out = tmp_path / "out"
        family = _single_family(_profile(corpus, out))
        assert family["entropy"]["classification"] == "high_entropy_body"
        assert "envelope" in family["entropy"]["note"]
        report = (out / PROFILE_REPORT_NAME).read_text(encoding="utf-8")
        assert "high_entropy_body" in report

    def test_structured_body_not_flagged(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus)
        family = _single_family(_profile(corpus, tmp_path / "out"))
        assert family["entropy"]["classification"] == "structured_body"


class TestTlv:
    def test_tlv_detected_on_length_prefixed_records(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        rng = random.Random(7)
        for i in range(10):
            data = b""
            for r in range(5 + i % 4):
                payload = rng.randbytes(rng.randrange(3, 60))
                data += bytes([r % 5]) + struct.pack("<H", len(payload)) + payload
            (corpus / f"rec{i:03d}.tlv").write_bytes(data)
        family = _single_family(_profile(corpus, tmp_path / "out"))
        tlv = family["tlv"]
        assert tlv["likelihood"] >= 0.9
        assert tlv["shape"]["type_size"] == 1
        assert tlv["shape"]["length_size"] == 2
        assert tlv["shape"]["endianness"] == "le"

    def test_tlv_not_claimed_on_random_blobs(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        rng = random.Random(11)
        for i in range(8):
            (corpus / f"blob{i:03d}.bin").write_bytes(rng.randbytes(500 + i * 37))
        family = _single_family(_profile(corpus, tmp_path / "out"))
        assert family["tlv"]["likelihood"] <= 0.5


class TestFamilyGrouping:
    def test_name_template_groups_counter_names(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=6, name_pattern="C-{i:08d}-00000042.sys")
        family = _single_family(_profile(corpus, tmp_path / "out"))
        assert family["sample_count"] == 6
        assert family["name_templates"] == ["a-9-9.a"]

    def test_headerless_family_not_fragmented_by_leading_bytes(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        rng = random.Random(3)
        for i in range(10):
            (corpus / f"rec{i:03d}.raw").write_bytes(rng.randbytes(200))
        profile = _profile(corpus, tmp_path / "out")
        assert profile["summary"]["family_count"] == 1
        assert profile["families"][0]["sample_count"] == 10

    def test_mixed_magic_directory_splits(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(5):
            (corpus / f"a{i}.dat").write_bytes(b"MAGA" + bytes([i]) * 50)
            (corpus / f"b{i}.dat").write_bytes(b"MAGB" + bytes([i]) * 70)
        profile = _profile(corpus, tmp_path / "out")
        assert profile["summary"]["family_count"] == 2
        keys = {f["key"] for f in profile["families"]}
        assert any(k.startswith(b"MAGA".hex()) for k in keys)
        assert any(k.startswith(b"MAGB".hex()) for k in keys)

    def test_family_glob_filters_samples(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        (corpus / "other.bin").write_bytes(b"XXXX" + b"\x00" * 40)
        profile = _profile(corpus, tmp_path / "out", family_glob="*.sys")
        assert profile["summary"]["samples_profiled"] == 4
        assert profile["summary"]["family_count"] == 1


class TestSeedMinset:
    def test_seed_minset_covers_enum_values_and_size_classes(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus)
        out = tmp_path / "out"
        profile = _profile(corpus, out)
        family = _single_family(profile)
        seed_dir = Path(profile["artifacts"]["seed_dir"])
        seeds = sorted(seed_dir.glob("*.bin"))
        assert seeds

        # Coverage property: every observed enum value at offset 8 and
        # every size class in the family appears in >= 1 copied seed.
        seen_enum = set()
        seen_classes = set()
        for seed in seeds:
            data = seed.read_bytes()
            if len(data) > 8:
                seen_enum.add(data[8])
            seen_classes.add(max(len(data), 1).bit_length() - 1)
        assert seen_enum >= {1, 2, 3}
        assert set(family["size_classes"]) <= seen_classes

    def test_seeds_are_copies_never_hard_links(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        source_inodes = {p.stat().st_ino for p in corpus.iterdir()}
        profile = _profile(corpus, tmp_path / "out")
        for seed in Path(profile["artifacts"]["seed_dir"]).glob("*.bin"):
            st = seed.stat()
            assert st.st_nlink == 1
            assert st.st_ino not in source_inodes

    def test_seed_names_are_generated_not_attacker_chosen(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(4):
            (corpus / f"evil\x1b]0;pwn{i}\x07.bin").write_bytes(b"MAGC" + bytes([i]) * 30)
        profile = _profile(corpus, tmp_path / "out")
        for seed in Path(profile["artifacts"]["seed_dir"]).iterdir():
            assert "\x1b" not in seed.name
            assert seed.name == "manifest.json" or seed.suffix == ".bin"

    def test_seed_budget_cap_enforced(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus)
        profile = _profile(
            corpus, tmp_path / "out", seed_budget_bytes=300,
        )
        total = sum(
            p.stat().st_size
            for p in Path(profile["artifacts"]["seed_dir"]).glob("*.bin")
        )
        assert total <= 300
        assert "seed_budget_bytes" in profile["summary"]["caps_hit"]

    def test_seed_dir_foreign_content_refused(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        out = tmp_path / "out"
        foreign = out / SEED_DIR_NAME
        foreign.mkdir(parents=True)
        (foreign / "precious.bin").write_bytes(b"operator data")
        with pytest.raises(ValueError, match="refusing to reset"):
            _profile(corpus, out)
        assert (foreign / "precious.bin").read_bytes() == b"operator data"

    def test_rerun_resets_only_own_seeds(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        out = tmp_path / "out"
        first = _profile(corpus, out)
        second = _profile(corpus, out)
        assert first["artifacts"]["seed_count"] == second["artifacts"]["seed_count"]


class TestDictionary:
    def test_dictionary_entry_cap_and_convention_cap(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        # Wide enum spread across many header offsets: enum-cardinality
        # flooding is exactly what the entry cap bounds.
        corpus.mkdir()
        rng = random.Random(5)
        for i in range(40):
            header = bytes(rng.randrange(0, 12) for _ in range(64))
            (corpus / f"s{i:03d}.dat").write_bytes(b"MAGD" + header + b"\x00" * 100)
        profile = _profile(corpus, tmp_path / "out", max_dict_entries=32)
        assert profile["artifacts"]["dict_entries"] <= 32
        assert "max_dict_entries" in profile["summary"]["caps_hit"]
        dict_path = Path(profile["artifacts"]["fuzz_dict"])
        assert dict_path.stat().st_size <= MAX_DICT_BYTES

    def test_dictionary_contains_magic_token(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus)
        profile = _profile(corpus, tmp_path / "out")
        content = Path(profile["artifacts"]["fuzz_dict"]).read_text(encoding="utf-8")
        assert 'magic="SAMP' in content

    def test_dictionary_merge_preserves_existing_lines(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        out = tmp_path / "out"
        out.mkdir()
        (out / "fuzz.dict").write_text('audit_token="KEEP"\n', encoding="utf-8")
        _profile(corpus, out)
        lines = (out / "fuzz.dict").read_text(encoding="utf-8").splitlines()
        assert lines[0] == 'audit_token="KEEP"'
        assert len(lines) > 1


class TestHostileInput:
    def test_hostile_filename_escaped_end_to_end(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(3):
            (corpus / f"evil\x1b]0;pwn{i}\x07.bin").write_bytes(b"MAGE" + bytes([i]) * 30)
        out = tmp_path / "out"
        profile = _profile(corpus, out)
        for artifact in (out / PROFILE_JSON_NAME, out / PROFILE_REPORT_NAME):
            raw = artifact.read_bytes()
            assert b"\x1b" not in raw
            assert b"\x07" not in raw
        # The escaped form is present (the name is recorded, inertly).
        assert "\\x1b" in (out / PROFILE_JSON_NAME).read_text(encoding="utf-8")
        assert profile["summary"]["samples_profiled"] == 3

    def test_symlinks_and_fifos_skipped(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        (corpus / "link.sys").symlink_to(corpus / "C-00000000.sys")
        os.mkfifo(corpus / "pipe.sys")
        profile = _profile(corpus, tmp_path / "out")
        assert profile["summary"]["samples_profiled"] == 4
        reasons = {s["reason"] for s in profile["summary"]["skipped"]}
        assert "not a readable regular file" in reasons

    def test_derived_from_target_marks_sample_fields(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        profile = _profile(corpus, tmp_path / "out")
        family = _single_family(profile)
        assert family["derived_from_target"] is True
        assert all(f["derived_from_target"] for f in family["fields"])
        assert all(s["derived_from_target"] for s in family["samples"])
        assert profile["provenance"]["tier"] == "corpus_statistic"
        assert family["corroboration"]["status"] == "uncorroborated"


class TestBudgets:
    def test_sample_count_cap(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=10)
        profile = _profile(corpus, tmp_path / "out", max_samples=5)
        assert profile["summary"]["samples_profiled"] == 5
        assert profile["summary"]["samples_seen"] == 10
        assert profile["summary"]["samples_skipped"] == 5
        assert "max_samples" in profile["summary"]["caps_hit"]

    def test_per_sample_byte_cap_survives_huge_file(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=3)
        # Sparse multi-MiB file: only the capped prefix may be read.
        huge = corpus / "huge.sys"
        with huge.open("wb") as fh:
            fh.seek(32 * 1024 * 1024 - 1)
            fh.write(b"\x00")
        profile = _profile(
            corpus, tmp_path / "out", max_bytes_per_sample=64 * 1024,
        )
        assert profile["summary"]["samples_profiled"] == 4
        # Exactly the huge member is cap-truncated, and the profile
        # says so (its entropy/TLV facts cover only the read prefix).
        assert sum(f["truncated_reads"] for f in profile["families"]) == 1

    def test_total_byte_budget_stops_collection(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=10)
        profile = _profile(corpus, tmp_path / "out", total_byte_budget=600)
        assert profile["summary"]["samples_profiled"] < 10
        assert "total_byte_budget" in profile["summary"]["caps_hit"]

    def test_family_cap_records_overflow(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        # 70 singleton families via distinct extensions.
        for i in range(70):
            (corpus / f"f{i}.e{i:02d}").write_bytes(bytes([i]) * 40)
        profile = _profile(corpus, tmp_path / "out")
        assert profile["summary"]["family_count"] <= 64
        assert "max_families" in profile["summary"]["caps_hit"]
        overflow = profile["summary"]["families_over_cap"]
        assert overflow["count"] == 6
        assert 0 < len(overflow["examples"]) <= 64


def _mk_sample(path: Path, rel_name: str, claimed_size: int) -> _Sample:
    return _Sample(
        rel_name=rel_name,
        path=path,
        size=claimed_size,
        header=b"",
        entropy_header=None,
        entropy_body=None,
        truncated_read=False,
    )


def _mk_pick(sample: _Sample, family: str = "F01") -> dict:
    return {
        "family": family,
        "sample": sample,
        "covers": {"size_class": 0, "enum_values": []},
    }


class TestSeedPathHardening:
    def test_write_seed_bytes_refuses_symlink_destination(self, tmp_path: Path) -> None:
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"operator data")
        dest = tmp_path / "F01-001.bin"
        dest.symlink_to(victim)
        reason = _write_seed_bytes(dest, b"attacker steered bytes")
        assert reason is not None
        assert victim.read_bytes() == b"operator data"

    def test_planted_symlink_in_owned_seed_dir_cannot_clobber_victim(
        self, tmp_path: Path,
    ) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"operator data")
        out = tmp_path / "out"
        seed_dir = out / SEED_DIR_NAME
        seed_dir.mkdir(parents=True)
        # A hostile artifact drop: our-source manifest + a symlink
        # squatting on the first deterministic destination name.
        (seed_dir / "manifest.json").write_text(
            json.dumps({"source": SEED_MANIFEST_SOURCE, "seeds": []}),
            encoding="utf-8",
        )
        (seed_dir / "F01-001.bin").symlink_to(victim)
        profile = _profile(corpus, out)
        assert victim.read_bytes() == b"operator data"
        written = seed_dir / "F01-001.bin"
        assert written.is_file() and not written.is_symlink()
        assert profile["artifacts"]["seed_count"] >= 1

    def test_reset_refuses_foreign_subdirectory(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=4)
        out = tmp_path / "out"
        seed_dir = out / SEED_DIR_NAME
        seed_dir.mkdir(parents=True)
        (seed_dir / "manifest.json").write_text(
            json.dumps({"source": SEED_MANIFEST_SOURCE, "seeds": []}),
            encoding="utf-8",
        )
        precious = seed_dir / "nested"
        precious.mkdir()
        (precious / "keep.txt").write_bytes(b"keep me")
        with pytest.raises(ValueError, match="directory"):
            _profile(corpus, out)
        assert (precious / "keep.txt").read_bytes() == b"keep me"

    def test_seed_copy_drops_grown_source(self, tmp_path: Path) -> None:
        source = tmp_path / "sample.bin"
        source.write_bytes(b"A" * 1000)  # grew since the claimed stat
        out = tmp_path / "out"
        out.mkdir()
        options = CorpusProfileOptions(samples_dir=tmp_path, out_dir=out)
        pick = _mk_pick(_mk_sample(source, "sample.bin", claimed_size=10))
        info, caps = _write_seed_minset([pick], options)
        assert info["seed_count"] == 0
        assert "seed_source_grew" in caps
        manifest = json.loads(Path(info["seed_manifest"]).read_text())
        assert any("grew" in (e.get("skipped") or "") for e in manifest["seeds"])
        assert not list(Path(info["seed_dir"]).glob("*.bin"))

    def test_seed_budget_enforced_against_bytes_actually_read(
        self, tmp_path: Path,
    ) -> None:
        a = tmp_path / "a.bin"
        b = tmp_path / "b.bin"
        a.write_bytes(b"A" * 200)
        b.write_bytes(b"B" * 200)
        out = tmp_path / "out"
        out.mkdir()
        options = CorpusProfileOptions(
            samples_dir=tmp_path, out_dir=out, seed_budget_bytes=300,
        )
        picks = [
            _mk_pick(_mk_sample(a, "a.bin", 200)),
            _mk_pick(_mk_sample(b, "b.bin", 200)),
        ]
        info, caps = _write_seed_minset(picks, options)
        assert info["seed_count"] == 1
        assert "seed_budget_bytes" in caps
        total = sum(p.stat().st_size for p in Path(info["seed_dir"]).glob("*.bin"))
        assert total <= 300


class TestMutationMatrix:
    """Boundary fixtures pinning each named constant in both
    directions where the constant has two directions."""

    def _agreement_corpus(self, corpus: Path, corrupt: int) -> None:
        corpus.mkdir()
        rng = random.Random(21)
        for i in range(20):
            body = bytes(rng.randrange(0, 40) for _ in range(100 + i * 16))
            total = 16 + len(body)
            value = total if i >= corrupt else total + 5000  # corrupt first N
            payload = (
                b"SAMP" + struct.pack("<I", value)
                + bytes([1 + i % 3]) + b"\x00" * 7 + body
            )
            (corpus / f"C-{i:08d}.sys").write_bytes(payload)

    def test_size_field_agreement_085_refused(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        self._agreement_corpus(corpus, corrupt=3)  # 17/20 = 0.85 < 0.9
        family = _single_family(_profile(corpus, tmp_path / "out"))
        assert not [
            c for c in family["size_field_candidates"]
            if c["offset"] == 4 and c["delta_k"] == 0
        ]

    def test_size_field_agreement_095_accepted(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        self._agreement_corpus(corpus, corrupt=1)  # 19/20 = 0.95 >= 0.9
        family = _single_family(_profile(corpus, tmp_path / "out"))
        assert [
            c for c in family["size_field_candidates"]
            if c["offset"] == 4 and c["delta_k"] == 0 and c["value_varies"]
        ]

    def test_tlv_constant_zero_corpus_scores_zero(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(8):
            (corpus / f"z{i}.bin").write_bytes(b"\x00" * (200 + i * 40))
        family = _single_family(_profile(corpus, tmp_path / "out"))
        assert family["tlv"]["likelihood"] == 0.0

    def test_high_cardinality_offset_is_variable(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(60):
            payload = b"MAGH" + bytes([i * 4 % 251]) + b"\x00" * 60
            (corpus / f"h{i:03d}.dat").write_bytes(payload)
        family = _single_family(_profile(corpus, tmp_path / "out"))
        covering = [
            f for f in family["fields"]
            if f["offset"] <= 4 < f["offset"] + f["length"]
        ]
        assert covering and covering[0]["kind"] == "variable"

    def test_enum_detected_at_window_edge_and_nothing_beyond(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(12):
            header = bytearray(b"\x55" * 300)
            header[0:4] = b"MAGW"
            header[128] = 1 + i % 3
            (corpus / f"w{i:03d}.dat").write_bytes(bytes(header))
        family = _single_family(_profile(corpus, tmp_path / "out"))
        enum_offsets = [
            f["offset"] for f in family["fields"] if f["kind"] == "enum_candidate"
        ]
        assert 128 in enum_offsets
        assert all(
            f["offset"] + f["length"] <= 256 for f in family["fields"]
        )

    def test_near_uniform_sizes_mint_no_confident_candidates(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        rng = random.Random(31)
        # 38 members of one size + 2 larger: 95% modal agreement at
        # every constant-byte offset — without the value-variance
        # requirement this minted full-confidence size fields and a
        # fabricated endianness vote.
        for i in range(38):
            (corpus / f"u{i:03d}.dat").write_bytes(
                b"MAGU" + b"\x02\x00\x00\x00" + rng.randbytes(504),
            )
        for i in range(2):
            (corpus / f"u9{i:02d}.dat").write_bytes(
                b"MAGU" + b"\x02\x00\x00\x00" + rng.randbytes(796),
            )
        family = _single_family(_profile(corpus, tmp_path / "out"))
        assert all(
            c["confidence"] < 0.5 for c in family["size_field_candidates"]
        )
        assert family["endianness_vote"] == "unknown"

    def test_small_random_family_makes_no_enum_claims(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        rng = random.Random(41)
        for i in range(10):
            (corpus / f"r{i:03d}.raw").write_bytes(rng.randbytes(300 + i * 20))
        profile = _profile(corpus, tmp_path / "out")
        family = _single_family(profile)
        # Ten samples cannot evidence an enum: without the observation
        # floor every varying offset became a "confidence-1.0 enum",
        # flooding fuzz.dict and degenerating the min-set to copy-all.
        assert not [
            f for f in family["fields"] if f["kind"] == "enum_candidate"
        ]
        assert profile["artifacts"]["dict_entries"] == 0
        assert profile["artifacts"]["seed_count"] <= len(family["size_classes"])


class TestTlvHeaderLayouts:
    def test_tlv_after_fixed_header_with_total_size_field(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        rng = random.Random(51)
        # [magic4][u32le total size][records...] — invisible from
        # probe start 0 (the header is not a record); recovered via
        # the size-field-derived start hint (offset + width == 8).
        for i in range(10):
            records = b""
            for r in range(4 + i % 3):
                payload = rng.randbytes(rng.randrange(5, 50))
                records += bytes([r % 4]) + struct.pack("<H", len(payload)) + payload
            total = 8 + len(records)
            (corpus / f"hdr{i:03d}.tlv").write_bytes(
                b"MAGT" + struct.pack("<I", total) + records,
            )
        family = _single_family(_profile(corpus, tmp_path / "out"))
        tlv = family["tlv"]
        assert tlv["likelihood"] >= 0.9
        # Pre-hint behavior scored 0.0: only a header-derived start
        # (end of the leading constant run, or the byte after the
        # size field) can carry the walk — start 0 cannot.
        assert tlv["shape"]["start_offset"] in (4, 8)

    def test_two_sample_corpus_needs_more_length_diversity(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        # Two files, records with only two distinct lengths: a "1.0"
        # earned from two near-constant samples must not score.
        for i in range(2):
            records = b""
            for r in range(6):
                length = 10 if r % 2 else 20
                records += bytes([r % 3]) + struct.pack("<H", length) + b"\xaa" * length
            (corpus / f"two{i}.tlv").write_bytes(records)
        family = _single_family(_profile(corpus, tmp_path / "out"))
        assert family["tlv"]["likelihood"] == 0.0


class TestDictionaryRobustness:
    def test_magic_tokens_survive_enum_flood_at_the_cap(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        rng = random.Random(61)
        # Family A: enum-rich (many claimed values across offsets).
        for i in range(40):
            header = bytes(rng.randrange(0, 8) for _ in range(48))
            (corpus / f"a{i:03d}.aaa").write_bytes(b"MAGA" + header + b"\x00" * 64)
        # Family B: small, magic only.
        for i in range(6):
            (corpus / f"b{i:03d}.bbb").write_bytes(b"MAGB" + b"\x00" * 64)
        profile = _profile(corpus, tmp_path / "out", max_dict_entries=8)
        content = Path(profile["artifacts"]["fuzz_dict"]).read_text(encoding="utf-8")
        # Magic/constant tokens are added for ALL families before any
        # enum token — the flood must not evict the second family's
        # magic at the cap.
        assert 'magic="MAGA' in content
        assert 'magic="MAGB' in content

    def test_oversized_foreign_dict_is_skipped_untouched(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=6)
        out = tmp_path / "out"
        out.mkdir()
        blob = b'x="y"\n' * (MAX_DICT_BYTES // 6 + 10)
        (out / "fuzz.dict").write_bytes(blob)
        profile = _profile(corpus, out)
        assert "dict_merge_skipped_oversized" in profile["summary"]["caps_hit"]
        assert (out / "fuzz.dict").read_bytes() == blob
        assert (out / PROFILE_JSON_NAME).is_file()

    def test_non_utf8_foreign_dict_degrades_not_destroys(self, tmp_path: Path) -> None:
        corpus = tmp_path / "corpus"
        _write_layout_corpus(corpus, count=6)
        out = tmp_path / "out"
        out.mkdir()
        blob = b"\xff\xfe not utf-8 \x80\x81\n"
        (out / "fuzz.dict").write_bytes(blob)
        profile = _profile(corpus, out)
        assert "dict_merge_failed" in profile["summary"]["caps_hit"]
        assert (out / "fuzz.dict").read_bytes() == blob
        assert (out / PROFILE_JSON_NAME).is_file()
        assert profile["artifacts"]["fuzz_dict"] is None
