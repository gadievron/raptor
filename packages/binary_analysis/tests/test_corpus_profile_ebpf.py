"""Tests for the eBPF TLV-value field-classification.

All candidate byte runs are hand-assembled in-test from instruction
encodings (never committed blobs). The external-decoder receipt paths
are exercised hermetically via monkeypatched seams; one host-only test
runs the real sandboxed decoder and skips when no ``llvm-objdump`` is
installed (CI runners may not carry one).
"""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

from packages.binary_analysis import corpus_profile
from packages.binary_analysis.corpus_profile import (
    EBPF_MIN_DISTINCT_INSNS,
    EBPF_MIN_INSNS,
    CorpusProfileOptions,
    _EBPF_EXAMPLE_CAP,
    _EBPF_EXTERNAL_CHECK_CAP,
    _EBPF_OBJDUMP_CANDIDATES,
    _ebpf_decode_check,
    _ebpf_external_agreement,
    _tlv_walk,
    profile_corpus,
)


def _insn(op: int, dst: int = 0, src: int = 0, off: int = 0, imm: int = 0) -> bytes:
    """One hand-assembled 8-byte eBPF instruction (little-endian)."""
    return struct.pack("<BBhi", op, (src << 4) | dst, off, imm)


def _valid_program(*, insns: int = 8, terminated: bool = True) -> bytes:
    """A plausible program: distinct ALU64 movs, one jump, then exit.

    ``insns`` counts logical instructions including the terminator
    slot (which becomes another distinct mov when ``terminated`` is
    False), so both floors (length, distinct) are exercised by count.
    """
    assert insns >= 3
    body = b"".join(
        _insn(0xB7, dst=i % 10, imm=100 + i)  # mov rN, imm — all distinct
        for i in range(insns - 2)
    )
    body += _insn(0x55, dst=0, off=1, imm=0)  # jne r0, 0, +1
    if terminated:
        body += _insn(0x95)  # exit
    else:
        body += _insn(0xB7, dst=0, imm=999)
    return body


def _receipts(value: bytes) -> dict:
    return _ebpf_decode_check(value)["receipts"]


class TestDecodeCheck:
    def test_valid_program_classifies_with_full_receipts(self) -> None:
        result = _ebpf_decode_check(_valid_program())
        assert result["classified"] is True
        assert result["insn_count"] == 8
        assert result["receipts"] == {
            "grid": "aligned",
            "opcodes": "valid",
            "length": "ok",
            "terminator": "present",
            "class_mix": "ok",
            "distinct": "ok",
        }

    def test_lddw_consumes_two_slots_and_counts_once(self) -> None:
        program = (
            _insn(0x18, dst=2, imm=0x55667788)
            + _insn(0x00, imm=0x11223344)  # second slot: high imm only
            + _valid_program()
        )
        result = _ebpf_decode_check(program)
        assert result["classified"] is True
        # 10 slots on disk, 9 logical instructions (lddw pairs).
        assert len(program) // 8 == 10
        assert result["insn_count"] == 9

    def test_lddw_unpaired_at_end_rejected(self) -> None:
        program = _valid_program()[:-8] + _insn(0x18, dst=1, imm=7)
        assert _receipts(program)["opcodes"] == "lddw_unpaired"
        assert _ebpf_decode_check(program)["classified"] is False

    def test_lddw_second_slot_reserved_bits_rejected(self) -> None:
        # Second slot must be zero except the high-immediate bytes:
        # a nonzero opcode, register byte, or offset all reject.
        for second in (
            _insn(0xB7, imm=1),          # nonzero opcode
            _insn(0x00, dst=1, imm=1),   # nonzero register field
            _insn(0x00, off=4, imm=1),   # nonzero offset
        ):
            program = _insn(0x18, dst=2, imm=3) + second + _valid_program()
            assert _receipts(program)["opcodes"] == "lddw_reserved_nonzero"

    def test_register_out_of_range_rejected(self) -> None:
        bad_dst = _insn(0xB7, dst=11, imm=1) + _valid_program()
        bad_src = _insn(0x0F, dst=0, src=11) + _valid_program()
        assert _receipts(bad_dst)["opcodes"] == "register_out_of_range"
        assert _receipts(bad_src)["opcodes"] == "register_out_of_range"

    def test_invalid_opcode_rejected(self) -> None:
        program = _valid_program()[:-8] + _insn(0xFF) + _insn(0x95)
        assert _receipts(program)["opcodes"] == "invalid_opcode"

    def test_exit_reserved_bits_rejected(self) -> None:
        program = _valid_program()[:-8] + _insn(0x95, imm=1)
        assert _receipts(program)["opcodes"] == "exit_reserved_nonzero"

    def test_bswap_width_two_directions(self) -> None:
        # The byte-swap family (to-LE / to-BE / bswap) fixes imm to
        # the swap width: exactly 16 / 32 / 64 are defined encodings.
        for op in (0xD4, 0xDC, 0xD7):
            for width in (16, 32, 64):
                program = _insn(op, dst=1, imm=width) + _valid_program()
                result = _ebpf_decode_check(program)
                assert result["classified"] is True, (hex(op), width)
                assert result["receipts"]["opcodes"] == "valid"
            for imm in (0, 8):
                program = _insn(op, dst=1, imm=imm) + _valid_program()
                receipts = _receipts(program)
                assert receipts["opcodes"] == "bswap_width_invalid", (
                    hex(op), imm,
                )

    def test_terminator_absent_recorded_but_still_classifies(self) -> None:
        result = _ebpf_decode_check(_valid_program(terminated=False))
        assert result["classified"] is True
        assert result["receipts"]["terminator"] == "absent"

    def test_grid_misaligned_and_empty_decline(self) -> None:
        assert _receipts(_valid_program() + b"\x00")["grid"] == "misaligned"
        assert _receipts(b"")["grid"] == "empty"
        assert _ebpf_decode_check(b"")["classified"] is False

    def test_min_insn_floor_two_directions(self) -> None:
        below = _ebpf_decode_check(_valid_program(insns=EBPF_MIN_INSNS - 1))
        at = _ebpf_decode_check(_valid_program(insns=EBPF_MIN_INSNS))
        assert below["classified"] is False
        assert below["receipts"]["length"] == "too_short_to_attest"
        assert at["classified"] is True
        assert at["receipts"]["length"] == "ok"

    def test_distinct_floor_two_directions(self) -> None:
        def program(distinct: int) -> bytes:
            # ``distinct`` total distinct words including jne + exit.
            filler = _insn(0xB7, dst=1, imm=1) * (EBPF_MIN_INSNS - distinct + 1)
            uniques = b"".join(
                _insn(0xB7, dst=2, imm=50 + i) for i in range(distinct - 3)
            )
            return filler + uniques + _insn(0x55, off=1) + _insn(0x95)

        below = _ebpf_decode_check(program(EBPF_MIN_DISTINCT_INSNS - 1))
        at = _ebpf_decode_check(program(EBPF_MIN_DISTINCT_INSNS))
        assert below["classified"] is False
        assert below["receipts"]["distinct"] == "degenerate_run"
        assert at["classified"] is True
        assert at["receipts"]["distinct"] == "ok"

    def test_identical_instruction_fill_does_not_classify(self) -> None:
        # A constant fill decodes as one valid instruction repeated —
        # the historical misdecode the degenerate guard exists for.
        fill = _insn(0x05, off=1) * 16  # ja +1, repeated
        result = _ebpf_decode_check(fill)
        assert result["classified"] is False
        assert result["receipts"]["distinct"] == "degenerate_run"
        assert result["receipts"]["class_mix"] == "single_class"

    def test_single_class_run_declines(self) -> None:
        # Distinct enough, but every instruction is JMP-class.
        jumps = b"".join(_insn(0x05, off=i + 1) for i in range(8)) + _insn(0x95)
        result = _ebpf_decode_check(jumps)
        assert result["classified"] is False
        assert result["receipts"]["distinct"] == "ok"
        assert result["receipts"]["class_mix"] == "single_class"

    def test_utf8_text_does_not_classify(self) -> None:
        text = (
            b"Licensed under the Apache License, Version 2.0; "
            b"you may not use this fi."
        )
        assert len(text) % 8 == 0
        assert _ebpf_decode_check(text)["classified"] is False

    def test_x86_code_does_not_classify(self) -> None:
        # A real x86-64 prologue/epilogue sequence, padded with nops
        # to the 8-byte grid so the opcode-level guards do the work.
        x86 = bytes.fromhex(
            "554889e54883ec20897dec8975e88b45ec0345e88945fc8b45fcc9c3"
            "0f1f440000662e0f1f8400000000000f1f40004889f84829f0c390"
            "0f1f40009090909090"
        )
        assert len(x86) % 8 == 0
        assert _ebpf_decode_check(x86)["classified"] is False

    def test_crafted_printable_ascii_classifies_documented_fp_channel(
        self,
    ) -> None:
        # DOCUMENTED FALSE-POSITIVE CHANNEL (pinned, not endorsed):
        # printable ASCII CAN be crafted so every 8-byte slot is a
        # valid load/store encoding — such text classifies (terminator
        # honestly absent, so family confidence is halved). External
        # cross-check cannot catch this class: the bytes ARE valid BPF
        # encodings, so llvm-objdump agrees. Agreement validates
        # ENCODING VALIDITY, not program intent; the hint-tier guard
        # bounds the cost. Any future tightening that changes this
        # behaviour must change this test deliberately.
        text = (
            b"aa main "  # 0x61 LDXW
            b"bb spin "  # 0x62 STW
            b"cc exec "  # 0x63 STXW
            b"ir loop "  # 0x69 LDXH
            b"js jump "  # 0x6a STH
            b"qq call "  # 0x71 LDXB
            b"rr trap "  # 0x72 STB
            b"yy done "  # 0x79 LDXDW
        )
        assert len(text) == 64
        assert all(32 <= c < 127 for c in text)
        result = _ebpf_decode_check(text)
        assert result["classified"] is True
        assert result["receipts"]["terminator"] == "absent"


class TestWalkSpans:
    def test_spans_recover_planted_record_values(self) -> None:
        payloads = [b"A" * 5, b"B" * 9, b"C" * 3]
        data = b"".join(
            bytes([i]) + struct.pack("<H", len(p)) + p
            for i, p in enumerate(payloads)
        )
        spans: list[tuple[int, int]] = []
        records, _ = _tlv_walk(data, 0, (1, 2, "little", False), spans=spans)
        assert records == len(payloads)
        assert [data[o:o + n] for o, n in spans] == payloads

    def test_spans_exclude_header_when_length_includes_it(self) -> None:
        payloads = [b"x" * 4, b"y" * 7, b"z" * 5]
        data = b"".join(
            bytes([9]) + struct.pack("<H", len(p) + 3) + p for p in payloads
        )
        spans: list[tuple[int, int]] = []
        records, _ = _tlv_walk(data, 0, (1, 2, "little", True), spans=spans)
        assert records == len(payloads)
        assert [data[o:o + n] for o, n in spans] == payloads


def _write_ebpf_tlv_corpus(corpus: Path, *, count: int = 4) -> None:
    """TLV files (type=1B, len=2B LE) whose values are eBPF programs.

    Record lengths vary across records (the walk demands length
    diversity) by varying the instruction count per program.
    """
    corpus.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        data = b""
        for r in range(3):
            program = _valid_program(insns=EBPF_MIN_INSNS + r + (i % 2))
            data += bytes([r]) + struct.pack("<H", len(program)) + program
        (corpus / f"chan{i:03d}.bin").write_bytes(data)


def _profile(corpus: Path, out: Path) -> dict:
    return profile_corpus(CorpusProfileOptions(samples_dir=corpus, out_dir=out))


def _family_classification(profile: dict) -> dict:
    assert profile["summary"]["family_count"] == 1, profile["summary"]
    return profile["families"][0]["tlv"]["value_classification"]


class TestFamilyClassification:
    def test_ebpf_valued_tlv_family_gets_hint_label(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(corpus_profile, "_find_bpf_objdump", lambda: None)
        _write_ebpf_tlv_corpus(tmp_path / "corpus")
        profile = _profile(tmp_path / "corpus", tmp_path / "out")
        classification = _family_classification(profile)
        assert classification["label"] == "ebpf_instruction_run"
        assert classification["tier"] == "hint"
        assert "never a verdict" in classification["note"]
        assert classification["records_classified"] == classification["records_checked"]
        assert classification["records_checked"] >= 3
        assert 0.0 < classification["confidence"] <= 0.95
        assert classification["derived_from_target"] is True
        # Honest degradation: label emitted, receipt says no decoder.
        assert classification["external_decoder"]["status"] == "unavailable"
        assert classification["external_decoder"]["tool"] is None
        for example in classification["classified_examples"]:
            assert example["derived_from_target"] is True
            assert example["receipts"]["opcodes"] == "valid"
        counts = classification["receipt_counts"]
        assert counts["opcodes=valid"] == classification["records_checked"]

    def test_non_ebpf_tlv_family_gets_no_label(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(corpus_profile, "_find_bpf_objdump", lambda: None)
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        import random

        rng = random.Random(7)
        for i in range(6):
            data = b""
            for r in range(5):
                payload = rng.randbytes(rng.randrange(3, 60))
                data += bytes([r]) + struct.pack("<H", len(payload)) + payload
            (corpus / f"rec{i:03d}.tlv").write_bytes(data)
        profile = _profile(corpus, tmp_path / "out")
        classification = _family_classification(profile)
        assert classification["label"] is None
        assert classification["records_classified"] == 0
        assert classification["confidence"] == 0.0
        # Decline receipts still land — honesty about why not.
        assert classification["records_checked"] > 0
        assert classification["receipt_counts"]

    def test_no_tlv_shape_means_no_classification_block(
        self, tmp_path: Path,
    ) -> None:
        # Constant-zero files: every shape reads a zero length field
        # (zero-advance), so no walk ever succeeds and no shape wins.
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(6):
            (corpus / f"blob{i:03d}.bin").write_bytes(b"\x00" * (400 + i * 37))
        profile = _profile(corpus, tmp_path / "out")
        assert profile["summary"]["family_count"] == 1
        tlv = profile["families"][0]["tlv"]
        assert tlv["shape"] is None
        assert tlv["value_classification"] is None

    def test_terminator_less_family_confidence_halved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(corpus_profile, "_find_bpf_objdump", lambda: None)
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(4):
            data = b""
            for r in range(3):
                program = _valid_program(
                    insns=EBPF_MIN_INSNS + r + (i % 2), terminated=False,
                )
                data += bytes([r]) + struct.pack("<H", len(program)) + program
            (corpus / f"frag{i:03d}.bin").write_bytes(data)
        classification = _family_classification(
            _profile(corpus, tmp_path / "out"),
        )
        assert classification["label"] == "ebpf_instruction_run"
        assert classification["terminator_present"] == 0
        # All records classify, but with no BPF_EXIT anywhere the
        # confidence is halved (1.0 -> 0.5), never full-weight.
        assert classification["confidence"] == 0.5

    def test_crafted_printable_tlv_family_pins_fp_channel(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # End-to-end pin of the documented printable-ASCII FP channel
        # (see the decode-level pin above): a TLV corpus of crafted
        # text earns the hint label at HALVED confidence (terminator
        # absent everywhere). Pinned so future tightening surfaces as
        # a deliberate test change, never silent drift.
        monkeypatch.setattr(corpus_profile, "_find_bpf_objdump", lambda: None)
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        words = [
            b"main", b"spin", b"exec", b"loop", b"jump", b"call",
            b"trap", b"done", b"read", b"send", b"recv", b"stop",
        ]
        opcodes = (0x61, 0x62, 0x63, 0x69, 0x71, 0x79)  # printable ld/st
        for i in range(6):
            data = b""
            for r in range(3 + i % 2):
                n_slots = 8 + (r + i) % 3
                value = b"".join(
                    bytes([opcodes[(r + k) % len(opcodes)]])
                    + b"a "
                    + words[(r + k) % len(words)]
                    + b" "
                    for k in range(n_slots)
                )
                assert len(value) == n_slots * 8
                assert all(32 <= c < 127 for c in value)
                data += bytes([r]) + struct.pack("<H", len(value)) + value
            (corpus / f"log{i:03d}.txt").write_bytes(data)
        classification = _family_classification(
            _profile(corpus, tmp_path / "out"),
        )
        assert classification["label"] == "ebpf_instruction_run"
        assert classification["terminator_present"] == 0
        assert classification["confidence"] == 0.5

    def test_classified_examples_bounded_by_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(corpus_profile, "_find_bpf_objdump", lambda: None)
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(4):
            data = b""
            for r in range(_EBPF_EXAMPLE_CAP + 4):
                program = _valid_program(insns=EBPF_MIN_INSNS + r % 3 + (i % 2))
                data += bytes([r]) + struct.pack("<H", len(program)) + program
            (corpus / f"many{i:03d}.bin").write_bytes(data)
        classification = _family_classification(
            _profile(corpus, tmp_path / "out"),
        )
        assert classification["records_classified"] > _EBPF_EXAMPLE_CAP
        assert len(classification["classified_examples"]) == _EBPF_EXAMPLE_CAP

    def test_report_renders_hint_tier_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(corpus_profile, "_find_bpf_objdump", lambda: None)
        _write_ebpf_tlv_corpus(tmp_path / "corpus")
        profile = _profile(tmp_path / "corpus", tmp_path / "out")
        report = Path(profile["artifacts"]["report"]).read_text(encoding="utf-8")
        assert "TLV value classification: ebpf_instruction_run" in report
        assert "hint-tier routing evidence" in report
        assert "never a verdict" in report


def _fake_objdump_output(lines: int, *, unknown: bool = False) -> str:
    rows = [
        f"       {i}:\tb7 00 00 00 01 00 00 00\tr0 = 0x1" for i in range(lines)
    ]
    if unknown and rows:
        rows[-1] = f"       {lines - 1}:\tff 00 00 00 00 00 00 00\t<unknown>"
    return (
        "candidate.o:\tfile format elf64-bpf\n\n"
        "Disassembly of section .text:\n\n"
        "0000000000000000 <.text>:\n" + "\n".join(rows) + "\n"
    )


class TestExternalDecoder:
    def test_agree_when_counts_match_and_no_unknown(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            corpus_profile, "_find_bpf_objdump", lambda: "/usr/bin/llvm-objdump",
        )
        monkeypatch.setattr(
            corpus_profile, "_run_bpf_objdump",
            lambda tool, code: _fake_objdump_output(8),
        )
        receipt = _ebpf_external_agreement([(_valid_program(), 8)])
        assert receipt["status"] == "agree"
        assert receipt["checked"] == 1
        assert receipt["agreed"] == 1
        assert receipt["tool"] == "llvm-objdump"

    def test_disagree_on_unknown_marker(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            corpus_profile, "_find_bpf_objdump", lambda: "/usr/bin/llvm-objdump",
        )
        monkeypatch.setattr(
            corpus_profile, "_run_bpf_objdump",
            lambda tool, code: _fake_objdump_output(8, unknown=True),
        )
        receipt = _ebpf_external_agreement([(_valid_program(), 8)])
        assert receipt["status"] == "disagree"
        assert receipt["disagreed"] == 1

    def test_disagree_on_instruction_count_mismatch(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            corpus_profile, "_find_bpf_objdump", lambda: "/usr/bin/llvm-objdump",
        )
        monkeypatch.setattr(
            corpus_profile, "_run_bpf_objdump",
            lambda tool, code: _fake_objdump_output(5),
        )
        receipt = _ebpf_external_agreement([(_valid_program(), 8)])
        assert receipt["status"] == "disagree"

    def test_execution_failure_degrades_to_unavailable(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            corpus_profile, "_find_bpf_objdump", lambda: "/usr/bin/llvm-objdump",
        )
        monkeypatch.setattr(
            corpus_profile, "_run_bpf_objdump", lambda tool, code: None,
        )
        receipt = _ebpf_external_agreement([(_valid_program(), 8)])
        assert receipt["status"] == "unavailable"
        assert receipt["execution_failed"] == 1
        assert receipt["detail"] == "decoder execution failed"

    def test_no_tool_is_unavailable_without_execution(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(corpus_profile, "_find_bpf_objdump", lambda: None)

        def _boom(tool: str, code: bytes) -> str:
            raise AssertionError("must not execute without a tool")

        monkeypatch.setattr(corpus_profile, "_run_bpf_objdump", _boom)
        receipt = _ebpf_external_agreement([(_valid_program(), 8)])
        assert receipt["status"] == "unavailable"
        assert receipt["tool"] is None

    def test_cross_check_bounded_by_cap(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    ) -> None:
        calls: list[bytes] = []

        def _fake_run(tool: str, code: bytes) -> str:
            calls.append(code)
            insns = len(code) // 8
            return _fake_objdump_output(insns)

        monkeypatch.setattr(
            corpus_profile, "_find_bpf_objdump", lambda: "/usr/bin/llvm-objdump",
        )
        monkeypatch.setattr(corpus_profile, "_run_bpf_objdump", _fake_run)
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        for i in range(4):
            data = b""
            for r in range(_EBPF_EXTERNAL_CHECK_CAP + 4):
                program = _valid_program(insns=EBPF_MIN_INSNS + r % 3 + (i % 2))
                data += bytes([r]) + struct.pack("<H", len(program)) + program
            (corpus / f"cap{i:03d}.bin").write_bytes(data)
        classification = _family_classification(
            _profile(corpus, tmp_path / "out"),
        )
        assert classification["records_classified"] > _EBPF_EXTERNAL_CHECK_CAP
        assert len(calls) == _EBPF_EXTERNAL_CHECK_CAP
        assert classification["external_decoder"]["checked"] == _EBPF_EXTERNAL_CHECK_CAP
        assert classification["external_decoder"]["status"] == "agree"

    @pytest.mark.skipif(
        not any(shutil.which(name) for name in _EBPF_OBJDUMP_CANDIDATES),
        reason="no llvm-objdump on this host",
    )
    def test_real_decoder_agrees_on_hand_assembled_program(self) -> None:
        program = (
            _insn(0x18, dst=2, imm=0x55667788)
            + _insn(0x00, imm=0x11223344)
            + _valid_program()
        )
        check = _ebpf_decode_check(program)
        assert check["classified"] is True
        receipt = _ebpf_external_agreement([(program, check["insn_count"])])
        assert receipt["status"] == "agree", receipt
