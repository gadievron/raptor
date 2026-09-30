"""Tests for packages.ghidra.ebpf_probe and the bridge capability stamp.

Unit tests are fully hermetic (captured llvm-objdump / dump-script
samples, synthetic decode maps). Live tests are skip-gated with named
reasons: the toolchain leg needs clang + llvm-objdump with BPF
support; the full-probe leg additionally needs a Ghidra install with
the eBPF processor module and is marked ``slow`` (real JVM spawn).
"""

from __future__ import annotations

import re
import shutil

import pytest

from packages.ghidra import bridge as bridge_mod
from packages.ghidra import ebpf_capability as cap_mod
from packages.ghidra import ebpf_probe as probe_mod
from packages.ghidra.ebpf_capability import (
    EbpfLifterCapability,
    TIER_DOWNGRADED,
    TIER_TRUSTED,
)
from packages.ghidra.ebpf_probe import (
    EbpfToolchain,
    GTInsn,
    GhidraProgramDump,
    PROBE_OBJECTS,
    _expected_target_offset,
    _find_versioned,
    _norm,
    evaluate_object,
    find_toolchain,
    generate_objects,
    parse_dump,
    parse_ground_truth,
    run_probe,
)
from packages.ghidra.model import REDatabase

# Captured llvm-objdump -d --triple=bpfel output (LLVM 21): includes
# a 16-byte lddw (objdump's leading counter is the instruction SLOT,
# not the byte offset — the parser must accumulate byte counts).
GT_SAMPLE = """\
lddw.o:\tfile format elf64-bpf

Disassembly of section .text:

0000000000000000 <x>:
       0:\t18 01 00 00 ef cd ab 89 00 00 00 00 67 45 23 01\tr1 = 0x123456789abcdef ll
       2:\tb7 00 00 00 00 00 00 00\tr0 = 0x0
       3:\t95 00 00 00 00 00 00 00\texit

Disassembly of section .other:

0000000000000000 <y>:
       0:\t95 00 00 00 00 00 00 00\texit
"""

# Captured EbpfProbeDump post-script output (Ghidra 12.1.2).
DUMP_SAMPLE = """\
PROGRAM\tsdiv_v4.o\teBPF:LE:64:default
BLOCK\t.text\t1048576\t32
INSN\t.text\t0\t8\tDIV R1,R2
INSN\t.text\t8\t8\tSDIV R1,R2
INSN\t.text\t16\t8\tMOV R0,0x0
INSN\t.text\t24\t8\tEXIT
PROGRAM\tbroken.o\teBPF:LE:64:default
BLOCK\t.text\t1048576\t16
INSN\t.text\t0\t8\tEXIT
UNDEF\t.text\t8
"""


def _probe(name: str):
    return next(p for p in PROBE_OBJECTS if p.name == name)


class TestGroundTruthParser:
    def test_lddw_offsets_accumulate_bytes(self):
        insns = parse_ground_truth(GT_SAMPLE)
        assert [(i.offset, i.length) for i in insns] == [
            (0, 16), (16, 8), (24, 8)]
        assert insns[0].text == "r1 = 0x123456789abcdef ll"
        assert insns[2].text == "exit"

    def test_non_text_sections_skipped(self):
        insns = parse_ground_truth(GT_SAMPLE)
        # The .other section's exit must not be appended.
        assert len(insns) == 3

    def test_symbol_and_header_lines_ignored(self):
        insns = parse_ground_truth("garbage\n0000 <x>:\nnot insn\n")
        assert insns == []

    def test_insn_cap_two_directions(self, monkeypatch):
        line = "       0:\t95 00 00 00 00 00 00 00\texit\n"
        monkeypatch.setattr(probe_mod, "MAX_GT_INSNS", 3)
        # At the cap: everything parses.
        assert len(parse_ground_truth(line * 3)) == 3
        # Past the cap: truncated at the cap, not ballooning.
        assert len(parse_ground_truth(line * 5)) == 3


class TestDumpParser:
    def test_sample(self):
        programs = parse_dump(DUMP_SAMPLE)
        assert set(programs) == {"sdiv_v4.o", "broken.o"}
        sdiv = programs["sdiv_v4.o"]
        assert sdiv.language_id == "eBPF:LE:64:default"
        assert sdiv.block_start == 1048576
        assert sdiv.insns[8] == (8, "SDIV R1,R2")
        broken = programs["broken.o"]
        assert broken.undefs == {8}

    def test_junk_lines_ignored(self):
        text = ("noise\nINSN\t.text\t0\t8\torphan-before-program\n"
                + DUMP_SAMPLE + "BLOCK\t.text\tnotint\t8\n"
                + "INSN\t.text\tx\ty\tz\n")
        programs = parse_dump(text)
        assert programs["sdiv_v4.o"].insns[0] == (8, "DIV R1,R2")


class TestNormAndTargets:
    def test_norm_whitespace_and_case_only(self):
        assert _norm("sdiv  r1,r2") == _norm("SDIV R1,R2")
        assert _norm("DIV R1,R2") != _norm("SDIV R1,R2")

    def test_forward_target(self):
        gt = GTInsn(offset=8, length=8, text="gotol +0x2 <LBL_B>")
        assert _expected_target_offset(gt) == 8 + 8 + 2 * 8

    def test_backward_target(self):
        gt = GTInsn(offset=24, length=8, text="goto -0x2 <L>")
        assert _expected_target_offset(gt) == 24 + 8 - 2 * 8

    def test_no_target(self):
        assert _expected_target_offset(
            GTInsn(offset=0, length=8, text="exit")) is None


def _sdiv_gt() -> list[GTInsn]:
    return [
        GTInsn(0, 8, "r1 /= r2"),
        GTInsn(8, 8, "r1 s/= r2"),
        GTInsn(16, 8, "r0 = 0x0"),
        GTInsn(24, 8, "exit"),
    ]


def _sdiv_dump(feature_text: str = "SDIV R1,R2") -> GhidraProgramDump:
    return GhidraProgramDump(
        language_id="eBPF:LE:64:default",
        block_start=0x100000,
        block_size=32,
        insns={0: (8, "DIV R1,R2"), 8: (8, feature_text),
               16: (8, "MOV R0,0x0"), 24: (8, "EXIT")},
    )


class TestEvaluateObject:
    def test_distinct_decode_passes(self):
        features = evaluate_object(
            _probe("sdiv_v4"), _sdiv_gt(), _sdiv_dump())
        entry = features["v4_sdiv"]
        assert entry["pass"] is True
        assert entry["checks"]["distinguishable"] is True

    def test_confusable_render_fails(self):
        # Wrong-but-valid decode: the v4 opcode rendered as its v1
        # confusable — boundaries are perfect, text is identical.
        features = evaluate_object(
            _probe("sdiv_v4"), _sdiv_gt(), _sdiv_dump("DIV R1,R2"))
        entry = features["v4_sdiv"]
        assert entry["pass"] is False
        assert entry["checks"]["distinguishable"] is False
        assert "identically" in entry["reason"]

    def test_jmp32_identical_text_fails_distinguishability(self):
        gt = [
            GTInsn(0, 8, "if r1 == r2 goto +0x2 <LBL_T>"),
            GTInsn(8, 8, "if w1 == w2 goto +0x1 <LBL_T>"),
            GTInsn(16, 8, "r0 = 0x0"),
            GTInsn(24, 8, "exit"),
        ]
        dump = GhidraProgramDump(
            language_id="eBPF:LE:64:default",
            block_start=0x100000, block_size=32,
            insns={0: (8, "JEQ R1,R2,0x00100018"),
                   8: (8, "JEQ R1,R2,0x00100018"),
                   16: (8, "MOV R0,0x0"), 24: (8, "EXIT")},
        )
        entry = evaluate_object(
            _probe("jmp32_v3"), gt, dump)["v3_jmp32_jeq"]
        assert entry["pass"] is False
        assert entry["checks"]["distinguishable"] is False
        # The target itself was decoded correctly: 8 + 8 + 1*8 = 24
        # → 0x100018 — the failure is purely distinguishability.
        assert entry["checks"]["target_ok"] is True

    def test_undecoded_feature_fails(self):
        dump = _sdiv_dump()
        del dump.insns[8]
        dump.undefs.add(8)
        entry = evaluate_object(
            _probe("sdiv_v4"), _sdiv_gt(), dump)["v4_sdiv"]
        assert entry["pass"] is False
        assert entry["checks"]["decoded_all"] is False
        assert entry["checks"]["feature_decoded"] is False

    def test_length_mismatch_fails_boundary(self):
        # Ghidra decoded AT the right offset but swallowed the next
        # unit into one instruction — offset presence alone is not
        # boundary agreement; the decoded length must match too.
        dump = _sdiv_dump()
        dump.insns[8] = (16, "SDIV R1,R2")
        entry = evaluate_object(
            _probe("sdiv_v4"), _sdiv_gt(), dump)["v4_sdiv"]
        assert entry["pass"] is False
        assert entry["checks"]["decoded_all"] is False

    def test_wrong_language_fails_all(self):
        dump = _sdiv_dump()
        dump.language_id = "x86:LE:64:default"
        features = evaluate_object(_probe("sdiv_v4"), _sdiv_gt(), dump)
        assert all(e["pass"] is False for e in features.values())
        assert "not eBPF" in features["v4_sdiv"]["reason"]

    def test_missing_dump_fails_all(self):
        features = evaluate_object(_probe("sdiv_v4"), _sdiv_gt(), None)
        assert features["v4_sdiv"]["pass"] is False

    def test_gotol_target_correct_passes(self):
        gt = [
            GTInsn(0, 8, "goto +0x0 <LBL_A>"),
            GTInsn(8, 8, "gotol +0x2 <LBL_B>"),
            GTInsn(16, 8, "r0 = 0x1"),
            GTInsn(24, 8, "r0 = 0x2"),
            GTInsn(32, 8, "r0 = 0x0"),
            GTInsn(40, 8, "exit"),
        ]
        insns = {0: (8, "JA 0x00100008"), 8: (8, "JA 0x00100020"),
                 16: (8, "MOV R0,0x1"), 24: (8, "MOV R0,0x2"),
                 32: (8, "MOV R0,0x0"), 40: (8, "EXIT")}
        dump = GhidraProgramDump(
            language_id="eBPF:LE:64:default",
            block_start=0x100000, block_size=48, insns=insns)
        entry = evaluate_object(_probe("gotol_v4"), gt, dump)["v4_gotol"]
        assert entry["pass"] is True
        assert entry["checks"]["target_ok"] is True

    def test_gotol_wrong_target_fails(self):
        gt = [
            GTInsn(0, 8, "goto +0x0 <LBL_A>"),
            GTInsn(8, 8, "gotol +0x2 <LBL_B>"),
            GTInsn(16, 8, "r0 = 0x1"),
            GTInsn(24, 8, "r0 = 0x2"),
            GTInsn(32, 8, "r0 = 0x0"),
            GTInsn(40, 8, "exit"),
        ]
        insns = {0: (8, "JA 0x00100008"), 8: (8, "JA 0x00100010"),
                 16: (8, "MOV R0,0x1"), 24: (8, "MOV R0,0x2"),
                 32: (8, "MOV R0,0x0"), 40: (8, "EXIT")}
        dump = GhidraProgramDump(
            language_id="eBPF:LE:64:default",
            block_start=0x100000, block_size=48, insns=insns)
        entry = evaluate_object(_probe("gotol_v4"), gt, dump)["v4_gotol"]
        assert entry["pass"] is False
        assert entry["checks"]["target_ok"] is False

    def test_target_substring_junk_does_not_pass(self):
        # At block_start=0 the wanted address renders short (0x10);
        # its digits appearing inside an unrelated token on the line
        # must not pass — only an operand VALUE equal to the target
        # counts (a substring test false-passed here).
        gt = [
            GTInsn(0, 8, "r1 += r2"),
            GTInsn(8, 8, "if r1 > r2 goto +0x0"),
            GTInsn(16, 8, "r0 = 0x0"),
            GTInsn(24, 8, "exit"),
        ]
        dump = GhidraProgramDump(
            language_id="eBPF:LE:64:default",
            block_start=0, block_size=32,
            insns={0: (8, "ADD R1,R2"),
                   8: (8, "JGT R1,R2,0x99 ; note 0x100 in a comment"),
                   16: (8, "MOV R0,0x0"), 24: (8, "EXIT")},
        )
        entry = evaluate_object(_probe("base_v1"), gt, dump)["v1_jgt"]
        assert entry["checks"]["target_ok"] is False
        assert entry["pass"] is False

    @pytest.mark.parametrize("rendering", [
        "JGT R1,R2,0x00000010",   # zero-padded literal
        "JGT R1,R2,LAB_00000010",  # label-style rendering
    ])
    def test_target_exact_value_matches(self, rendering):
        # Other direction: the correct target passes however Ghidra
        # pads or labels it — the comparison is by value.
        gt = [
            GTInsn(0, 8, "r1 += r2"),
            GTInsn(8, 8, "if r1 > r2 goto +0x0"),
            GTInsn(16, 8, "r0 = 0x0"),
            GTInsn(24, 8, "exit"),
        ]
        dump = GhidraProgramDump(
            language_id="eBPF:LE:64:default",
            block_start=0, block_size=32,
            insns={0: (8, "ADD R1,R2"), 8: (8, rendering),
                   16: (8, "MOV R0,0x0"), 24: (8, "EXIT")},
        )
        entry = evaluate_object(_probe("base_v1"), gt, dump)["v1_jgt"]
        assert entry["checks"]["target_ok"] is True
        assert entry["pass"] is True

    def test_feature_missing_from_ground_truth(self):
        gt = [GTInsn(0, 8, "r1 /= r2"), GTInsn(8, 8, "exit")]
        entry = evaluate_object(
            _probe("sdiv_v4"), gt, _sdiv_dump())["v4_sdiv"]
        assert entry["pass"] is False
        assert "toolchain drift" in entry["reason"]


class TestProbeCorpusInvariants:
    def test_object_names_unique(self):
        names = [p.name for p in PROBE_OBJECTS]
        assert len(names) == len(set(names))

    def test_check_names_unique_across_corpus(self):
        names = [c.name for p in PROBE_OBJECTS for c in p.checks]
        assert len(names) == len(set(names))

    def test_mcpu_values_valid(self):
        assert all(p.mcpu in {"v1", "v2", "v3", "v4"}
                   for p in PROBE_OBJECTS)

    def test_regexes_compile(self):
        for p in PROBE_OBJECTS:
            for c in p.checks:
                re.compile(c.feature_re)
                if c.baseline_re is not None:
                    re.compile(c.baseline_re)

    def test_every_check_verifies_something(self):
        # A check with neither a confusable baseline nor a target
        # check only proves boundary decode — allowed only for the
        # v1 sanity features.
        for p in PROBE_OBJECTS:
            for c in p.checks:
                if c.baseline_re is None and not c.target_check:
                    assert c.name.startswith("v1_")

    def test_sources_end_with_exit(self):
        assert all(p.asm.rstrip().endswith("exit")
                   for p in PROBE_OBJECTS)

    def test_isa_scope_covered(self):
        # The annex scope: v2 jlt-family, v3 jmp32 + atomics beyond
        # xadd, v4 sdiv/smod/movsx/bswap/gotol.
        names = {c.name for p in PROBE_OBJECTS for c in p.checks}
        for required in ("v2_jlt", "v3_jmp32_jeq", "v3_atomic_and",
                         "v3_atomic_fetch_add", "v3_atomic_xchg",
                         "v3_atomic_cmpxchg", "v4_sdiv", "v4_smod",
                         "v4_movsx8", "v4_movsx16", "v4_movsx32",
                         "v4_bswap16", "v4_bswap32", "v4_bswap64",
                         "v4_gotol"):
            assert required in names


class TestToolDiscovery:
    def test_plain_name_preferred(self, monkeypatch):
        monkeypatch.setattr(
            shutil, "which",
            lambda name: f"/usr/bin/{name}"
            if name in ("clang", "clang-21") else None,
        )
        assert _find_versioned("clang") == "/usr/bin/clang"

    def test_versioned_suffix_found(self, monkeypatch):
        monkeypatch.setattr(
            shutil, "which",
            lambda name: "/usr/bin/clang-19"
            if name == "clang-19" else None,
        )
        assert _find_versioned("clang") == "/usr/bin/clang-19"

    def test_suffix_range_two_directions(self, monkeypatch):
        # At the range floor: found.
        floor = probe_mod.TOOL_SUFFIX_MIN
        monkeypatch.setattr(
            shutil, "which",
            lambda name: f"/usr/bin/{name}"
            if name == f"clang-{floor}" else None,
        )
        assert _find_versioned("clang") == f"/usr/bin/clang-{floor}"
        # Below the floor: never probed (pre-v4 clangs cannot
        # assemble the corpus).
        monkeypatch.setattr(
            shutil, "which",
            lambda name: f"/usr/bin/{name}"
            if name == f"clang-{floor - 1}" else None,
        )
        assert _find_versioned("clang") is None

    def test_absent_everywhere(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        assert find_toolchain() is None


class TestStderrTail:
    def test_bounds_then_escapes(self):
        out = probe_mod._stderr_tail("x" * 600 + "\x1b[2J", 500)
        # Bounded first (tail of the raw text), escaped second.
        assert "\x1b" not in out
        assert out.endswith("\\x1b[2J")
        assert out.startswith("x")

    def test_none_is_empty(self):
        assert probe_mod._stderr_tail(None, 500) == ""


class TestRunProbeUnavailable:
    def test_no_toolchain(self, monkeypatch):
        monkeypatch.setattr(probe_mod, "find_toolchain", lambda: None)
        result = run_probe()
        assert result["status"] == "unavailable"
        assert "toolchain" in result["reason"]

    def test_no_ghidra(self, monkeypatch):
        monkeypatch.setattr(
            probe_mod, "find_toolchain",
            lambda: EbpfToolchain(clang="clang", objdump="llvm-objdump"))
        monkeypatch.setattr(cap_mod, "ghidra_install_root", lambda: None)
        result = run_probe()
        assert result["status"] == "unavailable"
        assert "Ghidra" in result["reason"]

    def test_no_module(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            probe_mod, "find_toolchain",
            lambda: EbpfToolchain(clang="clang", objdump="llvm-objdump"))
        monkeypatch.setattr(
            cap_mod, "ghidra_install_root", lambda: tmp_path)
        monkeypatch.setattr(
            cap_mod, "install_fingerprint", lambda root=None: None)
        result = run_probe()
        assert result["status"] == "unavailable"
        assert "module" in result["reason"]


def _ebpf_db(**metadata) -> REDatabase:
    return REDatabase(
        source_tool="ghidra",
        metadata={"language_id": "eBPF:LE:64:default", **metadata},
    )


class TestBridgeStamp:
    def test_downgraded_stamped_and_warned(self, monkeypatch, caplog):
        monkeypatch.setattr(
            cap_mod, "ebpf_lifter_capability",
            lambda: EbpfLifterCapability(
                tier=TIER_DOWNGRADED, reason="no probe record"),
        )
        db = _ebpf_db()
        with caplog.at_level("WARNING", logger="packages.ghidra.bridge"):
            bridge_mod._stamp_ebpf_capability(db)
        stamp = db.metadata["ebpf_lifter_capability"]
        assert stamp["tier"] == TIER_DOWNGRADED
        assert "no probe record" in stamp["reason"]
        assert any("DOWNGRADED" in r.message for r in caplog.records)

    def test_trusted_stamped_quietly(self, monkeypatch, caplog):
        monkeypatch.setattr(
            cap_mod, "ebpf_lifter_capability",
            lambda: EbpfLifterCapability(
                tier=TIER_TRUSTED, reason="probe gate passed",
                fingerprint="e" * 64),
        )
        db = _ebpf_db()
        with caplog.at_level("WARNING", logger="packages.ghidra.bridge"):
            bridge_mod._stamp_ebpf_capability(db)
        assert db.metadata["ebpf_lifter_capability"]["tier"] \
            == TIER_TRUSTED
        assert not any("DOWNGRADED" in r.message
                       for r in caplog.records)

    def test_non_ebpf_untouched(self, monkeypatch):
        monkeypatch.setattr(
            cap_mod, "ebpf_lifter_capability",
            lambda: pytest.fail("consult must not run for non-eBPF"),
        )
        db = REDatabase(source_tool="ghidra",
                        architecture="x86/64",
                        metadata={"language_id": "x86:LE:64:default"})
        bridge_mod._stamp_ebpf_capability(db)
        assert "ebpf_lifter_capability" not in db.metadata

    def test_architecture_only_detection(self, monkeypatch):
        monkeypatch.setattr(
            cap_mod, "ebpf_lifter_capability",
            lambda: EbpfLifterCapability(
                tier=TIER_DOWNGRADED, reason="r"),
        )
        db = REDatabase(source_tool="ghidra", architecture="eBPF/64")
        bridge_mod._stamp_ebpf_capability(db)
        assert "ebpf_lifter_capability" in db.metadata

    def test_hostile_reason_escaped_at_log_seam(self, monkeypatch,
                                                caplog):
        # Simulate a producer that forgot intake escaping: the bridge
        # log seam must still escape record-derived reason text.
        class _RawCap:
            def as_metadata(self):
                return {"tier": TIER_DOWNGRADED,
                        "reason": "failed for: v9_\x1b]0;evil\x07"}

        monkeypatch.setattr(
            cap_mod, "ebpf_lifter_capability", lambda: _RawCap())
        db = _ebpf_db()
        with caplog.at_level("WARNING", logger="packages.ghidra.bridge"):
            bridge_mod._stamp_ebpf_capability(db)
        warned = [r.getMessage() for r in caplog.records
                  if "DOWNGRADED" in r.getMessage()]
        assert warned
        assert all("\x1b" not in m and "\x07" not in m for m in warned)
        assert any("\\x1b" in m for m in warned)

    def test_consult_raising_stamps_downgraded(self, monkeypatch):
        def _boom():
            raise RuntimeError("broken consult")
        monkeypatch.setattr(cap_mod, "ebpf_lifter_capability", _boom)
        db = _ebpf_db()
        bridge_mod._stamp_ebpf_capability(db)
        stamp = db.metadata["ebpf_lifter_capability"]
        assert stamp["tier"] == TIER_DOWNGRADED
        assert "consult failed" in stamp["reason"]

    def test_write_re_database_persists_stamp(self, monkeypatch,
                                              tmp_path):
        monkeypatch.setattr(
            cap_mod, "ebpf_lifter_capability",
            lambda: EbpfLifterCapability(
                tier=TIER_DOWNGRADED, reason="no probe record"),
        )
        gpr = tmp_path / "proj.gpr"
        gpr.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<FILE_INFO><BASIC_INFO>"
            '<STATE NAME="OWNER" TYPE="string" VALUE="t" />'
            "</BASIC_INFO></FILE_INFO>\n",
            encoding="utf-8",
        )
        (tmp_path / "proj.rep").mkdir()
        bridge = bridge_mod.GhidraBridge(gpr)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        bridge._write_re_database(_ebpf_db(), out_dir)
        import json
        doc = json.loads(
            (out_dir / "re-database.json").read_text(encoding="utf-8"))
        assert doc["metadata"]["ebpf_lifter_capability"]["tier"] \
            == TIER_DOWNGRADED


_TOOLCHAIN = find_toolchain()

requires_toolchain = pytest.mark.skipif(
    _TOOLCHAIN is None,
    reason="LLVM BPF toolchain (clang + llvm-objdump) not installed",
)


@pytest.mark.slow
@requires_toolchain
class TestLiveToolchain:
    """Slow tier: assembling and disassembling the whole probe corpus
    is two real toolchain subprocess spawns (clang + llvm-objdump)
    per probe object — cost that is runner-dependent, not compute
    bound: sub-second on an unloaded host, past the default tier's
    per-test budget (``RAPTOR_MAX_TEST_SECONDS``) on a loaded
    runner — the marker's loaded-runner-variance clause exactly. The
    live-toolchain contract this proves — the corpus objects
    assemble and the ground-truth disassembly carries every checked
    feature — only moves when the corpus or the toolchain moves, so
    the nightly slow lane (which installs the pinned toolchain, like
    the sibling ``TestLiveProbe`` already marked slow) keeps the
    coverage; mocking the assembly step would gut exactly the live
    part the class name promises."""

    def test_corpus_assembles_and_ground_truth_matches(self, tmp_path):
        from packages.ghidra.ebpf_probe import disassemble_ground_truth
        generated = generate_objects(_TOOLCHAIN, tmp_path)
        for probe in PROBE_OBJECTS:
            gen = generated[probe.name]
            assert gen["path"] is not None, (
                f"{probe.name} failed to assemble: {gen['error']}")
            insns, err = disassemble_ground_truth(
                _TOOLCHAIN, gen["path"])
            assert not err, f"{probe.name}: {err}"
            for check in probe.checks:
                assert any(re.search(check.feature_re, i.text)
                           for i in insns), (
                    f"{check.name}: feature not in ground truth")
                if check.baseline_re is not None:
                    feat = next(
                        i for i in insns
                        if re.search(check.feature_re, i.text))
                    base = next(
                        (i for i in insns
                         if re.search(check.baseline_re, i.text)),
                        None,
                    )
                    assert base is not None, (
                        f"{check.name}: baseline not in ground truth")
                    # Baseline precedes the feature so a failed
                    # feature decode cannot cascade onto it.
                    assert base.offset < feat.offset


@pytest.mark.slow
@pytest.mark.skipif(
    _TOOLCHAIN is None,
    reason="LLVM BPF toolchain (clang + llvm-objdump) not installed",
)
@pytest.mark.skipif(
    cap_mod.install_fingerprint() is None,
    reason="Ghidra with the eBPF processor module not installed",
)
class TestLiveProbe:
    def test_full_probe_produces_complete_record(self, tmp_path):
        result = run_probe(work_dir=tmp_path)
        assert result["status"] == "ran"
        record = result["record"]
        expected = {c.name for p in PROBE_OBJECTS for c in p.checks}
        assert set(record["features"]) == expected
        for name, entry in record["features"].items():
            assert isinstance(entry.get("pass"), bool), name
        assert record["schema"] == cap_mod.CAPABILITY_SCHEMA
        assert record["kind"] == cap_mod.CAPABILITY_KIND
        assert record["install_fingerprint"] \
            == cap_mod.install_fingerprint()
        assert sorted(record["failed_features"]) == sorted(
            n for n, e in record["features"].items()
            if e["pass"] is not True
        )
        assert record["pass"] == (not record["failed_features"])
