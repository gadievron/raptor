"""Tests for ``core.binary.facts`` — the normalized cross-format
aggregation layer. Reuses the crafted fixture builders from the
per-format suites (no toolchain, no re-parsing logic of its own to
test — the mapping and its honesty rules are what is pinned here).
"""

from __future__ import annotations

import struct

import core.binary.elf as elf_mod
import pytest

from core.binary.facts import extract_format_facts

from packages.binary_analysis.tests.test_macho_facts import (
    CPU_ARM64,
    build_fat,
    build_thin,
    lc,
)
from packages.binary_analysis.tests.test_macho_mitigations import (
    _thin_with_strtab,
    symtab_cmd,
)

from .test_elf_facts import _standard_fixture
from .test_pe_facts import (
    _MACHINE_I386,
    _PE32_MAGIC,
    PeSpec,
    Sec,
    _optional_header,
    build_pe,
)
from .test_pe_loadconfig import _load_config_32, _pe32_with_load_config


@pytest.fixture(autouse=True)
def _stub_build_id(monkeypatch):
    """Hermetic: the ELF facts path shells out to sandboxed readelf
    for the build-id; CI runners may lack the toolchain."""
    monkeypatch.setattr(elf_mod, "_read_build_id",
                        lambda p: ("aa" * 20, None))


class TestElfMapping:
    def test_standard_fixture_maps(self, tmp_path):
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.binary_format == "elf"
        assert facts.arch == "x86"
        assert facts.bits == 64
        assert facts.endianness == "little"
        assert facts.linked_libraries == ["libfoo.so.1", "libbar.so.2"]
        assert facts.linked_library_count == 2
        assert facts.export_count == 3
        assert facts.import_count == 1
        assert facts.debug_ref == "app.debug"
        assert facts.identity_hint == "aa" * 20
        assert facts.size_bytes == p.stat().st_size
        # Honesty rules: facts the ELF shallow tier cannot answer
        # stay None, never a fabricated value.
        assert facts.entrypoint is None
        assert facts.stripped is None
        assert facts.mitigations == {}
        assert facts.debug_directory_present is None

    def test_to_dict_stamps_derived_from_target(self, tmp_path):
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_format_facts(p)
        assert facts is not None
        out = facts.to_dict()
        assert out["derived_from_target"] is True
        assert out["binary_format"] == "elf"


class TestPeMapping:
    def test_pe32_with_load_config_maps(self, tmp_path):
        p = tmp_path / "app.exe"
        p.write_bytes(build_pe(_pe32_with_load_config(
            _load_config_32(), dll_characteristics=0x0140)))
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.binary_format == "pe"
        assert facts.arch == "x86"
        assert facts.bits == 32
        assert facts.endianness == "little"
        assert facts.section_names == [".text", ".rdata"]
        assert facts.section_count == 2
        assert facts.entrypoint == 0x1000
        assert facts.mitigations["aslr"] is True
        assert facts.mitigations["dep"] is True
        assert facts.mitigations["cfg"] is False
        assert facts.mitigations["stack_cookie"] is True
        assert facts.mitigations["safeseh"] is True
        # No debug directory, no COFF symbols → stripped.
        assert facts.stripped is True
        assert facts.debug_directory_present is False

    def test_pe_import_dlls_become_linked_libraries(self, tmp_path):
        # The imports table walk is pinned in the PE suites; here
        # only the DLL-name mapping is asserted, off a crafted
        # single-descriptor table.
        name_rva = 0x2100
        int_rva = 0x2200
        hint_rva = 0x2300
        desc = struct.pack("<IIIII", int_rva, 0, 0, name_rva, 0x3000)
        desc += b"\x00" * 20
        rdata = bytearray(0x400)
        rdata[0x000:0x000 + len(desc)] = desc
        rdata[0x100:0x10C] = b"KERNEL32.dll"
        struct.pack_into("<I", rdata, 0x200, hint_rva)  # one thunk
        rdata[0x300:0x310] = struct.pack("<H", 1) + b"ReadFile\x00" + b"\x00" * 5
        p = tmp_path / "imp.exe"
        p.write_bytes(build_pe(PeSpec(
            machine=_MACHINE_I386, magic=_PE32_MAGIC,
            secs=[
                Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
                Sec(name=b".rdata", va=0x2000, data=bytes(rdata)),
            ],
            data_dirs={1: (0x2000, 40)},
        )))
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.linked_libraries == ["KERNEL32.dll"]
        assert facts.linked_library_count == 1
        assert facts.import_count == 1


class TestPeTriStateHonesty:
    def test_missing_optional_header_renders_unknowns(self, tmp_path):
        # A COFF-object shape (SizeOfOptionalHeader == 0): the
        # DllCharacteristics bits and the data-directory table were
        # never read — every derived boolean must be None, never a
        # fabricated confident False.
        p = tmp_path / "obj.exe"
        p.write_bytes(build_pe(PeSpec(
            optional_header=b"",
            secs=[Sec(name=b".text", va=0x1000, data=b"")],
        )))
        facts = extract_format_facts(p)
        assert facts is not None
        assert "optional_header_missing" in facts.caps_hit
        for key in ("aslr", "high_entropy_va", "dep", "cfg",
                    "no_seh"):
            assert facts.mitigations[key] is None, key
        assert facts.debug_directory_present is None
        assert facts.stripped is None
        assert facts.entrypoint is None

    def test_truncated_header_keeps_decoded_trues(self, tmp_path):
        # Truncation AFTER DllCharacteristics but BEFORE the data
        # directories: the decoded bits stay evidence-backed
        # (True/False would both be reads at offset 70), but the
        # dir-table-derived facts degrade to None — and a set bit
        # proves the field WAS read, so the mapper keeps the True.
        opt = _optional_header(dll_characteristics=0x0140)[:72]
        p = tmp_path / "cut.exe"
        p.write_bytes(build_pe(PeSpec(
            optional_header=opt,
            secs=[Sec(name=b".text", va=0x1000, data=b"")],
        )))
        facts = extract_format_facts(p)
        assert facts is not None
        assert "optional_header_truncated" in facts.caps_hit
        assert facts.mitigations["aslr"] is True
        assert facts.mitigations["dep"] is True
        # Unset bits under degradation: may be unread — None, not
        # False (the conservative collapse is deliberate; see
        # _PE_OPT_DEGRADED).
        assert facts.mitigations["cfg"] is None
        assert facts.mitigations["no_seh"] is None
        assert facts.debug_directory_present is None
        assert facts.stripped is None
        # The entrypoint field itself decoded before the cut.
        assert facts.entrypoint == 0x1000

    def test_zero_entrypoint_survives_on_healthy_header(
            self, tmp_path):
        # AddressOfEntryPoint == 0 is a legitimate value (a DLL with
        # no entry) — only a DEGRADED header turns 0 into unknown.
        p = tmp_path / "noentry.dll"
        p.write_bytes(build_pe(PeSpec(
            entrypoint=0,
            secs=[Sec(name=b".text", va=0x1000,
                      data=b"\xcc" * 0x40)],
        )))
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.entrypoint == 0


class TestRetentionCap:
    def test_over_cap_section_names_truncate_with_marker(
            self, tmp_path):
        # The >cap direction: more sections than the normalized
        # record retains — the list truncates at the cap, the honest
        # count keeps the real magnitude, and the truncation is
        # marker-visible.
        from core.binary.facts import _MAX_NAME_LIST
        n = _MAX_NAME_LIST + 6
        secs = [Sec(name=f".s{i:03d}".encode(),
                    va=0x1000 * (i + 1), data=b"")
                for i in range(n)]
        p = tmp_path / "many.exe"
        p.write_bytes(build_pe(PeSpec(secs=secs)))
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.section_count == n
        assert len(facts.section_names) == _MAX_NAME_LIST
        assert facts.section_names[0] == ".s000"
        assert "facts_section_names_capped" in facts.caps_hit

    def test_capped_helper_both_directions(self):
        # Same helper serves the libraries list — pin the marker
        # name and the at-cap no-op direction directly.
        from core.binary.facts import _MAX_NAME_LIST, _capped
        names = [f"lib{i}.so" for i in range(_MAX_NAME_LIST + 3)]
        caps: set[str] = set()
        out = _capped(names, caps, "facts_libraries_capped")
        assert out == names[:_MAX_NAME_LIST]
        assert caps == {"facts_libraries_capped"}
        at_cap = names[:_MAX_NAME_LIST]
        caps_ok: set[str] = set()
        assert _capped(at_cap, caps_ok,
                       "facts_libraries_capped") == at_cap
        assert caps_ok == set()


class TestMachoMapping:
    def test_slice_maps_with_mitigations(self, tmp_path):
        strtab = b"\x00___stack_chk_fail\x00"
        blob = _thin_with_strtab(strtab, flags=0x200000)   # MH_PIE
        p = tmp_path / "app.macho"
        p.write_bytes(blob)
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.binary_format == "macho"
        assert facts.bits == 64
        assert facts.mitigations["pie"] is True
        assert facts.mitigations["stack_canary"] is True
        assert facts.identity_hint is None
        assert facts.fat_slice_count == 0

    def test_canary_false_only_on_complete_scan(self, tmp_path):
        # A symtab scanned completely with no canary names is an
        # evidence-backed False...
        p = tmp_path / "plain.macho"
        p.write_bytes(_thin_with_strtab(b"\x00_main\x00"))
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.mitigations["stack_canary"] is False
        # ...but no symtab at all is None, never False.
        q = tmp_path / "nosymtab.macho"
        q.write_bytes(build_thin([]))
        facts_q = extract_format_facts(q)
        assert facts_q is not None
        assert facts_q.mitigations["stack_canary"] is None

    def test_canary_none_on_unscannable_claimed_region(self, tmp_path):
        # LC_SYMTAB claims a 4096-byte string region at offset 0 —
        # unscannable (marker-visible at the extractor); the
        # normalized canary answer must be None, never a confident
        # False off a scan that never ran.
        blob = build_thin([symtab_cmd(nsyms=5, stroff=0,
                                      strsize=4096)])
        p = tmp_path / "claimed.macho"
        p.write_bytes(blob)
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.mitigations["stack_canary"] is None
        assert "symtab_strings_unreadable" in facts.caps_hit

    def test_stripped_from_nsyms_zero(self, tmp_path):
        blob = build_thin([symtab_cmd(nsyms=0, strsize=0)])
        p = tmp_path / "stripped.macho"
        p.write_bytes(blob)
        facts = extract_format_facts(p)
        assert facts is not None
        assert facts.stripped is True

    def test_fat_slice_selection(self, tmp_path):
        x86 = build_thin([lc(0x3F3F)])
        arm = build_thin([lc(0x3F3F)], cputype=CPU_ARM64)
        p = tmp_path / "fat.macho"
        p.write_bytes(build_fat([x86, arm],
                                cputypes=[7 | 0x01000000, CPU_ARM64]))
        default = extract_format_facts(p)
        assert default is not None
        assert default.arch == "x86_64"
        assert default.fat_slice_count == 2
        picked = extract_format_facts(p, macho_slice_arch="aarch64")
        assert picked is not None
        assert picked.arch == "arm64"
        # An explicit request no slice satisfies refuses (never a
        # silent wrong-ISA fallback).
        assert extract_format_facts(p, macho_slice_arch="ppc") is None


class TestDispatch:
    def test_unrecognised_bytes_refused(self, tmp_path):
        p = tmp_path / "junk.bin"
        p.write_bytes(b"\x00\x01\x02RANDOM" * 64)
        assert extract_format_facts(p) is None

    def test_missing_file_refused(self, tmp_path):
        assert extract_format_facts(tmp_path / "absent") is None

    def test_mz_without_pe_signature_refused(self, tmp_path):
        p = tmp_path / "dos.bin"
        p.write_bytes(b"MZ" + b"\x00" * 200)
        assert extract_format_facts(p) is None
