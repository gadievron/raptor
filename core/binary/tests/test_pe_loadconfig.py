"""Tests for the PE load-config skim (``stack_cookie`` / ``safeseh``)
and the stripped-ness signals (``debug_directory_present`` /
``coff_symbol_count`` / ``no_seh``).

Reuses the crafted-PE builders from ``test_pe_facts`` — pure-python
byte assembly, no toolchain. Every case pins BOTH directions where a
cap or degradation rule exists: the honest shape extracts, the lying
shape degrades marker-visibly.
"""

from __future__ import annotations

import dataclasses
import struct

from core.binary.pe import extract_pe_facts

from .test_pe_facts import (
    _MACHINE_I386,
    _PE32_MAGIC,
    PeSpec,
    Sec,
    build_pe,
)

_DIR_LOAD_CONFIG = 10
_DIR_DEBUG = 6


def _load_config_32(
    *,
    size_field: int | None = None,
    cookie: int = 0x0040_3000,
    seh_table: int = 0x0040_4000,
    seh_count: int = 5,
    total: int = 72,
) -> bytes:
    """A crafted IMAGE_LOAD_CONFIG_DIRECTORY32 blob."""
    buf = bytearray(total)
    struct.pack_into("<I", buf, 0,
                     total if size_field is None else size_field)
    if total >= 64:
        struct.pack_into("<I", buf, 60, cookie)
    if total >= 72:
        struct.pack_into("<II", buf, 64, seh_table, seh_count)
    return bytes(buf)


def _load_config_64(*, cookie: int = 0x1_4000_3000,
                    total: int = 112) -> bytes:
    buf = bytearray(total)
    struct.pack_into("<I", buf, 0, total)
    if total >= 96:
        struct.pack_into("<Q", buf, 88, cookie)
    return bytes(buf)


def _pe32_with_load_config(blob: bytes, *, dir_size: int | None = None,
                           **spec_overrides) -> PeSpec:
    """A PE32 image whose .rdata section carries ``blob`` at RVA
    0x2000, named by the load-config data directory."""
    spec = PeSpec(
        machine=_MACHINE_I386,
        magic=_PE32_MAGIC,
        secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".rdata", va=0x2000, data=blob),
        ],
        data_dirs={_DIR_LOAD_CONFIG: (
            0x2000, len(blob) if dir_size is None else dir_size)},
    )
    return dataclasses.replace(spec, **spec_overrides)


class TestLoadConfig32:
    def test_safeseh_registered(self, tmp_path):
        p = tmp_path / "safeseh.exe"
        p.write_bytes(build_pe(_pe32_with_load_config(
            _load_config_32(seh_table=0x0040_4000, seh_count=5))))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.load_config_present is True
        assert facts.stack_cookie is True
        assert facts.safeseh is True
        assert facts.safeseh_handler_count == 5
        assert "load_config_short" not in facts.caps_hit
        assert "load_config_unreadable" not in facts.caps_hit

    def test_safeseh_absent_when_fields_zero(self, tmp_path):
        p = tmp_path / "noseh.exe"
        p.write_bytes(build_pe(_pe32_with_load_config(
            _load_config_32(seh_table=0, seh_count=0))))
        facts = extract_pe_facts(p)
        assert facts is not None
        # The fields are COVERED and register nothing — an evidence-
        # backed False, not an unknown.
        assert facts.safeseh is False
        assert facts.safeseh_handler_count == 0

    def test_zero_count_with_nonzero_table_is_not_safeseh(
            self, tmp_path):
        p = tmp_path / "zcount.exe"
        p.write_bytes(build_pe(_pe32_with_load_config(
            _load_config_32(seh_table=0x0040_4000, seh_count=0))))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.safeseh is False
        assert facts.safeseh_handler_count == 0

    def test_zero_cookie_recorded_false(self, tmp_path):
        p = tmp_path / "nocookie.exe"
        p.write_bytes(build_pe(_pe32_with_load_config(
            _load_config_32(cookie=0))))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.stack_cookie is False

    def test_pre_safeseh_short_struct_degrades_with_marker(
            self, tmp_path):
        # A real pre-SafeSEH struct version: 64 bytes covers the
        # cookie but not the SEH fields.
        p = tmp_path / "short.exe"
        p.write_bytes(build_pe(_pe32_with_load_config(
            _load_config_32(total=64))))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.stack_cookie is True
        assert facts.safeseh is None
        assert facts.safeseh_handler_count is None
        assert "load_config_short" in facts.caps_hit

    def test_struct_shorter_than_cookie_degrades_everything(
            self, tmp_path):
        p = tmp_path / "stub.exe"
        p.write_bytes(build_pe(_pe32_with_load_config(
            _load_config_32(total=8))))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.load_config_present is True
        assert facts.stack_cookie is None
        assert facts.safeseh is None
        assert "load_config_short" in facts.caps_hit

    def test_unmapped_directory_marks_unreadable(self, tmp_path):
        spec = _pe32_with_load_config(_load_config_32())
        # Point the directory at an RVA no section (and no header
        # region) claims.
        spec.data_dirs = {_DIR_LOAD_CONFIG: (0x9_0000, 72)}
        p = tmp_path / "unmapped.exe"
        p.write_bytes(build_pe(spec))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.load_config_present is True
        assert facts.stack_cookie is None
        assert facts.safeseh is None
        assert "load_config_unreadable" in facts.caps_hit

    def test_giant_size_claim_buys_the_fixed_window_only(
            self, tmp_path):
        # A u32-max directory size claim: the read is
        # min(claim, fixed need) — the extraction succeeds off the
        # section's real bytes and no cap or error fires.
        p = tmp_path / "giant.exe"
        p.write_bytes(build_pe(_pe32_with_load_config(
            _load_config_32(), dir_size=0xFFFF_FFFF)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.safeseh is True
        assert facts.stack_cookie is True
        assert "load_config_unreadable" not in facts.caps_hit

    def test_absent_directory_leaves_none(self, tmp_path):
        p = tmp_path / "plain.exe"
        p.write_bytes(build_pe(PeSpec(
            machine=_MACHINE_I386, magic=_PE32_MAGIC,
            secs=[Sec(name=b".text", va=0x1000,
                      data=b"\xcc" * 0x40)],
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.load_config_present is False
        assert facts.stack_cookie is None
        assert facts.safeseh is None
        assert facts.safeseh_handler_count is None


class TestLoadConfig64:
    def test_cookie_extracted_safeseh_stays_none(self, tmp_path):
        blob = _load_config_64(cookie=0x1_4000_3000)
        p = tmp_path / "lc64.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[
                Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
                Sec(name=b".rdata", va=0x2000, data=blob),
            ],
            data_dirs={_DIR_LOAD_CONFIG: (0x2000, len(blob))},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.load_config_present is True
        assert facts.stack_cookie is True
        # SafeSEH is a PE32 mechanism by definition — a PE32+ image
        # records None regardless of what the legacy fields carry.
        assert facts.safeseh is None
        assert facts.safeseh_handler_count is None
        assert "load_config_short" not in facts.caps_hit

    def test_nonzero_bytes_at_pe32_seh_offsets_stay_none(
            self, tmp_path):
        # In the 64-bit layout, offsets 64/68 carry unrelated
        # fields — a reader that applied the PE32 SEHandlerTable/
        # Count offsets to a PE32+ struct would fabricate a SafeSEH
        # claim from them. Pin: nonzero bytes there change nothing.
        blob = bytearray(_load_config_64(cookie=0x1_4000_3000))
        struct.pack_into("<II", blob, 64, 0xDEAD_BEEF, 7)
        p = tmp_path / "legacy64.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[
                Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
                Sec(name=b".rdata", va=0x2000, data=bytes(blob)),
            ],
            data_dirs={_DIR_LOAD_CONFIG: (0x2000, len(blob))},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.stack_cookie is True
        assert facts.safeseh is None
        assert facts.safeseh_handler_count is None


class TestSehCharacteristic:
    def test_no_seh_bit_surfaces(self, tmp_path):
        p = tmp_path / "noseh.exe"
        p.write_bytes(build_pe(PeSpec(
            dll_characteristics=0x0400,
            secs=[Sec(name=b".text", va=0x1000,
                      data=b"\xcc" * 0x40)],
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.no_seh is True

    def test_no_seh_default_false(self, tmp_path):
        p = tmp_path / "seh.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000,
                      data=b"\xcc" * 0x40)],
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.no_seh is False


class TestStrippedNessSignals:
    def test_debug_directory_presence_bit(self, tmp_path):
        with_dir = PeSpec(
            secs=[Sec(name=b".text", va=0x1000,
                      data=b"\xcc" * 0x40)],
            data_dirs={_DIR_DEBUG: (0x1000, 28)},
        )
        without = PeSpec(
            secs=[Sec(name=b".text", va=0x1000,
                      data=b"\xcc" * 0x40)],
        )
        p = tmp_path / "with.exe"
        p.write_bytes(build_pe(with_dir))
        q = tmp_path / "without.exe"
        q.write_bytes(build_pe(without))
        facts_with = extract_pe_facts(p)
        facts_without = extract_pe_facts(q)
        assert facts_with is not None and facts_without is not None
        assert facts_with.debug_directory_present is True
        assert facts_without.debug_directory_present is False

    def test_coff_symbol_count_needs_nonzero_pointer(self, tmp_path):
        # The builder emits PointerToSymbolTable=0, so a crafted
        # count claim over the zero pointer records nothing; a
        # real (pointer, count) pair records the claim.
        base = build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000,
                      data=b"\xcc" * 0x40)],
        ))
        blob = bytearray(base)
        e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
        coff_off = e_lfanew + 4
        # COFF: Machine(H) NumberOfSections(H) TimeDateStamp(I)
        # PointerToSymbolTable(I) NumberOfSymbols(I) ...
        struct.pack_into("<I", blob, coff_off + 8, 0x5000)   # pointer
        struct.pack_into("<I", blob, coff_off + 12, 42)      # count
        p = tmp_path / "symtab.exe"
        p.write_bytes(bytes(blob))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.coff_symbol_count == 42

        struct.pack_into("<I", blob, coff_off + 8, 0)    # zero pointer
        q = tmp_path / "zeroptr.exe"
        q.write_bytes(bytes(blob))
        facts_q = extract_pe_facts(q)
        assert facts_q is not None
        assert facts_q.coff_symbol_count == 0
