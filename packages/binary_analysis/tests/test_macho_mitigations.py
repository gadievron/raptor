"""Tests for the Mach-O mitigation facts: the named mach_header flag
booleans (PIE / stack-exec / heap-exec), the LC_SYMTAB header claims,
and the bounded symtab-strings stack-canary scan.

Reuses the crafted thin/fat builders from ``test_macho_facts`` —
pure-python byte assembly, no toolchain.
"""

from __future__ import annotations

import struct

from packages.binary_analysis import macho as macho_mod
from packages.binary_analysis.macho import extract_macho_facts

from .test_macho_facts import build_fat, build_thin, lc

_MH_PIE = 0x200000
_MH_ALLOW_STACK_EXECUTION = 0x20000
_MH_NO_HEAP_EXECUTION = 0x1000000

_HEADER_64 = 32          # mach_header_64 size


def symtab_cmd(symoff: int = 0, nsyms: int = 0, stroff: int = 0,
               strsize: int = 0, *, endian: str = "<",
               cmdsize: int | None = None) -> bytes:
    return lc(0x2, struct.pack(f"{endian}IIII", symoff, nsyms,
                               stroff, strsize),
              endian=endian, cmdsize=cmdsize)


def _thin_with_strtab(strtab: bytes, *, nsyms: int = 3,
                      strsize: int | None = None,
                      stroff: int | None = None,
                      flags: int = 0) -> bytes:
    """A 64-bit thin slice with one LC_SYMTAB whose string table is
    the ``tail`` bytes right after the command region."""
    cmds_size = 24
    tail_off = _HEADER_64 + cmds_size
    cmd = symtab_cmd(
        symoff=tail_off, nsyms=nsyms,
        stroff=tail_off if stroff is None else stroff,
        strsize=len(strtab) if strsize is None else strsize,
    )
    return build_thin([cmd], flags=flags, tail=strtab)


def _extract_one(blob: bytes, tmp_path):
    p = tmp_path / "t.bin"
    p.write_bytes(blob)
    facts = extract_macho_facts(p)
    assert facts is not None and facts.slices
    return facts.slices[0], facts


class TestHeaderFlagBooleans:
    def test_named_bits_surface(self, tmp_path):
        blob = build_thin(
            [], flags=(_MH_PIE | _MH_ALLOW_STACK_EXECUTION
                       | _MH_NO_HEAP_EXECUTION))
        item, _ = _extract_one(blob, tmp_path)
        assert item.pie is True
        assert item.allow_stack_execution is True
        assert item.no_heap_execution is True
        # The raw value survives beside the named booleans.
        assert item.flags & _MH_PIE

    def test_zero_flags_stay_false(self, tmp_path):
        item, _ = _extract_one(build_thin([], flags=0), tmp_path)
        assert item.pie is False
        assert item.allow_stack_execution is False
        assert item.no_heap_execution is False


class TestSymtabClaims:
    def test_symtab_recorded(self, tmp_path):
        item, _ = _extract_one(
            _thin_with_strtab(b"\x00_a\x00_b\x00", nsyms=2),
            tmp_path)
        assert item.symtab["nsyms"] == 2
        assert item.symtab["strsize"] == 7
        assert item.symtab["stroff"] == _HEADER_64 + 24
        assert item.symtab["symoff"] == _HEADER_64 + 24

    def test_absent_symtab_is_empty_dict(self, tmp_path):
        item, _ = _extract_one(build_thin([]), tmp_path)
        assert item.symtab == {}
        assert item.stack_canary_symbols == []

    def test_first_symtab_wins(self, tmp_path):
        first = symtab_cmd(nsyms=7, strsize=0)
        second = symtab_cmd(nsyms=99, strsize=0)
        item, _ = _extract_one(build_thin([first, second]), tmp_path)
        assert item.symtab["nsyms"] == 7

    def test_short_symtab_cmdsize_aborts_walk(self, tmp_path):
        # cmdsize below the 24-byte fixed header would decode the
        # NEXT command's bytes — invariant (a), cause-named abort.
        bad = symtab_cmd(nsyms=1, cmdsize=16)
        item, _ = _extract_one(build_thin([bad]), tmp_path)
        assert ("lc_walk_abort_fixed_header_truncated"
                in item.caps_hit)
        assert item.symtab == {}


class TestCanaryScan:
    def test_both_names_found(self, tmp_path):
        strtab = (b"\x00___stack_chk_fail\x00radr\x00"
                  b"___stack_chk_guard\x00")
        item, _ = _extract_one(_thin_with_strtab(strtab), tmp_path)
        assert item.stack_canary_symbols == [
            "___stack_chk_fail", "___stack_chk_guard"]
        assert "symtab_strings_capped" not in item.caps_hit

    def test_one_name_found(self, tmp_path):
        strtab = b"\x00___stack_chk_guard\x00_main\x00"
        item, _ = _extract_one(_thin_with_strtab(strtab), tmp_path)
        assert item.stack_canary_symbols == ["___stack_chk_guard"]

    def test_no_names_empty(self, tmp_path):
        strtab = b"\x00_main\x00_helper\x00"
        item, _ = _extract_one(_thin_with_strtab(strtab), tmp_path)
        assert item.stack_canary_symbols == []

    def test_name_at_table_start_matches(self, tmp_path):
        # stroff pointing directly at the name (no leading NUL in
        # the window): the startswith anchor covers it.
        strtab = b"___stack_chk_fail\x00"
        item, _ = _extract_one(_thin_with_strtab(strtab), tmp_path)
        assert item.stack_canary_symbols == ["___stack_chk_fail"]

    def test_superstring_does_not_alias(self, tmp_path):
        strtab = (b"\x00x___stack_chk_fail\x00"
                  b"___stack_chk_guardian\x00")
        item, _ = _extract_one(_thin_with_strtab(strtab), tmp_path)
        assert item.stack_canary_symbols == []

    def test_stroff_past_slice_marks_unreadable(self, tmp_path):
        blob = _thin_with_strtab(b"\x00abc\x00", stroff=1 << 30)
        item, _ = _extract_one(blob, tmp_path)
        assert "symtab_strings_unreadable" in item.caps_hit
        assert item.stack_canary_symbols == []

    def test_strsize_overclaim_clamps_and_marks(self, tmp_path):
        # strsize claims far past EOF: the window clamps to the
        # slice extent, the scan still answers over the real bytes,
        # and the truncation is marker-visible.
        strtab = b"\x00___stack_chk_fail\x00"
        blob = _thin_with_strtab(strtab, strsize=1 << 20)
        item, _ = _extract_one(blob, tmp_path)
        assert item.stack_canary_symbols == ["___stack_chk_fail"]
        assert "symtab_strings_capped" in item.caps_hit

    def test_file_level_budget_shared_across_fat_slices(
            self, tmp_path, monkeypatch):
        strtab = b"\x00___stack_chk_fail\x00"
        inner = _thin_with_strtab(strtab)
        # First slice's scan spends the whole file budget; the
        # second slice's scan is refused marker-visibly.
        monkeypatch.setattr(
            macho_mod, "_MAX_STRTAB_SCAN_TOTAL_BYTES", len(strtab))
        p = tmp_path / "fat.bin"
        p.write_bytes(build_fat([inner, inner]))
        facts = extract_macho_facts(p)
        assert facts is not None and len(facts.slices) == 2
        first, second = facts.slices
        assert first.stack_canary_symbols == ["___stack_chk_fail"]
        assert second.stack_canary_symbols == []
        assert "symtab_strings_capped" in second.caps_hit

    def test_zero_strsize_claims_no_region(self, tmp_path):
        item, _ = _extract_one(
            _thin_with_strtab(b"", strsize=0), tmp_path)
        assert item.stack_canary_symbols == []
        assert "symtab_strings_unreadable" not in item.caps_hit
        assert "symtab_strings_capped" not in item.caps_hit

    def test_zero_stroff_with_declared_size_marks_unreadable(
            self, tmp_path):
        # LC_SYMTAB claiming a large string region AT OFFSET 0 (the
        # mach header, not a string table): the region is unscannable
        # and the refusal must be marker-visible — a silent return
        # would let a downstream canary derivation mistake the
        # unscanned symtab for a complete no-canary scan.
        blob = build_thin([symtab_cmd(nsyms=5, stroff=0,
                                      strsize=4096)])
        item, _ = _extract_one(blob, tmp_path)
        assert item.stack_canary_symbols == []
        assert "symtab_strings_unreadable" in item.caps_hit
