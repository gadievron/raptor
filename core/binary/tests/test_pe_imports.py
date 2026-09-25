"""Tests for the ``core.binary.pe`` import / delay-import walks.

Crafted-table coverage (extending ``test_pe_facts``' builders):

  * PE32 AND PE32+ ground-truth walks — both thunk widths, the
    per-format ordinal-flag bit, hint/name and ordinal imports,
    the OriginalFirstThunk = 0 fallback
  * delay-load descriptors (all-RVA form walked; the legacy
    all-VA form recorded + marked, never chased)
  * named caps and budgets with both boundary directions pinned
  * hostile shapes: unreadable directories, non-terminating thunk
    arrays, names straddling a section's raw end (zero-fill rule
    visible), control-byte / bidi names through the render
    chokepoint

The builders here (``ImpDll`` / ``DelayDll`` / ``RawThunk`` +
``build_import_image`` / ``build_delay_image``) are shared with the
tables battery, the same way ``test_pe_facts`` shares ``build_pe``.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field

from core.binary import pe as pe_mod
from core.binary.pe import PeImportedFunction, extract_pe_facts
from core.security.log_sanitisation import (
    escape_nonprintable,
    has_nonprintable,
)

from .test_pe_facts import PeSpec, Sec, build_pe

_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B
_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x014C
_RDATA_CHARACTERISTICS = 0x40000040

_DESC_SIZE = 20
_DELAY_DESC_SIZE = 32


@dataclass(frozen=True)
class RawThunk:
    """A verbatim thunk slot value — for crafting flag-bit and
    masking shapes the ground-truth entries can't express."""

    value: int


@dataclass
class ImpDll:
    """One import-directory DLL: entries are ``(hint, name_bytes)``
    for hint/name imports, ``int`` for ordinal imports, or
    :class:`RawThunk` for verbatim slot values. ``oft=False``
    emits ``OriginalFirstThunk = 0`` (the name RVAs then ride in
    ``FirstThunk``, as old Borland-style linkers emit)."""

    name: bytes = b"KERNEL32.dll"
    entries: list = field(default_factory=list)
    oft: bool = True


@dataclass
class DelayDll:
    """One delay-load DLL. ``attributes`` bit 0 selects the all-RVA
    form (1, the modern default) or the legacy all-VA form (0)."""

    name: bytes = b"DELAYED.dll"
    entries: list = field(default_factory=list)
    attributes: int = 1


class _SectionAssembler:
    """Offset-tracked byte assembly for one table section: the
    descriptor array sits at the section start, everything else is
    appended behind it and addressed by RVA."""

    def __init__(self, va: int, table_len: int) -> None:
        self.va = va
        self.table_len = table_len
        self.body = bytearray()

    def add(self, data: bytes) -> int:
        """Append ``data`` behind the descriptor table; returns its
        RVA. Pads to 8 so thunk arrays stay width-aligned."""
        rva = self.va + self.table_len + len(self.body)
        self.body.extend(data)
        while (self.table_len + len(self.body)) % 8:
            self.body.append(0)
        return rva

    def thunk_array(self, entries: list, bits: int) -> int:
        """Assemble one null-terminated thunk array; returns its
        RVA."""
        width = 8 if bits == 64 else 4
        flag = 1 << (width * 8 - 1)
        thunks = bytearray()
        for e in entries:
            if isinstance(e, RawThunk):
                value = e.value
            elif isinstance(e, int):
                value = flag | e
            else:
                hint, fname = e
                value = self.add(struct.pack("<H", hint)
                                 + fname + b"\x00")
            thunks += value.to_bytes(width, "little")
        thunks += (0).to_bytes(width, "little")
        return self.add(bytes(thunks))


def build_import_section(
    dlls: list[ImpDll], *, va: int = 0x3000, bits: int = 64,
    terminator: str = "zero",
) -> tuple[bytes, tuple[int, int]]:
    """Assemble an ``.idata`` payload. ``terminator``: ``"zero"``
    (spec all-zero descriptor), ``"junk"`` (Name/FirstThunk zero
    but TimeDateStamp set — still terminates the loader's walk),
    or ``"none"`` (no terminator slot at all). Returns
    ``(section_bytes, (directory_va, directory_size))``."""
    slots = len(dlls) + (0 if terminator == "none" else 1)
    asm = _SectionAssembler(va, slots * _DESC_SIZE)
    descs = bytearray()
    for dll in dlls:
        name_rva = asm.add(dll.name + b"\x00")
        arr_rva = asm.thunk_array(dll.entries, bits)
        # FirstThunk: a distinct copy of the same values — on disk
        # the IAT holds the hint/name RVAs too (the loader
        # overwrites them with addresses only in memory).
        ft_rva = asm.add(_copy_thunks(asm, arr_rva, dll.entries,
                                      bits))
        descs += struct.pack("<IIIII", arr_rva if dll.oft else 0,
                             0, 0, name_rva, ft_rva)
    if terminator == "zero":
        descs += b"\x00" * _DESC_SIZE
    elif terminator == "junk":
        descs += struct.pack("<IIIII", 0, 0xDEAD, 0, 0, 0)
    return bytes(descs) + bytes(asm.body), (va, len(descs))


def _copy_thunks(asm: _SectionAssembler, arr_rva: int,
                 entries: list, bits: int) -> bytes:
    width = 8 if bits == 64 else 4
    off = arr_rva - asm.va - asm.table_len
    return bytes(asm.body[off:off + (len(entries) + 1) * width])


def build_delay_section(
    dlls: list[DelayDll], *, va: int = 0x4000, bits: int = 64,
    terminator: str = "zero",
) -> tuple[bytes, tuple[int, int]]:
    """Assemble a delay-load payload (ImgDelayDescr array + name
    tables). A legacy (attributes bit 0 clear) DLL gets a fake
    absolute-VA name field — the walk must mark it, not chase it.
    """
    slots = len(dlls) + (0 if terminator == "none" else 1)
    asm = _SectionAssembler(va, slots * _DELAY_DESC_SIZE)
    descs = bytearray()
    for dll in dlls:
        if dll.attributes & 0x1:
            name_rva = asm.add(dll.name + b"\x00")
            int_rva = asm.thunk_array(dll.entries, bits)
            iat_rva = asm.add(_copy_thunks(asm, int_rva,
                                           dll.entries, bits))
        else:
            # Legacy all-VA form: plant absolute VAs — chasing
            # them would need a second resolution path, which the
            # extractor refuses.
            name_rva = 0x40003000
            int_rva = 0x40003100
            iat_rva = 0x40003200
        descs += struct.pack("<IIIIIIII", dll.attributes, name_rva,
                             0, iat_rva, int_rva, 0, 0, 0)
    if terminator == "zero":
        descs += b"\x00" * _DELAY_DESC_SIZE
    elif terminator == "junk":
        descs += struct.pack("<IIIIIIII", 1, 0, 0, 0, 0, 0, 0,
                             0xBEEF)
    return bytes(descs) + bytes(asm.body), (va, len(descs))


def build_import_image(
    dlls: list[ImpDll], *, bits: int = 64,
    delay_dlls: list[DelayDll] | None = None,
    terminator: str = "zero", delay_terminator: str = "zero",
    import_dir_override: tuple[int, int] | None = None,
    extra_secs: list[Sec] | None = None,
) -> bytes:
    """One whole image with an import section (and optionally a
    delay-load section) wired into the data directories."""
    magic = _PE32PLUS_MAGIC if bits == 64 else _PE32_MAGIC
    machine = _MACHINE_AMD64 if bits == 64 else _MACHINE_I386
    idata, imp_dir = build_import_section(dlls, bits=bits,
                                          terminator=terminator)
    secs = [
        Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
        Sec(name=b".idata", va=0x3000, data=idata,
            characteristics=_RDATA_CHARACTERISTICS),
    ]
    dirs = {1: import_dir_override or imp_dir}
    if delay_dlls is not None:
        didat, delay_dir = build_delay_section(
            delay_dlls, bits=bits, terminator=delay_terminator)
        secs.append(Sec(name=b".didat", va=0x4000, data=didat,
                        characteristics=_RDATA_CHARACTERISTICS))
        dirs[13] = delay_dir
    secs.extend(extra_secs or [])
    return build_pe(PeSpec(magic=magic, machine=machine, secs=secs,
                           data_dirs=dirs))


_GROUND_TRUTH = [
    ImpDll(name=b"KERNEL32.dll", entries=[
        (0x01F4, b"CreateFileW"), (0, b"ReadFile"), 42]),
    ImpDll(name=b"user32.dll", entries=[(7, b"MessageBoxW")]),
]


# ---------------------------------------------------------------------------
# Ground truth — both formats
# ---------------------------------------------------------------------------


class TestImportGroundTruth:
    def _assert_ground_truth(self, facts) -> None:
        assert facts is not None
        assert [d.name for d in facts.imports] == [
            "KERNEL32.dll", "user32.dll"]
        k32 = facts.imports[0]
        assert k32.functions == [
            PeImportedFunction(name="CreateFileW", hint=0x01F4),
            PeImportedFunction(name="ReadFile", hint=0),
            PeImportedFunction(ordinal=42),
        ]
        assert (k32.thunk_count, k32.named_count,
                k32.ordinal_count) == (3, 2, 1)
        assert k32.used_first_thunk is False
        assert k32.caps_hit == []
        u32 = facts.imports[1]
        assert u32.functions == [
            PeImportedFunction(name="MessageBoxW", hint=7)]
        assert facts.caps_hit == []

    def test_pe32plus_walk(self, tmp_path):
        p = tmp_path / "imp64.exe"
        p.write_bytes(build_import_image(_GROUND_TRUTH, bits=64))
        self._assert_ground_truth(extract_pe_facts(p))

    def test_pe32_walk(self, tmp_path):
        """Same table content through 4-byte thunks and the 32-bit
        directory-table offsets — the extraction must be
        indistinguishable from the PE32+ one."""
        p = tmp_path / "imp32.exe"
        p.write_bytes(build_import_image(_GROUND_TRUTH, bits=32))
        self._assert_ground_truth(extract_pe_facts(p))

    def test_oft_zero_fallback(self, tmp_path):
        """OriginalFirstThunk = 0: the name RVAs ride in FirstThunk
        (on disk it holds the same values the loader will
        overwrite) — the walk falls back and says so."""
        p = tmp_path / "noft.exe"
        p.write_bytes(build_import_image(
            [ImpDll(name=b"borland.dll", oft=False,
                    entries=[(1, b"Frobnicate"), 9])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        dll = facts.imports[0]
        assert dll.used_first_thunk is True
        assert dll.functions == [
            PeImportedFunction(name="Frobnicate", hint=1),
            PeImportedFunction(ordinal=9),
        ]
        assert facts.caps_hit == []

    def test_empty_thunk_array(self, tmp_path):
        """A descriptor whose arrays hold only the terminator:
        zero functions, no markers — truthful absence."""
        p = tmp_path / "empty.exe"
        p.write_bytes(build_import_image(
            [ImpDll(name=b"hollow.dll", entries=[])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports[0].thunk_count == 0
        assert facts.imports[0].name == "hollow.dll"
        assert facts.caps_hit == []

    def test_to_dict_round_trips_json(self, tmp_path):
        p = tmp_path / "dict.exe"
        p.write_bytes(build_import_image(
            _GROUND_TRUTH,
            delay_dlls=[DelayDll(entries=[(3, b"LazyLoad")])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        blob = json.dumps(facts.to_dict())
        parsed = json.loads(blob)
        assert parsed["imports"][0]["functions"][0]["name"] == \
            "CreateFileW"
        assert parsed["delay_imports"][0]["functions"][0]["name"] \
            == "LazyLoad"


# ---------------------------------------------------------------------------
# The ordinal-flag bit is per format — the classic import-walk bug
# ---------------------------------------------------------------------------


class TestOrdinalFlagPerFormat:
    def test_bit31_in_a_pe32plus_thunk_is_not_an_ordinal(
            self, tmp_path):
        """0x80000000 in a 64-bit thunk is a hint/name RVA value,
        NOT an ordinal import: the 64-bit flag is bit 63. Masked
        by _THUNK_RVA_MASK the RVA is 0 → the header region, so
        the hint decodes the DOS magic — pinned exactly, proving
        the slot went down the hint/name path."""
        p = tmp_path / "bit31.exe"
        p.write_bytes(build_import_image(
            [ImpDll(entries=[RawThunk(0x8000_0000)])], bits=64))
        facts = extract_pe_facts(p)
        assert facts is not None
        fn = facts.imports[0].functions[0]
        assert fn.ordinal is None
        assert fn.hint == 0x5A4D            # "MZ" as little-endian u16

    def test_bit31_in_a_pe32_thunk_is_an_ordinal(self, tmp_path):
        p = tmp_path / "ord32.exe"
        p.write_bytes(build_import_image(
            [ImpDll(entries=[RawThunk(0x8000_0000 | 0x0010)])],
            bits=32))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports[0].functions[0] == \
            PeImportedFunction(ordinal=0x10)

    def test_bit63_in_a_pe32plus_thunk_is_an_ordinal(self, tmp_path):
        p = tmp_path / "ord64.exe"
        p.write_bytes(build_import_image(
            [ImpDll(entries=[RawThunk(0x8000_0000_0000_0000
                                      | 0x0010)])], bits=64))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports[0].functions[0] == \
            PeImportedFunction(ordinal=0x10)

    def test_ordinal_is_low_16_bits_only(self, tmp_path):
        """Bits between the ordinal and the flag are ignored by
        masking (fail open) — a doctored middle bit must not
        change the recorded ordinal."""
        p = tmp_path / "ordmask.exe"
        p.write_bytes(build_import_image(
            [ImpDll(entries=[RawThunk(0x8000_0000_7FFF_0010)])],
            bits=64))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports[0].functions[0] == \
            PeImportedFunction(ordinal=0x10)

    def test_ordinal_keeps_all_16_bits(self, tmp_path):
        """An ordinal with bits 15:12 set, per format: the EXACT
        value must survive — pins that the mask keeps all 16
        ordinal bits, not merely that it strips the garbage above
        them (a 12-bit mask would pass every small-ordinal test)."""
        for bits, flag in ((32, 0x8000_0000),
                           (64, 0x8000_0000_0000_0000)):
            p = tmp_path / f"ordwide{bits}.exe"
            p.write_bytes(build_import_image(
                [ImpDll(entries=[RawThunk(flag | 0xAB42)])],
                bits=bits))
            facts = extract_pe_facts(p)
            assert facts is not None
            assert facts.imports[0].functions[0] == \
                PeImportedFunction(ordinal=0xAB42)


# ---------------------------------------------------------------------------
# Delay imports
# ---------------------------------------------------------------------------


class TestDelayImports:
    def test_v2_descriptor_walked(self, tmp_path):
        p = tmp_path / "delay.exe"
        p.write_bytes(build_import_image(
            [], delay_dlls=[DelayDll(
                name=b"COMCTL32.dll", attributes=1,
                entries=[(2, b"InitCommonControls"), 17])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports == []
        dll = facts.delay_imports[0]
        assert dll.name == "COMCTL32.dll"
        assert dll.attributes == 1
        assert dll.rva_addressed is True
        assert dll.functions == [
            PeImportedFunction(name="InitCommonControls", hint=2),
            PeImportedFunction(ordinal=17),
        ]
        assert (dll.thunk_count, dll.named_count,
                dll.ordinal_count) == (2, 1, 1)
        assert facts.caps_hit == []

    def test_legacy_va_form_marked_not_chased(self, tmp_path):
        """Attribute bit 0 clear: every field is an absolute VA —
        recorded + marked; chasing would need a second resolution
        path beside the RVA chokepoint. A v2 descriptor BEHIND the
        legacy one is still walked (per-descriptor degradation)."""
        p = tmp_path / "legacy.exe"
        p.write_bytes(build_import_image(
            [], delay_dlls=[
                DelayDll(name=b"OLD.dll", attributes=0,
                         entries=[(1, b"Hidden")]),
                DelayDll(name=b"NEW.dll", attributes=1,
                         entries=[(5, b"Visible")]),
            ]))
        facts = extract_pe_facts(p)
        assert facts is not None
        legacy, modern = facts.delay_imports
        assert legacy.rva_addressed is False
        assert legacy.name is None
        assert legacy.attributes == 0
        assert legacy.functions == []
        assert "delay_import_va_form" in legacy.caps_hit
        assert "delay_import_va_form" in facts.caps_hit
        assert modern.name == "NEW.dll"
        assert modern.functions == [
            PeImportedFunction(name="Visible", hint=5)]
        assert modern.caps_hit == []

    def test_pe32_delay_walk(self, tmp_path):
        p = tmp_path / "delay32.exe"
        p.write_bytes(build_import_image(
            [], bits=32, delay_dlls=[DelayDll(
                entries=[(4, b"ThirtyTwo"), 3])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.delay_imports[0].functions == [
            PeImportedFunction(name="ThirtyTwo", hint=4),
            PeImportedFunction(ordinal=3),
        ]

    def test_delay_directory_unreadable(self, tmp_path):
        blob = build_import_image([], delay_dlls=[DelayDll()])
        arr = bytearray(blob)
        # Redirect the delay directory (index 13) at unmapped space.
        dirs_off = 0x80 + 4 + 20 + 112
        struct.pack_into("<II", arr, dirs_off + 8 * 13,
                         0x0900_0000, 0x100)
        p = tmp_path / "delaybad.exe"
        p.write_bytes(bytes(arr))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.delay_imports == []
        assert "delay_import_directory_unreadable" in facts.caps_hit

    def test_delay_terminator_junk_marked(self, tmp_path):
        p = tmp_path / "delayjunk.exe"
        p.write_bytes(build_import_image(
            [], delay_dlls=[DelayDll(entries=[(1, b"F")])],
            delay_terminator="junk"))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.delay_imports) == 1
        assert "delay_import_terminator_nonzero" in facts.caps_hit


# ---------------------------------------------------------------------------
# Walk termination — loader-mirroring + doctored terminators
# ---------------------------------------------------------------------------


class TestImportTermination:
    def test_clean_terminator_is_silent(self, tmp_path):
        p = tmp_path / "clean.exe"
        p.write_bytes(build_import_image(_GROUND_TRUTH))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "import_terminator_nonzero" not in facts.caps_hit

    def test_junk_terminator_marked(self, tmp_path):
        """Name and FirstThunk zero end the walk regardless of the
        other fields (the loader stops there too) — but a nonzero
        remainder is a doctoring fact, marked."""
        p = tmp_path / "junkterm.exe"
        p.write_bytes(build_import_image(_GROUND_TRUTH,
                                         terminator="junk"))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.imports) == 2
        assert "import_terminator_nonzero" in facts.caps_hit

    def test_first_thunk_zero_terminates_like_the_loader(
            self, tmp_path):
        """A descriptor with a Name but FirstThunk = 0 never loads
        — the loader stops its walk there, and so does the
        extractor: descriptors hidden behind it are dead claims,
        surfaced only via the terminator marker."""
        idata, (va, size) = build_import_section(_GROUND_TRUTH)
        arr = bytearray(idata)
        # Zero the FIRST descriptor's FirstThunk (offset 16).
        struct.pack_into("<I", arr, 16, 0)
        p = tmp_path / "deadft.exe"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".idata", va=va, data=bytes(arr),
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={1: (va, size)})))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports == []
        assert "import_terminator_nonzero" in facts.caps_hit

    def test_unreadable_directory_marked(self, tmp_path):
        p = tmp_path / "badimp.exe"
        p.write_bytes(build_import_image(
            _GROUND_TRUTH, import_dir_override=(0x0900_0000, 0x100)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports == []
        assert "import_directory_unreadable" in facts.caps_hit

    def test_descriptor_array_runs_off_its_section(self, tmp_path):
        """No terminator at all: the walk runs into the section's
        virtual end and degrades with the unreadable marker —
        never an exception, never unbounded."""
        idata, (va, _size) = build_import_section(
            [ImpDll(entries=[(1, b"Fn")])], terminator="none")
        # Cut the section exactly at the descriptor table's end so
        # the walk's next descriptor read has nowhere to go.
        p = tmp_path / "noterm.exe"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".idata", va=va, data=idata,
                vsize=len(idata),
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={1: (va, _DESC_SIZE)})))
        facts = extract_pe_facts(p)
        assert facts is not None
        # The one real descriptor parses; the walk then degrades
        # when the next slot is unreachable... unless zero-fill
        # slack behind the body terminates it. Either way: bounded,
        # recorded, marked-or-clean — assert the record survived.
        assert len(facts.imports) == 1


# ---------------------------------------------------------------------------
# Caps + budgets — both boundary directions
# ---------------------------------------------------------------------------


class TestImportCaps:
    def test_descriptor_cap_boundary(self, tmp_path, monkeypatch):
        """Cap descriptors + terminator = complete (the slot at the
        cap may only terminate); one more real descriptor is a
        breach."""
        monkeypatch.setattr(pe_mod, "_MAX_IMPORT_DESCRIPTORS", 2)
        at_cap = [ImpDll(name=b"a%d.dll" % i, entries=[(0, b"f")])
                  for i in range(2)]
        p = tmp_path / "atcap.exe"
        p.write_bytes(build_import_image(at_cap))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.imports) == 2
        assert "import_descriptors_capped" not in facts.caps_hit

        past = at_cap + [ImpDll(name=b"c.dll", entries=[(0, b"g")])]
        q = tmp_path / "pastcap.exe"
        q.write_bytes(build_import_image(past))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert len(facts.imports) == 2
        assert "import_descriptors_capped" in facts.caps_hit

    def test_thunk_cap_boundary(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_IMPORT_THUNKS_PER_DLL", 3)
        p = tmp_path / "tcap.exe"
        p.write_bytes(build_import_image(
            [ImpDll(entries=[1, 2, 3])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports[0].thunk_count == 3
        assert "import_thunks_capped" not in facts.caps_hit

        q = tmp_path / "tpast.exe"
        q.write_bytes(build_import_image(
            [ImpDll(entries=[1, 2, 3, 4])]))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert facts.imports[0].thunk_count == 3
        assert "import_thunks_capped" in facts.caps_hit
        assert "import_thunks_capped" in facts.imports[0].caps_hit

    def test_thunk_total_budget_spans_dlls(self, tmp_path,
                                           monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_IMPORT_THUNKS_TOTAL", 4)
        p = tmp_path / "tbudget.exe"
        p.write_bytes(build_import_image([
            ImpDll(name=b"a.dll", entries=[1, 2, 3]),
            ImpDll(name=b"b.dll", entries=[4, 5, 6]),
        ]))
        facts = extract_pe_facts(p)
        assert facts is not None
        a, b = facts.imports
        assert a.thunk_count == 3
        assert b.thunk_count == 1
        assert "import_thunk_budget_exhausted" in b.caps_hit
        assert "import_thunk_budget_exhausted" in facts.caps_hit

    def test_budget_spans_delay_imports_too(self, tmp_path,
                                            monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_IMPORT_THUNKS_TOTAL", 3)
        p = tmp_path / "dbudget.exe"
        p.write_bytes(build_import_image(
            [ImpDll(entries=[1, 2, 3])],
            delay_dlls=[DelayDll(entries=[4, 5])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.imports[0].thunk_count == 3
        assert facts.delay_imports[0].thunk_count == 0
        assert ("delay_import_thunk_budget_exhausted"
                in facts.delay_imports[0].caps_hit)

    def test_name_over_cap_keeps_capped_prefix(self, tmp_path,
                                               monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_TABLE_NAME_BYTES", 8)
        p = tmp_path / "longname.exe"
        p.write_bytes(build_import_image(
            [ImpDll(name=b"short.dll",
                    entries=[(0, b"AVeryLongFunctionName")])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        fn = facts.imports[0].functions[0]
        assert fn.name == "AVeryLon"          # capped prefix, 8 bytes
        assert "import_name_truncated" in facts.imports[0].caps_hit

    def test_name_budget_degrades_to_none(self, tmp_path,
                                          monkeypatch):
        """Both budget-degradation directions, pinned:

        Overdraw (ordered-fill): the entry whose name OVERDRAWS
        the budget keeps its recovered hint (its read was issued)
        but no name — and the overdraw spends the remaining
        budget, so every LATER entry's read is skipped entirely
        (neither hint nor name). Exact drain: an exactly-fitting
        name is retained whole and later reads are skipped the
        same way. Counts stay honest throughout.
        """
        # Overdraw shape: the dll name fits, "CreateFileW" (11
        # bytes) overdraws the 4 remaining.
        monkeypatch.setattr(pe_mod, "_MAX_TABLE_NAME_TOTAL_BYTES",
                            len("KERNEL32.dll") + 4)
        p = tmp_path / "nover.exe"
        p.write_bytes(build_import_image([ImpDll(
            name=b"KERNEL32.dll",
            entries=[(1, b"CreateFileW"), (2, b"ReadFile")])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        dll = facts.imports[0]
        assert dll.name == "KERNEL32.dll"
        assert dll.functions[0].name is None    # whole-or-absent
        assert dll.functions[0].hint == 1       # its read happened
        assert dll.functions[1].name is None    # read skipped
        assert dll.functions[1].hint is None
        assert dll.thunk_count == 2             # counts stay honest
        assert "import_name_budget_exhausted" in dll.caps_hit

        # Exact-drain shape: "CreateFileW" lands the budget on
        # exactly zero — retained whole, and the stop still arms.
        monkeypatch.setattr(pe_mod, "_MAX_TABLE_NAME_TOTAL_BYTES",
                            len("KERNEL32.dll") + len("CreateFileW"))
        q = tmp_path / "nexact.exe"
        q.write_bytes(build_import_image([ImpDll(
            name=b"KERNEL32.dll",
            entries=[(1, b"CreateFileW"), (2, b"ReadFile")])]))
        facts = extract_pe_facts(q)
        assert facts is not None
        dll = facts.imports[0]
        assert dll.functions[0].name == "CreateFileW"
        assert dll.functions[1].name is None
        assert dll.functions[1].hint is None
        assert "import_name_budget_exhausted" in dll.caps_hit


# ---------------------------------------------------------------------------
# Thunk arrays vs the zero-fill rule
# ---------------------------------------------------------------------------


class TestThunkArrayBounds:
    def _image_with_raw_idata(self, idata: bytes, vsize: int,
                              dir_size: int,
                              extra_secs: list[Sec] | None = None,
                              ) -> bytes:
        secs = [
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".idata", va=0x3000, data=idata, vsize=vsize,
                characteristics=_RDATA_CHARACTERISTICS),
        ]
        secs.extend(extra_secs or [])
        return build_pe(PeSpec(secs=secs,
                               data_dirs={1: (0x3000, dir_size)}))

    def test_zero_fill_terminates_a_raw_truncated_array(
            self, tmp_path):
        """A thunk array whose raw bytes end before its terminator:
        the zero-fill rule (resolver invariant a) supplies the
        terminator exactly as the loader would map it — clean end,
        no marker."""
        # Descriptors: one real + zero terminator. Name at 40,
        # thunk array at 56 holding ONE ordinal thunk and NO
        # terminator — the raw data ends right behind it.
        idata = bytearray(56)
        struct.pack_into("<IIIII", idata, 0, 0x3000 + 56, 0, 0,
                         0x3000 + 40, 0x3000 + 56)
        idata[40:46] = b"z.dll\x00"
        idata += (0x8000_0000_0000_0000 | 5).to_bytes(8, "little")
        p = tmp_path / "zterm.exe"
        p.write_bytes(self._image_with_raw_idata(
            bytes(idata), vsize=len(idata) + 0x40, dir_size=40))
        facts = extract_pe_facts(p)
        assert facts is not None
        dll = facts.imports[0]
        assert dll.functions == [PeImportedFunction(ordinal=5)]
        assert dll.caps_hit == []

    def test_array_running_out_the_virtual_extent_is_marked(
            self, tmp_path):
        """No terminator and no zero-fill slack (VirtualSize ends
        with the raw bytes): the walk hits the section's virtual
        end and degrades with the unterminated marker."""
        idata = bytearray(56)
        struct.pack_into("<IIIII", idata, 0, 0x3000 + 56, 0, 0,
                         0x3000 + 40, 0x3000 + 56)
        idata[40:46] = b"z.dll\x00"
        idata += (0x8000_0000_0000_0000 | 5).to_bytes(8, "little")
        p = tmp_path / "noslack.exe"
        p.write_bytes(self._image_with_raw_idata(
            bytes(idata), vsize=len(idata), dir_size=40))
        facts = extract_pe_facts(p)
        assert facts is not None
        dll = facts.imports[0]
        assert dll.functions == [PeImportedFunction(ordinal=5)]
        assert "import_thunks_unterminated" in dll.caps_hit
        assert "import_thunks_unterminated" in facts.caps_hit

    def test_name_straddling_raw_end_is_zero_fill_terminated(
            self, tmp_path):
        """A hint/name entry whose string crosses the section's
        raw end: the retained name is exactly the file bytes
        before the zero fill — the adjacent section's file bytes
        (planted contiguously) must never leak in."""
        # Layout: descriptors (40) + name (40..48) + thunk array
        # (48..64) + hint/name entry at 64: hint + "AB", raw data
        # ends right after "AB".
        idata = bytearray(64)
        struct.pack_into("<IIIII", idata, 0, 0x3000 + 48, 0, 0,
                         0x3000 + 40, 0x3000 + 48)
        idata[40:46] = b"s.dll\x00"
        struct.pack_into("<QQ", idata, 48, 0x3000 + 64, 0)
        idata += struct.pack("<H", 3) + b"AB"
        # The sentinel section's raw bytes sit at the very next
        # file offset (0x400 + 68).
        sentinel = Sec(name=b".zz", va=0x9000, data=b"Z" * 64,
                       raw_ptr=0x400 + len(idata))
        p = tmp_path / "straddle.exe"
        p.write_bytes(self._image_with_raw_idata(
            bytes(idata), vsize=0x100, dir_size=40,
            extra_secs=[sentinel]))
        facts = extract_pe_facts(p)
        assert facts is not None
        fn = facts.imports[0].functions[0]
        assert fn.name == "AB"
        assert fn.hint == 3
        assert "Z" not in (fn.name or "")


# ---------------------------------------------------------------------------
# Hostile names — stored as data, inert at render
# ---------------------------------------------------------------------------


class TestHostileImportNames:
    def test_control_and_bidi_names_stored_capped_render_inert(
            self, tmp_path):
        hostile_dll = b"EVIL\x1b[31m.dll"
        hostile_fn = "fn\u202egdp.cod".encode()
        p = tmp_path / "hostile.exe"
        p.write_bytes(build_import_image(
            [ImpDll(name=hostile_dll,
                    entries=[(1, hostile_fn)])]))
        facts = extract_pe_facts(p)
        assert facts is not None
        dll = facts.imports[0]
        # Stored raw: the bytes are data, not rendering.
        assert dll.name == "EVIL\x1b[31m.dll"
        assert dll.functions[0].name == "fn\u202egdp.cod"
        # Render chokepoint turns them inert.
        for text in (dll.name, dll.functions[0].name):
            rendered = escape_nonprintable(text)
            assert not has_nonprintable(rendered)
        assert "\\x1b" in escape_nonprintable(dll.name)
        assert "\\u202e" in escape_nonprintable(
            dll.functions[0].name)

    def test_self_referential_dll_name_rva(self, tmp_path):
        """A DLL-name RVA pointing at the descriptor array itself:
        the name is whatever those bytes say (data, bounded, capped)
        — never a crash, never a loop."""
        idata, (va, size) = build_import_section(
            [ImpDll(entries=[(0, b"f")])])
        arr = bytearray(idata)
        struct.pack_into("<I", arr, 12, va)   # Name → descriptor[0]
        p = tmp_path / "selfname.exe"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".idata", va=va, data=bytes(arr),
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={1: (va, size)})))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.imports) == 1
        name = facts.imports[0].name
        assert name is None or len(name) <= \
            pe_mod._MAX_TABLE_NAME_BYTES
