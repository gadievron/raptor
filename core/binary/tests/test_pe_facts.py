"""Tests for ``core.binary.pe.extract_pe_facts`` — the shallow PE
header / layout facts extractor.

Crafted-PE coverage (pure-python byte assembly, no toolchain):

  * Well-formed extraction per fact (machine/arch, bits FROM THE
    OPTIONAL-HEADER MAGIC, subsystem, characteristics and
    DLL-characteristics mitigation booleans, section table,
    SizeOfHeaders, entrypoint)
  * Fail-open enum handling (unknown machine / subsystem /
    optional magic record the raw value, never raise)
  * Malformed headers — whole-parse ``None`` up to the COFF
    header, per-field degradation + ``caps_hit`` markers after it

The crafted builders here are shared by the resolver and hostile
suites (mirroring how ``test_elf_facts`` shares ``test_elf``'s
builders).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from core.binary import pe as pe_mod
from core.binary.pe import extract_pe_facts, is_pe

_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B
_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x014C

# IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
_TEXT_CHARACTERISTICS = 0x60000020
# IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
_RDATA_CHARACTERISTICS = 0x40000040

_FILE_ALIGN = 0x200
_DEFAULT_SIZE_OF_HEADERS = 0x400


@dataclass
class Sec:
    """One crafted section: header claims + raw file bytes.

    ``vsize`` / ``raw_size`` default to ``len(data)``; override
    them to craft VirtualSize/SizeOfRawData skew. ``raw_ptr`` is
    auto-assigned file-alignment-sequentially when ``None``.
    """

    name: bytes = b".text"
    va: int = 0x1000
    data: bytes = b""
    vsize: int | None = None
    raw_size: int | None = None
    raw_ptr: int | None = None
    characteristics: int = _TEXT_CHARACTERISTICS


def _optional_header(
    *,
    magic: int = _PE32PLUS_MAGIC,
    entrypoint: int = 0x1000,
    image_base: int = 0x140000000,
    size_of_image: int = 0x5000,
    size_of_headers: int = _DEFAULT_SIZE_OF_HEADERS,
    subsystem: int = 3,
    dll_characteristics: int = 0,
    data_dirs: dict[int, tuple[int, int]] | None = None,
    n_dirs: int = 16,
    n_dirs_claimed: int | None = None,
) -> bytes:
    """Assemble a PE32 / PE32+ optional header by field offset."""
    if magic == _PE32PLUS_MAGIC:
        base_size, dirs_off = 112, 112
    else:
        base_size, dirs_off = 96, 96
    buf = bytearray(base_size + n_dirs * 8)
    struct.pack_into("<H", buf, 0, magic)
    struct.pack_into("<I", buf, 16, entrypoint)
    if magic == _PE32PLUS_MAGIC:
        struct.pack_into("<Q", buf, 24, image_base)
    else:
        # PE32 (and unknown-magic layouts, where the field is
        # ignored by the parser): the base must fit u32.
        if image_base > 0xFFFFFFFF:
            image_base = 0x400000
        struct.pack_into("<I", buf, 28, image_base)
    struct.pack_into("<I", buf, 32, 0x1000)        # SectionAlignment
    struct.pack_into("<I", buf, 36, _FILE_ALIGN)   # FileAlignment
    struct.pack_into("<I", buf, 56, size_of_image)
    struct.pack_into("<I", buf, 60, size_of_headers)
    struct.pack_into("<H", buf, 68, subsystem)
    struct.pack_into("<H", buf, 70, dll_characteristics)
    claimed = n_dirs if n_dirs_claimed is None else n_dirs_claimed
    struct.pack_into("<I", buf, dirs_off - 4, claimed)
    for idx, (va, size) in (data_dirs or {}).items():
        struct.pack_into("<II", buf, dirs_off + 8 * idx, va, size)
    return bytes(buf)


@dataclass
class PeSpec:
    """Knobs for :func:`build_pe`. Every override exists to craft
    one hostile shape; defaults produce a clean minimal image."""

    machine: int = _MACHINE_AMD64
    magic: int = _PE32PLUS_MAGIC
    characteristics: int = 0x0022      # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    dll_characteristics: int = 0
    subsystem: int = 3
    entrypoint: int = 0x1000
    size_of_headers: int = _DEFAULT_SIZE_OF_HEADERS
    e_lfanew: int = 0x80
    timestamp: int = 0
    secs: list[Sec] = field(default_factory=list)
    data_dirs: dict[int, tuple[int, int]] = field(default_factory=dict)
    n_dirs: int = 16
    n_dirs_claimed: int | None = None
    n_sections_claimed: int | None = None
    size_of_optional_claimed: int | None = None
    optional_header: bytes | None = None
    overlay: bytes = b""


def build_pe(spec: PeSpec | None = None, **overrides) -> bytes:
    """Assemble a whole PE image from a :class:`PeSpec` (or from
    keyword overrides over the default spec)."""
    if spec is None:
        spec = PeSpec(**overrides)
    secs = spec.secs

    opt = spec.optional_header
    if opt is None:
        opt = _optional_header(
            magic=spec.magic,
            entrypoint=spec.entrypoint,
            size_of_headers=spec.size_of_headers,
            subsystem=spec.subsystem,
            dll_characteristics=spec.dll_characteristics,
            data_dirs=spec.data_dirs,
            n_dirs=spec.n_dirs,
            n_dirs_claimed=spec.n_dirs_claimed,
        )
    size_of_optional = (len(opt) if spec.size_of_optional_claimed is None
                        else spec.size_of_optional_claimed)
    n_sections = (len(secs) if spec.n_sections_claimed is None
                  else spec.n_sections_claimed)

    # Auto-assign raw pointers after the headers, file-aligned.
    cursor = spec.size_of_headers
    placed: list[tuple[Sec, int, int]] = []   # (sec, raw_ptr, raw_size)
    for sec in secs:
        raw_size = len(sec.data) if sec.raw_size is None else sec.raw_size
        raw_ptr = cursor if sec.raw_ptr is None else sec.raw_ptr
        if sec.raw_ptr is None and raw_size:
            cursor = raw_ptr + raw_size
            cursor += (-cursor) % _FILE_ALIGN
        placed.append((sec, raw_ptr, raw_size))

    table = bytearray()
    for sec, raw_ptr, raw_size in placed:
        vsize = len(sec.data) if sec.vsize is None else sec.vsize
        table += struct.pack(
            "<8sIIIIIIHHI",
            sec.name[:8].ljust(8, b"\x00"),
            vsize, sec.va, raw_size, raw_ptr, 0, 0, 0, 0,
            sec.characteristics,
        )

    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, spec.e_lfanew)

    coff = struct.pack(
        "<HHIIIHH",
        spec.machine, n_sections, spec.timestamp, 0, 0,
        size_of_optional, spec.characteristics,
    )

    blob = bytearray(dos)
    blob += b"\x00" * (spec.e_lfanew - len(blob))
    blob += b"PE\x00\x00" + coff + opt + table
    if len(blob) < spec.size_of_headers:
        blob += b"\x00" * (spec.size_of_headers - len(blob))
    for sec, raw_ptr, raw_size in placed:
        if not sec.data:
            continue        # a claim-only section places no bytes
        end = raw_ptr + len(sec.data)
        if len(blob) < end:
            blob += b"\x00" * (end - len(blob))
        blob[raw_ptr:raw_ptr + len(sec.data)] = sec.data
    return bytes(blob) + spec.overlay


def _standard_spec(**overrides) -> PeSpec:
    """A clean two-section image exercising every header fact."""
    defaults = dict(
        dll_characteristics=0x0160,   # HIGH_ENTROPY_VA | DYNAMIC_BASE | NX
        secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x200),
            Sec(name=b".rdata", va=0x2000, data=b"R" * 0x80,
                characteristics=_RDATA_CHARACTERISTICS),
        ],
    )
    defaults.update(overrides)
    return PeSpec(**defaults)


# ---------------------------------------------------------------------------
# Well-formed extraction
# ---------------------------------------------------------------------------


class TestWellFormed:
    def test_header_facts_pe32plus(self, tmp_path):
        p = tmp_path / "clean.exe"
        p.write_bytes(build_pe(_standard_spec()))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.binary_format == "pe"
        assert facts.machine == _MACHINE_AMD64
        assert facts.arch == "x86"
        assert facts.bits == 64
        assert facts.pe_format == "pe32+"
        assert facts.optional_magic == _PE32PLUS_MAGIC
        assert facts.subsystem == 3
        assert facts.subsystem_name == "windows_cui"
        assert facts.entrypoint == 0x1000
        assert facts.image_base == 0x140000000
        assert facts.size_of_headers == _DEFAULT_SIZE_OF_HEADERS
        assert facts.is_executable_image is True
        assert facts.is_dll is False
        assert facts.caps_hit == []

    def test_mitigation_booleans(self, tmp_path):
        p = tmp_path / "mitig.exe"
        p.write_bytes(build_pe(_standard_spec(
            dll_characteristics=0x4160)))   # + GUARD_CF
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.dll_characteristics == 0x4160
        assert facts.aslr is True
        assert facts.high_entropy_va is True
        assert facts.dep is True
        assert facts.cfg is True

        q = tmp_path / "none.exe"
        q.write_bytes(build_pe(_standard_spec(dll_characteristics=0)))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert (facts.aslr, facts.high_entropy_va, facts.dep,
                facts.cfg) == (False, False, False, False)

    def test_section_table(self, tmp_path):
        p = tmp_path / "secs.exe"
        p.write_bytes(build_pe(_standard_spec()))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.declared_section_count == 2
        assert [s.name for s in facts.sections] == [".text", ".rdata"]
        text = facts.sections[0]
        assert text.virtual_address == 0x1000
        assert text.virtual_size == 0x200
        assert text.raw_size == 0x200
        assert text.raw_offset == _DEFAULT_SIZE_OF_HEADERS
        assert text.characteristics == _TEXT_CHARACTERISTICS
        assert facts.sections[1].characteristics == _RDATA_CHARACTERISTICS

    def test_pe32_twin(self, tmp_path):
        p = tmp_path / "clean32.exe"
        p.write_bytes(build_pe(_standard_spec(
            machine=_MACHINE_I386, magic=_PE32_MAGIC)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.bits == 32
        assert facts.pe_format == "pe32"
        assert facts.arch == "x86"
        assert facts.entrypoint == 0x1000
        # ImageBase sits at a DIFFERENT offset in the PE32 layout
        # (28, u32) than PE32+ (24, u64) — the exact value pins the
        # offset arithmetic, not just the magic dispatch.
        assert facts.image_base == 0x400000
        assert facts.size_of_headers == _DEFAULT_SIZE_OF_HEADERS
        assert facts.caps_hit == []

    def test_dll_bit(self, tmp_path):
        p = tmp_path / "lib.dll"
        p.write_bytes(build_pe(_standard_spec(characteristics=0x2022)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.is_dll is True

    def test_timestamp_recorded(self, tmp_path):
        p = tmp_path / "stamp.exe"
        p.write_bytes(build_pe(_standard_spec(timestamp=0x5F0A1B2C)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.timestamp == 0x5F0A1B2C

    def test_is_pe(self, tmp_path):
        p = tmp_path / "yes.exe"
        p.write_bytes(build_pe(_standard_spec()))
        assert is_pe(p) is True
        q = tmp_path / "no.bin"
        q.write_bytes(b"MZ" + b"\x00" * 200)      # MZ but no PE sig
        assert is_pe(q) is False
        assert is_pe(tmp_path / "absent") is False

    def test_is_pe_bounded_like_the_extractor(self, tmp_path):
        """A file truncated right at the PE signature is not 'a PE'
        for the probe either: it demands the COFF header fit, so
        is_pe and extract_pe_facts never disagree on truncated
        headers."""
        blob = build_pe(_standard_spec())
        p = tmp_path / "sigonly.exe"
        p.write_bytes(blob[:0x84])         # MZ + sig, no COFF header
        assert is_pe(p) is False
        assert extract_pe_facts(p) is None


# ---------------------------------------------------------------------------
# Bits come from the optional-header magic, never the machine field
# ---------------------------------------------------------------------------


class TestBitsFromMagic:
    def test_amd64_machine_with_pe32_magic_is_32(self, tmp_path):
        p = tmp_path / "lie64.exe"
        p.write_bytes(build_pe(_standard_spec(
            machine=_MACHINE_AMD64, magic=_PE32_MAGIC)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.bits == 32
        assert facts.pe_format == "pe32"
        assert facts.machine == _MACHINE_AMD64   # both recorded

    def test_i386_machine_with_pe32plus_magic_is_64(self, tmp_path):
        p = tmp_path / "lie32.exe"
        p.write_bytes(build_pe(_standard_spec(
            machine=_MACHINE_I386, magic=_PE32PLUS_MAGIC)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.bits == 64
        assert facts.pe_format == "pe32+"
        assert facts.machine == _MACHINE_I386


# ---------------------------------------------------------------------------
# Fail-open enum handling — raw value recorded, never raised on
# ---------------------------------------------------------------------------


class TestFailOpenEnums:
    def test_unknown_machine(self, tmp_path):
        p = tmp_path / "exotic.exe"
        p.write_bytes(build_pe(_standard_spec(machine=0xBEEF)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.arch == "unknown"
        assert facts.machine == 0xBEEF
        assert facts.bits == 64                  # magic still decodes

    def test_unknown_subsystem(self, tmp_path):
        p = tmp_path / "oddsub.exe"
        p.write_bytes(build_pe(_standard_spec(subsystem=0x7777)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.subsystem == 0x7777
        assert facts.subsystem_name is None
        assert facts.caps_hit == []              # not a gap, a fact

    def test_unknown_optional_magic(self, tmp_path):
        """ROM / hostile magic: the layout is unknown, so optional
        fields stay default with a marker — but the section table
        (positioned by the DECLARED SizeOfOptionalHeader) still
        parses."""
        p = tmp_path / "rom.exe"
        p.write_bytes(build_pe(_standard_spec(magic=0x107)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.optional_magic == 0x107
        assert facts.bits == 0
        assert facts.pe_format is None
        assert "optional_magic_unknown" in facts.caps_hit
        assert [s.name for s in facts.sections] == [".text", ".rdata"]


# ---------------------------------------------------------------------------
# Whole-parse refusals — not a usable PE at all
# ---------------------------------------------------------------------------


class TestWholeParseRefusals:
    def test_non_pe_inputs(self, tmp_path):
        p = tmp_path / "text"
        p.write_bytes(b"plain text, no magic")
        assert extract_pe_facts(p) is None
        assert extract_pe_facts(tmp_path / "absent") is None
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        assert extract_pe_facts(empty) is None

    def test_elf_is_not_pe(self, tmp_path):
        p = tmp_path / "elf"
        p.write_bytes(b"\x7fELF" + b"\x00" * 64)
        assert extract_pe_facts(p) is None

    def test_e_lfanew_past_eof(self, tmp_path):
        blob = bytearray(build_pe(_standard_spec()))
        struct.pack_into("<I", blob, 0x3C, len(blob) + 100)
        p = tmp_path / "farlfanew.exe"
        p.write_bytes(bytes(blob))
        assert extract_pe_facts(p) is None

    def test_e_lfanew_u32_max(self, tmp_path):
        blob = bytearray(build_pe(_standard_spec()))
        struct.pack_into("<I", blob, 0x3C, 2**32 - 1)
        p = tmp_path / "maxlfanew.exe"
        p.write_bytes(bytes(blob))
        assert extract_pe_facts(p) is None

    def test_bad_pe_signature(self, tmp_path):
        blob = bytearray(build_pe(_standard_spec()))
        blob[0x80:0x84] = b"PF\x00\x00"
        p = tmp_path / "badsig.exe"
        p.write_bytes(bytes(blob))
        assert extract_pe_facts(p) is None

    def test_truncated_coff_header(self, tmp_path):
        blob = build_pe(_standard_spec())
        p = tmp_path / "shortcoff.exe"
        p.write_bytes(blob[:0x84 + 10])          # sig + half the COFF
        assert extract_pe_facts(p) is None


# ---------------------------------------------------------------------------
# Per-field degradation — markers, never silent
# ---------------------------------------------------------------------------


class TestDegradedOptionalHeader:
    def test_optional_header_missing(self, tmp_path):
        p = tmp_path / "coffobj.exe"
        p.write_bytes(build_pe(_standard_spec(
            optional_header=b"", secs=[])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "optional_header_missing" in facts.caps_hit
        assert facts.bits == 0
        assert facts.machine == _MACHINE_AMD64    # COFF facts survive

    def test_optional_header_truncated_short_buffer(self, tmp_path):
        """SizeOfOptionalHeader cuts the header at 40 bytes: magic,
        entrypoint and image base decode; everything past the cut is
        a recorded gap and the section table still parses (it sits
        at the DECLARED distance)."""
        full = _optional_header(magic=_PE32PLUS_MAGIC,
                                dll_characteristics=0x0160)
        p = tmp_path / "shortopt.exe"
        p.write_bytes(build_pe(_standard_spec(
            optional_header=full[:40])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "optional_header_truncated" in facts.caps_hit
        assert facts.bits == 64
        assert facts.entrypoint == 0x1000
        assert facts.image_base == 0x140000000
        assert facts.size_of_headers == 0          # past the cut
        assert facts.dll_characteristics == 0
        assert [s.name for s in facts.sections] == [".text", ".rdata"]

    def test_optional_header_claim_past_eof(self, tmp_path):
        """SizeOfOptionalHeader claims more bytes than the file has
        — the short read is a marker, not a crash."""
        spec = _standard_spec(secs=[])
        blob = build_pe(spec)
        blob = blob[:0x98]                       # cut inside the optional
        blob_arr = bytearray(blob)
        p = tmp_path / "optpasteof.exe"
        p.write_bytes(bytes(blob_arr))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "optional_header_truncated" in facts.caps_hit


class TestSectionTable:
    def test_truncated_table_keeps_prefix(self, tmp_path):
        """Declared 4 sections, file carries 2 — the parsed prefix
        is kept and the truncation is a marker."""
        spec = _standard_spec(n_sections_claimed=4)
        blob = build_pe(spec)
        # The builder wrote 2 real entries; the claim of 4 reads
        # into header padding... craft harder: cut the file right
        # after the two real entries so the table read hits EOF.
        table_off = 0x80 + 4 + 20 + (112 + 16 * 8)
        p = tmp_path / "shorttable.exe"
        p.write_bytes(blob[:table_off + 2 * 40])
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.sections) == 2
        assert facts.declared_section_count == 4
        assert "section_table_truncated" in facts.caps_hit

    def test_section_flood_capped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_SECTIONS", 2)
        secs = [Sec(name=b".s%d" % i, va=0x1000 * (i + 1),
                    data=b"x" * 16) for i in range(5)]
        p = tmp_path / "flood.exe"
        p.write_bytes(build_pe(_standard_spec(secs=secs)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.sections) == 2
        assert facts.declared_section_count == 5
        assert "section_table_capped" in facts.caps_hit

    def test_section_count_at_cap_boundary_is_clean(self, tmp_path,
                                                    monkeypatch):
        """Exactly at the cap → no marker; one past → marker. Both
        directions of the boundary pinned."""
        monkeypatch.setattr(pe_mod, "_MAX_SECTIONS", 3)
        secs = [Sec(name=b".s%d" % i, va=0x1000 * (i + 1),
                    data=b"x" * 16) for i in range(3)]
        p = tmp_path / "atcap.exe"
        p.write_bytes(build_pe(_standard_spec(secs=secs)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.sections) == 3
        assert "section_table_capped" not in facts.caps_hit

        secs.append(Sec(name=b".s3", va=0x5000, data=b"x" * 16))
        q = tmp_path / "pastcap.exe"
        q.write_bytes(build_pe(_standard_spec(secs=secs)))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert len(facts.sections) == 3
        assert "section_table_capped" in facts.caps_hit

    def test_full_8_byte_name_no_terminator(self, tmp_path):
        """A full-width name has no NUL — well-formed, captured
        whole, never read past the 8-byte field."""
        p = tmp_path / "fullname.exe"
        p.write_bytes(build_pe(_standard_spec(
            secs=[Sec(name=b"ABCDEFGH", va=0x1000, data=b"x" * 16)])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.sections[0].name == "ABCDEFGH"

    def test_non_utf8_name_replaced_not_fatal(self, tmp_path):
        p = tmp_path / "rawname.exe"
        p.write_bytes(build_pe(_standard_spec(
            secs=[Sec(name=b"\xff\xfeAB", va=0x1000, data=b"x" * 16)])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "AB" in facts.sections[0].name
        assert len(facts.sections[0].name.encode(
            "utf-8", "replace")) <= 16   # 2 replacement chars + text

    def test_hostile_name_is_stored_raw(self, tmp_path):
        """Control bytes in a section name come back as data — no
        crash, no silent munging; escaping is the RENDER boundary's
        job (see the hostile suite for the render contract)."""
        p = tmp_path / "escname.exe"
        p.write_bytes(build_pe(_standard_spec(
            secs=[Sec(name=b"\x1b[31mX", va=0x1000, data=b"x" * 16)])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.sections[0].name == "\x1b[31mX"


# ---------------------------------------------------------------------------
# Per-section entropy — raw numbers, bounded reads, deterministic
# ---------------------------------------------------------------------------


class TestSectionEntropy:
    def test_known_values(self, tmp_path):
        p = tmp_path / "entropy.exe"
        p.write_bytes(build_pe(_standard_spec(secs=[
            Sec(name=b".zeros", va=0x1000, data=b"\x00" * 1024),
            Sec(name=b".cycle", va=0x2000, data=bytes(range(256)) * 4),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        by_name = {s.name: s for s in facts.sections}
        assert by_name[".zeros"].entropy == 0.0
        assert by_name[".cycle"].entropy == 8.0
        assert by_name[".zeros"].raw_size == 1024
        assert by_name[".zeros"].sampled == 1024

    def test_deterministic(self, tmp_path):
        p = tmp_path / "det.exe"
        p.write_bytes(build_pe(_standard_spec()))
        a = extract_pe_facts(p)
        b = extract_pe_facts(p)
        assert a is not None and b is not None
        assert a.sections == b.sections

    def test_sample_window_recorded(self, tmp_path, monkeypatch):
        """A section larger than the window is sampled, and the
        record SAYS so (sampled < raw_size)."""
        monkeypatch.setattr(pe_mod, "_MAX_ENTROPY_SECTION_BYTES", 16)
        p = tmp_path / "window.exe"
        p.write_bytes(build_pe(_standard_spec(secs=[
            Sec(name=b".big", va=0x1000, data=bytes(range(256))),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        rec = facts.sections[0]
        assert rec.raw_size == 256 and rec.sampled == 16
        assert rec.entropy == 4.0                # 16 distinct bytes

    def test_total_budget_capped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_ENTROPY_TOTAL_BYTES", 8)
        p = tmp_path / "budget.exe"
        p.write_bytes(build_pe(_standard_spec(secs=[
            Sec(name=b".one", va=0x1000, data=b"x" * 64),
            Sec(name=b".two", va=0x2000, data=b"y" * 64),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "entropy_budget_exhausted" in facts.caps_hit
        by_name = {s.name: s for s in facts.sections}
        # The row survives; only the measurement is skipped.
        assert by_name[".two"].entropy is None
        assert by_name[".two"].sampled == 0
        # The budget participates in the read bound itself: the
        # first section is clipped to it, not read whole.
        assert by_name[".one"].sampled == 8

    def test_measured_count_capped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_ENTROPY_SECTIONS", 1)
        p = tmp_path / "count.exe"
        p.write_bytes(build_pe(_standard_spec(secs=[
            Sec(name=b".one", va=0x1000, data=b"x" * 8),
            Sec(name=b".two", va=0x2000, data=b"y" * 8),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert len(facts.sections) == 2          # rows never dropped
        assert facts.sections[0].entropy is not None
        assert facts.sections[1].entropy is None
        assert "entropy_sections_capped" in facts.caps_hit

    def test_raw_offset_past_eof_marked(self, tmp_path):
        p = tmp_path / "ghost.exe"
        p.write_bytes(build_pe(_standard_spec(secs=[
            Sec(name=b".ghost", va=0x1000, data=b"", raw_size=64,
                raw_ptr=0x40000000),
            Sec(name=b".real", va=0x2000, data=b"payload!"),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        by_name = {s.name: s for s in facts.sections}
        assert by_name[".ghost"].entropy is None
        assert by_name[".real"].entropy is not None
        assert "section_data_unreadable" in facts.caps_hit

    def test_offset_screen_degrades_one_measurement(self, tmp_path,
                                                    monkeypatch):
        """A raw pointer past the seek screen degrades that ONE
        measurement with a marker — the walk and the record survive.
        (u32 fields cannot genuinely exceed 2**62, so the screen is
        exercised by lowering it: the marker path must hold if the
        arithmetic around it ever changes.)"""
        monkeypatch.setattr(pe_mod, "_MAX_SEEK_OFFSET", 0x500)
        p = tmp_path / "screen.exe"
        p.write_bytes(build_pe(_standard_spec(secs=[
            Sec(name=b".near", va=0x1000, data=b"payload!"),   # @0x400
            Sec(name=b".far", va=0x2000, data=b"q" * 16,
                raw_ptr=0x600),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        by_name = {s.name: s for s in facts.sections}
        assert by_name[".near"].entropy is not None
        assert by_name[".far"].entropy is None
        assert "section_data_unreadable" in facts.caps_hit

    def test_no_raw_bytes_is_not_a_gap(self, tmp_path):
        """A bss-style section (VirtualSize > 0, SizeOfRawData 0)
        occupies no file bytes — entropy None WITHOUT a marker:
        truthful absence, not degradation."""
        p = tmp_path / "bss.exe"
        p.write_bytes(build_pe(_standard_spec(secs=[
            Sec(name=b".bss", va=0x1000, data=b"", vsize=0x2000,
                raw_size=0, raw_ptr=0),
        ])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.sections[0].entropy is None
        assert facts.sections[0].sampled == 0
        assert "section_data_unreadable" not in facts.caps_hit


# ---------------------------------------------------------------------------
# Cap parity with the ELF tier
# ---------------------------------------------------------------------------


class TestCapParityWithElf:
    def test_shared_bounds_match_the_elf_tier(self):
        """The entropy caps and the seek screen are VALUE-COUPLED to
        the ELF facts extractor: a consumer comparing elf/pe records
        must never read a cap difference as a content difference.
        Change both modules together, or split them here
        deliberately with a recorded reason."""
        from core.binary import elf as elf_mod
        assert (pe_mod._MAX_ENTROPY_SECTION_BYTES
                == elf_mod._MAX_ENTROPY_SECTION_BYTES)
        assert (pe_mod._MAX_ENTROPY_TOTAL_BYTES
                == elf_mod._MAX_ENTROPY_TOTAL_BYTES)
        assert (pe_mod._MAX_ENTROPY_SECTIONS
                == elf_mod._MAX_ENTROPY_SECTIONS)
        assert pe_mod._MAX_SEEK_OFFSET == elf_mod._MAX_SEEK_OFFSET


# ---------------------------------------------------------------------------
# Overlay — bytes past every mapped extent
# ---------------------------------------------------------------------------


class TestOverlay:
    def test_clean_image_has_no_overlay(self, tmp_path):
        p = tmp_path / "clean.exe"
        p.write_bytes(build_pe(_standard_spec()))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.overlay_present is False
        assert facts.overlay_offset is None
        assert facts.overlay_size == 0

    def test_appended_overlay_detected(self, tmp_path):
        spec = _standard_spec(overlay=b"OVERLAY!" * 16)
        p = tmp_path / "tail.exe"
        p.write_bytes(build_pe(spec))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.overlay_present is True
        assert facts.overlay_size == 128
        last = max(s.raw_offset + s.raw_size for s in facts.sections)
        assert facts.overlay_offset == last

    def test_sectionless_image_overlay_after_headers(self, tmp_path):
        p = tmp_path / "hdrsonly.exe"
        p.write_bytes(build_pe(_standard_spec(
            secs=[], overlay=b"X" * 32)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.overlay_present is True
        assert facts.overlay_offset == facts.size_of_headers
        assert facts.overlay_size == 32

    def test_raw_claim_past_eof_establishes_no_extent(self, tmp_path):
        """A section claiming raw bytes past EOF must not turn the
        claim into a mapped extent (which could swallow a real
        overlay or invent a negative one)."""
        spec = _standard_spec(secs=[
            Sec(name=b".huge", va=0x1000, data=b"x" * 16,
                raw_size=0x10000000),
        ])
        p = tmp_path / "hugeclaim.exe"
        p.write_bytes(build_pe(spec))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.overlay_present is False
        assert facts.overlay_size == 0
