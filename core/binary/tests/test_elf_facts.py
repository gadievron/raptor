"""Tests for ``core.binary.elf.extract_elf_facts`` — the shallow
linkage / identity / layout facts extractor.

Crafted-ELF coverage:

  * Well-formed extraction per fact (DT_NEEDED order, DT_SONAME,
    exports + export_types, .gnu_debuglink, PT_INTERP, entropy)
  * Malformed dynamic sections, oversized counts, out-of-range
    offsets — tolerated per field, surfaced in ``caps_hit``
  * Hostile symbol names (control bytes, no-NUL strtabs) capped
    and contained
  * Entropy determinism + known-value anchors
  * Regression pins: ``parse_elf`` still excludes linkage names;
    ``is_packed`` ignores entropy in both directions
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from core.binary import elf as elf_mod
from core.binary.elf import extract_elf_facts, is_packed, parse_elf

from .test_elf import _build_elf64_with_dynsym

_SYM = struct.Struct("<IBBHQQ")
_SYM32 = struct.Struct("<IIIBBH")
_SH = struct.Struct("<IIQQQQIIQQ")
_SH32 = struct.Struct("<IIIIIIIIII")

# st_info = (binding << 4) | type
_GLOBAL_FUNC = 0x12
_GLOBAL_OBJ = 0x11
_GLOBAL_IFUNC = 0x1A         # GLOBAL binding, type 10 (STT_GNU_IFUNC)
_GNU_UNIQUE_OBJ = 0xA1       # STB_GNU_UNIQUE binding, OBJ type
_WEAK_UNKNOWN_TYPE = 0x2D    # WEAK binding, type 13 (no mapping)
_LOCAL_FUNC = 0x02
_PT_INTERP = 3
_PT_DYNAMIC = 2
_DT_NEEDED = 1
_DT_SONAME = 14
_DT_NULL = 0

# The real wrapper, captured at import time — individual tests
# restore it to exercise the wrapper's own error handling under
# stubbed oracle internals.
_REAL_READ_BUILD_ID = elf_mod._read_build_id


@pytest.fixture(autouse=True)
def _stub_build_id(monkeypatch):
    """Keep the unit tests hermetic: the real helper shells out to
    sandboxed readelf, which CI runners may lack. Dedicated tests
    re-patch to assert the wiring; the gated live test unpatches."""
    monkeypatch.setattr(elf_mod, "_read_build_id",
                        lambda p: (None, None))


def _strtab(names: list[bytes]) -> tuple[bytes, dict[bytes, int]]:
    """NUL-led string table + name→offset index."""
    table = bytearray(b"\x00")
    offsets: dict[bytes, int] = {}
    for name in names:
        offsets[name] = len(table)
        table += name + b"\x00"
    return bytes(table), offsets


def _build_elf64_facts(
    specs: list[tuple[bytes, int, bytes, int, int]],
    *,
    phdr_types: tuple[int, ...] = (),
) -> bytes:
    """Composable little-endian ELF64 builder for the facts tests.

    ``specs``: one entry per section as ``(name, sh_type, payload,
    sh_link, sh_entsize)``. Section indices seen by ``sh_link``:
    0 = null, 1..N = specs in order, N+1 = the auto-added
    ``.shstrtab``. Complements ``_build_elf64_with_dynsym`` (fixed
    import-walk layout) rather than replacing it.
    """
    ehsize, phentsize = 64, 56
    phnum = len(phdr_types)
    phoff = ehsize if phnum else 0

    shstrtab = bytearray(b"\x00")
    name_off: dict[bytes, int] = {}
    for name in [s[0] for s in specs] + [b".shstrtab"]:
        if name not in name_off:
            name_off[name] = len(shstrtab)
            shstrtab += name + b"\x00"

    payload_start = ehsize + phnum * phentsize
    body = bytearray()
    payload_offs: list[int] = []
    for _, _, payload, _, _ in specs:
        payload_offs.append(payload_start + len(body))
        body += payload
    shstrtab_off = payload_start + len(body)
    shoff = shstrtab_off + len(shstrtab)
    shoff += (-shoff) % 8

    shdrs = bytearray(_SH.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    for i, (name, sh_type, payload, sh_link, entsize) in enumerate(specs):
        shdrs += _SH.pack(name_off[name], sh_type, 0, 0,
                          payload_offs[i], len(payload), sh_link, 0, 0,
                          entsize)
    shdrs += _SH.pack(name_off[b".shstrtab"], 3, 0, 0,
                      shstrtab_off, len(shstrtab), 0, 0, 0, 0)

    shnum = len(specs) + 2
    shstrndx = len(specs) + 1
    ehdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack(
        "<HHIQQQIHHHHHH",
        3, 0x3E, 1,                    # e_type=ET_DYN, x86_64
        0, phoff, shoff, 0, ehsize,
        phentsize if phnum else 0, phnum,
        64, shnum, shstrndx,
    )
    phdrs = b"".join(
        struct.pack("<IIQQQQQQ", p_type, 0, 0, 0, 0, 0, 0, 0)
        for p_type in phdr_types
    )
    blob = bytearray(ehdr + phdrs + body + shstrtab)
    blob += b"\x00" * (shoff - len(blob))
    return bytes(blob + shdrs)


def _dyn(entries: list[tuple[int, int]]) -> bytes:
    return b"".join(struct.pack("<qQ", tag, val) for tag, val in entries)


def _shdr_field_offset(blob: bytes, section_index: int,
                       field_index: int) -> int:
    """Byte offset of one field inside ELF64 section header
    ``section_index`` (fields 0..9 in _SH order)."""
    (e_shoff,) = struct.unpack_from("<Q", blob, 0x28)
    base = e_shoff + section_index * 64
    # I I Q Q Q Q I I Q Q → cumulative offsets
    offs = [0, 4, 8, 16, 24, 32, 40, 44, 48, 56]
    return base + offs[field_index]


def _build_elf32_facts(
    specs: list[tuple[bytes, int, bytes, int, int]],
    *,
    phdr_types: tuple[int, ...] = (),
) -> bytes:
    """ELF32 little-endian twin of :func:`_build_elf64_facts` — pins
    the 32-bit dynamic-entry ("iI") and symbol unpack formats."""
    ehsize, phentsize, shentsize = 52, 32, 40
    phnum = len(phdr_types)
    phoff = ehsize if phnum else 0

    shstrtab = bytearray(b"\x00")
    name_off: dict[bytes, int] = {}
    for name in [s[0] for s in specs] + [b".shstrtab"]:
        if name not in name_off:
            name_off[name] = len(shstrtab)
            shstrtab += name + b"\x00"

    payload_start = ehsize + phnum * phentsize
    body = bytearray()
    payload_offs: list[int] = []
    for _, _, payload, _, _ in specs:
        payload_offs.append(payload_start + len(body))
        body += payload
    shstrtab_off = payload_start + len(body)
    shoff = shstrtab_off + len(shstrtab)
    shoff += (-shoff) % 4

    shdrs = bytearray(_SH32.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    for i, (name, sh_type, payload, sh_link, entsize) in enumerate(specs):
        shdrs += _SH32.pack(name_off[name], sh_type, 0, 0,
                            payload_offs[i], len(payload), sh_link, 0,
                            0, entsize)
    shdrs += _SH32.pack(name_off[b".shstrtab"], 3, 0, 0,
                        shstrtab_off, len(shstrtab), 0, 0, 0, 0)

    shnum = len(specs) + 2
    shstrndx = len(specs) + 1
    ehdr = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + struct.pack(
        "<HHIIIIIHHHHHH",
        3, 0x03, 1,                    # e_type=ET_DYN, i386
        0, phoff, shoff, 0, ehsize,
        phentsize if phnum else 0, phnum,
        shentsize, shnum, shstrndx,
    )
    phdrs = b"".join(
        struct.pack("<IIIIIIII", p_type, 0, 0, 0, 0, 0, 0, 0)
        for p_type in phdr_types
    )
    blob = bytearray(ehdr + phdrs + body + shstrtab)
    blob += b"\x00" * (shoff - len(blob))
    return bytes(blob + shdrs)


def _dyn32(entries: list[tuple[int, int]]) -> bytes:
    return b"".join(struct.pack("<iI", tag, val) for tag, val in entries)


def _standard_fixture(
    *, phdr_types: tuple[int, ...] = (_PT_INTERP, _PT_DYNAMIC),
) -> bytes:
    """One ELF64 exercising every fact: two DT_NEEDED (order matters),
    DT_SONAME, a mixed .dynsym (exports of several types, a local, an
    import), and a well-formed .gnu_debuglink."""
    dynstr, off = _strtab([
        b"libfoo.so.1", b"libbar.so.2", b"libself.so.3",
        b"fn_export", b"obj_export", b"weak_fn",
        b"local_sym", b"imp_undef",
    ])
    dynsym = (
        _SYM.pack(0, 0, 0, 0, 0, 0)                                  # null
        + _SYM.pack(off[b"fn_export"], _GLOBAL_FUNC, 0, 1, 0, 0)
        + _SYM.pack(off[b"obj_export"], _GLOBAL_OBJ, 0, 1, 0, 0)
        + _SYM.pack(off[b"weak_fn"], _WEAK_UNKNOWN_TYPE, 0, 1, 0, 0)
        + _SYM.pack(off[b"local_sym"], _LOCAL_FUNC, 0, 1, 0, 0)      # local
        + _SYM.pack(off[b"imp_undef"], _GLOBAL_FUNC, 0, 0, 0, 0)     # import
    )
    dynamic = _dyn([
        (_DT_NEEDED, off[b"libfoo.so.1"]),
        (_DT_NEEDED, off[b"libbar.so.2"]),
        (_DT_SONAME, off[b"libself.so.3"]),
        (_DT_NULL, 0),
    ])
    debuglink = b"app.debug\x00\x00\x00" + b"\xde\xad\xbe\xef"  # pad + CRC
    return _build_elf64_facts(
        [
            (b".dynstr", 3, dynstr, 0, 0),          # index 1
            (b".dynsym", 11, dynsym, 1, 24),        # index 2
            (b".dynamic", 6, dynamic, 1, 16),       # index 3
            (b".gnu_debuglink", 1, debuglink, 0, 0),
        ],
        phdr_types=phdr_types,
    )


# ---------------------------------------------------------------------------
# Well-formed extraction
# ---------------------------------------------------------------------------


class TestWellFormed:
    def test_needed_in_link_order(self, tmp_path):
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == ["libfoo.so.1", "libbar.so.2"]

    def test_soname(self, tmp_path):
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.soname == "libself.so.3"

    def test_exports_and_types(self, tmp_path):
        """Defined GLOBAL/WEAK names are exports; locals and
        SHN_UNDEF imports are not. Types carry the FUNC/OBJ
        vocabulary; an unmapped st_info type keeps the NAME visible
        but stays out of export_types (consumers fail open)."""
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == sorted(
            ["fn_export", "obj_export", "weak_fn"])
        assert facts.export_types == {
            "fn_export": "FUNC",
            "obj_export": "OBJ",
        }

    def test_debuglink(self, tmp_path):
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.debuglink == "app.debug"

    def test_interpreter_presence_both_ways(self, tmp_path):
        p = tmp_path / "exec.elf"
        p.write_bytes(_standard_fixture(
            phdr_types=(_PT_INTERP, _PT_DYNAMIC)))
        facts = extract_elf_facts(p)
        assert facts is not None and facts.has_interpreter is True

        q = tmp_path / "lib.elf"
        q.write_bytes(_standard_fixture(phdr_types=(_PT_DYNAMIC,)))
        facts = extract_elf_facts(q)
        assert facts is not None and facts.has_interpreter is False

    def test_no_caps_hit_on_clean_fixture(self, tmp_path):
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.caps_hit == []

    def test_build_id_wiring(self, tmp_path, monkeypatch):
        """extract_elf_facts takes whatever the shared helper
        returns — the value is not re-derived here."""
        monkeypatch.setattr(elf_mod, "_read_build_id",
                            lambda p: ("ab" * 20, None))
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.build_id == "ab" * 20

    def test_build_id_sandbox_refusal_is_a_recorded_gap(
            self, tmp_path, monkeypatch):
        """SandboxSetupError is BaseException by design and would
        otherwise escape the never-raises wrapper. The wrapper names
        it: nothing executed on refusal (no containment weakened),
        build_id degrades to None, and the gap is a caps_hit marker
        rather than a silent None."""
        from core.sandbox import SandboxSetupError

        import core.analysis.binary_oracle as oracle_mod

        def _refuse(path):
            raise SandboxSetupError("isolation could not engage")

        monkeypatch.setattr(elf_mod, "_read_build_id",
                            _REAL_READ_BUILD_ID)
        monkeypatch.setattr(oracle_mod, "read_build_id", _refuse)
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.build_id is None
        assert "build_id_sandbox_refused" in facts.caps_hit

    def test_gnu_unique_binding_exported(self, tmp_path):
        """STB_GNU_UNIQUE (g++ vague linkage — nm's ``u`` set) is a
        real externally visible export class; a GLOBAL/WEAK-only
        filter silently dropped it on every C++ library."""
        dynstr, off = _strtab([b"unique_guard"])
        dynsym = (
            _SYM.pack(0, 0, 0, 0, 0, 0)
            + _SYM.pack(off[b"unique_guard"], _GNU_UNIQUE_OBJ, 0, 1,
                        0, 0)
        )
        p = tmp_path / "unique.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynsym", 11, dynsym, 1, 24),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == ["unique_guard"]
        assert facts.export_types["unique_guard"] == "OBJ"

    def test_ifunc_type_mapped(self, tmp_path):
        dynstr, off = _strtab([b"resolved_fn"])
        dynsym = (
            _SYM.pack(0, 0, 0, 0, 0, 0)
            + _SYM.pack(off[b"resolved_fn"], _GLOBAL_IFUNC, 0, 1,
                        0, 0)
        )
        p = tmp_path / "ifunc.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynsym", 11, dynsym, 1, 24),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.export_types["resolved_fn"] == "IFUNC"

    def test_first_mapped_type_wins(self, tmp_path):
        """A versioned symbol repeats its name; the first MAPPED
        type is recorded (.dynsym file order), later ones ignored."""
        dynstr, off = _strtab([b"dup_name"])
        dynsym = (
            _SYM.pack(0, 0, 0, 0, 0, 0)
            + _SYM.pack(off[b"dup_name"], _GLOBAL_FUNC, 0, 1, 0, 0)
            + _SYM.pack(off[b"dup_name"], _GLOBAL_OBJ, 0, 1, 0, 0)
        )
        p = tmp_path / "dup.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynsym", 11, dynsym, 1, 24),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == ["dup_name"]
        assert facts.export_types["dup_name"] == "FUNC"

    def test_non_elf_and_missing_return_none(self, tmp_path):
        p = tmp_path / "notelf"
        p.write_bytes(b"plain text, no magic")
        assert extract_elf_facts(p) is None
        assert extract_elf_facts(tmp_path / "absent") is None
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        assert extract_elf_facts(empty) is None


class TestLiveBinary:
    """Gated live probe — the crafted fixtures prove correctness;
    this proves the walk holds on a real toolchain-produced ELF."""

    @pytest.fixture(autouse=True)
    def _require_elf_host(self, monkeypatch):
        p = Path("/bin/ls")
        try:
            ok = p.is_file() and p.read_bytes()[:4] == b"\x7fELF"
        except OSError:
            ok = False
        if not ok:
            pytest.skip("/bin/ls is not an ELF binary on this host")

    def test_bin_ls_facts(self):
        facts = extract_elf_facts(Path("/bin/ls"))
        assert facts is not None
        assert any(n.startswith("libc.so") for n in facts.needed)
        assert facts.has_interpreter is True     # executable, not lib
        assert facts.soname is None
        assert facts.section_entropy               # populated
        # build_id is autouse-stubbed to None here; the crafted-ELF
        # wiring test covers the joint. Live readelf coverage belongs
        # to the oracle's own suite.
        assert facts.build_id is None


# ---------------------------------------------------------------------------
# Malformed / hostile structures — tolerated per field, surfaced
# ---------------------------------------------------------------------------


class TestMalformedDynamic:
    def test_needed_offsets_out_of_range(self, tmp_path):
        dynstr, _ = _strtab([b"libfoo.so.1"])
        dynamic = _dyn([(_DT_NEEDED, 2**32 - 5), (_DT_NULL, 0)])
        p = tmp_path / "badneeded.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynamic", 6, dynamic, 1, 16),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == []
        assert "needed_name_malformed" in facts.caps_hit

    def test_soname_offset_malformed(self, tmp_path):
        dynstr, _ = _strtab([b"libfoo.so.1"])
        dynamic = _dyn([(_DT_SONAME, 10**6), (_DT_NULL, 0)])
        p = tmp_path / "badsoname.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynamic", 6, dynamic, 1, 16),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.soname is None
        assert "soname_malformed" in facts.caps_hit

    def test_dynamic_without_any_strtab(self, tmp_path):
        """.dynamic present but neither a valid sh_link nor a .dynstr
        section — linkage stays empty with a recorded gap."""
        dynamic = _dyn([(_DT_NEEDED, 1), (_DT_NULL, 0)])
        p = tmp_path / "nostrtab.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynamic", 6, dynamic, 0, 16),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == []
        assert "dynamic_strtab_missing" in facts.caps_hit

    def test_dynamic_walk_capped(self, tmp_path, monkeypatch):
        """No DT_NULL and an oversized table — the walk stops at the
        entry cap and says so."""
        monkeypatch.setattr(elf_mod, "_MAX_DYN_ENTRIES", 2)
        dynstr, off = _strtab([b"a.so", b"b.so", b"c.so"])
        dynamic = _dyn([
            (_DT_NEEDED, off[b"a.so"]),
            (_DT_NEEDED, off[b"b.so"]),
            (_DT_NEEDED, off[b"c.so"]),
        ])   # no DT_NULL terminator
        p = tmp_path / "unterminated.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynamic", 6, dynamic, 1, 16),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == ["a.so", "b.so"]
        assert "dynamic_entries_capped" in facts.caps_hit

    def test_needed_retention_capped(self, tmp_path, monkeypatch):
        """The retention cap skips further NEEDED entries but does
        not abandon the walk: a DT_SONAME after the capped names is
        still extracted."""
        monkeypatch.setattr(elf_mod, "_MAX_NEEDED_ENTRIES", 1)
        dynstr, off = _strtab([b"a.so", b"b.so", b"self.so"])
        dynamic = _dyn([
            (_DT_NEEDED, off[b"a.so"]),
            (_DT_NEEDED, off[b"b.so"]),
            (_DT_SONAME, off[b"self.so"]),
            (_DT_NULL, 0),
        ])
        p = tmp_path / "manyneeded.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynamic", 6, dynamic, 1, 16),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == ["a.so"]
        assert facts.soname == "self.so"
        assert "needed_truncated" in facts.caps_hit

    def test_dt_null_terminates_walk(self, tmp_path):
        """Entries past the DT_NULL terminator are dead by spec —
        a crafted tail must not resurrect them."""
        dynstr, off = _strtab([b"live.so", b"dead.so"])
        dynamic = _dyn([
            (_DT_NEEDED, off[b"live.so"]),
            (_DT_NULL, 0),
            (_DT_NEEDED, off[b"dead.so"]),
        ])
        p = tmp_path / "nullterm.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynamic", 6, dynamic, 1, 16),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == ["live.so"]

    def test_first_soname_wins(self, tmp_path):
        dynstr, off = _strtab([b"first.so", b"second.so"])
        dynamic = _dyn([
            (_DT_SONAME, off[b"first.so"]),
            (_DT_SONAME, off[b"second.so"]),
            (_DT_NULL, 0),
        ])
        p = tmp_path / "twosonames.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynamic", 6, dynamic, 1, 16),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.soname == "first.so"

    def test_sh_link_strtab_beats_named_decoy(self, tmp_path):
        """sh_link is the authoritative string-table join; a decoy
        STRTAB section NAMED .dynstr must not capture the linkage
        names."""
        real, off = _strtab([b"libreal.so"])
        decoy, _ = _strtab([b"libdecoy.x"])   # same offsets, wrong text
        dynamic = _dyn([
            (_DT_NEEDED, off[b"libreal.so"]),
            (_DT_NULL, 0),
        ])
        p = tmp_path / "decoy.elf"
        p.write_bytes(_build_elf64_facts([
            (b".realnames", 3, real, 0, 0),        # index 1 (sh_link)
            (b".dynstr", 3, decoy, 0, 0),          # index 2 (decoy)
            (b".dynamic", 6, dynamic, 1, 16),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == ["libreal.so"]

    def test_stripped_dynamic_sections_recorded(self, tmp_path):
        """PT_DYNAMIC says the binary links dynamically, but the
        sections are gone (sstrip shape) — a gap, not a truthful
        'no dynamic facts'."""
        p = tmp_path / "doctored.elf"
        p.write_bytes(_build_elf64_facts(
            [(b".rodata", 1, b"hello world", 0, 0)],
            phdr_types=(_PT_DYNAMIC,),
        ))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == []
        assert "dynamic_sections_stripped" in facts.caps_hit

    def test_fully_sectionless_elf_keeps_header_facts(self, tmp_path):
        """The sstrip fixture from the import suite: parse_elf bails
        to its fallback tier, the facts extractor degrades to
        header-only facts with the gap recorded."""
        p = tmp_path / "sstripped.elf"
        p.write_bytes(_build_elf64_with_dynsym(sections=False))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == [] and facts.exports == []
        assert "section_headers_unusable" in facts.caps_hit


class TestMalformedSymbols:
    def test_oversized_sym_entsize(self, tmp_path):
        """sh_entsize past the sanity cap — exports refused with a
        marker, everything else intact."""
        blob = bytearray(_standard_fixture())
        off = _shdr_field_offset(blob, 2, 9)        # .dynsym sh_entsize
        blob[off:off + 8] = struct.pack("<Q", 2**40)
        p = tmp_path / "badentsize.elf"
        p.write_bytes(bytes(blob))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == []
        assert "dynsym_malformed" in facts.caps_hit
        assert facts.needed == ["libfoo.so.1", "libbar.so.2"]

    def test_oversized_entry_count(self, tmp_path, monkeypatch):
        monkeypatch.setattr(elf_mod, "_MAX_DYNSYM_ENTRIES", 2)
        p = tmp_path / "manysyms.elf"
        p.write_bytes(_standard_fixture())    # 6 entries > 2
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == []
        assert "dynsym_malformed" in facts.caps_hit

    @pytest.mark.parametrize("hostile_offset", [
        2**63 + 16,          # past off_t: seek itself would raise
        2**63 - 1,           # off_t ceiling: seek OK, read EINVALs
        2**63 - 4096,        # last page below 2**63: read EINVALs
        2**64 - 1,           # u64 max
    ])
    def test_out_of_range_dynstr_offset(self, tmp_path, hostile_offset):
        """A pathological sh_offset on .dynstr must degrade that
        field, not unwind the whole record (parse_elf's whole-parse
        None is the wrong shape for a facts record). The near-2**63
        rows pin the kernel window where the SEEK succeeds but the
        READ raises OSError — a screen at the off_t ceiling alone
        let one crafted offset self-exempt the binary from the
        facts inventory."""
        blob = bytearray(_standard_fixture())
        off = _shdr_field_offset(blob, 1, 4)        # .dynstr sh_offset
        blob[off:off + 8] = struct.pack("<Q", hostile_offset)
        p = tmp_path / "hugestroff.elf"
        p.write_bytes(bytes(blob))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == []
        assert "dynstr_unreadable" in facts.caps_hit
        assert facts.has_interpreter is True       # header facts kept

    def test_hostile_export_name_contained(self, tmp_path):
        """Control bytes in an export name come back as data — no
        crash, no truncation at the control byte; escaping is the
        RENDER boundary's job and the record documents that."""
        hostile = b"evil\x1b[31mname"
        dynstr, off = _strtab([hostile])
        dynsym = (
            _SYM.pack(0, 0, 0, 0, 0, 0)
            + _SYM.pack(off[hostile], _GLOBAL_FUNC, 0, 1, 0, 0)
        )
        p = tmp_path / "hostile.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynsym", 11, dynsym, 1, 24),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == ["evil\x1b[31mname"]
        assert facts.export_types["evil\x1b[31mname"] == "FUNC"

    def test_no_nul_dynstr_drops_names_with_marker(self, tmp_path):
        dynstr = b"A" * 10_000                     # no NUL anywhere
        dynsym = (
            _SYM.pack(0, 0, 0, 0, 0, 0)
            + _SYM.pack(1, _GLOBAL_FUNC, 0, 1, 0, 0)
            + _SYM.pack(5000, _GLOBAL_FUNC, 0, 1, 0, 0)
        )
        p = tmp_path / "nonul.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynsym", 11, dynsym, 1, 24),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == []
        assert "export_name_malformed" in facts.caps_hit

    def test_export_name_volume_capped_loudly(self, tmp_path,
                                              monkeypatch):
        monkeypatch.setattr(elf_mod, "_MAX_TOTAL_NAME_BYTES", 8)
        dynstr, off = _strtab([b"alpha", b"bravo", b"charlie"])
        dynsym = _SYM.pack(0, 0, 0, 0, 0, 0) + b"".join(
            _SYM.pack(off[n], _GLOBAL_FUNC, 0, 1, 0, 0)
            for n in (b"alpha", b"bravo", b"charlie")
        )
        p = tmp_path / "volume.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynsym", 11, dynsym, 1, 24),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert len(facts.exports) < 3
        assert "export_names_truncated" in facts.caps_hit

    def test_truncated_debuglink_payload(self, tmp_path):
        """No NUL inside the payload window → malformed, recorded."""
        p = tmp_path / "badlink.elf"
        p.write_bytes(_build_elf64_facts([
            (b".gnu_debuglink", 1, b"unterminated-name", 0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.debuglink is None
        assert "debuglink_malformed" in facts.caps_hit

    def test_nobits_debuglink_decoy_rejected(self, tmp_path):
        """A NOBITS section named .gnu_debuglink aliases arbitrary
        file bytes; honoring it by name alone would read those bytes
        back as the debug-file name. The type filter rejects it —
        and its absence is truthful, not a gap."""
        p = tmp_path / "decoylink.elf"
        p.write_bytes(_build_elf64_facts([
            (b".gnu_debuglink", 8, b"leaked.debug\x00\x00\x00\x00",
             0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.debuglink is None
        assert "debuglink_malformed" not in facts.caps_hit


# ---------------------------------------------------------------------------
# Per-section entropy — raw numbers, bounded reads, deterministic
# ---------------------------------------------------------------------------


class TestSectionEntropy:
    def test_known_values(self, tmp_path):
        zeros = b"\x00" * 1024
        cycle = bytes(range(256)) * 4
        p = tmp_path / "entropy.elf"
        p.write_bytes(_build_elf64_facts([
            (b".zeros", 1, zeros, 0, 0),
            (b".cycle", 1, cycle, 0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        by_name = {r.name: r for r in facts.section_entropy}
        assert by_name[".zeros"].entropy == 0.0
        assert by_name[".cycle"].entropy == 8.0
        assert by_name[".zeros"].size == 1024
        assert by_name[".zeros"].sampled == 1024

    def test_deterministic(self, tmp_path):
        p = tmp_path / "det.elf"
        p.write_bytes(_standard_fixture())
        a = extract_elf_facts(p)
        b = extract_elf_facts(p)
        assert a is not None and b is not None
        assert a.section_entropy == b.section_entropy

    def test_sample_window_recorded(self, tmp_path, monkeypatch):
        """A section larger than the window is sampled, and the
        record SAYS so (sampled < size) — no silent full-read, no
        silent partial claim."""
        monkeypatch.setattr(elf_mod, "_MAX_ENTROPY_SECTION_BYTES", 16)
        p = tmp_path / "window.elf"
        p.write_bytes(_build_elf64_facts([
            (b".big", 1, bytes(range(256)), 0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        rec = {r.name: r for r in facts.section_entropy}[".big"]
        assert rec.size == 256 and rec.sampled == 16
        assert rec.entropy == 4.0                  # 16 distinct bytes

    def test_total_budget_capped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(elf_mod, "_MAX_ENTROPY_TOTAL_BYTES", 8)
        p = tmp_path / "budget.elf"
        p.write_bytes(_build_elf64_facts([
            (b".one", 1, b"x" * 64, 0, 0),
            (b".two", 1, b"y" * 64, 0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert "entropy_budget_exhausted" in facts.caps_hit
        names = [r.name for r in facts.section_entropy]
        assert ".two" not in names
        # The budget participates in the read bound itself (min of
        # size / window / remaining budget) — the first section is
        # clipped to the 8-byte budget, not read whole.
        rec_one = {r.name: r for r in facts.section_entropy}[".one"]
        assert rec_one.sampled == 8

    def test_record_count_capped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(elf_mod, "_MAX_ENTROPY_SECTIONS", 1)
        p = tmp_path / "count.elf"
        p.write_bytes(_build_elf64_facts([
            (b".one", 1, b"x" * 8, 0, 0),
            (b".two", 1, b"y" * 8, 0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert len(facts.section_entropy) == 1
        assert "entropy_sections_capped" in facts.caps_hit

    def test_offset_past_eof_skipped(self, tmp_path):
        blob = bytearray(_build_elf64_facts([
            (b".ghost", 1, b"z" * 8, 0, 0),
        ]))
        (e_shoff,) = struct.unpack_from("<Q", blob, 0x28)
        off = e_shoff + 1 * 64 + 24                # .ghost sh_offset
        blob[off:off + 8] = struct.pack("<Q", 2**32)   # far past EOF
        p = tmp_path / "pasteof.elf"
        p.write_bytes(bytes(blob))
        facts = extract_elf_facts(p)
        assert facts is not None
        # The unreadable section is skipped; readable siblings
        # (here .shstrtab) keep their records.
        assert ".ghost" not in [r.name for r in facts.section_entropy]
        assert "section_data_unreadable" in facts.caps_hit

    def test_hostile_section_name_length_capped(self, tmp_path):
        long_name = b"." + b"n" * 600
        p = tmp_path / "longname.elf"
        p.write_bytes(_build_elf64_facts([
            (long_name, 1, b"data", 0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        names = [r.name for r in facts.section_entropy]
        cap = elf_mod._MAX_SECTION_RECORD_NAME
        assert any(len(n) == cap for n in names)
        assert all(len(n) <= cap for n in names)
        assert "section_name_truncated" in facts.caps_hit

    def test_name_cap_counts_bytes_not_characters(self, tmp_path):
        """A multibyte name must not dodge the retention bound: the
        cap counts UTF-8 BYTES (what is actually retained)."""
        # 200 two-byte codepoints = 400 bytes but only 200 chars —
        # a char-counted cap would keep it whole.
        wide_name = ("é" * 200).encode("utf-8")
        p = tmp_path / "widename.elf"
        p.write_bytes(_build_elf64_facts([
            (wide_name, 1, b"data", 0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        cap = elf_mod._MAX_SECTION_RECORD_NAME
        for rec in facts.section_entropy:
            assert len(rec.name.encode("utf-8")) <= cap + 2
        assert "section_name_truncated" in facts.caps_hit

    def test_unresolvable_section_name_marked(self, tmp_path):
        """A name over the strtab lookup cap resolves to '' — the
        record keeps the empty string, but no longer silently: the
        gap is a marker."""
        over_cap_name = b"." + b"x" * 5000     # > _MAX_STRTAB_NAME_BYTES
        p = tmp_path / "overcapname.elf"
        p.write_bytes(_build_elf64_facts([
            (over_cap_name, 1, b"data", 0, 0),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert any(r.name == "" for r in facts.section_entropy)
        assert "section_name_malformed" in facts.caps_hit

    def test_nobits_skipped_even_with_aliasing_size(self, tmp_path):
        """SHT_NOBITS occupies no file bytes; a crafted NOBITS header
        whose offset/size alias REAL file bytes must not smuggle
        those bytes in as a section-entropy fact."""
        blob = bytearray(_build_elf64_facts([
            (b".bss", 8, b"", 0, 0),
            (b".real", 1, b"payload!", 0, 0),
        ]))
        # Point .bss at the file start with a nonzero size.
        off_off = _shdr_field_offset(blob, 1, 4)    # .bss sh_offset
        size_off = _shdr_field_offset(blob, 1, 5)   # .bss sh_size
        blob[off_off:off_off + 8] = struct.pack("<Q", 0)
        blob[size_off:size_off + 8] = struct.pack("<Q", 64)
        p = tmp_path / "aliasing.elf"
        p.write_bytes(bytes(blob))
        facts = extract_elf_facts(p)
        assert facts is not None
        names = [r.name for r in facts.section_entropy]
        assert ".bss" not in names
        assert ".real" in names


# ---------------------------------------------------------------------------
# Honesty witnesses — empty caps_hit must MEAN complete
# ---------------------------------------------------------------------------


class TestHonestyWitnesses:
    def test_dynamic_section_doctored_away_is_marked(self, tmp_path):
        """PT_DYNAMIC present, .dynsym/.dynstr intact, but the
        .dynamic SECTION header removed: needed=[]/soname=None must
        not read as 'links nothing' — same witness as the exports
        branch."""
        dynstr, off = _strtab([b"fn_export"])
        dynsym = (
            _SYM.pack(0, 0, 0, 0, 0, 0)
            + _SYM.pack(off[b"fn_export"], _GLOBAL_FUNC, 0, 1, 0, 0)
        )
        p = tmp_path / "nodynamic.elf"
        p.write_bytes(_build_elf64_facts(
            [
                (b".dynstr", 3, dynstr, 0, 0),
                (b".dynsym", 11, dynsym, 1, 24),
            ],
            phdr_types=(_PT_DYNAMIC,),
        ))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == []
        assert "dynamic_sections_stripped" in facts.caps_hit
        assert facts.exports == ["fn_export"]      # exports unharmed

    def test_dynsym_without_dynstr_is_marked(self, tmp_path):
        """.dynsym is itself evidence of dynamic linkage — exports=[]
        with no readable .dynstr is a gap even when no program
        headers survive to say PT_DYNAMIC."""
        dynsym = (
            _SYM.pack(0, 0, 0, 0, 0, 0)
            + _SYM.pack(1, _GLOBAL_FUNC, 0, 1, 0, 0)
        )
        p = tmp_path / "nodynstr.elf"
        p.write_bytes(_build_elf64_facts([
            (b".dynsym", 11, dynsym, 0, 24),
        ]))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.exports == []
        assert "dynstr_unreadable" in facts.caps_hit

    def test_malformed_phdr_table_is_marked(self, tmp_path):
        """An existing-but-malformed program header table yields NO
        absence evidence: both flags stay False AND the gap is
        recorded — silently-False flags would also suppress the
        stripped-sections witness."""
        blob = bytearray(_standard_fixture())
        # e_phentsize (H at 54) smaller than one phdr record.
        blob[54:56] = struct.pack("<H", 8)
        p = tmp_path / "badphdrs.elf"
        p.write_bytes(bytes(blob))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.has_interpreter is False
        assert "phdr_table_unreadable" in facts.caps_hit


# ---------------------------------------------------------------------------
# Offset-screen marker paths — every screen leaves a trace
# ---------------------------------------------------------------------------


class TestOffsetScreenMarkers:
    def test_pathological_e_phoff_marked(self, tmp_path):
        blob = bytearray(_standard_fixture())
        blob[32:40] = struct.pack("<Q", 2**63 + 1)   # e_phoff
        p = tmp_path / "hugephoff.elf"
        p.write_bytes(bytes(blob))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.has_interpreter is False
        assert "phdr_table_unreadable" in facts.caps_hit

    def test_pathological_shstrtab_offset_marked(self, tmp_path):
        blob = bytearray(_standard_fixture())
        # .shstrtab is the last section (index = specs + 1 = 5).
        off = _shdr_field_offset(blob, 5, 4)
        blob[off:off + 8] = struct.pack("<Q", 2**63 - 4096)
        p = tmp_path / "hugeshstr.elf"
        p.write_bytes(bytes(blob))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert "shstrtab_unreadable" in facts.caps_hit
        assert facts.has_interpreter is True       # phdr facts kept

    def test_pathological_dynamic_offset_marked(self, tmp_path):
        blob = bytearray(_standard_fixture())
        off = _shdr_field_offset(blob, 3, 4)        # .dynamic sh_offset
        blob[off:off + 8] = struct.pack("<Q", 2**63 - 1)
        p = tmp_path / "hugedyn.elf"
        p.write_bytes(bytes(blob))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == []
        assert "dynamic_unreadable" in facts.caps_hit
        assert facts.exports != []                  # exports unharmed


# ---------------------------------------------------------------------------
# ELF32 parity — pins the 32-bit dynamic/symbol formats
# ---------------------------------------------------------------------------


class TestElf32:
    def test_linkage_soname_exports(self, tmp_path):
        dynstr, off = _strtab([
            b"lib32.so.1", b"self32.so", b"fn32", b"obj32",
        ])
        dynsym = (
            _SYM32.pack(0, 0, 0, 0, 0, 0)
            + _SYM32.pack(off[b"fn32"], 0, 0, _GLOBAL_FUNC, 0, 1)
            + _SYM32.pack(off[b"obj32"], 0, 0, _GLOBAL_OBJ, 0, 1)
        )
        dynamic = _dyn32([
            (_DT_NEEDED, off[b"lib32.so.1"]),
            (_DT_SONAME, off[b"self32.so"]),
            (_DT_NULL, 0),
        ])
        p = tmp_path / "facts32.elf"
        p.write_bytes(_build_elf32_facts(
            [
                (b".dynstr", 3, dynstr, 0, 0),
                (b".dynsym", 11, dynsym, 1, 16),
                (b".dynamic", 6, dynamic, 1, 8),
            ],
            phdr_types=(_PT_INTERP, _PT_DYNAMIC),
        ))
        facts = extract_elf_facts(p)
        assert facts is not None
        assert facts.needed == ["lib32.so.1"]
        assert facts.soname == "self32.so"
        assert facts.exports == ["fn32", "obj32"]
        assert facts.export_types == {"fn32": "FUNC", "obj32": "OBJ"}
        assert facts.has_interpreter is True
        assert facts.caps_hit == []


# ---------------------------------------------------------------------------
# Regression pins — this series changes neither verdict surface
# ---------------------------------------------------------------------------


class TestRegressionPins:
    def test_parse_elf_still_excludes_linkage(self, tmp_path):
        """The capability parse keeps its shape: imports only —
        DT_NEEDED names stay the facts record's business."""
        p = tmp_path / "full.elf"
        p.write_bytes(_standard_fixture())
        meta = parse_elf(p)
        assert meta is not None
        assert meta.imports == {"imp_undef"}
        assert not hasattr(meta, "needed")

    def test_is_packed_ignores_entropy_both_directions(self, tmp_path):
        """The recorded refusal holds: a high-entropy body without a
        packer signature is NOT packed; a signature match still is.
        Entropy numbers exist as facts on the same file either way."""
        high_entropy = bytes((i * 89 + 11) % 256 for i in range(4096))
        p = tmp_path / "entropic.elf"
        p.write_bytes(_build_elf64_facts([
            (b".blob", 1, high_entropy, 0, 0),
        ]))
        assert is_packed(p) is None
        facts = extract_elf_facts(p)
        assert facts is not None
        assert any(r.entropy > 7.0 for r in facts.section_entropy)

        q = tmp_path / "upx.bin"
        q.write_bytes(b"\x7fELF" + b"\x00" * 12 + b"UPX!" + b"\x00" * 64)
        assert is_packed(q) == "upx"

    def test_import_fixture_facts_parity(self, tmp_path):
        """The import suite's canonical fixture through the facts
        walk: its two SHN_UNDEF symbols are imports, so exports stay
        empty — the two walks partition .dynsym, never double-count."""
        p = tmp_path / "imports.elf"
        p.write_bytes(_build_elf64_with_dynsym(sections=True))
        meta = parse_elf(p)
        facts = extract_elf_facts(p)
        assert meta is not None and facts is not None
        assert meta.imports == {"execve", "recv"}
        assert facts.exports == []
