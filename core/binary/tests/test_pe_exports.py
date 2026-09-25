"""Tests for the ``core.binary.pe`` export-table walk.

Crafted-table coverage (extending ``test_pe_facts``' builders):

  * ground truth through BOTH formats: declared name, ordinal
    base, named exports {name, ordinal, rva}, ordinal-only
    entries, unused-slot gaps
  * forwarders captured as CAPPED LITERAL STRINGS — text data,
    never resolved or chased (module invariant g)
  * declared-vs-walked counts: attacker u32s recorded verbatim,
    walked under the named caps with both boundary directions
  * malformation markers: NumberOfNames > NumberOfFunctions,
    ordinal-table entries out of range, unreadable directory /
    arrays, arrays pointing into headers or at each other
  * hostile names / forwarders through the render chokepoint

``build_export_section`` / ``build_export_image`` are shared with
the tables battery.
"""

from __future__ import annotations

import json
import struct

from core.binary import pe as pe_mod
from core.binary.pe import extract_pe_facts
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

_DIR_LEN = 40


def build_export_section(
    slots: list, names: list[tuple[bytes, int]], *,
    dll_name: bytes | None = b"MYLIB.dll", base: int = 1,
    va: int = 0x5000,
    n_funcs_override: int | None = None,
    n_names_override: int | None = None,
    funcs_rva_override: int | None = None,
    names_rva_override: int | None = None,
    ords_rva_override: int | None = None,
    dir_size_override: int | None = None,
) -> tuple[bytes, tuple[int, int]]:
    """Assemble an ``.edata`` payload.

    ``slots`` items: an ``int`` (a function RVA — 0 = unused
    slot), or ``bytes`` (forwarder text placed inside the section;
    the slot value becomes its RVA, which lands inside the export
    directory's extent — the forwarder shape by format
    definition). ``names``: ``(name_bytes, ordinal_index)`` pairs.
    The directory size defaults to the whole payload, the same
    convention real linkers use for .edata. Overrides exist to
    craft each hostile shape. Returns
    ``(section_bytes, (directory_va, directory_size))``.
    """
    body = bytearray(_DIR_LEN)

    def add(data: bytes) -> int:
        rva = va + len(body)
        body.extend(data)
        while len(body) % 4:
            body.append(0)
        return rva

    name_rva = add(dll_name + b"\x00") if dll_name is not None else 0
    slot_values = [add(s + b"\x00") if isinstance(s, bytes) else s
                   for s in slots]
    funcs_rva = add(b"".join(struct.pack("<I", v)
                             for v in slot_values))
    sym_rvas = [add(nb + b"\x00") for nb, _ in names]
    names_rva = add(b"".join(struct.pack("<I", r)
                             for r in sym_rvas))
    ords_rva = add(b"".join(struct.pack("<H", ix)
                            for _, ix in names))
    struct.pack_into(
        "<IIHHIIIIIII", body, 0,
        0, 0, 0, 0,
        name_rva, base,
        len(slots) if n_funcs_override is None else n_funcs_override,
        len(names) if n_names_override is None else n_names_override,
        funcs_rva if funcs_rva_override is None else funcs_rva_override,
        names_rva if names_rva_override is None else names_rva_override,
        ords_rva if ords_rva_override is None else ords_rva_override,
    )
    size = len(body) if dir_size_override is None else dir_size_override
    return bytes(body), (va, size)


def build_export_image(
    slots: list, names: list[tuple[bytes, int]], *,
    bits: int = 64, export_dir_override: tuple[int, int] | None = None,
    **section_kwargs,
) -> bytes:
    magic = _PE32PLUS_MAGIC if bits == 64 else _PE32_MAGIC
    machine = _MACHINE_AMD64 if bits == 64 else _MACHINE_I386
    edata, exp_dir = build_export_section(slots, names,
                                          **section_kwargs)
    return build_pe(PeSpec(magic=magic, machine=machine, secs=[
        Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
        Sec(name=b".edata", va=0x5000, data=edata,
            characteristics=_RDATA_CHARACTERISTICS),
    ], data_dirs={0: export_dir_override or exp_dir}))


_GT_SLOTS = [0x1111, 0x2222, b"NTDLL.RtlDoThing", 0, 0x3333]
_GT_NAMES = [(b"alpha", 0), (b"beta", 1), (b"fwd_alias", 2)]


# ---------------------------------------------------------------------------
# Ground truth — both formats
# ---------------------------------------------------------------------------


class TestExportGroundTruth:
    def _assert_ground_truth(self, facts) -> None:
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.dll_name == "MYLIB.dll"
        assert exp.ordinal_base == 5
        assert exp.declared_function_count == 5
        assert exp.declared_name_count == 3
        assert exp.walked_function_count == 5
        assert exp.walked_name_count == 3
        by_name = {s.name: s for s in exp.named}
        assert by_name["alpha"].ordinal == 5
        assert by_name["alpha"].rva == 0x1111
        assert by_name["alpha"].forwarder is None
        assert by_name["beta"].ordinal == 6
        assert by_name["beta"].rva == 0x2222
        fwd = by_name["fwd_alias"]
        assert fwd.ordinal == 7
        assert fwd.forwarder == "NTDLL.RtlDoThing"
        assert exp.forwarder_count == 1
        # Slot 3 is zero — an unused ordinal, absent by design;
        # slot 4 has no name — ordinal-only.
        assert [(s.ordinal, s.rva) for s in exp.ordinal_only] == \
            [(9, 0x3333)]
        assert exp.caps_hit == []
        assert facts.caps_hit == []

    def test_pe32plus(self, tmp_path):
        p = tmp_path / "exp64.dll"
        p.write_bytes(build_export_image(_GT_SLOTS, _GT_NAMES,
                                         base=5))
        self._assert_ground_truth(extract_pe_facts(p))

    def test_pe32(self, tmp_path):
        """Same table through the 32-bit directory-table offsets —
        extraction must be indistinguishable."""
        p = tmp_path / "exp32.dll"
        p.write_bytes(build_export_image(_GT_SLOTS, _GT_NAMES,
                                         base=5, bits=32))
        self._assert_ground_truth(extract_pe_facts(p))

    def test_two_names_one_slot(self, tmp_path):
        """Alias exports (two names, one ordinal index) both
        record; the slot leaves ordinal_only exactly once."""
        p = tmp_path / "alias.dll"
        p.write_bytes(build_export_image(
            [0x4000], [(b"first", 0), (b"second", 0)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert [s.name for s in exp.named] == ["first", "second"]
        assert all(s.rva == 0x4000 for s in exp.named)
        assert exp.ordinal_only == []

    def test_dll_name_rva_zero_is_absence(self, tmp_path):
        p = tmp_path / "noname.dll"
        p.write_bytes(build_export_image([0x1000], [],
                                         dll_name=None))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.exports is not None
        assert facts.exports.dll_name is None
        assert "export_dll_name_unreadable" not in facts.caps_hit

    def test_to_dict_round_trips_json(self, tmp_path):
        p = tmp_path / "dict.dll"
        p.write_bytes(build_export_image(_GT_SLOTS, _GT_NAMES,
                                         base=5))
        facts = extract_pe_facts(p)
        assert facts is not None
        parsed = json.loads(json.dumps(facts.to_dict()))
        assert parsed["exports"]["dll_name"] == "MYLIB.dll"
        assert parsed["exports"]["named"][2]["forwarder"] == \
            "NTDLL.RtlDoThing"


# ---------------------------------------------------------------------------
# Forwarders are literal text — never resolved (invariant g)
# ---------------------------------------------------------------------------


class TestForwarders:
    def test_hostile_forwarder_is_captured_literally_and_inert(
            self, tmp_path):
        """A forwarder is attacker text. This one carries a
        control byte, a bidi override, and a plausible-looking
        chase target — it must come back as the exact capped
        literal (data), and the render chokepoint must make it
        inert. No resolution happens: the record holds the text
        and the slot RVA, nothing more."""
        hostile = "EVIL\x1b]0;x.DLL.Fn\u202e".encode()
        p = tmp_path / "fwd.dll"
        p.write_bytes(build_export_image(
            [hostile], [(b"f", 0)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        sym = exp.named[0]
        assert sym.forwarder == "EVIL\x1b]0;x.DLL.Fn\u202e"
        assert exp.forwarder_count == 1
        # The slot RVA (where the text lives) is retained as a raw
        # fact beside the literal.
        assert sym.rva is not None
        rendered = escape_nonprintable(sym.forwarder)
        assert not has_nonprintable(rendered)
        assert "\\x1b" in rendered and "\\u202e" in rendered

    def test_forwarder_to_a_forwarder_shaped_string_is_not_chased(
            self, tmp_path):
        """Even when the forwarder text names another export of
        this same DLL (the classic cycle bait), it stays one
        literal capture — there is no resolution step to loop."""
        p = tmp_path / "cycle.dll"
        p.write_bytes(build_export_image(
            [b"MYLIB.cyc_b", b"MYLIB.cyc_a"],
            [(b"cyc_a", 0), (b"cyc_b", 1)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        by_name = {s.name: s for s in exp.named}
        assert by_name["cyc_a"].forwarder == "MYLIB.cyc_b"
        assert by_name["cyc_b"].forwarder == "MYLIB.cyc_a"
        assert exp.forwarder_count == 2
        assert facts.caps_hit == []

    def test_unterminated_forwarder_keeps_capped_prefix(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_TABLE_NAME_BYTES", 8)
        p = tmp_path / "fwdtrunc.dll"
        p.write_bytes(build_export_image(
            [b"NTDLL.RtlVeryLongForwardName"], [(b"f", 0)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.named[0].forwarder == "NTDLL.Rt"
        assert "export_forwarder_truncated" in exp.caps_hit

    def test_rva_outside_directory_extent_is_not_a_forwarder(
            self, tmp_path):
        """The forwarder test is the directory-extent rule the
        loader applies — an RVA one byte past the extent is a
        plain function RVA."""
        edata, (va, size) = build_export_section(
            [0], [(b"edge", 0)])
        arr = bytearray(edata)
        # Patch function slot 0 to the first RVA PAST the
        # directory extent; the funcs array is located through the
        # directory header itself.
        (funcs_rva,) = struct.unpack_from("<I", arr, 28)
        struct.pack_into("<I", arr, funcs_rva - va, va + size)
        p = tmp_path / "edge.dll"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".edata", va=va, data=bytes(arr),
                vsize=size + 0x40,
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={0: (va, size)})))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.named[0].forwarder is None
        assert exp.named[0].rva == va + size
        assert exp.forwarder_count == 0


# ---------------------------------------------------------------------------
# Declared vs walked counts — attacker u32s under named caps
# ---------------------------------------------------------------------------


class TestExportCounts:
    def test_function_cap_boundary(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_EXPORT_FUNCTIONS", 4)
        p = tmp_path / "fatcap.dll"
        p.write_bytes(build_export_image(
            [0x1000 + i for i in range(4)], []))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.walked_function_count == 4
        assert "export_functions_capped" not in exp.caps_hit

        q = tmp_path / "fpast.dll"
        q.write_bytes(build_export_image(
            [0x1000 + i for i in range(5)], []))
        facts = extract_pe_facts(q)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.declared_function_count == 5
        assert exp.walked_function_count == 4
        assert "export_functions_capped" in exp.caps_hit
        assert "export_functions_capped" in facts.caps_hit

    def test_name_cap_boundary(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_EXPORT_NAMES", 2)
        slots = [0x1000, 0x1004, 0x1008]
        at_cap = [(b"n0", 0), (b"n1", 1)]
        p = tmp_path / "natcap.dll"
        p.write_bytes(build_export_image(slots, at_cap))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.walked_name_count == 2
        assert "export_names_capped" not in exp.caps_hit

        q = tmp_path / "npast.dll"
        q.write_bytes(build_export_image(
            slots, at_cap + [(b"n2", 2)]))
        facts = extract_pe_facts(q)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.declared_name_count == 3
        assert exp.walked_name_count == 2
        assert "export_names_capped" in exp.caps_hit
        # The uncounted slot still surfaces as ordinal-only — the
        # walk drops the NAME row, never the function fact.
        assert [s.ordinal for s in exp.ordinal_only] == [3]

    def test_u32_max_declared_counts_stay_bounded(self, tmp_path):
        """NumberOfFunctions / NumberOfNames at u32-max: recorded
        verbatim, walked to the caps, degraded by the short bulk
        read — bounded and marked, never a 4-billion-row walk."""
        p = tmp_path / "u32max.dll"
        p.write_bytes(build_export_image(
            [0x1111], [(b"one", 0)],
            n_funcs_override=0xFFFF_FFFF,
            n_names_override=0xFFFF_FFFF))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.declared_function_count == 0xFFFF_FFFF
        assert exp.declared_name_count == 0xFFFF_FFFF
        assert "export_functions_capped" in exp.caps_hit
        assert "export_names_capped" in exp.caps_hit
        assert "export_functions_unreadable" in exp.caps_hit
        assert exp.walked_function_count < \
            pe_mod._MAX_EXPORT_FUNCTIONS
        # The u32-max claim also exceeds the function count —
        # that malformation fact is recorded independently.
        assert "export_names_exceed_functions" not in exp.caps_hit
        assert facts.caps_hit  # mirrored


# ---------------------------------------------------------------------------
# Malformation markers
# ---------------------------------------------------------------------------


class TestExportMalformations:
    def test_names_exceed_functions_marked(self, tmp_path):
        p = tmp_path / "excess.dll"
        p.write_bytes(build_export_image(
            [0x1000], [(b"a", 0)], n_names_override=2,
            n_funcs_override=1))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert "export_names_exceed_functions" in exp.caps_hit

    def test_ordinal_out_of_range_records_addressless_name(
            self, tmp_path):
        p = tmp_path / "oob.dll"
        p.write_bytes(build_export_image(
            [0x1000, 0x2000], [(b"ghost", 7)], base=10))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert "export_ordinal_out_of_range" in exp.caps_hit
        ghost = exp.named[0]
        assert ghost.name == "ghost"
        assert ghost.rva is None
        assert ghost.ordinal == 17          # base + claimed index
        assert ghost.forwarder is None

    def test_ordinal_base_overflow_masked_and_marked(self, tmp_path):
        """ordinal_base + index past u32: consumers may assume a
        u32 export ordinal, so the value is masked into range and
        the degeneracy marked — in-range field, honest record."""
        p = tmp_path / "bigbase.dll"
        p.write_bytes(build_export_image(
            [0x1000, 0x2000], [(b"wrap", 1)], base=0xFFFF_FFFF))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.ordinal_base == 0xFFFF_FFFF
        wrapped = exp.named[0]
        assert wrapped.ordinal == 0          # (0xFFFFFFFF + 1) masked
        assert "export_ordinal_overflow" in exp.caps_hit
        # Index 0 stays in range — recorded unmasked.
        assert [s.ordinal for s in exp.ordinal_only] == [0xFFFF_FFFF]

    def test_zero_name_rva_is_marked_not_fabricated(self, tmp_path):
        """A zero AddressOfNames slot must not resolve through the
        header-region rule into DOS-stub text — the name is a
        marked absence."""
        edata, (va, size) = build_export_section(
            [0x1000], [(b"real", 0)])
        arr = bytearray(edata)
        (names_rva,) = struct.unpack_from("<I", arr, 32)
        struct.pack_into("<I", arr, names_rva - va, 0)
        p = tmp_path / "zeroname.dll"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".edata", va=va, data=bytes(arr),
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={0: (va, size)})))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.named[0].name is None
        assert "export_name_rva_zero" in exp.caps_hit
        assert "MZ" not in (exp.named[0].name or "")

    def test_unreadable_directory(self, tmp_path):
        p = tmp_path / "badexp.dll"
        p.write_bytes(build_export_image(
            [0x1000], [], export_dir_override=(0x0900_0000, 0x100)))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.exports is None
        assert "export_directory_unreadable" in facts.caps_hit

    def test_arrays_pointing_into_headers_stay_bounded(
            self, tmp_path):
        """AddressOfFunctions/Names/Ordinals aimed at the DOS
        header: the header region identity-maps (resolver
        invariant c), so the walk reads bounded header bytes as
        slots — garbage-in-bounded-garbage-out, never a crash."""
        p = tmp_path / "hdrarrays.dll"
        p.write_bytes(build_export_image(
            [0x1000], [(b"x", 0)],
            funcs_rva_override=0x10,
            names_rva_override=0x20,
            ords_rva_override=0x30))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.walked_function_count <= 1
        assert exp.walked_name_count <= 1

    def test_arrays_pointing_at_each_other_stay_bounded(
            self, tmp_path):
        """AddressOfNames aimed at the function array (and the
        directory at itself as a name): self-referential tables
        parse to bounded data-shaped noise with markers where
        reads fail — the contract is no exception, no loop."""
        edata, (va, size) = build_export_section(
            [0x1111, 0x2222], [(b"n0", 0), (b"n1", 1)])
        arr = bytearray(edata)
        (funcs_rva,) = struct.unpack_from("<I", arr, 28)
        struct.pack_into("<I", arr, 32, funcs_rva)   # names → funcs
        struct.pack_into("<I", arr, 16, va)          # dll name → dir
        p = tmp_path / "selfref.dll"
        p.write_bytes(build_pe(PeSpec(secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x40),
            Sec(name=b".edata", va=va, data=bytes(arr),
                characteristics=_RDATA_CHARACTERISTICS),
        ], data_dirs={0: (va, size)})))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.walked_name_count == 2


# ---------------------------------------------------------------------------
# Hostile names + budgets
# ---------------------------------------------------------------------------


class TestHostileExportNames:
    def test_control_byte_names_stored_raw_render_inert(
            self, tmp_path):
        hostile = b"ex\x1b[2Jport\x07"
        p = tmp_path / "hostname.dll"
        p.write_bytes(build_export_image([0x1000], [(hostile, 0)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        name = exp.named[0].name
        assert name == "ex\x1b[2Jport\x07"
        rendered = escape_nonprintable(name)
        assert not has_nonprintable(rendered)
        assert "\\x1b" in rendered

    def test_name_budget_degrades_to_none(self, tmp_path,
                                          monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_TABLE_NAME_TOTAL_BYTES",
                            len("MYLIB.dll") + len("kept"))
        p = tmp_path / "nbudget.dll"
        p.write_bytes(build_export_image(
            [0x1000, 0x2000], [(b"kept", 0), (b"dropped", 1)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.dll_name == "MYLIB.dll"
        assert exp.named[0].name == "kept"
        assert exp.named[1].name is None
        assert exp.named[1].rva == 0x2000    # the fact survives
        assert "export_name_budget_exhausted" in exp.caps_hit
        assert exp.walked_name_count == 2    # counts stay honest

    def test_budget_dropped_forwarder_not_counted(self, tmp_path,
                                                  monkeypatch):
        """forwarder_count counts CAPTURED literals: a forwarder-
        shaped slot whose string was dropped by the spent budget
        leaves the marker, not a count that disagrees with the
        record's contents."""
        monkeypatch.setattr(pe_mod, "_MAX_TABLE_NAME_TOTAL_BYTES",
                            len("MYLIB.dll") + len("n0"))
        p = tmp_path / "fwdbudget.dll"
        p.write_bytes(build_export_image(
            [b"NTDLL.Dropped"], [(b"n0", 0)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        exp = facts.exports
        assert exp is not None
        assert exp.named[0].name == "n0"
        assert exp.named[0].forwarder is None
        assert exp.forwarder_count == 0
        assert "export_forwarder_budget_exhausted" in exp.caps_hit
