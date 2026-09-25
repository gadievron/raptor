"""Tests for the PE data-directory facts and the RSDS debug
identity: presence bits (Authenticode / CLR), the debug-directory
walk rules (first RSDS wins, conflict marker, PointerToRawData
preference), and the canonical identity serialization with its
NORMATIVE byte-level vectors.

The vectors here are the contract for every future consumer of
``canonical_pe_identity``: a known RSDS record's raw bytes must
serialize to exactly the pinned string, and a dashed/uppercase GUID
string must land on the same spelling.
"""

from __future__ import annotations

import json
import struct

import pytest

from core.binary import pe as pe_mod
from core.binary.pe import (
    canonical_pe_identity,
    canonical_pe_identity_from_guid_string,
    extract_pe_facts,
    pe_facts_evidence,
)

from .test_pe_facts import PeSpec, Sec, build_pe

# --- Normative vector -------------------------------------------------
# GUID {A1B2C3D4-E5F6-0718-90AB-CDEF01234567}, age 42.
# Raw RSDS storage is little-endian Data1/Data2/Data3 + Data4 as-is.
_VEC_GUID_RAW = bytes.fromhex("d4c3b2a1f6e5180790abcdef01234567")
_VEC_GUID_TEXT = "A1B2C3D4-E5F6-0718-90AB-CDEF01234567"
_VEC_AGE = 42
_VEC_CANONICAL = "a1b2c3d4e5f6071890abcdef012345672a"

_DEBUG_ENTRY_SIZE = 28


def _rsds_blob(guid: bytes, age: int, path: bytes) -> bytes:
    return b"RSDS" + guid + struct.pack("<I", age) + path + b"\x00"


def _debug_entry(*, dtype: int = 2, size_of_data: int,
                 addr: int, ptr: int) -> bytes:
    return struct.pack("<IIHHIIII", 0, 0, 0, 0, dtype,
                       size_of_data, addr, ptr)


def _image_with_debug(
    entries_and_blobs: list[tuple[int, bytes]],
    *,
    dbg_va: int = 0x4000,
    dbg_raw: int = 0x800,
    extra_dirs: dict[int, tuple[int, int]] | None = None,
    n_entries_claimed: int | None = None,
) -> bytes:
    """One image whose .dbg section carries a debug directory.

    ``entries_and_blobs``: per entry, ``(blob_offset_in_section,
    blob_bytes)`` — the entry's AddressOfRawData / PointerToRawData
    both point at the blob (RVA and file offset respectively).
    A negative offset means "entry with no data pointers".
    """
    n = len(entries_and_blobs)
    section = bytearray(0x400)
    for i, (blob_off, blob) in enumerate(entries_and_blobs):
        if blob_off < 0:
            entry = _debug_entry(size_of_data=0, addr=0, ptr=0)
        else:
            section[blob_off:blob_off + len(blob)] = blob
            entry = _debug_entry(
                size_of_data=len(blob),
                addr=dbg_va + blob_off,
                ptr=dbg_raw + blob_off,
            )
        section[i * _DEBUG_ENTRY_SIZE:
                (i + 1) * _DEBUG_ENTRY_SIZE] = entry
    dirs = {6: (dbg_va, (n_entries_claimed if n_entries_claimed
                         is not None else n) * _DEBUG_ENTRY_SIZE)}
    dirs.update(extra_dirs or {})
    return build_pe(PeSpec(
        secs=[
            Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x100),
            Sec(name=b".dbg", va=dbg_va, data=bytes(section),
                raw_ptr=dbg_raw),
        ],
        data_dirs=dirs,
    ))


# ---------------------------------------------------------------------------
# Canonical serialization — normative vectors
# ---------------------------------------------------------------------------


class TestCanonicalIdentity:
    def test_normative_raw_byte_vector(self):
        assert canonical_pe_identity(_VEC_GUID_RAW, _VEC_AGE) \
            == _VEC_CANONICAL

    def test_normative_guid_string_vector(self):
        assert canonical_pe_identity_from_guid_string(
            _VEC_GUID_TEXT, _VEC_AGE) == _VEC_CANONICAL

    def test_both_helpers_agree_on_every_spelling(self):
        for text in (
            _VEC_GUID_TEXT,
            _VEC_GUID_TEXT.lower(),
            "{" + _VEC_GUID_TEXT + "}",
            _VEC_GUID_TEXT.replace("-", ""),
        ):
            assert canonical_pe_identity_from_guid_string(
                text, _VEC_AGE) == canonical_pe_identity(
                _VEC_GUID_RAW, _VEC_AGE)

    def test_age_is_unpadded_lowercase_hex(self):
        base = canonical_pe_identity(_VEC_GUID_RAW, 1)
        assert base.endswith("2345671")          # "1", never "01"
        assert canonical_pe_identity(_VEC_GUID_RAW, 0xAB).endswith("ab")
        assert canonical_pe_identity(_VEC_GUID_RAW, 0).endswith("670")

    def test_all_zero_guid_serializes_verbatim(self):
        # Degenerate-identity screening is the CONSUMER's policy;
        # the serializer spells what it was given.
        assert canonical_pe_identity(b"\x00" * 16, 5) == "0" * 32 + "5"

    @pytest.mark.parametrize("bad_guid", [b"", b"\x00" * 15,
                                          b"\x00" * 17])
    def test_wrong_guid_width_refused(self, bad_guid):
        with pytest.raises(ValueError):
            canonical_pe_identity(bad_guid, 1)

    def test_negative_age_refused(self):
        with pytest.raises(ValueError):
            canonical_pe_identity(_VEC_GUID_RAW, -1)
        with pytest.raises(ValueError):
            canonical_pe_identity_from_guid_string(_VEC_GUID_TEXT, -1)

    @pytest.mark.parametrize("bad_text", [
        "", "not-a-guid",
        "A1B2C3D4-E5F6-0718-90AB-CDEF0123456",      # 31 digits
        "A1B2C3D4-E5F6-0718-90AB-CDEF01234567AB",   # 34 digits
        "G1B2C3D4-E5F6-0718-90AB-CDEF01234567",     # non-hex
    ])
    def test_non_guid_text_refused(self, bad_text):
        with pytest.raises(ValueError):
            canonical_pe_identity_from_guid_string(bad_text, 1)


# ---------------------------------------------------------------------------
# Directory presence bits
# ---------------------------------------------------------------------------


class TestPresenceBits:
    def test_authenticode_presence(self, tmp_path):
        p = tmp_path / "signedclaim.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)],
            data_dirs={4: (0x9000, 0x100)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.authenticode_present is True

    def test_authenticode_absent_and_zero_size(self, tmp_path):
        p = tmp_path / "plain.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.authenticode_present is False

        q = tmp_path / "zerosize.exe"
        q.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)],
            data_dirs={4: (0x9000, 0)},
        )))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert facts.authenticode_present is False

    def test_dotnet_presence(self, tmp_path):
        p = tmp_path / "managed.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)],
            data_dirs={14: (0x3000, 72)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.dotnet_present is True

        q = tmp_path / "native.exe"
        q.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)])))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert facts.dotnet_present is False

    def test_directory_count_flood_capped(self, tmp_path):
        p = tmp_path / "manydirs.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)],
            n_dirs_claimed=2**31,
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "data_directories_capped" in facts.caps_hit

    def test_sixteen_directories_is_clean(self, tmp_path):
        p = tmp_path / "exactly16.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)])))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert "data_directories_capped" not in facts.caps_hit


# ---------------------------------------------------------------------------
# Debug-directory RSDS identity
# ---------------------------------------------------------------------------


class TestDebugIdentity:
    def test_end_to_end_normative_vector(self, tmp_path):
        blob = _rsds_blob(_VEC_GUID_RAW, _VEC_AGE,
                          b"c:\\build\\out\\app.pdb")
        p = tmp_path / "rsds.exe"
        p.write_bytes(_image_with_debug([(0x40, blob)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_guid == _VEC_GUID_RAW.hex()
        assert facts.debug_age == _VEC_AGE
        assert facts.pdb_basename == "app.pdb"
        assert facts.debug_identity == _VEC_CANONICAL
        assert "conflicting_debug_entries" not in facts.caps_hit

    def test_forward_slash_and_bare_names(self, tmp_path):
        blob = _rsds_blob(_VEC_GUID_RAW, 1, b"/mnt/build/lib.pdb")
        p = tmp_path / "slash.exe"
        p.write_bytes(_image_with_debug([(0x40, blob)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.pdb_basename == "lib.pdb"

        blob = _rsds_blob(_VEC_GUID_RAW, 1, b"bare.pdb")
        q = tmp_path / "bare.exe"
        q.write_bytes(_image_with_debug([(0x40, blob)]))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert facts.pdb_basename == "bare.pdb"

    def test_all_zero_guid_recorded_verbatim(self, tmp_path):
        # The extractor records the degenerate value; screening it
        # (e.g. falling through to a content hash) is the identity
        # front door's policy decision, made at its layer.
        blob = _rsds_blob(b"\x00" * 16, 5, b"zero.pdb")
        p = tmp_path / "zeroguid.exe"
        p.write_bytes(_image_with_debug([(0x40, blob)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_guid == "0" * 32
        assert facts.debug_age == 5
        assert facts.debug_identity == "0" * 32 + "5"

    def test_first_rsds_wins_and_conflict_is_marked(self, tmp_path):
        other_guid = bytes(range(16))
        first = _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"first.pdb")
        second = _rsds_blob(other_guid, 7, b"second.pdb")
        p = tmp_path / "twosources.exe"
        p.write_bytes(_image_with_debug([(0x80, first),
                                         (0x140, second)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_identity == _VEC_CANONICAL
        assert facts.pdb_basename == "first.pdb"
        assert "conflicting_debug_entries" in facts.caps_hit

    def test_duplicate_identical_rsds_is_not_a_conflict(self, tmp_path):
        blob = _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"same.pdb")
        p = tmp_path / "dup.exe"
        p.write_bytes(_image_with_debug([(0x80, blob), (0x140, blob)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_identity == _VEC_CANONICAL
        assert "conflicting_debug_entries" not in facts.caps_hit

    def test_pointer_to_raw_data_preferred_on_disagreement(
            self, tmp_path):
        """The RVA points at a DIFFERENT (garbage) blob than the
        file pointer — the file pointer's bytes win."""
        good = _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"good.pdb")
        decoy = _rsds_blob(bytes(range(16)), 9, b"decoy.pdb")
        section = bytearray(0x400)
        section[0x40:0x40 + len(decoy)] = decoy      # at the RVA
        section[0x140:0x140 + len(good)] = good      # at the file ptr
        dbg_va, dbg_raw = 0x4000, 0x800
        entry = _debug_entry(size_of_data=len(good),
                             addr=dbg_va + 0x40,
                             ptr=dbg_raw + 0x140)
        section[0:_DEBUG_ENTRY_SIZE] = entry
        p = tmp_path / "disagree.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".dbg", va=dbg_va, data=bytes(section),
                      raw_ptr=dbg_raw)],
            data_dirs={6: (dbg_va, _DEBUG_ENTRY_SIZE)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.pdb_basename == "good.pdb"
        assert facts.debug_identity == _VEC_CANONICAL

    def test_rva_only_entry_resolves_through_chokepoint(self, tmp_path):
        blob = _rsds_blob(_VEC_GUID_RAW, 3, b"rvaonly.pdb")
        section = bytearray(0x400)
        section[0x40:0x40 + len(blob)] = blob
        dbg_va, dbg_raw = 0x4000, 0x800
        entry = _debug_entry(size_of_data=len(blob),
                             addr=dbg_va + 0x40, ptr=0)
        section[0:_DEBUG_ENTRY_SIZE] = entry
        p = tmp_path / "rvaonly.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".dbg", va=dbg_va, data=bytes(section),
                      raw_ptr=dbg_raw)],
            data_dirs={6: (dbg_va, _DEBUG_ENTRY_SIZE)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.pdb_basename == "rvaonly.pdb"

    def test_non_codeview_entries_skipped_silently(self, tmp_path):
        pogo = _debug_entry(dtype=13, size_of_data=0, addr=0, ptr=0)
        blob = _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"after.pdb")
        section = bytearray(0x400)
        section[0:_DEBUG_ENTRY_SIZE] = pogo
        section[0x140:0x140 + len(blob)] = blob
        dbg_va, dbg_raw = 0x4000, 0x800
        entry = _debug_entry(size_of_data=len(blob),
                             addr=dbg_va + 0x140,
                             ptr=dbg_raw + 0x140)
        section[_DEBUG_ENTRY_SIZE:2 * _DEBUG_ENTRY_SIZE] = entry
        p = tmp_path / "pogo.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".dbg", va=dbg_va, data=bytes(section),
                      raw_ptr=dbg_raw)],
            data_dirs={6: (dbg_va, 2 * _DEBUG_ENTRY_SIZE)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.pdb_basename == "after.pdb"
        assert "debug_directory_unreadable" not in facts.caps_hit

    def test_unmapped_debug_directory_marked(self, tmp_path):
        p = tmp_path / "ghostdir.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"x" * 16)],
            data_dirs={6: (0x900000, 2 * _DEBUG_ENTRY_SIZE)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_identity is None
        assert "debug_directory_unreadable" in facts.caps_hit

    def test_entry_flood_capped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pe_mod, "_MAX_DEBUG_DIR_ENTRIES", 2)
        blob = _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"deep.pdb")
        entries = [(-1, b""), (-1, b""), (0x200, blob)]
        p = tmp_path / "flood.exe"
        p.write_bytes(_image_with_debug(entries))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_identity is None      # third entry unwalked
        assert "debug_entries_capped" in facts.caps_hit

    def test_size_of_data_is_never_a_read_budget(self, tmp_path):
        """SizeOfData = u32 max: the blob read is capped at the
        fixed part + the pdb-path cap and the identity still
        extracts from the in-section bytes."""
        blob = _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"capped.pdb")
        section = bytearray(0x400)
        section[0x40:0x40 + len(blob)] = blob
        dbg_va, dbg_raw = 0x4000, 0x800
        entry = _debug_entry(size_of_data=2**32 - 1,
                             addr=dbg_va + 0x40,
                             ptr=dbg_raw + 0x40)
        section[0:_DEBUG_ENTRY_SIZE] = entry
        p = tmp_path / "hugeclaim.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".dbg", va=dbg_va, data=bytes(section),
                      raw_ptr=dbg_raw)],
            data_dirs={6: (dbg_va, _DEBUG_ENTRY_SIZE)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_identity == _VEC_CANONICAL
        assert facts.pdb_basename == "capped.pdb"

    def test_unterminated_pdb_path_is_marked(self, tmp_path):
        # No NUL inside the blob (size_of_data bounds the read to
        # the unterminated text): guid/age are fixed-offset facts
        # and survive; the name is a recorded gap.
        raw = b"RSDS" + _VEC_GUID_RAW + struct.pack("<I", _VEC_AGE) \
            + b"unterminated"
        section = bytearray(0x400)
        section[0x40:0x40 + len(raw)] = raw
        dbg_va, dbg_raw = 0x4000, 0x800
        entry = _debug_entry(size_of_data=len(raw),
                             addr=dbg_va + 0x40,
                             ptr=dbg_raw + 0x40)
        section[0:_DEBUG_ENTRY_SIZE] = entry
        p = tmp_path / "nonul.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".dbg", va=dbg_va, data=bytes(section),
                      raw_ptr=dbg_raw)],
            data_dirs={6: (dbg_va, _DEBUG_ENTRY_SIZE)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_guid == _VEC_GUID_RAW.hex()
        assert facts.debug_age == _VEC_AGE
        assert facts.debug_identity == _VEC_CANONICAL
        assert facts.pdb_basename is None
        assert "pdb_name_malformed" in facts.caps_hit

    def test_unparsed_codeview_entry_is_marked(self, tmp_path):
        """A CodeView entry that yields no identity — both data
        pointers zero here, short/garbled payloads equivalently —
        leaves a marker: absent identity stays distinguishable from
        absent debug info."""
        p = tmp_path / "nopointers.exe"
        p.write_bytes(_image_with_debug([(-1, b"")]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.debug_identity is None
        assert "debug_codeview_unparsed" in facts.caps_hit

        short = b"RSDS" + b"\x00" * 8      # shorter than GUID + age
        q = tmp_path / "shortrsds.exe"
        q.write_bytes(_image_with_debug([(0x40, short)]))
        facts = extract_pe_facts(q)
        assert facts is not None
        assert facts.debug_identity is None
        assert "debug_codeview_unparsed" in facts.caps_hit

        # A clean RSDS carries neither the marker nor a gap.
        clean = _rsds_blob(_VEC_GUID_RAW, 1, b"clean.pdb")
        r = tmp_path / "clean.exe"
        r.write_bytes(_image_with_debug([(0x40, clean)]))
        facts = extract_pe_facts(r)
        assert facts is not None
        assert facts.debug_identity is not None
        assert "debug_codeview_unparsed" not in facts.caps_hit

    def test_pe32_image_directories_and_identity_end_to_end(
            self, tmp_path):
        """Full PE32 (0x10B) image: the data-directory table sits at
        DIFFERENT offsets than PE32+ (count at 92, table at 96, vs
        108/112) — presence bits and the RSDS identity must extract
        identically through the 32-bit layout, so a transposed
        offset in either arm cannot survive."""
        blob = _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"c:\\x\\pe32.pdb")
        section = bytearray(0x400)
        section[0x40:0x40 + len(blob)] = blob
        dbg_va, dbg_raw = 0x4000, 0x800
        entry = _debug_entry(size_of_data=len(blob),
                             addr=dbg_va + 0x40, ptr=dbg_raw + 0x40)
        section[0:_DEBUG_ENTRY_SIZE] = entry
        p = tmp_path / "pe32full.exe"
        p.write_bytes(build_pe(PeSpec(
            machine=0x014C, magic=0x10B,
            dll_characteristics=0x0140,      # DYNAMIC_BASE | NX
            secs=[
                Sec(name=b".text", va=0x1000, data=b"\xcc" * 0x100),
                Sec(name=b".dbg", va=dbg_va, data=bytes(section),
                    raw_ptr=dbg_raw),
            ],
            data_dirs={4: (0x9000, 0x100),
                       6: (dbg_va, _DEBUG_ENTRY_SIZE),
                       14: (0x5000, 72)},
        )))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.bits == 32
        assert facts.pe_format == "pe32"
        assert facts.image_base == 0x400000
        assert facts.aslr is True and facts.dep is True
        assert facts.authenticode_present is True
        assert facts.dotnet_present is True
        assert facts.debug_identity == _VEC_CANONICAL
        assert facts.debug_age == _VEC_AGE
        assert facts.pdb_basename == "pe32.pdb"
        assert "conflicting_debug_entries" not in facts.caps_hit

    def test_oversized_basename_capped_with_marker(self, tmp_path):
        long_name = b"n" * 300 + b".pdb"
        blob = _rsds_blob(_VEC_GUID_RAW, 1, b"c:\\x\\" + long_name)
        p = tmp_path / "longbase.exe"
        p.write_bytes(_image_with_debug([(0x40, blob)]))
        facts = extract_pe_facts(p)
        assert facts is not None
        assert facts.pdb_basename is not None
        assert len(facts.pdb_basename.encode("utf-8")) \
            <= pe_mod._MAX_PDB_BASENAME_BYTES
        assert "pdb_name_truncated" in facts.caps_hit


# ---------------------------------------------------------------------------
# Evidence record + JSON shape
# ---------------------------------------------------------------------------


class TestEvidenceAndSerialization:
    def test_facts_evidence_record(self, tmp_path):
        from core.evidence import EvidenceTier
        p = tmp_path / "ev.exe"
        p.write_bytes(_image_with_debug(
            [(0x40, _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"ev.pdb"))]))
        facts = extract_pe_facts(p)
        assert facts is not None
        record = pe_facts_evidence("ab" * 32, p, facts)
        assert record.tier is EvidenceTier.HEADER_BACKED
        assert record.kind == "pe_facts"
        assert record.reproducible is True
        assert record.data["facts"]["debug_identity"] == _VEC_CANONICAL
        # Same bytes → same evidence id (stable, content-bound).
        again = pe_facts_evidence("ab" * 32, p, facts)
        assert record.id == again.id

    def test_to_dict_is_json_serializable(self, tmp_path):
        p = tmp_path / "json.exe"
        p.write_bytes(_image_with_debug(
            [(0x40, _rsds_blob(_VEC_GUID_RAW, 1, b"j.pdb"))]))
        facts = extract_pe_facts(p)
        assert facts is not None
        payload = json.loads(json.dumps(facts.to_dict()))
        assert payload["debug_age"] == 1
        assert payload["sections"][0]["name"] == ".text"
        # The pre-declared signing slot ships in the record from
        # day one, empty = unexamined — schema-stable before the
        # signing-facts extraction populates it.
        assert payload["claimed_signer"] == ""
        assert facts.claimed_signer == ""
