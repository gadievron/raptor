"""Tests for core.binary.identity — the kind-aware identity front door.

The anchor-derivation vectors here are NORMATIVE: every join key in
the repo is derived by :func:`identity_anchor`, so a change that
moves any expected value below is an identity migration, not a
refactor.
"""

from __future__ import annotations

import hashlib

import pytest

from core.binary import addrmap
from core.binary.identity import (
    IDENTITY_KINDS,
    KIND_ELF_BUILD_ID,
    KIND_MACHO_UUID,
    KIND_PE_GUID_AGE,
    KIND_SHA256,
    ContentIdentity,
    content_identity,
    identity_anchor,
    manifest_anchor,
)
from packages.binary_analysis.tests.test_macho_facts import (
    build_fat,
    build_thin,
    uuid_cmd,
)

from .test_pe_identity import (
    _VEC_AGE,
    _VEC_CANONICAL,
    _VEC_GUID_RAW,
    _image_with_debug,
    _rsds_blob,
)

BUILD_ID = "fa1544052f2d4bfa87d3d3bfb1b7b9f4aa11c0de"

# sha256(_VEC_CANONICAL)[:16] — the normative hashed-anchor vector for
# pe_guid_age. A value-PREFIX anchor would be GUID-only (the age falls
# past 16 hex); the hash folds the age in.
_VEC_HASHED_ANCHOR = "8dc1cd84b4bda0e0"
# Same GUID, age 1 — must anchor differently (incremental relink).
_VEC_CANONICAL_AGE1 = _VEC_CANONICAL[:-2] + "1"
_VEC_HASHED_ANCHOR_AGE1 = "62a60e7d8402ce65"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _patch_build_id(monkeypatch, value):
    import core.analysis.binary_oracle as oracle
    if isinstance(value, BaseException):
        def probe(_p):
            raise value
        monkeypatch.setattr(oracle, "read_build_id", probe)
    else:
        monkeypatch.setattr(oracle, "read_build_id", lambda _p: value)


# ---------------------------------------------------------------------------
# Anchor derivation — the per-kind rule table
# ---------------------------------------------------------------------------


class TestIdentityAnchor:
    def test_prefix_kinds_truncate_to_16(self):
        for kind in (KIND_ELF_BUILD_ID, KIND_MACHO_UUID, KIND_SHA256):
            assert identity_anchor(kind, BUILD_ID) == BUILD_ID[:16]

    def test_kind_absent_is_elf_or_unknown_prefix(self):
        # Old records predate the kind field — the prefix rule, never
        # an error.
        assert identity_anchor(None, BUILD_ID) == BUILD_ID[:16]
        assert identity_anchor("", BUILD_ID) == BUILD_ID[:16]

    def test_pe_guid_age_is_hashed_not_prefixed(self):
        anchor = identity_anchor(KIND_PE_GUID_AGE, _VEC_CANONICAL)
        assert anchor == _VEC_HASHED_ANCHOR
        assert anchor != _VEC_CANONICAL[:16]

    def test_age_bump_moves_the_anchor(self):
        # MSVC incremental relinks keep the GUID and bump the age; a
        # prefix anchor would alias those builds.
        assert _VEC_CANONICAL_AGE1[:16] == _VEC_CANONICAL[:16]
        assert identity_anchor(KIND_PE_GUID_AGE, _VEC_CANONICAL_AGE1) \
            == _VEC_HASHED_ANCHOR_AGE1
        assert _VEC_HASHED_ANCHOR_AGE1 != _VEC_HASHED_ANCHOR

    def test_unknown_kind_refuses(self):
        assert identity_anchor("te", BUILD_ID) is None
        assert identity_anchor("pe_guid_age_v2", BUILD_ID) is None

    def test_junk_values_refuse(self):
        for kind in (*IDENTITY_KINDS, None):
            assert identity_anchor(kind, None) is None
            assert identity_anchor(kind, "") is None
            assert identity_anchor(kind, "not hex!") is None
            assert identity_anchor(kind, "abc") is None  # < 8 hex

    def test_case_and_space_normalised(self):
        assert identity_anchor(KIND_ELF_BUILD_ID, f"  {BUILD_ID.upper()} ") \
            == BUILD_ID[:16]
        assert identity_anchor(KIND_PE_GUID_AGE, _VEC_CANONICAL.upper()) \
            == _VEC_HASHED_ANCHOR


# ---------------------------------------------------------------------------
# ELF arm
# ---------------------------------------------------------------------------


class TestElfArm:
    def test_build_id_identity(self, monkeypatch, tmp_path):
        p = tmp_path / "t"
        p.write_bytes(b"\x7fELF" + b"\x00" * 32)
        _patch_build_id(monkeypatch, BUILD_ID)
        assert content_identity(p) == ContentIdentity(
            KIND_ELF_BUILD_ID, BUILD_ID, BUILD_ID[:16])

    def test_uppercase_build_id_normalised(self, monkeypatch, tmp_path):
        p = tmp_path / "t"
        p.write_bytes(b"\x7fELF" + b"\x00" * 32)
        _patch_build_id(monkeypatch, BUILD_ID.upper())
        ident = content_identity(p)
        assert ident is not None
        assert ident.value == BUILD_ID
        assert ident.anchor_hex == BUILD_ID[:16]

    def test_no_build_id_falls_to_sha256(self, monkeypatch, tmp_path):
        data = b"\x7fELF no note here"
        p = tmp_path / "t"
        p.write_bytes(data)
        _patch_build_id(monkeypatch, None)
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])

    def test_implausible_build_id_falls_to_sha256(
        self, monkeypatch, tmp_path,
    ):
        # A sub-8-hex build-id (ld --build-id=0x1234) fails the
        # plausibility screen; the file still identifies (sha256)
        # instead of anchoring nothing.
        data = b"\x7fELF tiny note"
        p = tmp_path / "t"
        p.write_bytes(data)
        _patch_build_id(monkeypatch, "1234")
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])

    def test_sandbox_refusal_degrades_loudly(
        self, monkeypatch, tmp_path, caplog,
    ):
        from core.sandbox.errors import SandboxSetupError
        data = b"\x7fELF payload"
        p = tmp_path / "t"
        p.write_bytes(data)
        _patch_build_id(monkeypatch, SandboxSetupError("refused", "hint"))
        with caplog.at_level("WARNING", logger="core.binary.identity"):
            ident = content_identity(p)
        assert ident == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])
        assert any("refused" in r.message for r in caplog.records)

    def test_probe_exception_falls_to_sha256(self, monkeypatch, tmp_path):
        data = b"\x7fELF payload"
        p = tmp_path / "t"
        p.write_bytes(data)
        _patch_build_id(monkeypatch, RuntimeError("tool exploded"))
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])


# ---------------------------------------------------------------------------
# PE arm
# ---------------------------------------------------------------------------


class TestPeArm:
    def _pe_with_rsds(self, tmp_path, guid=_VEC_GUID_RAW, age=_VEC_AGE):
        blob = _rsds_blob(guid, age, b"app.pdb")
        p = tmp_path / "t.exe"
        p.write_bytes(_image_with_debug([(0x40, blob)]))
        return p

    def test_rsds_identity_normative_vector(self, tmp_path):
        p = self._pe_with_rsds(tmp_path)
        assert content_identity(p) == ContentIdentity(
            KIND_PE_GUID_AGE, _VEC_CANONICAL, _VEC_HASHED_ANCHOR)

    def test_all_zero_guid_is_degenerate(self, tmp_path):
        p = self._pe_with_rsds(tmp_path, guid=b"\x00" * 16, age=5)
        ident = content_identity(p)
        assert ident is not None
        assert ident.kind == KIND_SHA256
        assert ident.value == _sha(p.read_bytes())

    def test_pe_without_debug_directory_falls_to_sha256(self, tmp_path):
        from .test_pe_facts import PeSpec, Sec, build_pe
        p = tmp_path / "t.exe"
        p.write_bytes(build_pe(PeSpec(
            secs=[Sec(name=b".text", va=0x1000, data=b"\xcc" * 16)])))
        ident = content_identity(p)
        assert ident is not None
        assert ident.kind == KIND_SHA256

    def test_mz_garbage_falls_to_sha256(self, tmp_path):
        data = b"MZ" + b"\xff" * 40
        p = tmp_path / "t.exe"
        p.write_bytes(data)
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])


# ---------------------------------------------------------------------------
# Mach-O arm
# ---------------------------------------------------------------------------

_UUID = bytes(range(16))
_UUID_HEX = _UUID.hex()


class TestMachoArm:
    def test_thin_uuid_identity(self, tmp_path):
        p = tmp_path / "t"
        p.write_bytes(build_thin([uuid_cmd(_UUID)]))
        assert content_identity(p) == ContentIdentity(
            KIND_MACHO_UUID, _UUID_HEX, _UUID_HEX[:16])

    def test_thin_all_zero_uuid_is_degenerate(self, tmp_path):
        data = build_thin([uuid_cmd(b"\x00" * 16)])
        p = tmp_path / "t"
        p.write_bytes(data)
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])

    def test_thin_without_uuid_falls_to_sha256(self, tmp_path):
        data = build_thin([])
        p = tmp_path / "t"
        p.write_bytes(data)
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])

    def test_fat_without_selection_is_whole_file_sha256(self, tmp_path):
        # The slices DO carry UUIDs — but no slice was analysed, so
        # no slice identity may be claimed.
        data = build_fat([build_thin([uuid_cmd(_UUID)])])
        p = tmp_path / "fat"
        p.write_bytes(data)
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])

    def _fat_with_slice(self, tmp_path):
        inner = build_thin([uuid_cmd(_UUID)])
        data = build_fat([inner])
        p = tmp_path / "fat"
        p.write_bytes(data)
        offset = data.index(inner)
        return p, offset, len(inner)

    def test_fat_with_tuple_selection(self, tmp_path):
        p, offset, size = self._fat_with_slice(tmp_path)
        assert content_identity(p, slice_selection=(offset, size)) \
            == ContentIdentity(KIND_MACHO_UUID, _UUID_HEX, _UUID_HEX[:16])

    def test_fat_with_slice_object_selection(self, tmp_path):
        from packages.binary_analysis.macho import MachOSlice
        p, offset, size = self._fat_with_slice(tmp_path)
        selection = MachOSlice(
            arch="x86_64", cpu_type=0x01000007, cpu_subtype=0,
            offset=offset, size=size, bits=64, sha256="",
        )
        ident = content_identity(p, slice_selection=selection)
        assert ident == ContentIdentity(
            KIND_MACHO_UUID, _UUID_HEX, _UUID_HEX[:16])

    def test_invalid_selection_falls_to_sha256(self, tmp_path):
        p, _offset, _size = self._fat_with_slice(tmp_path)
        ident = content_identity(p, slice_selection=(2**63, 64))
        assert ident is not None
        assert ident.kind == KIND_SHA256

    def test_relipoed_containers_never_alias(self, tmp_path):
        # Same slice, different container arrangements: without a
        # selection each container is its own sha256 identity, and
        # neither aliases the slice's UUID identity.
        inner = build_thin([uuid_cmd(_UUID)])
        one = tmp_path / "one"
        one.write_bytes(build_fat([inner]))
        two = tmp_path / "two"
        two.write_bytes(build_fat([inner, build_thin([])]))
        ident_one = content_identity(one)
        ident_two = content_identity(two)
        assert ident_one is not None and ident_two is not None
        assert ident_one.kind == ident_two.kind == KIND_SHA256
        assert ident_one.value != ident_two.value
        assert ident_one.anchor_hex != _UUID_HEX[:16]
        assert ident_two.anchor_hex != _UUID_HEX[:16]

    def test_selection_ignored_for_non_macho(self, monkeypatch, tmp_path):
        data = b"\x7fELF ignore selection"
        p = tmp_path / "t"
        p.write_bytes(data)
        _patch_build_id(monkeypatch, BUILD_ID)
        ident = content_identity(p, slice_selection=(0, 4))
        assert ident is not None
        assert ident.kind == KIND_ELF_BUILD_ID


# ---------------------------------------------------------------------------
# Fallback + hostile input contract
# ---------------------------------------------------------------------------


class TestFallbackContract:
    def test_unknown_magic_is_sha256(self, tmp_path):
        data = b"#!/bin/sh\necho hello\n"
        p = tmp_path / "t.sh"
        p.write_bytes(data)
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(data), _sha(data)[:16])

    def test_empty_file_is_sha256(self, tmp_path):
        p = tmp_path / "empty"
        p.write_bytes(b"")
        assert content_identity(p) == ContentIdentity(
            KIND_SHA256, _sha(b""), _sha(b"")[:16])

    def test_short_head_is_sha256(self, tmp_path):
        p = tmp_path / "tiny"
        p.write_bytes(b"MZ")
        ident = content_identity(p)
        assert ident is not None
        assert ident.kind == KIND_SHA256

    def test_nonexistent_path_is_none(self, tmp_path):
        assert content_identity(tmp_path / "missing") is None

    def test_directory_path_is_none(self, tmp_path):
        assert content_identity(tmp_path) is None

    @pytest.mark.parametrize("data", [
        b"\x7fELF",                       # magic only, nothing else
        b"\xcf\xfa\xed\xfe",              # thin Mach-O magic only
        b"\xca\xfe\xba\xbe\xff\xff\xff\xff",  # fat header lying
        b"MZ\x00",
    ])
    def test_truncated_headers_never_raise(
        self, monkeypatch, tmp_path, data,
    ):
        _patch_build_id(monkeypatch, None)
        p = tmp_path / "t"
        p.write_bytes(data)
        ident = content_identity(p)
        assert ident is not None
        assert ident.kind == KIND_SHA256


# ---------------------------------------------------------------------------
# Cross-format non-aliasing
# ---------------------------------------------------------------------------


class TestCrossFormatAliasing:
    def test_shared_leading_hex_does_not_share_anchors(
        self, monkeypatch, tmp_path,
    ):
        # An ELF whose build-id copies the PE canonical value's first
        # 16 hex: the prefix anchors would collide; the PE hashed
        # anchor keeps them apart.
        elf = tmp_path / "elf"
        elf.write_bytes(b"\x7fELF" + b"\x00" * 16)
        _patch_build_id(monkeypatch, _VEC_CANONICAL[:32])
        elf_ident = content_identity(elf)
        pe = tmp_path / "t.exe"
        pe.write_bytes(_image_with_debug(
            [(0x40, _rsds_blob(_VEC_GUID_RAW, _VEC_AGE, b"a.pdb"))]))
        pe_ident = content_identity(pe)
        assert elf_ident is not None and pe_ident is not None
        assert elf_ident.value[:16] == pe_ident.value[:16]
        assert elf_ident.anchor_hex != pe_ident.anchor_hex


# ---------------------------------------------------------------------------
# Validator compatibility — the four existing acceptors
# ---------------------------------------------------------------------------


class TestValidatorCompat:
    def _anchors(self):
        return [
            identity_anchor(KIND_ELF_BUILD_ID, BUILD_ID),
            identity_anchor(KIND_MACHO_UUID, _UUID_HEX),
            identity_anchor(KIND_PE_GUID_AGE, _VEC_CANONICAL),
            identity_anchor(KIND_SHA256, "ab" * 32),
        ]

    def test_anchors_are_16_lowercase_hex(self):
        for anchor in self._anchors():
            assert anchor is not None
            assert len(anchor) == 16
            assert anchor == anchor.lower()
            int(anchor, 16)

    def test_addrmap_hex_run_accepts(self):
        for anchor in self._anchors():
            assert addrmap._HEX_RUN_RE.fullmatch(anchor)

    def test_fid_roundtrip_accepts(self):
        for anchor in self._anchors():
            fid = addrmap.make_fid(anchor, 0x1010, 0x1000)
            assert fid == f"{anchor}:0x10"
            assert addrmap.from_fid(fid) == (anchor, 0x10)

    def test_edges_build_id_re_accepts_values_and_anchors(self):
        from core.analysis.binary_oracle_edges import _BUILD_ID_RE
        for value in (BUILD_ID, _UUID_HEX, _VEC_CANONICAL, "ab" * 32):
            assert _BUILD_ID_RE.fullmatch(value)
        for anchor in self._anchors():
            assert _BUILD_ID_RE.fullmatch(anchor)

    def test_function_cfg_cache_key_re_accepts(self):
        from packages.binary_analysis.function_cfg import _CACHE_KEY_RE
        for value in (BUILD_ID, _UUID_HEX, _VEC_CANONICAL):
            assert _CACHE_KEY_RE.fullmatch(value)
        assert _CACHE_KEY_RE.fullmatch(f"sha256:{'ab' * 32}")


# ---------------------------------------------------------------------------
# Manifest-shaped anchor derivation
# ---------------------------------------------------------------------------


class _ManifestLike:
    def __init__(self, build_id="", identity_kind="", binary_sha256=""):
        self.build_id = build_id
        self.identity_kind = identity_kind
        self.binary_sha256 = binary_sha256


class TestManifestAnchor:
    def test_dict_and_object_shapes_agree(self):
        record = {
            "build_id": _VEC_CANONICAL,
            "identity_kind": KIND_PE_GUID_AGE,
            "binary_sha256": "cd" * 32,
        }
        obj = _ManifestLike(_VEC_CANONICAL, KIND_PE_GUID_AGE, "cd" * 32)
        assert manifest_anchor(record) == manifest_anchor(obj) \
            == _VEC_HASHED_ANCHOR

    def test_old_record_kind_absent_uses_prefix(self):
        # build_id set, kind absent: elf-or-unknown, the prefix rule.
        assert manifest_anchor({"build_id": BUILD_ID}) == BUILD_ID[:16]
        assert manifest_anchor(_ManifestLike(build_id=BUILD_ID)) \
            == BUILD_ID[:16]

    def test_unknown_kind_falls_to_sha_leg(self):
        record = {
            "build_id": BUILD_ID,
            "identity_kind": "quantum_checksum",
            "binary_sha256": "cd" * 32,
        }
        assert manifest_anchor(record) == "cd" * 8

    def test_junk_identity_falls_to_sha_leg(self):
        assert manifest_anchor({
            "build_id": "junk!", "binary_sha256": "cd" * 32,
        }) == "cd" * 8

    def test_nothing_anchors_nothing(self):
        assert manifest_anchor({}) is None
        assert manifest_anchor(_ManifestLike()) is None
        assert manifest_anchor(None) is None
