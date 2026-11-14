"""Synthetic object-byte controls, without compiling or executing a target."""

from dataclasses import FrozenInstanceError
import hashlib
import struct

import pytest

from core.audit.prepared_compiler_abi import ABIProbeObservation, ABIProbeUnavailable, observe_abi_probe_object


NONCE = bytes(range(1, 17))
PREFIX = ".raptor.abi."
SCALARS = ("char", "short", "int", "long", "long_long")


def _object(*, sizes=(1, 2, 4, 8, 8), extra=()):
    payloads = []
    for name, size in zip(SCALARS, sizes):
        bits = size * 8
        payloads.append((PREFIX + name, b"\xff" * size
                         + (-(1 << (bits - 1))).to_bytes(size, "little", signed=True)
                         + ((1 << (bits - 1)) - 1).to_bytes(size, "little", signed=True)))
    payloads += [(PREFIX + "meta", b"RABIPROB\x01\x08" + bytes(sizes) + b"\x08" + NONCE),
                 (PREFIX + "endian", b"\x08\x07\x06\x05\x04\x03\x02\x01"), *extra]
    names = b"\0.shstrtab\0"
    offsets = {}
    for name, _ in payloads:
        offsets[name] = len(names)
        names += name.encode() + b"\0"
    raw = bytearray(64)
    sections = [(0,) * 10]
    name_offset = len(raw)
    raw += names
    sections.append((1, 3, 0, 0, name_offset, len(names), 0, 0, 1, 0))
    for name, data in payloads:
        offset = len(raw)
        raw += data
        sections.append((offsets[name], 1, 2, 0, offset, len(data), 0, 0, 1, 0))
    shoff = len(raw)
    raw += b"".join(struct.pack("<IIQQQQIIQQ", *section) for section in sections)
    raw[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections), 1)
    return raw, sections, shoff


def _observe(raw, **caps):
    return observe_abi_probe_object(bytes(raw), expected_nonce=NONCE, **{
        "max_object_bytes": 4096, "max_sections": 32, "max_string_bytes": 512, **caps})


def test_owned_section_shape_observes_widths_without_preparation_authority():
    raw, _, _ = _object()
    result = _observe(raw)
    assert isinstance(result, ABIProbeObservation)
    assert result.scalar_bits == (8, 16, 32, 64, 64) and result.pointer_bits == 64
    assert result.object_sha256 == hashlib.sha256(raw).hexdigest() and result.nonce == NONCE
    assert result.representation == "twos-complement-no-padding"
    with pytest.raises(FrozenInstanceError):
        result.machine = 3


@pytest.mark.parametrize("sizes", [(1, 2, 4, 4, 8), (1, 2, 8, 8, 8)])
def test_supported_observed_storage_models_are_not_host_inferences(sizes):
    assert _observe(_object(sizes=sizes)[0]).scalar_bits == tuple(size * 8 for size in sizes)


@pytest.mark.parametrize("offset,value", [(4, 1), (5, 2), (6, 0), (7, 9), (8, 1), (16, 2), (18, 3), (20, 0), (24, 1), (32, 1), (48, 1), (52, 63), (54, 1), (56, 1), (58, 63), (60, 0), (62, 255)])
def test_unsupported_or_malformed_header_refuses(offset, value):
    raw, _, _ = _object()
    raw[offset] = value
    assert isinstance(_observe(raw), ABIProbeUnavailable)


@pytest.mark.parametrize("field,value", [(1, 8), (2, 3), (2, 6), (2, 0x802), (3, 1), (6, 1), (7, 1), (8, 8), (9, 1)])
def test_probe_sections_require_exact_readonly_ordinary_semantics(field, value):
    raw, sections, shoff = _object()
    section = list(sections[2]); section[field] = value
    struct.pack_into("<IIQQQQIIQQ", raw, shoff + 2 * 64, *section)
    assert isinstance(_observe(raw), ABIProbeUnavailable)


@pytest.mark.parametrize("change", ["duplicate", "unknown", "missing", "payload", "nonce", "endian", "width", "overlap", "table-overlap", "bad-name", "relocation"])
def test_incomplete_ambiguous_or_changed_probe_material_refuses(change):
    if change in {"duplicate", "unknown"}:
        name = PREFIX + ("char" if change == "duplicate" else "other")
        raw, sections, shoff = _object(extra=((name, b"abc"),))
    elif change == "relocation":
        raw, sections, shoff = _object(extra=((".rela.probe", bytes(24)),))
    else:
        raw, sections, shoff = _object()
    if change == "missing":
        raw[sections[2][0] + sections[1][4]] = ord("x")
    elif change == "payload":
        raw[sections[2][4]] = 0
    elif change == "nonce":
        raw[sections[7][4] + 16] ^= 1
    elif change == "endian":
        raw[sections[8][4]] ^= 1
    elif change == "width":
        raw[sections[7][4] + 12] = 1
    elif change in {"overlap", "table-overlap"}:
        section = list(sections[2]); section[4] = sections[3][4] if change == "overlap" else shoff
        struct.pack_into("<IIQQQQIIQQ", raw, shoff + 2 * 64, *section)
    elif change == "bad-name":
        struct.pack_into("<I", raw, shoff + 2 * 64, 0xffffffff)
    elif change == "relocation":
        section = list(sections[-1]); section[1] = 4; section[7] = 2
        struct.pack_into("<IIQQQQIIQQ", raw, shoff + (len(sections) - 1) * 64, *section)
    result = _observe(raw)
    assert isinstance(result, ABIProbeUnavailable)
    if change == "relocation":
        assert result.reason == "probe_relocation_unavailable"


@pytest.mark.parametrize("cap", [True, None, 0, -1, 1.5])
def test_explicit_budgets_are_positive_integers(cap):
    raw, _, _ = _object()
    for field in ("max_object_bytes", "max_sections", "max_string_bytes"):
        assert _observe(raw, **{field: cap}).reason == "invalid_probe_budget"


def test_exact_budgets_and_whole_result_refusals():
    raw, sections, _ = _object()
    assert isinstance(_observe(raw, max_object_bytes=len(raw), max_sections=len(sections),
                               max_string_bytes=sections[1][5]), ABIProbeObservation)
    for caps in ({"max_object_bytes": len(raw) - 1}, {"max_sections": len(sections) - 1},
                 {"max_string_bytes": sections[1][5] - 1}):
        assert isinstance(_observe(raw, **caps), ABIProbeUnavailable)
    assert isinstance(_observe(raw[:-1]), ABIProbeUnavailable)


def test_reserved_section_count_is_not_an_ordinary_large_table():
    raw, _, shoff = _object()
    # ELF requires extended numbering at SHN_LORESERVE, which this narrow
    # format explicitly refuses. Fill a complete tail so a bounds error
    # cannot stand in for that contract.
    count = 0xff00
    raw.extend(bytes(shoff + count * 64 - len(raw)))
    struct.pack_into("<H", raw, 60, count)
    result = _observe(raw, max_object_bytes=len(raw), max_sections=0xffff)
    assert isinstance(result, ABIProbeUnavailable)
    assert result.reason == "unsupported_probe_header"


def test_compressed_name_table_cannot_be_read_as_raw_names():
    raw, sections, shoff = _object()
    names = list(sections[1])
    names[2] = 0x800
    struct.pack_into("<IIQQQQIIQQ", raw, shoff + 64, *names)
    result = _observe(raw)
    assert isinstance(result, ABIProbeUnavailable)
    assert result.reason == "probe_names_unavailable"


@pytest.mark.parametrize("nonce", [b"", bytes(16), b"x" * 15, "x" * 16])
def test_nonce_is_exact_nonzero_owned_material(nonce):
    raw, _, _ = _object()
    result = observe_abi_probe_object(bytes(raw), expected_nonce=nonce, max_object_bytes=4096,
                                      max_sections=32, max_string_bytes=512)
    assert result.reason == "invalid_probe_nonce"
