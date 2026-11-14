"""Bounded observations of the owned Linux ABI probe's object sections.

A matching object, nonce or public observation grants no compiler, source/build
or preparation authority. The capture owner must retain and admit the actual
compiler operation, probe source, environment and complete input namespace.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct


@dataclass(frozen=True)
class ABIProbeUnavailable:
    reason: str


@dataclass(frozen=True)
class ABIProbeObservation:
    object_sha256: str
    nonce: bytes
    scalar_bits: tuple[int, ...]
    pointer_bits: int
    machine: int = 62
    byteorder: str = "little"
    representation: str = "twos-complement-no-padding"


_PREFIX = ".raptor.abi."
_SCALARS = ("char", "short", "int", "long", "long_long")
_REQUIRED = frozenset(_PREFIX + name for name in (*_SCALARS, "meta", "endian"))
_HEADER = struct.Struct("<HHIQQQIHHHHHH")
_SECTION = struct.Struct("<IIQQQQIIQQ")


def observe_abi_probe_object(
    raw: bytes, *, expected_nonce: bytes, max_object_bytes: int,
    max_sections: int, max_string_bytes: int,
) -> ABIProbeObservation | ABIProbeUnavailable:
    """Decode only ELF64, little-endian, machine 62, relocatable probe objects.

    Explicit budgets bound the complete input, section table and name table.
    Unknown or malformed material refuses the whole observation. No file is
    opened, compiler invoked, target executed or ``IntegerABI`` manufactured.
    """
    if any(type(cap) is not int or cap < 1 for cap in
           (max_object_bytes, max_sections, max_string_bytes)):
        return ABIProbeUnavailable("invalid_probe_budget")
    if type(expected_nonce) is not bytes or len(expected_nonce) != 16 or not any(expected_nonce):
        return ABIProbeUnavailable("invalid_probe_nonce")
    if type(raw) is not bytes or len(raw) > max_object_bytes:
        return ABIProbeUnavailable("probe_object_byte_budget")
    if (len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01"
            or raw[7] not in (0, 3) or any(raw[8:16])):
        return ABIProbeUnavailable("unsupported_probe_object")
    (kind, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = _HEADER.unpack_from(raw, 16)
    if ((kind, machine, version, entry, phoff, flags, ehsize, phentsize, phnum, shentsize)
            != (1, 62, 1, 0, 0, 0, 64, 0, 0, 64)
            or shnum < 2 or shnum >= 0xff00 or shnum > max_sections
            or shstrndx == 0 or shstrndx >= shnum):
        return ABIProbeUnavailable("unsupported_probe_header")
    table_end = shoff + shnum * 64
    if shoff < 64 or table_end > len(raw):
        return ABIProbeUnavailable("probe_section_table_unavailable")
    sections = tuple(_SECTION.unpack_from(raw, shoff + index * 64) for index in range(shnum))
    if any(sections[0]):
        return ABIProbeUnavailable("probe_null_section_unavailable")
    strings = sections[shstrndx]
    if ((strings[1], strings[2], strings[3], strings[6], strings[7], strings[8], strings[9])
            != (3, 0, 0, 0, 0, 1, 0)
            or strings[5] < 1 or strings[5] > max_string_bytes
            or strings[4] < 64 or strings[4] + strings[5] > len(raw)
            or (strings[4] < table_end and shoff < strings[4] + strings[5])):
        return ABIProbeUnavailable("probe_names_unavailable")
    names = raw[strings[4]:strings[4] + strings[5]]
    if names[0] != 0:
        return ABIProbeUnavailable("probe_names_unavailable")
    owned: dict[str, tuple[int, tuple[int, ...]]] = {}
    physical: list[tuple[int, int, int]] = []
    for index, section in enumerate(sections[1:], 1):
        name_at, section_type, section_flags, address, offset, size, link, info, align, entsize = section
        if name_at >= len(names):
            return ABIProbeUnavailable("probe_section_name_unavailable")
        end = names.find(b"\0", name_at)
        if end < 0:
            return ABIProbeUnavailable("probe_section_name_unavailable")
        try:
            name = names[name_at:end].decode("ascii")
        except UnicodeError:
            return ABIProbeUnavailable("probe_section_name_unavailable")
        if size and section_type != 8:
            if offset < 64 or offset + size > len(raw):
                return ABIProbeUnavailable("probe_section_range_unavailable")
            physical.append((index, offset, offset + size))
        if name.startswith(_PREFIX):
            if name not in _REQUIRED or name in owned:
                return ABIProbeUnavailable("probe_section_set_unavailable")
            if (section_type, section_flags, address, link, info, align, entsize) != (1, 2, 0, 0, 0, 1, 0):
                return ABIProbeUnavailable("probe_section_semantics_unavailable")
            owned[name] = (index, section)
    if frozenset(owned) != _REQUIRED:
        return ABIProbeUnavailable("probe_section_set_unavailable")
    indices = {index for index, _ in owned.values()}
    for section in sections:
        if section[1] in (4, 9) and section[7] in indices:
            return ABIProbeUnavailable("probe_relocation_unavailable")
    for index, section in owned.values():
        start, end = section[4], section[4] + section[5]
        if (section[5] == 0 or start < 64 or end > len(raw)
                or (start < table_end and shoff < end)
                or any(other != index and start < stop and begin < end
                       for other, begin, stop in physical)):
            return ABIProbeUnavailable("probe_section_overlap")
    payloads = {name: raw[section[4]:section[4] + section[5]] for name, (_, section) in owned.items()}
    meta = payloads[_PREFIX + "meta"]
    if (len(meta) != 32 or meta[:10] != b"RABIPROB\x01\x08" or meta[16:] != expected_nonce
            or payloads[_PREFIX + "endian"] != b"\x08\x07\x06\x05\x04\x03\x02\x01"):
        return ABIProbeUnavailable("probe_metadata_unavailable")
    sizes = tuple(meta[10:15])
    if (sizes[0] != 1 or any(size not in (1, 2, 4, 8) for size in sizes)
            or sizes != tuple(sorted(sizes)) or sizes[2] < 2 or sizes[3] < 4
            or sizes[4] != 8 or meta[15] not in (4, 8)):
        return ABIProbeUnavailable("probe_widths_unavailable")
    for name, size in zip(_SCALARS, sizes):
        bits = size * 8
        expected = (b"\xff" * size + (-(1 << (bits - 1))).to_bytes(size, "little", signed=True)
                    + ((1 << (bits - 1)) - 1).to_bytes(size, "little", signed=True))
        if payloads[_PREFIX + name] != expected:
            return ABIProbeUnavailable("probe_representation_unavailable")
    return ABIProbeObservation(hashlib.sha256(raw).hexdigest(), expected_nonce,
                               tuple(size * 8 for size in sizes), meta[15] * 8)
