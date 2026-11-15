"""Bounded caller-byte directory-group declarations, without filesystem authority."""
from dataclasses import dataclass, field
import struct

_HEADER = struct.Struct('<III')
_ENTRY = struct.Struct('<HhHH')


@dataclass(frozen=True)
class EntryDeclaration:
    name: bytes
    logical_inode: int
    inode_block: int
    inode_offset: int
    declared_kind: int


@dataclass(frozen=True)
class GroupDeclaration:
    entries: tuple[EntryDeclaration, ...]
    namespace_complete: bool = field(default=False, init=False)
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


def decode_exact_group(payload, *, max_bytes, max_entries, max_name_bytes,
                       declared_inode_count):
    """Require exactly one complete group; no reads, lookup or ownership claim.

    Caller bytes are untrusted declarations, not owned backing measurements.
    A refusal publishes no partial entries. No text decoding or path joining.
    """
    for limit in (max_bytes, max_entries, max_name_bytes, declared_inode_count):
        if type(limit) is not int or limit <= 0:
            raise ValueError('positive integer limits required')
    if declared_inode_count > 0xffffffff:
        raise ValueError('inode count exceeds supported width')
    if type(payload) is not bytes or len(payload) > min(max_bytes, 8192):
        raise ValueError('unsupported payload')
    if len(payload) < _HEADER.size:
        raise ValueError('truncated group header')
    encoded_count, block, base = _HEADER.unpack_from(payload)
    count = encoded_count + 1
    if count > min(max_entries, 256):
        raise ValueError('entry limit exceeded')
    position = _HEADER.size
    entries = []
    names = set()
    for _ in range(count):
        if position + _ENTRY.size > len(payload):
            raise ValueError('truncated entry')
        offset, delta, kind, encoded_size = _ENTRY.unpack_from(payload, position)
        position += _ENTRY.size
        size = encoded_size + 1
        if size > min(max_name_bytes, 256) or position + size > len(payload):
            raise ValueError('name outside limits')
        name = payload[position:position + size]
        position += size
        logical = base + delta
        if (offset >= 8192 or not 1 <= logical <= min(declared_inode_count, 0xffffffff)
                or not 1 <= kind <= 7):
            raise ValueError('unsupported entry declaration')
        if (b'\x00' in name or b'/' in name or name in (b'.', b'..')
                or name in names):
            raise ValueError('ambiguous name')
        names.add(name)
        entries.append(EntryDeclaration(name, logical, block, offset, kind))
    if position != len(payload):
        raise ValueError('trailing bytes or additional groups unsupported')
    return GroupDeclaration(tuple(entries))
