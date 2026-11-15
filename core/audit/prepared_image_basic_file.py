"""Bounded basic-file bytes selected from a freshly read retained root group.

This is a strict single-block subset, not a filesystem or host file identity.
"""
from dataclasses import dataclass, field
import hashlib
import struct

from .prepared_image_backing import ImageBackingDescription, ImageBackingOwner
from .prepared_image_envelope import (
    BackingEnvelopeOnly, MetadataBytesOnly, probe_owned_header, read_uncompressed_metadata,
)
from .prepared_image_owned_group import OwnedRootGroupDeclaration, probe_owned_root_group

_REG = struct.Struct('<4H6I')


@dataclass(frozen=True)
class BasicFileUnavailable:
    reason: str


@dataclass(frozen=True)
class RetainedBasicFileBytes:
    artifact_sha256: str
    artifact_bytes: int
    name: bytes
    logical_inode: int
    content: bytes = field(repr=False)
    content_sha256: str
    measurement_scope: str = 'retained_root_single_block_basic_file_bytes_only'
    namespace_complete: bool = field(default=False, init=False)
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


def read_owned_basic_file(owner, reference, name, *, max_artifact_bytes, max_inodes,
                         max_ids, max_group_bytes, max_entries, max_name_bytes,
                         max_file_bytes):
    """Read an exact raw-name selection; missing/unsupported is not absent proof.

    Locators and inode counts come from live retained reads, never a supplied
    declaration. Only basic regular inodes, no fragments, and at most one
    uncompressed data block are supported. No decoder or native tool is used.
    """
    for limit in (max_artifact_bytes, max_inodes, max_ids, max_group_bytes,
                  max_entries, max_name_bytes, max_file_bytes):
        if type(limit) is not int or limit <= 0:
            raise ValueError('positive integer file inspection budgets required')
    if type(name) is not bytes or not 0 < len(name) <= min(max_name_bytes, 256):
        raise ValueError('bounded raw byte name required')
    if type(owner) is not ImageBackingOwner:
        return BasicFileUnavailable('unowned backing source')
    try:
        before = owner.describe(reference)
        if type(before) is not ImageBackingDescription:
            return BasicFileUnavailable('backing unavailable')
        header = probe_owned_header(owner, reference,
            max_artifact_bytes=max_artifact_bytes, max_inodes=max_inodes, max_ids=max_ids)
        if type(header) is not BackingEnvelopeOnly:
            return BasicFileUnavailable('owned header unavailable')
        root = probe_owned_root_group(owner, reference,
            max_artifact_bytes=max_artifact_bytes, max_inodes=max_inodes, max_ids=max_ids,
            max_group_bytes=max_group_bytes, max_entries=max_entries,
            max_name_bytes=max_name_bytes)
        if (type(root) is not OwnedRootGroupDeclaration
                or root.artifact_sha256 != header.artifact_sha256
                or root.artifact_bytes != header.artifact_bytes
                or header.artifact_sha256 != before.identity.sha256
                or header.artifact_bytes != before.identity.byte_count):
            return BasicFileUnavailable('owned root group unavailable')
        selected = [entry for entry in root.group.entries if entry.name == name]
        if len(selected) != 1 or selected[0].declared_kind != 2:
            return BasicFileUnavailable('selected basic file unavailable')
        entry = selected[0]
        inode_table, directory_table = header.envelope.table_offsets[:2]
        block = read_uncompressed_metadata(owner, reference, inode_table + entry.inode_block,
            region_end=directory_table, max_block_bytes=8192)
        start = entry.inode_offset
        if type(block) is not MetadataBytesOnly or start + _REG.size > len(block.payload):
            return BasicFileUnavailable('short or spanning regular inode unsupported')
        (kind, _, uid, gid, _, number, data_start, fragment,
         fragment_offset, size) = _REG.unpack_from(block.payload, start)
        if (kind != 2 or number != entry.logical_inode
                or uid >= header.envelope.id_count or gid >= header.envelope.id_count
                or fragment != 0xffffffff or fragment_offset != 0):
            return BasicFileUnavailable('unsupported regular inode declarations')
        if size > min(max_file_bytes, header.envelope.block_bytes, 65536):
            return BasicFileUnavailable('regular file exceeds supported single-block budget')
        content = b''
        if size:
            if start + _REG.size + 4 > len(block.payload):
                return BasicFileUnavailable('missing single-block descriptor')
            encoded = int.from_bytes(block.payload[start + _REG.size:start + _REG.size + 4], 'little')
            if encoded >> 25 or not encoded & (1 << 24) or (encoded & 0xffffff) != size:
                return BasicFileUnavailable('compressed, sparse or mismatched data unsupported')
            if not 96 <= data_start or data_start + size > inode_table:
                return BasicFileUnavailable('data outside supported region')
            content = owner._read(reference, data_start, size)
            if type(content) is not bytes or len(content) != size:
                return BasicFileUnavailable('file bytes unavailable')
        result = RetainedBasicFileBytes(header.artifact_sha256, header.artifact_bytes,
            name, number, content, hashlib.sha256(content).hexdigest())
        after = owner.describe(reference)
        if type(after) is not ImageBackingDescription or after != before:
            return BasicFileUnavailable('backing retired during file inspection')
        return result
    except Exception:
        return BasicFileUnavailable('basic file inspection unavailable')
