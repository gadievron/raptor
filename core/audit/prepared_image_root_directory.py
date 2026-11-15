"""Basic root-directory declarations from retained image metadata.

No directory entries, regular-file contents, extended inodes or compressed
metadata are interpreted. These declarations confer no filesystem validity,
physical source identity, namespace, consumption or currentness authority.
"""
from dataclasses import dataclass, field
import struct

from .prepared_image_backing import ImageBackingOwner, ImageBackingDescription
from .prepared_image_envelope import (
    BackingEnvelopeOnly, MetadataBytesOnly, probe_owned_header, read_uncompressed_metadata,
)

_BASIC_DIR = struct.Struct('<4H4I2HI')
_ABSENT = (1 << 64) - 1


@dataclass(frozen=True)
class RootDirectoryUnavailable:
    reason: str


@dataclass(frozen=True)
class BasicRootDirectoryDeclaration:
    artifact_sha256: str
    artifact_bytes: int
    declared_mode: int
    declared_uid_index: int
    declared_gid_index: int
    declared_mtime: int
    declared_inode_number: int
    declared_start_block: int
    declared_nlink: int
    declared_size: int
    declared_offset: int
    declared_parent_inode: int
    measurement_scope: str = 'retained_basic_root_directory_declaration_only'
    namespace_complete: bool = field(default=False, init=False)
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


def probe_basic_root_directory(owner, reference, *, max_artifact_bytes,
                               max_inodes, max_ids, max_directory_declared_bytes):
    """Inspect one basic DIR inode, wholly within one uncompressed block.

    Root reference and ID count come from the same owned header, never a caller
    inventory. Ownership remains with the caller. Raw inode/time/mode/parent
    values are declarations, not host stat identities or effective policy.
    Underlying read failures revoke according to ImageBackingOwner; pure parse
    refusal does not retire bytes that may have another unsupported format.
    """
    for budget in (max_artifact_bytes, max_inodes, max_ids, max_directory_declared_bytes):
        if type(budget) is not int or budget <= 0:
            raise ValueError('positive integer root declaration budgets required')
    if type(owner) is not ImageBackingOwner:
        return RootDirectoryUnavailable('unowned backing source')
    try:
        before = owner.describe(reference)
        if type(before) is not ImageBackingDescription:
            return RootDirectoryUnavailable('backing unavailable')
        observed = probe_owned_header(owner, reference, max_artifact_bytes=max_artifact_bytes,
                                      max_inodes=max_inodes, max_ids=max_ids)
        if (type(observed) is not BackingEnvelopeOnly
                or observed.artifact_sha256 != before.identity.sha256
                or observed.artifact_bytes != before.identity.byte_count):
            return RootDirectoryUnavailable('owned header unavailable')
        envelope = observed.envelope
        inode_start, directory_start, fragment_start, lookup_start, id_start, _ = envelope.table_offsets
        metadata_start = inode_start + (envelope.root_inode >> 16)
        offset = envelope.root_inode & 0xffff
        block = read_uncompressed_metadata(owner, reference, metadata_start,
                                          region_end=directory_start, max_block_bytes=8192)
        if (type(block) is not MetadataBytesOnly or type(block.payload) is not bytes
                or len(block.payload) > 8192 or offset + _BASIC_DIR.size > len(block.payload)):
            return RootDirectoryUnavailable('short or spanning root inode unsupported')
        (kind, mode, uid, gid, mtime, number, start, nlink, size,
         directory_offset, parent) = _BASIC_DIR.unpack_from(block.payload, offset)
        if kind != 1:
            return RootDirectoryUnavailable('only basic directory root supported')
        if (not 1 <= number <= envelope.inodes or uid >= envelope.id_count
                or gid >= envelope.id_count or nlink == 0):
            return RootDirectoryUnavailable('root declarations outside header bounds')
        if size > max_directory_declared_bytes or directory_offset >= 8192:
            return RootDirectoryUnavailable('root directory declaration exceeds budget')
        directory_end = min(value for value in (fragment_start, lookup_start, id_start)
                            if value != _ABSENT)
        if directory_start + start + 2 > directory_end:
            return RootDirectoryUnavailable('declared directory framing outside region')
        result = BasicRootDirectoryDeclaration(observed.artifact_sha256,
            observed.artifact_bytes, mode, uid, gid, mtime, number, start, nlink,
            size, directory_offset, parent)
        after = owner.describe(reference)
        if type(after) is not ImageBackingDescription or after != before:
            return RootDirectoryUnavailable('backing retired during root inspection')
        return result
    except Exception:
        return RootDirectoryUnavailable('root inspection unavailable')
