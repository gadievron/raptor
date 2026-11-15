"""Bounded image declarations and retained uncompressed metadata inspection.

These checks do not establish filesystem validity, complete path resolution,
child consumption or namespace authority. Compressed metadata, xattrs and
filesystem walking are unavailable. No backing provider is activated here.
"""
from dataclasses import dataclass, field
import struct

_HEADER = struct.Struct('<5I6H8Q')
_ABSENT = (1 << 64) - 1


@dataclass(frozen=True)
class EnvelopeRefusal:
    reason: str


@dataclass(frozen=True)
class EnvelopeOnly:
    inodes: int
    block_bytes: int
    compression_id: int
    declared_bytes: int
    trailing_bytes: int
    table_offsets: tuple[int, ...]
    index_spans: tuple[tuple[int, int], ...]
    root_inode: int
    id_count: int
    namespace_complete: bool = field(default=False, init=False)
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


def inspect_header(header, artifact_bytes, *, max_artifact_bytes, max_inodes, max_ids):
    """Parse exactly96 untrusted bytes under explicit scalar budgets.

    Caller metadata is not independently measured backing identity. Returned
    fields are declarations only; even a syntactically acceptable header does
    not establish a valid, immutable, fully interpreted filesystem.
    """
    for budget in (max_artifact_bytes, max_inodes, max_ids):
        if type(budget) is not int or budget <= 0:
            raise ValueError('positive integer envelope budgets required')
    if type(artifact_bytes) is not int or not _HEADER.size <= artifact_bytes <= max_artifact_bytes:
        return EnvelopeRefusal('artifact size unavailable or exceeds budget')
    if type(header) is not bytes or len(header) != _HEADER.size:
        return EnvelopeRefusal('exact header bytes required')
    fields = _HEADER.unpack(header)
    (magic, inodes, _, block_bytes, fragments, compression, block_log, flags,
     ids, major, minor, root_inode, used, id_table, xattr_table, inode_table,
     directory_table, fragment_table, lookup_table) = fields
    if magic != 0x73717368 or (major, minor) != (4, 0):
        return EnvelopeRefusal('unsupported image format/version')
    if not 0 < inodes <= max_inodes or not 0 < ids <= max_ids or fragments > max_inodes:
        return EnvelopeRefusal('declared count exceeds envelope budget')
    if (not 4096 <= block_bytes <= 1048576 or block_bytes & (block_bytes - 1)
            or block_log != block_bytes.bit_length() - 1):
        return EnvelopeRefusal('invalid declared block geometry')
    if compression not in (1, 2, 3, 4, 5, 6):
        return EnvelopeRefusal('unknown compression declaration')
    # Conservative supported subset. Other flags require an explicit format
    # interpretation decision; accepting an ID does not install a decompressor.
    known_flags = sum(1 << bit for bit in (0, 1, 3, 4, 5, 6, 7, 10))
    if flags & ~known_flags:
        return EnvelopeRefusal('unsupported image flags')
    if not _HEADER.size < used <= artifact_bytes:
        return EnvelopeRefusal('declared image bytes outside backing')
    required = (inode_table, directory_table, id_table)
    optional = (fragment_table, lookup_table)
    if any(not _HEADER.size <= offset < used for offset in required):
        return EnvelopeRefusal('required table outside declared image')
    if any(offset != _ABSENT and not _HEADER.size <= offset < used for offset in optional):
        return EnvelopeRefusal('optional table outside declared image')
    # The xattr table has its own header/counts. Its complete index geometry
    # cannot be established from this superblock-only inspection.
    if xattr_table != _ABSENT:
        return EnvelopeRefusal('xattr metadata unsupported by this reader')
    if not inode_table + 2 <= directory_table < id_table:
        return EnvelopeRefusal('invalid required table ordering')
    if bool(fragments) != (fragment_table != _ABSENT):
        return EnvelopeRefusal('fragment declaration/table mismatch')
    if (flags & (1 << 4)) and (fragments or flags & (1 << 5)):
        return EnvelopeRefusal('conflicting fragment declarations')
    if bool(flags & (1 << 7)) != (lookup_table != _ABSENT):
        return EnvelopeRefusal('export declaration/table mismatch')

    def index_bytes(entries, entry_size):
        return ((entries * entry_size + 8191) // 8192) * 8

    # These are pointer-index spans, not the extents of the indexed metadata.
    # Proving those compressed/uncompressed bodies requires a separate walker.
    spans = [(id_table, index_bytes(ids, 4))]
    if id_table + spans[0][1] > used:
        return EnvelopeRefusal('ID index extends outside declared image')
    boundary = id_table
    if lookup_table != _ABSENT:
        length = index_bytes(inodes, 8)
        if not directory_table < lookup_table or lookup_table + length > boundary:
            return EnvelopeRefusal('export index aliases or escapes region')
        spans.append((lookup_table, length))
        boundary = lookup_table
    if fragment_table != _ABSENT:
        length = index_bytes(fragments, 16)
        if not directory_table < fragment_table or fragment_table + length > boundary:
            return EnvelopeRefusal('fragment index aliases or escapes region')
        spans.append((fragment_table, length))
        boundary = fragment_table
    if directory_table + 2 > boundary:
        return EnvelopeRefusal('directory region lacks metadata framing')
    # Kernel SQUASHFS_INODE_BLK uses a 32-bit block. Refuse high bits
    # rather than silently interpreting a different Python block address.
    if root_inode >> 48:
        return EnvelopeRefusal('unsupported root inode reference bits')
    if (root_inode & 0xffff >= 8192
            or inode_table + (root_inode >> 16) + 2 > directory_table):
        return EnvelopeRefusal('root inode outside declared inode region')
    return EnvelopeOnly(inodes, block_bytes, compression, used, artifact_bytes - used,
                        (inode_table, directory_table, fragment_table, lookup_table,
                         id_table, xattr_table), tuple(spans), root_inode, ids)



@dataclass(frozen=True)
class BackingEnvelopeOnly:
    artifact_sha256: str
    artifact_bytes: int
    envelope: EnvelopeOnly
    measurement_scope: str = 'retained_backing_header_only'
    namespace_complete: bool = field(default=False, init=False)
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


def probe_owned_header(owner, reference, *, max_artifact_bytes, max_inodes, max_ids):
    """Inspect an owned header without raw FD or filesystem lease issuance.

    Ownership remains with caller. An invalid format doesn't retire its bytes;
    the artifact could have another format. Backend read failure revocation is
    owned by ImageBackingOwner. A parser result is withheld after expiry.
    """
    for budget in (max_artifact_bytes, max_inodes, max_ids):
        if type(budget) is not int or budget <= 0:
            raise ValueError('positive integer envelope budgets required')
    from core.audit.prepared_image_backing import ImageBackingOwner, ImageBackingDescription
    if type(owner) is not ImageBackingOwner:
        return EnvelopeRefusal('unowned backing source')
    before = owner.describe(reference)
    if type(before) is not ImageBackingDescription:
        return EnvelopeRefusal('backing unavailable')
    if before.identity.byte_count > max_artifact_bytes:
        return EnvelopeRefusal('artifact exceeds inspection budget')
    header = owner._read(reference, 0, _HEADER.size)
    result = inspect_header(header, before.identity.byte_count,
                            max_artifact_bytes=max_artifact_bytes,
                            max_inodes=max_inodes, max_ids=max_ids)
    if type(result) is not EnvelopeOnly:
        return result
    after = owner.describe(reference)
    if type(after) is not ImageBackingDescription or before != after:
        return EnvelopeRefusal('backing retired during header inspection')
    return BackingEnvelopeOnly(after.identity.sha256, after.identity.byte_count, result)


@dataclass(frozen=True)
class MetadataBytesOnly:
    payload: bytes = field(repr=False)
    next_offset: int
    measurement_scope: str = 'retained_uncompressed_metadata_bytes_only'
    namespace_complete: bool = field(default=False, init=False)
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


def read_uncompressed_metadata(owner, reference, offset, *, region_end, max_block_bytes):
    """Read bounded metadata framing, not inode/directory or filesystem validation.

    region_end is a requested inspection bound, not an independently proven
    filesystem-table boundary. Compressed blocks are explicitly unsupported.
    The existing owner charges each read attempt; no extra descriptor escapes.
    """
    if type(max_block_bytes) is not int or not 0 < max_block_bytes <= 8192:
        raise ValueError('metadata block budget must be within 1..8192 bytes')
    from core.audit.prepared_image_backing import ImageBackingOwner, ImageBackingDescription
    if type(owner) is not ImageBackingOwner:
        return EnvelopeRefusal('unowned backing source')
    before = owner.describe(reference)
    if type(before) is not ImageBackingDescription:
        return EnvelopeRefusal('backing unavailable')
    if (type(offset) is not int or offset < 0 or type(region_end) is not int
            or not offset + 2 <= region_end <= before.identity.byte_count):
        return EnvelopeRefusal('metadata framing outside requested region')
    prefix = owner._read(reference, offset, 2)
    if type(prefix) is not bytes or len(prefix) != 2:
        return EnvelopeRefusal('metadata framing unavailable')
    encoded = int.from_bytes(prefix, 'little')
    length = encoded & 0x7fff
    if not encoded & 0x8000:
        return EnvelopeRefusal('compressed metadata unsupported by this reader')
    if not 0 < length <= max_block_bytes or offset + 2 + length > region_end:
        return EnvelopeRefusal('metadata block outside bounded region')
    content = owner._read(reference, offset + 2, length)
    if type(content) is not bytes or len(content) != length:
        return EnvelopeRefusal('metadata block unavailable')
    after = owner.describe(reference)
    if type(after) is not ImageBackingDescription or before != after:
        return EnvelopeRefusal('backing retired during metadata inspection')
    return MetadataBytesOnly(content, offset + 2 + length)
