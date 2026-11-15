"""Single-group declarations derived from a live retained basic root.

No child inode resolution, name lookup or filesystem completeness is inferred.
"""
from dataclasses import dataclass, field

from .prepared_image_backing import ImageBackingDescription, ImageBackingOwner
from .prepared_image_directory_group import GroupDeclaration, decode_exact_group
from .prepared_image_envelope import (
    BackingEnvelopeOnly, MetadataBytesOnly, probe_owned_header,
    read_uncompressed_metadata,
)
from .prepared_image_root_directory import (
    BasicRootDirectoryDeclaration, probe_basic_root_directory,
)

_ABSENT = (1 << 64) - 1


@dataclass(frozen=True)
class OwnedGroupUnavailable:
    reason: str


@dataclass(frozen=True)
class OwnedRootGroupDeclaration:
    artifact_sha256: str
    artifact_bytes: int
    group: GroupDeclaration
    measurement_scope: str = 'retained_basic_root_single_group_declarations_only'
    namespace_complete: bool = field(default=False, init=False)
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


def probe_owned_root_group(owner, reference, *, max_artifact_bytes, max_inodes,
                           max_ids, max_group_bytes, max_entries, max_name_bytes):
    """Derive all locators/counts from fresh owned reads, without caller stamps.

    Supports exactly one nonempty group wholly within one uncompressed frame.
    The raw basic-directory size includes three synthetic dot-position bytes;
    these are not present in the stored group. Caller retains backing ownership.
    """
    for limit in (max_artifact_bytes, max_inodes, max_ids, max_group_bytes,
                  max_entries, max_name_bytes):
        if type(limit) is not int or limit <= 0:
            raise ValueError('positive integer owned group budgets required')
    if type(owner) is not ImageBackingOwner:
        return OwnedGroupUnavailable('unowned backing source')
    try:
        before = owner.describe(reference)
        if type(before) is not ImageBackingDescription:
            return OwnedGroupUnavailable('backing unavailable')
        header = probe_owned_header(owner, reference,
            max_artifact_bytes=max_artifact_bytes, max_inodes=max_inodes, max_ids=max_ids)
        if type(header) is not BackingEnvelopeOnly:
            return OwnedGroupUnavailable('owned header unavailable')
        root = probe_basic_root_directory(owner, reference,
            max_artifact_bytes=max_artifact_bytes, max_inodes=max_inodes,
            max_ids=max_ids, max_directory_declared_bytes=min(max_group_bytes, 8192) + 3)
        if (type(root) is not BasicRootDirectoryDeclaration
                or root.artifact_sha256 != header.artifact_sha256
                or root.artifact_bytes != header.artifact_bytes
                or header.artifact_sha256 != before.identity.sha256
                or header.artifact_bytes != before.identity.byte_count):
            return OwnedGroupUnavailable('owned root unavailable')
        length = root.declared_size - 3
        if not 0 < length <= min(max_group_bytes, 8192):
            return OwnedGroupUnavailable('empty or oversized root group unsupported')
        _, directory, fragment, lookup, ids, _ = header.envelope.table_offsets
        end = min(value for value in (fragment, lookup, ids) if value != _ABSENT)
        block = read_uncompressed_metadata(owner, reference,
            directory + root.declared_start_block, region_end=end, max_block_bytes=8192)
        start = root.declared_offset
        if (type(block) is not MetadataBytesOnly
                or start + length > len(block.payload)):
            return OwnedGroupUnavailable('spanning root group unsupported')
        group = decode_exact_group(block.payload[start:start + length],
            max_bytes=max_group_bytes, max_entries=max_entries,
            max_name_bytes=max_name_bytes, declared_inode_count=header.envelope.inodes)
        result = OwnedRootGroupDeclaration(header.artifact_sha256,
                                           header.artifact_bytes, group)
        after = owner.describe(reference)
        if type(after) is not ImageBackingDescription or after != before:
            return OwnedGroupUnavailable('backing retired during group inspection')
        return result
    except Exception:
        return OwnedGroupUnavailable('owned root group inspection unavailable')
