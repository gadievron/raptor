"""Collect every supported entry of one retained flat root declaration.

This does not establish kernel lookup behavior, physical source identity or
whole filesystem validity. Unsupported entries withhold the entire view.
"""
from dataclasses import dataclass, field

from .prepared_image_backing import ImageBackingDescription, ImageBackingOwner
from .prepared_image_basic_file import RetainedBasicFileBytes, read_owned_basic_file
from .prepared_image_owned_group import OwnedRootGroupDeclaration, probe_owned_root_group
from .prepared_image_root_directory import (
    BasicRootDirectoryDeclaration, probe_basic_root_directory,
)


@dataclass(frozen=True)
class FlatViewUnavailable:
    reason: str


@dataclass(frozen=True)
class RetainedFlatRootView:
    artifact_sha256: str
    artifact_bytes: int
    files: tuple[RetainedBasicFileBytes, ...] = field(repr=False)
    file_payload_bytes: int
    measurement_scope: str = 'retained_supported_flat_root_entries_and_bytes_only'
    namespace_complete: bool = field(default=False, init=False)
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


def collect_owned_flat_root(owner, reference, *, max_artifact_bytes, max_inodes,
                           max_ids, max_group_bytes, max_files, max_name_bytes,
                           max_file_bytes, max_total_file_bytes):
    """Collect all declared root files, never truncate or ignore unsupported kinds.

    Canonical raw-name order and distinct logical inodes define this narrow
    supported subset. Hardlinks, nested directories and empty root groups are
    unavailable. Payload caps count retained file bytes, not process RSS or
    metadata reads; the backing owner's cumulative read budget remains binding.
    """
    for limit in (max_artifact_bytes, max_inodes, max_ids, max_group_bytes,
                  max_files, max_name_bytes, max_file_bytes, max_total_file_bytes):
        if type(limit) is not int or limit <= 0:
            raise ValueError('positive integer flat view budgets required')
    if type(owner) is not ImageBackingOwner:
        return FlatViewUnavailable('unowned backing source')
    try:
        before = owner.describe(reference)
        if type(before) is not ImageBackingDescription:
            return FlatViewUnavailable('backing unavailable')
        root = probe_basic_root_directory(owner, reference,
            max_artifact_bytes=max_artifact_bytes, max_inodes=max_inodes, max_ids=max_ids,
            max_directory_declared_bytes=min(max_group_bytes, 8192) + 3)
        group = probe_owned_root_group(owner, reference,
            max_artifact_bytes=max_artifact_bytes, max_inodes=max_inodes, max_ids=max_ids,
            max_group_bytes=max_group_bytes, max_entries=max_files,
            max_name_bytes=max_name_bytes)
        if (type(root) is not BasicRootDirectoryDeclaration
                or type(group) is not OwnedRootGroupDeclaration
                or root.artifact_sha256 != before.identity.sha256
                or root.artifact_bytes != before.identity.byte_count
                or group.artifact_sha256 != root.artifact_sha256
                or group.artifact_bytes != root.artifact_bytes):
            return FlatViewUnavailable('owned root declarations unavailable')
        entries = group.group.entries
        names = tuple(entry.name for entry in entries)
        numbers = tuple(entry.logical_inode for entry in entries)
        if (not entries or len(entries) > min(max_files, 256)
                or names != tuple(sorted(names))
                or len(set(numbers)) != len(numbers)
                or root.declared_inode_number in numbers
                or any(entry.declared_kind != 2 for entry in entries)):
            return FlatViewUnavailable('unsupported flat root declarations')
        files: list[RetainedBasicFileBytes] = []
        total = 0
        for entry in entries:
            remaining = max_total_file_bytes - total
            if remaining <= 0:
                return FlatViewUnavailable('aggregate file payload budget exhausted')
            value = read_owned_basic_file(owner, reference, entry.name,
                max_artifact_bytes=max_artifact_bytes, max_inodes=max_inodes,
                max_ids=max_ids, max_group_bytes=max_group_bytes, max_entries=max_files,
                max_name_bytes=max_name_bytes, max_file_bytes=min(max_file_bytes, remaining))
            if (type(value) is not RetainedBasicFileBytes
                    or value.artifact_sha256 != root.artifact_sha256
                    or value.artifact_bytes != root.artifact_bytes
                    or value.name != entry.name or value.logical_inode != entry.logical_inode
                    or len(value.content) > remaining):
                return FlatViewUnavailable('flat root file unavailable')
            total += len(value.content)
            files.append(value)
        result = RetainedFlatRootView(root.artifact_sha256, root.artifact_bytes,
                                      tuple(files), total)
        after = owner.describe(reference)
        if type(after) is not ImageBackingDescription or after != before:
            return FlatViewUnavailable('backing retired during flat view collection')
        return result
    except Exception:
        return FlatViewUnavailable('flat root collection unavailable')
