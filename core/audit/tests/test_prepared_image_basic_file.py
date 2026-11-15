"""Retained basic-file controls with no actual kernel or native operations."""
import hashlib
from pathlib import Path
import struct
import time

import pytest

from core.testing.module_bindings import patch_module_attribute
from core.audit import prepared_image_backing as backing
from core.audit import prepared_image_basic_file as module
from core.audit import prepared_image_envelope as envelope
from core.audit import prepared_image_owned_group as owned_group
from core.audit.tests import test_prepared_image_backing as backing_helpers
from core.audit.tests import test_prepared_image_envelope as envelope_helpers


@pytest.fixture
def case(monkeypatch):
    audit = Path(__file__).resolve().parents[1]
    for mod in (backing, module, envelope, owned_group):
        assert Path(mod.__file__).resolve() == audit / (mod.__name__.rsplit('.', 1)[1] + '.py')
    for mod in (backing_helpers, envelope_helpers):
        assert Path(mod.__file__).resolve() == audit / 'tests' / (mod.__name__.rsplit('.', 1)[1] + '.py')
    assert module.probe_owned_root_group is owned_group.probe_owned_root_group
    assert module.probe_owned_header is envelope.probe_owned_header
    clock = [0.0]
    patch_module_attribute(monkeypatch, backing, 'time', 'monotonic', lambda: clock[0])
    assert backing.time is not time
    owners = []

    def make(*, content=b'hello', changes=None, encoded=None, budget=4096,
             entry_kind=2, entry_number=2, header_changes=None, inode_tail=None,
             child_block=0, child_offset=32):
        fields = dict(kind=2, mode=0o644, uid=0, gid=0, mtime=0, number=2,
                      start=96, fragment=0xffffffff, offset=0, size=len(content))
        fields.update(changes or {})
        file_inode = struct.pack('<4H6I', *fields.values())
        descriptor = (1 << 24) | len(content) if encoded is None else encoded
        tail = descriptor.to_bytes(4, 'little') if inode_tail is None else inode_tail
        group = struct.pack('<IIIHhHH', 0, child_block, entry_number, child_offset, 0, entry_kind, 0) + b'a'
        root = struct.pack('<4H4I2HI', 1, 0o755, 0, 0, 0, 1, 20, 2,
                           len(group) + 3, 4, 1)
        body = root + file_inode + tail
        if child_block:
            decoy = dict(fields, number=4, start=101)
            body = root + struct.pack('<4H6I', *decoy.values()) + tail
        header = dict(inode_table=160, directory_table=280, id_table=480, inodes=4)
        if child_block:
            header['directory_table'] = 320
        header.update(header_changes or {})
        image = bytearray(envelope_helpers.header(**header) + b'\0' * 416)
        image[96:96 + len(content)] = content
        image[160:162 + len(body)] = (0x8000 | len(body)).to_bytes(2, 'little') + body
        if child_block:
            child = b'P' * child_offset + file_inode + tail
            at = 160 + child_block
            image[at:at + 2 + len(child)] = (0x8000 | len(child)).to_bytes(2, 'little') + child
        directory = b'Z' * 4 + group
        directory_at = header['directory_table'] + 20
        image[directory_at:directory_at + 2 + len(directory)] = (0x8000 | len(directory)).to_bytes(2, 'little') + directory
        kernel = backing_helpers.SyntheticKernel(bytes(image))
        monkeypatch.setattr(backing, '_linux_api', lambda: (kernel, kernel))
        monkeypatch.setattr(backing, '_production_backing_backend', backing._LinuxSeals)
        owner = backing.ImageBackingOwner(max_images=1, max_artifact_bytes=512,
            max_retained_bytes=512, lifetime_seconds=30, max_read_bytes=budget)
        owners.append(owner)
        identity = backing.SuppliedArtifactIdentity(512, hashlib.sha256(image).hexdigest())
        ref = owner.acquire(9, identity)
        kernel.events.clear()
        return owner, ref, kernel, clock, identity
    yield make
    for owner in owners:
        owner.close()


def read(owner, ref, name=b'a', **changes):
    limits = dict(max_artifact_bytes=512, max_inodes=16, max_ids=16,
                  max_group_bytes=8192, max_entries=256, max_name_bytes=256,
                  max_file_bytes=65536)
    limits.update(changes)
    return module.read_owned_basic_file(owner, ref, name, **limits)


def test_retained_file_uses_actual_name_inode_and_exact_read_budget(case):
    owner, ref, kernel, _, identity = case(budget=460)
    kernel.data[9][96:101] = b'other'
    value = read(owner, ref, max_file_bytes=5)
    assert type(value) is module.RetainedBasicFileBytes
    assert value.content == b'hello' and value.content_sha256 == hashlib.sha256(b'hello').hexdigest()
    assert (value.artifact_sha256, value.artifact_bytes, value.name, value.logical_inode) == (
        identity.sha256, 512, b'a', 2)
    assert not value.namespace_complete and not value.authenticated_build and not value.observed_child_context
    assert owner._read_bytes_remaining == 0
    assert [e[1:] for e in kernel.events if e[0] == 'read'] == [
        (100, 96, 0), (100, 96, 0), (100, 96, 0), (100, 2, 160),
        (100, 68, 162), (100, 2, 300), (100, 25, 302),
        (100, 2, 160), (100, 68, 162), (100, 5, 96)]


def test_empty_basic_file_needs_no_data_read(case):
    owner, ref, kernel, _, _ = case(content=b'')
    value = read(owner, ref)
    assert type(value) is module.RetainedBasicFileBytes and value.content == b''
    assert value.content_sha256 == hashlib.sha256(b'').hexdigest()
    assert not any(e[0] == 'read' and e[-1] == 96 for e in kernel.events)


@pytest.mark.parametrize('changes', [dict(kind=1), dict(kind=9), dict(number=3),
    dict(uid=1), dict(gid=1), dict(fragment=0), dict(offset=1), dict(size=4097),
    dict(start=95), dict(start=158)])
def test_unsupported_or_mismatched_inode_never_reads_data(case, changes):
    owner, ref, kernel, _, _ = case(changes=changes)
    assert type(read(owner, ref)) is module.BasicFileUnavailable
    assert ('read', 100, 5, 96) not in kernel.events


@pytest.mark.parametrize('encoded', [0, 5, (1 << 24) | 4, (1 << 25) | 5])
def test_compressed_sparse_or_bad_size_is_not_read(case, encoded):
    owner, ref, kernel, _, _ = case(encoded=encoded)
    assert type(read(owner, ref)) is module.BasicFileUnavailable
    assert ('read', 100, 5, 96) not in kernel.events


def test_missing_block_descriptor_refuses(case):
    owner, ref, _, _, _ = case(inode_tail=b'')
    assert type(read(owner, ref)) is module.BasicFileUnavailable


@pytest.mark.parametrize('name', [b'b', b'.', b'a/b'])
def test_missing_or_unsupported_selection_is_not_absence_proof(case, name):
    owner, ref, kernel, _, _ = case()
    assert type(read(owner, ref, name)) is module.BasicFileUnavailable
    assert ('read', 100, 5, 96) not in kernel.events


def test_group_type_must_match_actual_basic_regular_kind(case):
    owner, ref, _, _, _ = case(entry_kind=1)
    assert type(read(owner, ref)) is module.BasicFileUnavailable


@pytest.mark.parametrize('budget', [0, 95, 192, 288, 384, 454, 459])
def test_read_budget_never_publishes_partial_file(case, budget):
    owner, ref, _, _, _ = case(budget=budget)
    assert type(read(owner, ref)) is module.BasicFileUnavailable


def test_expiry_after_content_hash_withholds_result(case, monkeypatch):
    owner, ref, _, clock, _ = case()
    constructor = module.RetainedBasicFileBytes
    def expire(*args):
        result = constructor(*args)
        clock[0] = 31
        return result
    monkeypatch.setattr(module, 'RetainedBasicFileBytes', expire)
    assert type(read(owner, ref)) is module.BasicFileUnavailable
    assert type(owner.describe(ref)) is backing.ImageBackingUnavailable


@pytest.mark.parametrize('error', [OSError, MemoryError, KeyboardInterrupt])
def test_actual_data_read_fault_revokes_once(case, error):
    owner, ref, kernel, _, _ = case()
    reached = []
    def fail(name, *args):
        if name == 'read' and args == (100, 5, 96):
            reached.append(args)
            raise error
    kernel.fault = fail
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            read(owner, ref)
    else:
        assert type(read(owner, ref)) is module.BasicFileUnavailable
    assert reached and type(owner.describe(ref)) is backing.ImageBackingUnavailable
    owner.close()
    assert [e for e in kernel.events if e == ('close', 100)] == [('close', 100)]


@pytest.mark.parametrize('name', ['', b'', b'x' * 257, None])
def test_invalid_name_refuses_before_backend(case, name):
    owner, ref, kernel, _, _ = case()
    with pytest.raises(ValueError):
        read(owner, ref, name)
    assert not kernel.events


def test_actual_file_budget_is_checked_before_content_read(case):
    owner, ref, kernel, _, _ = case()
    assert type(read(owner, ref, max_file_bytes=4)) is module.BasicFileUnavailable
    assert ('read', 100, 5, 96) not in kernel.events


def test_displaced_child_inode_and_actual_owned_counts(case):
    owner, ref, kernel, _, _ = case(child_block=96, child_offset=4,
        changes=dict(number=5, uid=1, gid=2), entry_number=5,
        header_changes=dict(inodes=5, ids=3))
    value = read(owner, ref)
    assert type(value) is module.RetainedBasicFileBytes
    assert value.logical_inode == 5 and value.content == b'hello'
    assert [e[1:] for e in kernel.events if e[0] == 'read'] == [
        (100, 96, 0), (100, 96, 0), (100, 96, 0), (100, 2, 160),
        (100, 68, 162), (100, 2, 340), (100, 25, 342),
        (100, 2, 256), (100, 40, 258), (100, 5, 96)]


@pytest.mark.parametrize('error', [MemoryError, KeyboardInterrupt])
def test_result_construction_fault_preserves_borrowed_owner(case, monkeypatch, error):
    owner, ref, kernel, _, _ = case()
    reached = []
    def fail(*args):
        reached.append(args)
        raise error
    monkeypatch.setattr(module, 'RetainedBasicFileBytes', fail)
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            read(owner, ref)
    else:
        assert type(read(owner, ref)) is module.BasicFileUnavailable
    assert reached and ('read', 100, 5, 96) in kernel.events
    assert type(owner.describe(ref)) is backing.ImageBackingDescription
    owner.close()
    assert [e for e in kernel.events if e == ('close', 100)] == [('close', 100)]
