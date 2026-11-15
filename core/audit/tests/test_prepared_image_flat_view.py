"""Flat-view collection through synthetic retained images, without kernel calls."""
import hashlib
from pathlib import Path
import struct
import time

import pytest

from core.testing.module_bindings import patch_module_attribute
from core.audit import prepared_image_backing as backing
from core.audit import prepared_image_basic_file as files
from core.audit import prepared_image_flat_view as module
from core.audit import prepared_image_owned_group as groups
from core.audit import prepared_image_root_directory as roots
from core.audit.tests import test_prepared_image_backing as backing_helpers
from core.audit.tests import test_prepared_image_envelope as envelope_helpers


@pytest.fixture
def case(monkeypatch):
    audit = Path(__file__).resolve().parents[1]
    for mod in (backing, files, module, groups, roots):
        assert Path(mod.__file__).resolve() == audit / (mod.__name__.rsplit('.', 1)[1] + '.py')
    for mod in (backing_helpers, envelope_helpers):
        assert Path(mod.__file__).resolve() == audit / 'tests' / (mod.__name__.rsplit('.', 1)[1] + '.py')
    assert module.read_owned_basic_file is files.read_owned_basic_file
    assert module.probe_owned_root_group is groups.probe_owned_root_group
    assert module.probe_basic_root_directory is roots.probe_basic_root_directory
    clock = [0.0]
    patch_module_attribute(monkeypatch, backing, 'time', 'monotonic', lambda: clock[0])
    assert backing.time is not time
    owners = []

    def make(*, names=(b'a', b'b'), numbers=(2, 3), kinds=(2, 2),
             inode_kinds=(2, 2), budget=8192):
        contents = (b'hello', b'bye')
        group = struct.pack('<III', 1, 0, 0)
        inodes = b''
        at = 96
        image = bytearray(envelope_helpers.header(inode_table=160,
            directory_table=280, id_table=480, inodes=3) + b'\0' * 416)
        for index in range(2):
            content = contents[index]
            group += struct.pack('<HhHH', 32 + 36 * index, numbers[index],
                                 kinds[index], len(names[index]) - 1) + names[index]
            inodes += struct.pack('<4H7I', inode_kinds[index], 0o644, 0, 0,
                0, numbers[index], at, 0xffffffff, 0, len(content), (1 << 24) | len(content))
            image[at:at + len(content)] = content
            at += len(content)
        root = struct.pack('<4H4I2HI', 1, 0o755, 0, 0, 0, 1, 20, 2,
                           len(group) + 3, 4, 1)
        metadata = root + inodes
        image[160:162 + len(metadata)] = (0x8000 | len(metadata)).to_bytes(2, 'little') + metadata
        directory = b'P' * 4 + group
        image[300:302 + len(directory)] = (0x8000 | len(directory)).to_bytes(2, 'little') + directory
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


def collect(owner, ref, **changes):
    limits = dict(max_artifact_bytes=512, max_inodes=16, max_ids=16,
                  max_group_bytes=8192, max_files=16, max_name_bytes=256,
                  max_file_bytes=64, max_total_file_bytes=64)
    limits.update(changes)
    return module.collect_owned_flat_root(owner, ref, **limits)


def test_collects_every_declared_file_from_retained_bytes_under_exact_budget(case):
    owner, ref, kernel, _, identity = case(budget=1616)
    kernel.data[9][96:104] = b'changed!'
    view = collect(owner, ref, max_total_file_bytes=8)
    assert type(view) is module.RetainedFlatRootView
    assert [(f.name, f.logical_inode, f.content) for f in view.files] == [
        (b'a', 2, b'hello'), (b'b', 3, b'bye')]
    assert view.file_payload_bytes == 8 and view.artifact_sha256 == identity.sha256
    assert view.artifact_bytes == 512 and owner._read_bytes_remaining == 0
    assert not view.namespace_complete and not view.authenticated_build and not view.observed_child_context
    assert all(not f.namespace_complete for f in view.files)
    assert [e[1:] for e in kernel.events if e[0] == 'read' and e[-1] in (96, 101)] == [
        (100, 5, 96), (100, 3, 101)]


@pytest.mark.parametrize('changes', [dict(names=(b'b', b'a')), dict(names=(b'a', b'a')),
    dict(numbers=(2, 2)), dict(numbers=(1, 3)), dict(kinds=(2, 1)), dict(kinds=(3, 2))])
def test_unsupported_order_alias_or_kind_never_returns_partial_view(case, changes):
    owner, ref, kernel, _, _ = case(**changes)
    assert type(collect(owner, ref)) is module.FlatViewUnavailable
    assert ('read', 100, 5, 96) not in kernel.events


@pytest.mark.parametrize('limit', [4, 5, 7])
def test_total_payload_cap_withholds_whole_view(case, limit):
    owner, ref, kernel, _, _ = case()
    assert type(collect(owner, ref, max_total_file_bytes=limit)) is module.FlatViewUnavailable
    assert ('read', 100, 3, 101) not in kernel.events
    if limit >= 5:
        assert ('read', 100, 5, 96) in kernel.events


def test_file_count_cap_is_not_silent_truncation(case):
    owner, ref, kernel, _, _ = case()
    assert type(collect(owner, ref, max_files=1)) is module.FlatViewUnavailable
    assert ('read', 100, 5, 96) not in kernel.events


def test_second_inode_failure_withholds_already_read_first_file(case):
    owner, ref, kernel, _, _ = case(inode_kinds=(2, 9))
    assert type(collect(owner, ref)) is module.FlatViewUnavailable
    assert ('read', 100, 5, 96) in kernel.events
    assert ('read', 100, 3, 101) not in kernel.events


def test_last_data_read_budget_failure_has_no_partial_result(case):
    owner, ref, kernel, _, _ = case(budget=1615)
    assert type(collect(owner, ref)) is module.FlatViewUnavailable
    assert ('read', 100, 5, 96) in kernel.events


def test_expiry_after_view_allocation_withholds_view(case, monkeypatch):
    owner, ref, _, clock, _ = case()
    constructor = module.RetainedFlatRootView
    def expire(*args):
        result = constructor(*args)
        clock[0] = 31
        return result
    monkeypatch.setattr(module, 'RetainedFlatRootView', expire)
    assert type(collect(owner, ref)) is module.FlatViewUnavailable
    assert type(owner.describe(ref)) is backing.ImageBackingUnavailable


def test_cancellation_during_second_file_revokes_once(case):
    owner, ref, kernel, _, _ = case()
    reached = []
    def fail(name, *args):
        if name == 'read' and args == (100, 3, 101):
            reached.append(args)
            raise KeyboardInterrupt
    kernel.fault = fail
    with pytest.raises(KeyboardInterrupt):
        collect(owner, ref)
    assert reached and ('read', 100, 5, 96) in kernel.events
    assert type(owner.describe(ref)) is backing.ImageBackingUnavailable
    owner.close()
    assert [e for e in kernel.events if e == ('close', 100)] == [('close', 100)]


@pytest.mark.parametrize('error', [MemoryError, KeyboardInterrupt])
def test_view_construction_fault_keeps_borrowed_owner(case, monkeypatch, error):
    owner, ref, kernel, _, _ = case()
    reached = []
    def fail(*args):
        reached.append(args)
        raise error
    monkeypatch.setattr(module, 'RetainedFlatRootView', fail)
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            collect(owner, ref)
    else:
        assert type(collect(owner, ref)) is module.FlatViewUnavailable
    assert reached and ('read', 100, 3, 101) in kernel.events
    assert type(owner.describe(ref)) is backing.ImageBackingDescription


@pytest.mark.parametrize('key', ['max_artifact_bytes', 'max_inodes', 'max_ids',
    'max_group_bytes', 'max_files', 'max_name_bytes', 'max_file_bytes', 'max_total_file_bytes'])
def test_invalid_budget_refuses_before_backing_activity(case, key):
    owner, ref, kernel, _, _ = case()
    with pytest.raises(ValueError):
        collect(owner, ref, **{key: False})
    assert not kernel.events
