"""Owned root/group integration through synthetic OS seams only."""
import hashlib
from pathlib import Path
import struct
import time

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.audit import prepared_image_backing as backing
from core.audit import prepared_image_owned_group as module
from core.audit import prepared_image_directory_group as groups
from core.audit import prepared_image_envelope as envelope
from core.audit import prepared_image_root_directory as roots
from core.audit.tests import test_prepared_image_backing as backing_helpers
from core.audit.tests import test_prepared_image_envelope as envelope_helpers


def group(name=b'a', delta=-1):
    return struct.pack('<IIIHhHH', 0, 48, 3, 7, delta, 2, len(name) - 1) + name


@pytest.fixture
def case(monkeypatch):
    audit = Path(__file__).resolve().parents[1]
    for mod in (backing, module, groups, envelope, roots):
        assert Path(mod.__file__).resolve() == audit / (mod.__name__.rsplit('.', 1)[1] + '.py')
    for mod in (backing_helpers, envelope_helpers):
        assert Path(mod.__file__).resolve() == audit / 'tests' / (mod.__name__.rsplit('.', 1)[1] + '.py')
    assert module.decode_exact_group is groups.decode_exact_group
    assert module.probe_basic_root_directory is roots.probe_basic_root_directory
    assert module.probe_owned_header is envelope.probe_owned_header
    clock = [0.0]
    patch_module_attribute(monkeypatch, backing, 'time', 'monotonic', lambda: clock[0])
    assert backing.time is not time
    owners = []

    def make(*, payload=None, offset=4, start=20, size=None, budget=4096,
             compressed=False, inodes=4):
        payload = group() if payload is None else payload
        declared_size = len(payload) + 3 if size is None else size
        image = bytearray(envelope_helpers.header(inodes=inodes) + b'\0' * 416)
        inode = struct.pack('<4H4I2HI', 1, 0o755, 0, 0, 0, 1, start, 2,
                            declared_size, offset, 1)
        image[96:130] = (0x8000 | 32).to_bytes(2, 'little') + inode
        body = b'Z' * offset + payload
        encoded = len(body) | (0 if compressed else 0x8000)
        frame = encoded.to_bytes(2, 'little') + body
        image[200 + start:200 + start + len(frame)] = frame
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


def probe(owner, ref, **changes):
    limits = dict(max_artifact_bytes=512, max_inodes=16, max_ids=16,
                  max_group_bytes=8192, max_entries=256, max_name_bytes=256)
    limits.update(changes)
    return module.probe_owned_root_group(owner, ref, **limits)


def test_reads_displaced_retained_group_with_exact_budget(case):
    owner, ref, kernel, _, identity = case(budget=253)
    kernel.data[9][220:247] = b'X' * 27
    result = probe(owner, ref)
    assert type(result) is module.OwnedRootGroupDeclaration
    assert (result.artifact_sha256, result.artifact_bytes) == (identity.sha256, 512)
    entry, = result.group.entries
    assert (entry.name, entry.logical_inode) == (b'a', 2)
    assert not result.namespace_complete and not result.authenticated_build
    assert not result.observed_child_context and not result.group.namespace_complete
    assert owner._read_bytes_remaining == 0
    assert [e[1:] for e in kernel.events if e[0] == 'read'] == [
        (100, 96, 0), (100, 96, 0), (100, 2, 96), (100, 32, 98),
        (100, 2, 220), (100, 25, 222)]


@pytest.mark.parametrize('budget', [0, 95, 96, 191, 192, 225, 226, 227, 252])
def test_read_budget_refuses_without_partial_group(case, budget):
    owner, ref, _, _, _ = case(budget=budget)
    assert type(probe(owner, ref)) is module.OwnedGroupUnavailable


@pytest.mark.parametrize('payload', [b'', b'x', group()[:-1], group() + group(),
                                    group(b'.'), group(b'a/b'), group(delta=2)])
def test_malformed_or_multiple_groups_do_not_publish(case, payload):
    owner, ref, _, _, _ = case(payload=payload)
    assert type(probe(owner, ref)) is module.OwnedGroupUnavailable


@pytest.mark.parametrize('size', [0, 1, 2, 3, 100])
def test_declared_slice_must_fit_one_frame(case, size):
    owner, ref, _, _, _ = case(size=size)
    assert type(probe(owner, ref)) is module.OwnedGroupUnavailable


def test_compressed_group_is_not_decoded(case):
    owner, ref, kernel, _, _ = case(compressed=True)
    assert type(probe(owner, ref)) is module.OwnedGroupUnavailable
    assert ('read', 100, 25, 222) not in kernel.events


def test_final_lifetime_check_withholds_decoded_group(case, monkeypatch):
    owner, ref, _, clock, _ = case()
    constructor = module.OwnedRootGroupDeclaration
    def expired(*args):
        result = constructor(*args)
        clock[0] = 31
        return result
    monkeypatch.setattr(module, 'OwnedRootGroupDeclaration', expired)
    assert type(probe(owner, ref)) is module.OwnedGroupUnavailable
    assert type(owner.describe(ref)) is backing.ImageBackingUnavailable


def test_parse_cancellation_propagates_without_stealing_owner(case, monkeypatch):
    owner, ref, kernel, _, _ = case()
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(module, 'decode_exact_group', interrupted)
    with pytest.raises(KeyboardInterrupt):
        probe(owner, ref)
    assert type(owner.describe(ref)) is backing.ImageBackingDescription
    owner.close()
    assert [e for e in kernel.events if e == ('close', 100)] == [('close', 100)]


def test_foreign_reference_cannot_alias_owned_group(case):
    owner, ref, kernel, _, _ = case()
    class Forged:
        def __hash__(self):
            return hash(ref)
        def __eq__(self, other):
            return True
    assert type(probe(owner, Forged())) is module.OwnedGroupUnavailable
    assert not kernel.events
    assert type(probe(owner, ref)) is module.OwnedRootGroupDeclaration


@pytest.mark.parametrize('key', ['max_artifact_bytes', 'max_inodes', 'max_ids',
                                'max_group_bytes', 'max_entries', 'max_name_bytes'])
def test_invalid_limit_refuses_before_backing_activity(case, key):
    owner, ref, kernel, _, _ = case()
    with pytest.raises(ValueError):
        probe(owner, ref, **{key: False})
    assert not kernel.events


def test_changed_owned_inode_count_admits_actual_logical_inode(case):
    owner, ref, _, _, _ = case(payload=group(delta=2), inodes=5)
    result = probe(owner, ref)
    assert type(result) is module.OwnedRootGroupDeclaration
    assert result.group.entries[0].logical_inode == 5


@pytest.mark.parametrize('offset', [0, 96, 98, 220, 222])
def test_actual_backend_cancellation_revokes_and_closes_once(case, offset):
    owner, ref, kernel, _, _ = case()
    reached = []
    def interrupt(name, *args):
        if name == 'read' and args[0] == 100 and args[2] == offset:
            reached.append(args)
            raise KeyboardInterrupt
    kernel.fault = interrupt
    with pytest.raises(KeyboardInterrupt):
        probe(owner, ref)
    assert reached
    assert type(owner.describe(ref)) is backing.ImageBackingUnavailable
    owner.close()
    assert [e for e in kernel.events if e == ('close', 100)] == [('close', 100)]
