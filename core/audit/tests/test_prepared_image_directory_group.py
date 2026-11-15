"""Controls for bounded caller-byte directory-group declarations."""
import struct

import pytest

from pathlib import Path

from core.audit import prepared_image_directory_group as directory_group
from core.audit.prepared_image_directory_group import decode_exact_group


def decode(payload, **overrides):
    limits = dict(max_bytes=8192, max_entries=256, max_name_bytes=256,
                  declared_inode_count=20)
    limits.update(overrides)
    return decode_exact_group(payload, **limits)


def group(name=b'entry', *, delta=-2, count=0, offset=7, kind=2):
    return (struct.pack('<III', count, 48, 10)
            + struct.pack('<HhHH', offset, delta, kind, len(name) - 1) + name)


def test_signed_delta_and_raw_name_have_no_authority():
    result = decode(group(b'\xffentry'))
    entry, = result.entries
    assert (entry.name, entry.logical_inode, entry.inode_block,
            entry.inode_offset, entry.declared_kind) == (b'\xffentry', 8, 48, 7, 2)
    assert not result.namespace_complete
    assert not result.authenticated_build
    assert not result.observed_child_context


@pytest.mark.parametrize('name', [b'.', b'..', b'a/b', b'a\x00b'])
def test_ambiguous_names_refuse(name):
    with pytest.raises(ValueError, match='ambiguous name'):
        decode(group(name))


@pytest.mark.parametrize('cut', range(len(group(b'entry-long'))))
def test_every_incomplete_prefix_refuses(cut):
    payload = group(b'entry-long')
    assert cut < len(payload)
    with pytest.raises(ValueError):
        decode(payload[:cut])


def test_duplicate_and_trailing_groups_refuse_without_partial_result():
    one = group()
    duplicate = struct.pack('<III', 1, 48, 10) + one[12:] + one[12:]
    with pytest.raises(ValueError, match='ambiguous name'):
        decode(duplicate)
    with pytest.raises(ValueError, match='trailing bytes'):
        decode(one + one)


@pytest.mark.parametrize('changes', [dict(count=256), dict(offset=8192),
                                     dict(kind=0), dict(kind=8), dict(delta=-10)])
def test_count_offset_kind_and_logical_bounds_refuse(changes):
    with pytest.raises(ValueError):
        decode(group(**changes))


@pytest.mark.parametrize('limits', [dict(max_bytes=24), dict(max_name_bytes=4),
                                    dict(declared_inode_count=7)])
def test_explicit_limits_refuse(limits):
    with pytest.raises(ValueError):
        decode(group(), **limits)


def test_multiple_entries_at_exact_limits():
    payload = (struct.pack('<III', 1, 48, 10)
               + struct.pack('<HhHH', 7, -2, 2, 0) + b'a'
               + struct.pack('<HhHH', 9, 2, 1, 0) + b'b')
    result = decode(payload, max_bytes=len(payload), max_entries=2,
                    max_name_bytes=1, declared_inode_count=12)
    assert [(e.name, e.logical_inode) for e in result.entries] == [(b'a', 8), (b'b', 12)]
    with pytest.raises(ValueError, match='entry limit'):
        decode(payload, max_entries=1)
    with pytest.raises(ValueError, match='declaration'):
        decode(payload, declared_inode_count=11)


def test_oversized_encoded_name_refuses_before_copy():
    payload = struct.pack('<IIIHhHH', 0, 48, 10, 7, 0, 2, 256) + b'x' * 257
    with pytest.raises(ValueError, match='name outside limits'):
        decode(payload)


@pytest.mark.parametrize('value', [False, True, 0, -1, 1.5, None, '8'])
@pytest.mark.parametrize('key', ['max_bytes', 'max_entries', 'max_name_bytes',
                                 'declared_inode_count'])
def test_invalid_limits_refuse(key, value):
    with pytest.raises(ValueError, match='positive integer'):
        decode(group(), **{key: value})


def test_u32_inode_overflow_refuses_without_large_allocation():
    payload = struct.pack('<IIIHhHH', 0, 48, 0xffffffff, 7, 1, 2, 0) + b'a'
    with pytest.raises(ValueError):
        decode(payload, declared_inode_count=0x100000000)


def test_highest_u32_inode_is_admitted_at_exact_bound():
    payload = struct.pack('<IIIHhHH', 0, 48, 0xffffffff, 7, 0, 2, 0) + b'a'
    result = decode(payload, declared_inode_count=0xffffffff)
    assert result.entries[0].logical_inode == 0xffffffff


@pytest.fixture(autouse=True)
def actual_module_origin():
    root = Path(__file__).resolve().parents[3]
    assert Path(directory_group.__file__).resolve() == root / 'core/audit/prepared_image_directory_group.py'
    assert decode_exact_group is directory_group.decode_exact_group
