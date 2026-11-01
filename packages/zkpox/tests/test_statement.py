"""Adversarial statement and delivery binding checks."""
from dataclasses import replace
import hashlib
import struct
import pytest
from packages.zkpox.statement import Statement, commitment, source_hash


def positive():
    return Statement(1, 2, 3, 1, 16, commitment(1, 2, b's' * 32, b'A' * 17), source_hash(1))


def test_fixed_public_encoding():
    s = positive()
    expected = struct.pack('<IIIIIi', 2, 1, 2, 3, 1, 16) + s.witness_commitment + s.target_source_hash
    assert s.encode() == expected
    assert Statement.decode(expected) == s
    assert Statement.from_dict(s.to_dict()) == s


@pytest.mark.parametrize('changes', [
    {'flags': 0, 'oob_count': 0, 'oob_first_offset': -(2**31)},
    {'target_id': 3}, {'gadget_id': 99}, {'flags': 7},
    {'oob_first_offset': 0}, {'oob_first_offset': -17},
    {'oob_count': 0}, {'oob_first_offset': 2**30},
    {'target_id': True}, {'flags': True},
])
def test_rejects_false_or_inconsistent_claims(changes):
    with pytest.raises(ValueError):
        replace(positive(), **changes).validate()


def test_commitment_is_hiding_and_context_bound():
    original = commitment(1, 2, b's' * 32, b'A' * 17)
    assert original != hashlib.sha256(b'A' * 17).digest()
    assert original != commitment(1, 2, b't' * 32, b'A' * 17)
    assert original != commitment(2, 2, b's' * 32, b'A' * 17)
    assert original != commitment(1, 1, b's' * 32, b'A' * 17)
    assert original != commitment(1, 2, b's' * 32, b'B' * 17)


def test_public_values_reject_extra_bytes():
    with pytest.raises(ValueError):
        Statement.decode(positive().encode() + b'\0')


def test_commitment_detects_delivery_substitution():
    s = positive()
    assert commitment(s.target_id, s.gadget_id, b's' * 32, b'A' * 17) == s.witness_commitment
    assert commitment(s.target_id, s.gadget_id, b's' * 32, b'B' * 17) != s.witness_commitment
