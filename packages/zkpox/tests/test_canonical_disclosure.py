"""Reject ambiguous disclosure encodings before either verifier sees them."""
import pytest
cbor2 = pytest.importorskip('cbor2')
from packages.zkpox.disclosure import from_cbor, _validate_profile

@pytest.mark.parametrize('blob', [
    b'\xa2\x61a\x01\x61a\x02',  # duplicate map key, Python otherwise keeps last
    b'\xa1\x61a\x01\x00',       # trailing second object
    b'\xa1\x61a\x18\x01',       # nonminimal integer
    b'\xbf\x61a\x01\xff',       # indefinite map
    b'\xa2\x61b\x01\x61a\x02', # wrong canonical order
    b'\xfa\x00\x00\x00\x00',  # float
])
def test_rejects_ambiguous_encoding(blob):
    with pytest.raises(ValueError):
        from_cbor(blob)


def test_rejects_excessive_depth():
    nested = 0
    for _ in range(66):
        nested = [nested]
    with pytest.raises(ValueError, match='nesting'):
        _validate_profile(nested)


def test_rejects_typed_tag_and_nontext_key():
    for value in (cbor2.CBORTag(999, b'a'), {1: 'a'}):
        with pytest.raises(ValueError):
            _validate_profile(value)

@pytest.mark.parametrize('tag',[0,1,2,3,4,5,28,29,30,37])
def test_semantic_tags_rejected_before_decode(monkeypatch,tag):
    from packages.zkpox import disclosure
    blob=cbor2.dumps({'metadata':cbor2.CBORTag(tag,[1,1])},canonical=True)
    def unexpected(*args,**kwargs):
        pytest.fail('semantic decoder must not receive forbidden tags')
    monkeypatch.setattr(disclosure.cbor2,'loads',unexpected)
    with pytest.raises(ValueError,match='semantic tags'):
        disclosure.from_cbor(blob)

def test_opaque_proof_bytes_are_not_scanned_as_structure():
    from packages.zkpox.disclosure import _scan_cbor_profile
    _scan_cbor_profile(cbor2.dumps({'bytes':bytes(range(256))*8},canonical=True))

def test_huge_container_count_rejected_without_allocating():
    from packages.zkpox.disclosure import _scan_cbor_profile
    with pytest.raises(ValueError,match='count exceeds'):
        _scan_cbor_profile(b'\x9b'+b'\xff'*8)
