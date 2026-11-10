"""V2 builders bind claims and never publish private witness provenance."""
from dataclasses import replace
import pytest
pytest.importorskip("cbor2")
from packages.zkpox.bundle import ZKPoXBundle
from packages.zkpox.disclosure import (BUNDLE_VERSION,HarnessRef,Proof,VendorEnvelope,
 disclosure_from_manifest,disclosure_from_statement,from_cbor,manifest_target_bare_hex,
 sha256_bytes,target_hash_matches,to_cbor)
from packages.zkpox.statement import Statement,SYSTEM,source_hash

def _manifest(**overrides):
    fields=dict(witness_hash='b'*64,witness_len=42,source='fuzz',observed_outcome='exit_signal',
        outcome_detail={'secret':'private-outcome'},target_binary_hash='a'*64,
        target_source_hash=source_hash(1).hex(),produced_by='raptor',timestamp=None,
        attestation={'claim':'private-attestation-'+'b'*64},tier='0/1',reproduction=None)
    fields.update(overrides)
    return ZKPoXBundle(**fields)

def _statement():
    return Statement(1,2,3,1,16,b'c'*32,source_hash(1))

def _material():
    return dict(proof=Proof(SYSTEM,b'codec-fixture-not-a-proof','sp1-vk:'+'00'*32),
        harness=HarnessRef(None,None,'sha256:'+'11'*32),
        vendor_envelope=VendorEnvelope('zkpox-none/v2',b'',b'',b'',None,'',sha256_bytes(b'')))

def _project(manifest,**overrides):
    fields=dict(statement=_statement(),vuln_class='memory-safety',gadget_id='oob_write',
        gadget_id_hash=sha256_bytes(b'oob_write'),**_material())
    fields.update(overrides)
    return disclosure_from_manifest(manifest,**fields)

def test_projection_binds_source_not_binary():
    bundle=_project(_manifest())
    assert bundle.target.kind=='source'
    assert bundle.target.hash=='sha256:'+source_hash(1).hex()
    assert bundle.version==BUNDLE_VERSION
    assert bundle.statement==_statement().to_dict()

def test_projection_accepts_prefixed_source():
    assert _project(_manifest(target_source_hash='sha256:'+source_hash(1).hex())).target.hash=='sha256:'+source_hash(1).hex()

@pytest.mark.parametrize('source',[None,'d'*64])
def test_projection_rejects_wrong_or_missing_source(source):
    with pytest.raises(ValueError,match='source hash'):
        _project(_manifest(target_source_hash=source))

def test_projection_omits_private_provenance():
    manifest=_manifest(tier='1.5',reproduction={'reproduced':True,'private':'secret-reproduction'})
    bundle=_project(manifest)
    payload=to_cbor(bundle)
    assert bundle.provenance is None
    assert bundle.target.metadata=={}
    for secret in (manifest.witness_hash,'private-attestation','private-outcome','secret-reproduction'):
        assert secret.encode() not in payload
    assert from_cbor(payload)==bundle

@pytest.mark.parametrize('override',[
 {'target_kind':'elf'},{'vuln_class':'rce'},{'gadget_id':'crash_only'},
 {'gadget_id_hash':'sha256:wrong'},{'gadget_code_hash':'sha256:unbound'},
 {'leaked_fields':['unbound claim']}])
def test_projection_rejects_unproven_claims(override):
    with pytest.raises(ValueError,match='claim metadata'):
        _project(_manifest(),**override)

def test_factory_rejects_benign_statement():
    with pytest.raises(ValueError,match='did not demonstrate'):
        disclosure_from_statement(replace(_statement(),flags=0,oob_count=0,oob_first_offset=-(2**31)),**_material())

def test_factory_rejects_other_proof_system():
    material=_material()
    material['proof']=replace(material['proof'],system='sp1-core')
    with pytest.raises(ValueError,match='Groth16'):
        disclosure_from_statement(_statement(),**material)

# # Target reconciliation (anti re-keying)
# ---------------------------------------------------------------------------

def test_target_hash_matches_accepts_same_artifact():
    m = _manifest(target_binary_hash="a" * 64)
    assert target_hash_matches(m, "a" * 64) is True


def test_target_hash_matches_rejects_different_artifact():
    m = _manifest(target_binary_hash="a" * 64)
    assert target_hash_matches(m, "f" * 64) is False


def test_target_hash_matches_tolerates_prefixed_manifest_hash():
    m = _manifest(target_binary_hash="sha256:" + "a" * 64)
    assert manifest_target_bare_hex(m) == "a" * 64
    assert target_hash_matches(m, "a" * 64) is True


def test_target_hash_matches_when_manifest_has_no_hash():
    """Nothing to reconcile against → vacuously matches (the projection
    is what rejects a hash-less manifest)."""
    m = _manifest(target_binary_hash=None, target_source_hash=None)
    assert manifest_target_bare_hex(m) is None
    assert target_hash_matches(m, "a" * 64) is True
