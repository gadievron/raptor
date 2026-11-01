"""Real SP1 proofs. Opt in explicitly; no mock prover can satisfy these tests.

Crypto checks use fixed, repository-owned witnesses. The separate CLI roundtrip
also requires RAPTOR's production sandbox and never lowers its containment floor.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest
pytest.importorskip("cbor2")
pytest.importorskip("cryptography")

from core.config import RaptorConfig
from packages.zkpox.disclosure import (BUNDLE_VERSION, DisclosureBundle, Target,
    Vulnerability, Proof, HarnessRef, VendorEnvelope, to_cbor, from_cbor)
from packages.zkpox.statement import Statement, SYSTEM, source_hash

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / 'packages/zkpox/native'
BUILD = Path(os.environ.get('CARGO_TARGET_DIR', NATIVE / 'target')) / 'release'
pytestmark = [pytest.mark.slow, pytest.mark.skipif(os.environ.get('ZKPOX_FULL_PROOFS') != '1', reason='set ZKPOX_FULL_PROOFS=1 for real proof tests')]


def run(command, **kwargs):
    env = RaptorConfig.get_safe_env()
    for key in ('SP1_GROTH16_CIRCUIT_PATH', 'RAYON_NUM_THREADS', 'TMPDIR'):
        if key in os.environ:
            env[key] = os.environ[key]
    return subprocess.run([str(value) for value in command], env=env, capture_output=True,
                          text=True, timeout=7200, **kwargs)


def prove(work, witness, wrap='groth16'):
    work.mkdir()
    path = work / 'witness.bin'
    path.write_bytes(witness)
    salt = work / 'salt.bin'
    salt.write_bytes(os.urandom(32))
    record, proof = work / 'record.json', work / 'proof.bin'
    result = run([BUILD / 'zkpox-prove', '--witness', path, '--salt', salt,
        '--target', '01', '--gadget', '2', '--prove', '--wrap', wrap,
        '--proof-out', proof, '--record', record])
    assert result.returncode == 0, result.stderr
    data = json.loads(record.read_text())
    assert data['verified'] is True
    statement = Statement.from_dict(data['statement'])
    return DisclosureBundle(BUNDLE_VERSION, Target('source', 'sha256:' + source_hash(1).hex()),
        Vulnerability('memory-safety', 'oob_write', 'sha256:' + hashlib.sha256(b'oob_write').hexdigest()),
        Proof(SYSTEM, proof.read_bytes(), data['verifier_key_hash']),
        HarnessRef(None, None, data['harness_hash']),
        VendorEnvelope('zkpox-none/v2', b'', b'', b'', None, '', 'sha256:' + hashlib.sha256(b'').hexdigest()),
        statement=statement.to_dict())


@pytest.fixture(scope='module')
def positive_private(tmp_path_factory):
    return tmp_path_factory.mktemp('real-positive') / 'private'


@pytest.fixture(scope='module')
def positive(positive_private):
    return prove(positive_private, b'A' * 17)


def verify(work, bundle, success):
    path = work / 'bundle.cbor'
    path.write_bytes(to_cbor(bundle))
    result = run([BUILD / 'zkpox-verify', path, '--json'])
    assert (result.returncode == 0) is success, result.stdout + result.stderr
    return result


def test_real_groth16_roundtrip(positive, tmp_path):
    result = verify(tmp_path, positive, True)
    assert json.loads(result.stdout)['delivery_verification'] == 'absent'


def test_valid_benign_proof_is_rejected(tmp_path):
    benign = prove(tmp_path / 'private', b'A')
    assert benign.statement['flags'] == 0
    verify(tmp_path, benign, False)


def test_core_proof_cannot_be_relabelled_groth16(tmp_path):
    core = prove(tmp_path / 'private', b'A' * 17, wrap='core')
    verify(tmp_path, core, False)


@pytest.mark.parametrize('mutation', ['source', 'gadget', 'commitment', 'verdict', 'proof', 'harness', 'vkey'])
def test_rejects_public_claim_substitution(positive, tmp_path, mutation):
    bundle = positive
    if mutation == 'source':
        bundle = replace(bundle, target=replace(bundle.target, hash='sha256:' + source_hash(3).hex()))
    elif mutation == 'gadget':
        bundle = replace(bundle, vulnerability=replace(bundle.vulnerability, gadget_id='crash_only'))
    elif mutation in ('commitment', 'verdict'):
        statement = dict(bundle.statement)
        statement['witness_commitment' if mutation == 'commitment' else 'flags'] = 'sha256:' + '00'*32 if mutation == 'commitment' else 0
        bundle = replace(bundle, statement=statement)
    elif mutation == 'proof':
        bundle = replace(bundle, proof=replace(bundle.proof, bytes=bundle.proof.bytes[:-1] + bytes([bundle.proof.bytes[-1] ^ 1])))
    elif mutation == 'harness':
        bundle = replace(bundle, harness=replace(bundle.harness, hash='sha256:' + '00'*32))
    else:
        bundle = replace(bundle, proof=replace(bundle.proof, verifier_key_hash='sp1-vk:' + '00'*32))
    verify(tmp_path, bundle, False)


@pytest.mark.skipif(os.environ.get('ZKPOX_CLI_ROUNDTRIP') != '1', reason='production CLI check needs a working mount namespace')
def test_production_cli_roundtrip(tmp_path):
    private = tmp_path / 'private'
    private.mkdir()
    witness = b'A' * 17
    (private / 'witness.bin').write_bytes(witness)
    (private / 'manifest.json').write_text(json.dumps({'witness_hash':hashlib.sha256(witness).hexdigest(),
        'witness_len':len(witness), 'target_source_hash':source_hash(1).hex()}))
    out = tmp_path / 'public'
    env = RaptorConfig.get_safe_env()
    env.update({'_RAPTOR_TRUSTED':'1', 'RAPTOR_DIR':str(ROOT), 'PATH': str(BUILD) + os.pathsep + env.get('PATH', '/usr/bin:/bin')})
    if 'SP1_GROTH16_CIRCUIT_PATH' in os.environ:
        env['SP1_GROTH16_CIRCUIT_PATH'] = os.environ['SP1_GROTH16_CIRCUIT_PATH']
    result = subprocess.run([str(ROOT / 'libexec/raptor-zkpox'), 'prove', str(private), '--target', '01', '--out', str(out)],
                            env=env, capture_output=True, text=True, timeout=7200)
    assert result.returncode == 0, result.stdout + result.stderr
    assert set(p.name for p in out.iterdir()) == {'bundle.cbor', 'verification.json'}
    bundle = from_cbor((out / 'bundle.cbor').read_bytes())
    assert bundle.provenance is None
    assert hashlib.sha256(witness).hexdigest().encode() not in (out / 'bundle.cbor').read_bytes()
    verify(tmp_path, bundle, True)


@pytest.mark.skipif(os.environ.get('RAPTOR_NET_TESTS') != '1', reason='delivery check reads public Drand beacons')
def test_real_delivery_openings(positive, positive_private, tmp_path, monkeypatch):
    from argparse import Namespace
    import time
    from packages.zkpox import cli, envelope
    from packages.zkpox.disclosure import vendor_envelope_from
    monkeypatch.setenv('PATH', str(BUILD) + os.pathsep + os.environ.get('PATH', ''))
    pair = envelope.gen_age_keypair()
    try:
        statement = Statement.from_dict(positive.statement)
        salt = (positive_private / 'salt.bin').read_bytes()
        witness = (positive_private / 'witness.bin').read_bytes()
        payload = salt + witness
        aad = b'raptor-zkpox-delivery-v2\0' + statement.encode()
        sealed = envelope.seal(payload, pair.public_key, duration='8s', aad=aad)
        disclosure = replace(positive, vendor_envelope=vendor_envelope_from(sealed,
                             vendor_pubkey=pair.public_key, drand_round_min=None))
        result = verify(tmp_path, disclosure, True)
        assert json.loads(result.stdout)['delivery_verification'] == 'encrypted_unchecked'
        bundle_path = tmp_path / 'bundle.cbor'
        vendor_out = tmp_path / 'vendor-witness'
        assert cli._cmd_open(Namespace(bundle=str(bundle_path), identity=str(pair.secret_key_path),
                              after_release=False, out=str(vendor_out))) == 0
        assert vendor_out.read_bytes() == witness
        assert vendor_out.stat().st_mode & 0o777 == 0o600
        time.sleep(12)
        release_out = tmp_path / 'released-witness'
        assert cli._cmd_open(Namespace(bundle=str(bundle_path), identity=None,
                              after_release=True, out=str(release_out))) == 0
        assert release_out.read_bytes() == witness
        # A producer can encrypt a different payload under the right AAD.
        # Public verification remains unchecked; opening must reject it.
        substituted = envelope.seal(salt + b'different witness', pair.public_key, duration='8s', aad=aad)
        bad = replace(disclosure, vendor_envelope=vendor_envelope_from(substituted,
                      vendor_pubkey=pair.public_key, drand_round_min=None))
        bundle_path.write_bytes(to_cbor(bad))
        bad_out = tmp_path / 'must-not-exist'
        with pytest.raises(ValueError, match='does not match'):
            cli._cmd_open(Namespace(bundle=str(bundle_path), identity=str(pair.secret_key_path),
                          after_release=False, out=str(bad_out)))
        assert not bad_out.exists()
    finally:
        import shutil
        shutil.rmtree(pair.secret_key_path.parent)


def test_runtime_file_limit_preflight(tmp_path):
    from core.sandbox import run_untrusted
    from packages.zkpox.proving_deps import SP1_JIT_FILE_LIMIT_MB
    for limit,accepted in ((10240,False),(SP1_JIT_FILE_LIMIT_MB,True)):
        result=run_untrusted([str(BUILD/'zkpox-prove'),'--check-runtime'],output=str(tmp_path),
            tool_paths=[str(BUILD)],limits={'max_file_mb':limit},capture_output=True,text=True,
            timeout=20,caller_label='zkpox-runtime-preflight')
        assert (result.returncode==0) is accepted,result.stdout+result.stderr
        if accepted:
            assert json.loads(result.stdout)['jit_shared_memory_bytes']==limit*1024*1024
        else:
            assert '2 TiB sparse shared-memory' in result.stderr
