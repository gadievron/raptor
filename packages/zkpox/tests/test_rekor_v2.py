"""Offline protocol and trust-boundary tests; never publish log entries."""
from dataclasses import replace
import base64
import hashlib
import json
from types import SimpleNamespace
import pytest
pytest.importorskip("cbor2")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from packages.zkpox import rekor_v2
from packages.zkpox.disclosure import (BUNDLE_VERSION, DisclosureBundle, Target,
                                     Vulnerability, Proof, HarnessRef, VendorEnvelope)

b64 = lambda b: base64.b64encode(b).decode()
ORIGIN = 'rekor.example.test'


def fixture():
    log = ec.generate_private_key(ec.SECP256R1())
    der = log.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = log.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    bundle = DisclosureBundle(BUNDLE_VERSION, Target('source', 'sha256:' + '11'*32),
        Vulnerability('memory-safety', 'oob_write', 'sha256:' + '22'*32),
        Proof('sp1-groth16/6.5.0', b'fixture-not-a-proof', 'sp1-vk:' + '33'*32),
        HarnessRef(None, None, 'sha256:' + '44'*32),
        VendorEnvelope('zkpox-none/v2', b'', b'', b'', None, '', 'sha256:' + hashlib.sha256(b'').hexdigest()))
    calls = []
    def post_json(url, request, **kwargs):
        calls.append((url, kwargs))
        record = request['hashedRekordRequestV002']
        body = {'kind':'hashedrekord', 'apiVersion':'0.0.2', 'spec': {'hashedRekordV002': {
            'data': {'algorithm':'SHA2_256', 'digest': record['digest']}, 'signature': record['signature']}}}
        raw = json.dumps(body, separators=(',', ':'), sort_keys=True).encode()
        root = hashlib.sha256(b'\0' + raw).digest()
        checkpoint = f'{ORIGIN}\n1\n{b64(root)}\n'
        signature = hashlib.sha256(der).digest()[:4] + log.sign(checkpoint.encode(), ec.ECDSA(hashes.SHA256()))
        return {'logIndex':'0', 'canonicalizedBody':b64(raw), 'inclusionProof': {
            'hashes': [], 'checkpoint': {'envelope':checkpoint + '\n— ' + ORIGIN + ' ' + b64(signature) + '\n'}}}
    return bundle, pem, SimpleNamespace(post_json=post_json), calls


def test_v2_write_and_offline_verification():
    bundle, pem, http, calls = fixture()
    anchored = rekor_v2.anchor(bundle, url='https://' + ORIGIN, trusted_key=pem, origin=ORIGIN, http=http)
    assert calls == [('https://' + ORIGIN + '/api/v2/log/entries', {'timeout':60, 'retries':0, 'follow_redirects':False})]
    assert rekor_v2.verify(anchored, trusted_key=pem, origin=ORIGIN) == {'status':'verified_inclusion', 'timestamp':'absent', 'origin':ORIGIN}
    assert anchored.timestamp is None


def test_rejects_artifact_substitution():
    bundle, pem, http, _ = fixture()
    anchored = rekor_v2.anchor(bundle, url='https://' + ORIGIN, trusted_key=pem, origin=ORIGIN, http=http)
    tampered = replace(anchored, proof=replace(anchored.proof, bytes=b'changed'))
    with pytest.raises(ValueError, match='does not bind'):
        rekor_v2.verify(tampered, trusted_key=pem, origin=ORIGIN)


def test_rejects_wrong_log_key_or_origin():
    bundle, pem, http, _ = fixture()
    anchored = rekor_v2.anchor(bundle, url='https://' + ORIGIN, trusted_key=pem, origin=ORIGIN, http=http)
    _, wrong_key, _, _ = fixture()
    for key, origin in ((wrong_key, ORIGIN), (pem, 'attacker.example')):
        with pytest.raises(ValueError):
            rekor_v2.verify(anchored, trusted_key=key, origin=origin)


def test_rejects_leaf_mutation():
    bundle, pem, http, _ = fixture()
    anchored = rekor_v2.anchor(bundle, url='https://' + ORIGIN, trusted_key=pem, origin=ORIGIN, http=http)
    response = dict(anchored.transparency['response'])
    response['logIndex'] = '1'
    with pytest.raises(ValueError):
        rekor_v2.verify(replace(anchored, transparency={'api_version':2, 'response':response}), trusted_key=pem, origin=ORIGIN)
