"""Rekor v2 inclusion with an explicitly pinned operator trust root.

An authenticated checkpoint proves log inclusion, not a wall-clock timestamp.
No SET or integratedTime is inferred from a v2 response. RFC3161 is separate.
"""
from __future__ import annotations
import base64
from dataclasses import replace
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .anchor import _default_http_for, verify_inclusion_proof
from .disclosure import DisclosureBundle, to_cbor


def _b64(text: str) -> bytes:
    if type(text) is not str:
        raise ValueError("expected base64 text")
    return base64.b64decode(text, validate=True)


def _integer(value) -> int:
    if type(value) is str and value.isascii() and value.isdecimal():
        value = int(value)
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError("invalid log index/tree size")
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in log entry")
        result[key] = value
    return result


def _artifact(bundle: DisclosureBundle) -> bytes:
    return to_cbor(replace(bundle, transparency=None, timestamp=None))


def _checkpoint(envelope: str, pem: bytes, origin: str) -> tuple[int, bytes]:
    if type(envelope) is not str or len(envelope) > 64 * 1024:
        raise ValueError("invalid checkpoint")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("checkpoint trust key must be ECDSA P-256")
    body, signatures = envelope.split("\n\n", 1)
    body += "\n"
    lines = body.splitlines()
    if len(lines) != 3 or lines[0] != origin:
        raise ValueError("checkpoint origin mismatch")
    size, root = _integer(lines[1]), _b64(lines[2])
    if not size or len(root) != 32:
        raise ValueError("invalid checkpoint tree")
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(der).digest()[:4]
    for line in signatures.splitlines():
        fields = line.split(" ")
        if len(fields) != 3 or fields[0] != "—" or fields[1] != origin:
            continue
        signed = _b64(fields[2])
        if signed[:4] != key_id:
            continue
        try:
            key.verify(signed[4:], body.encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            continue
        return size, root
    raise ValueError("checkpoint is not signed by the pinned log key")


def verify(bundle: DisclosureBundle, *, trusted_key: bytes, origin: str) -> dict:
    if bundle.timestamp is not None:
        raise ValueError("v2 inclusion cannot carry a legacy v1 timestamp")
    entry = bundle.transparency
    if type(entry) is not dict or set(entry) != {"api_version", "response"} or entry["api_version"] != 2:
        raise ValueError("bundle has no supported Rekor v2 inclusion")
    response = entry["response"]
    inclusion = response["inclusionProof"]
    size, root = _checkpoint(inclusion["checkpoint"]["envelope"], trusted_key, origin)
    raw = _b64(response["canonicalizedBody"])
    if len(raw) > 1024 * 1024:
        raise ValueError("log entry exceeds size limit")
    body = json.loads(raw, object_pairs_hook=_unique)
    if body.get("kind") != "hashedrekord" or body.get("apiVersion") != "0.0.2":
        raise ValueError("unsupported Rekor entry kind/version")
    record = body["spec"]["hashedRekordV002"]
    digest = hashlib.sha256(_artifact(bundle)).digest()
    if record["data"]["algorithm"] != "SHA2_256" or _b64(record["data"]["digest"]) != digest:
        raise ValueError("log entry does not bind this disclosure")
    signature = record["signature"]
    verifier = signature["verifier"]
    if verifier["keyDetails"] != "PKIX_ECDSA_P256_SHA_256":
        raise ValueError("unsupported artifact signing key")
    key = serialization.load_der_public_key(_b64(verifier["publicKey"]["rawBytes"]))
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("artifact signing key is not P-256")
    try:
        key.verify(_b64(signature["content"]), digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature as exc:
        raise ValueError("invalid artifact signature in log entry") from exc
    path = inclusion.get("hashes", [])
    if type(path) is not list or len(path) > 64:
        raise ValueError("invalid inclusion path")
    index = _integer(response["logIndex"])
    if index >= size:
        raise ValueError("log index is outside the signed checkpoint tree")
    if not verify_inclusion_proof(raw, log_index=index, tree_size=size,
                                  audit_path_hex=[_b64(item).hex() for item in path], expected_root_hex=root.hex()):
        raise ValueError("log inclusion proof failed")
    return {"status": "verified_inclusion", "timestamp": "absent", "origin": origin}


def anchor(bundle: DisclosureBundle, *, url: str, trusted_key: bytes, origin: str, http=None) -> DisclosureBundle:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Rekor URL must be an HTTPS service URL")
    if bundle.transparency is not None or bundle.timestamp is not None:
        raise ValueError("disclosure is already anchored")
    key = ec.generate_private_key(ec.SECP256R1())
    digest = hashlib.sha256(_artifact(bundle)).digest()
    signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    b64 = lambda value: base64.b64encode(value).decode("ascii")
    request = {"hashedRekordRequestV002": {"digest": b64(digest), "signature": {
        "content": b64(signature), "verifier": {"keyDetails": "PKIX_ECDSA_P256_SHA_256", "publicKey": {"rawBytes": b64(der)}}}}}
    client = http or _default_http_for(url)
    response = client.post_json(url.rstrip("/") + "/api/v2/log/entries", request, timeout=60, retries=0, follow_redirects=False)
    if not isinstance(response, dict):
        raise ValueError("invalid Rekor response")
    result = replace(bundle, transparency={"api_version": 2, "response": response})
    verify(result, trusted_key=trusted_key, origin=origin)
    return result
