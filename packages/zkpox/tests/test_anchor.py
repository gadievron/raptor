"""Tests for packages.zkpox.anchor.

Offline tests: keypair generation, PEM round-trip, signing.

Network-gated tests (RAPTOR_NET_TESTS=1) actually anchor a synthetic
bundle to the public Sigstore Rekor instance. That writes a permanent
public entry — fine for the spike (the entry is meaningless without
the bundle), but worth knowing.
"""

from __future__ import annotations

import os
import secrets

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("cbor2")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from packages.zkpox import (
    DisclosureBundle,
    BUNDLE_VERSION,
    Envelope,
    HarnessRef,
    Proof,
    Target,
    Vulnerability,
    anchor_bundle,
    bundle_hash_pre_timestamp,
    confirm_anchor_matches,
    gen_ed25519_keypair,
    sha256_bytes,
    vendor_envelope_from,
)


def _fresh_bundle() -> DisclosureBundle:
    env = Envelope(
        aes_blob=secrets.token_bytes(60),
        ct_K_age=secrets.token_bytes(232),
        ct_K_tlock=secrets.token_bytes(391),
    )
    return DisclosureBundle(
        version=BUNDLE_VERSION,
        target=Target(kind="elf", hash=sha256_bytes(b"binary"), metadata={}),
        vulnerability=Vulnerability(
            cls="memory-safety",
            gadget_id="memory-safety::oob-write@0.1.0",
            gadget_id_hash=sha256_bytes(b"gadget"),
        ),
        proof=Proof(
            system="sp1-stark-core/v6.1.0",
            bytes=secrets.token_bytes(2048),
            verifier_key_hash=sha256_bytes(b"vk"),
        ),
        harness=HarnessRef(
            git_url=None, rev=None, hash=sha256_bytes(b"harness"),
        ),
        vendor_envelope=vendor_envelope_from(
            env, vendor_pubkey="age1example", drand_round_min=None,
        ),
    )


# ---------------------------------------------------------------------------
# Offline: keypair + signing
# ---------------------------------------------------------------------------

def test_gen_keypair_signs_and_self_verifies():
    kp = gen_ed25519_keypair()
    msg = b"the bundle hash we'd be sending to rekor"
    sig = kp.sign(msg)
    # cryptography raises on bad sig, returns None on good.
    kp.public_key.verify(sig, msg)


def test_pem_pubkey_round_trip():
    """The PEM bytes we send to Rekor must be a parseable SPKI form
    of an ed25519 public key — otherwise the log rejects the entry."""
    from cryptography.hazmat.primitives import serialization
    kp = gen_ed25519_keypair()
    pem = kp.pem_public()
    assert b"-----BEGIN PUBLIC KEY-----" in pem
    parsed = serialization.load_pem_public_key(pem)
    assert isinstance(parsed, Ed25519PublicKey)


def test_signature_is_deterministic_per_message():
    """Ed25519 signatures are deterministic — repeated sign() on the
    same key+message yields identical bytes. Useful invariant for
    test reproducibility."""
    kp = gen_ed25519_keypair()
    msg = b"x" * 100
    assert kp.sign(msg) == kp.sign(msg)


def test_signature_differs_across_keys():
    msg = b"same message"
    a = gen_ed25519_keypair().sign(msg)
    b = gen_ed25519_keypair().sign(msg)
    assert a != b


# ---------------------------------------------------------------------------
# Offline: _make_hashedrekord_entry schema shape
# ---------------------------------------------------------------------------

def test_hashedrekord_entry_shape():
    """Rekor's hashedrekord/0.0.1 schema requires specific nested keys.
    A drift here is an immediate 400 from Rekor; catching it offline
    is much cheaper than discovering it in CI."""
    from packages.zkpox.anchor import _make_hashedrekord_entry
    entry = _make_hashedrekord_entry(
        bundle_hash_hex="ab" * 32,
        signature_b64="aGVsbG8=",
        pubkey_pem_b64="dGVzdA==",
    )
    assert entry["apiVersion"] == "0.0.1"
    assert entry["kind"] == "hashedrekord"
    assert entry["spec"]["data"]["hash"]["algorithm"] == "sha256"
    assert entry["spec"]["data"]["hash"]["value"] == "ab" * 32
    assert entry["spec"]["signature"]["content"] == "aGVsbG8="
    assert entry["spec"]["signature"]["publicKey"]["content"] == "dGVzdA=="


def test_rekor_url_env_override(monkeypatch):
    from packages.zkpox.anchor import DEFAULT_REKOR_URL, rekor_url
    monkeypatch.delenv("ZKPOX_REKOR_URL", raising=False)
    assert rekor_url() == DEFAULT_REKOR_URL
    monkeypatch.setenv("ZKPOX_REKOR_URL", "https://rekor.example.invalid/")
    assert rekor_url() == "https://rekor.example.invalid"  # trailing / trimmed


# ---------------------------------------------------------------------------
# Network: real Rekor anchor + verify (gated on RAPTOR_NET_TESTS=1)
# ---------------------------------------------------------------------------

net_rekor = pytest.mark.skipif(
    os.environ.get("RAPTOR_NET_TESTS") != "1",
    reason="set RAPTOR_NET_TESTS=1 to run network tests (writes a public Rekor entry)",
)


@net_rekor
def test_anchor_and_confirm_round_trip():
    """End-to-end against the public Sigstore Rekor instance:

      1. Build a synthetic bundle.
      2. Anchor it (POST to Rekor, get log index + inclusion proof).
      3. GET the entry back, parse the embedded hashedrekord body,
         confirm the data hash matches our local computation.
    """
    bundle = _fresh_bundle()
    pre_hash = bundle_hash_pre_timestamp(bundle).hex()

    anchored, _kp = anchor_bundle(bundle)

    assert anchored.timestamp is not None
    assert anchored.timestamp.rekor_log_index > 0
    assert anchored.timestamp.rekor_log_id  # non-empty
    assert anchored.timestamp.entry_uuid    # non-empty

    # Hash is invariant under adding the timestamp.
    assert bundle_hash_pre_timestamp(anchored).hex() == pre_hash

    # And Rekor's record matches what we sent.
    assert confirm_anchor_matches(anchored) is True


# ---------------------------------------------------------------------------
# Phase 1.5.3 — Merkle inclusion + SET signature primitives.
# ---------------------------------------------------------------------------
#
# Offline. Builds synthetic RFC 6962 trees (the reference recursive
# implementation a verifier can be checked against) and round-trips
# SET signatures across both algorithm families (Ed25519 + ECDSA
# P-256) Sigstore Rekor v1 uses.

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from packages.zkpox import (
    InclusionProofError,
    SignatureError,
    canonical_set_payload,
    verify_inclusion_proof,
    verify_set,
)
from packages.zkpox.anchor import (
    _rfc6962_leaf_hash,
    _rfc6962_node_hash,
)


def _build_tree(leaves: list[bytes], idx: int) -> tuple[str, list[str]]:
    """RFC 6962 reference tree + audit path. Same shape the Rust mirror
    in ``core/zkpox/verifier/src/rekor.rs`` builds; both crash if they
    disagree on a single bit (pinning algorithmic parity across the
    Python and Rust sides)."""

    def recurse(level: list[bytes], local: int) -> tuple[bytes, list[bytes]]:
        if len(level) == 1:
            return level[0], []
        k = 1
        while k * 2 < len(level):
            k *= 2
        left, right = level[:k], level[k:]
        if local < k:
            l_h, l_path = recurse(left, local)
            r_h, _ = recurse(right, 0)
            return _rfc6962_node_hash(l_h, r_h), l_path + [r_h]
        l_h, _ = recurse(left, 0)
        r_h, r_path = recurse(right, local - k)
        return _rfc6962_node_hash(l_h, r_h), r_path + [l_h]

    level = [_rfc6962_leaf_hash(d) for d in leaves]
    root, path = recurse(level, idx)
    return root.hex(), [h.hex() for h in path]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 11, 23])
def test_merkle_every_leaf_verifies(n):
    """Across the full 1-23 range the Rust mirror also tests, every
    leaf in a synthetic tree must verify against the reference root."""
    leaves = [f"leaf-{i}".encode() for i in range(n)]
    for i in range(n):
        root_hex, path = _build_tree(leaves, i)
        assert (
            verify_inclusion_proof(
                leaves[i], log_index=i, tree_size=n,
                audit_path_hex=path, expected_root_hex=root_hex,
            )
            is True
        )


def test_merkle_rejects_tampered_path():
    leaves = [f"leaf-{i}".encode() for i in range(7)]
    root_hex, path = _build_tree(leaves, 3)
    tampered = list(path)
    tampered[0] = "00" * 32
    assert (
        verify_inclusion_proof(
            leaves[3], log_index=3, tree_size=7,
            audit_path_hex=tampered, expected_root_hex=root_hex,
        )
        is False
    )


def test_merkle_rejects_tampered_leaf():
    leaves = [f"leaf-{i}".encode() for i in range(7)]
    root_hex, path = _build_tree(leaves, 3)
    assert (
        verify_inclusion_proof(
            b"different-leaf-bytes", log_index=3, tree_size=7,
            audit_path_hex=path, expected_root_hex=root_hex,
        )
        is False
    )


def test_merkle_rejects_wrong_root():
    leaves = [f"leaf-{i}".encode() for i in range(7)]
    _, path = _build_tree(leaves, 0)
    assert (
        verify_inclusion_proof(
            leaves[0], log_index=0, tree_size=7,
            audit_path_hex=path,
            expected_root_hex="ff" * 32,
        )
        is False
    )


def test_merkle_out_of_range_index_raises():
    leaves = [b"a", b"b"]
    root_hex, path = _build_tree(leaves, 0)
    with pytest.raises(InclusionProofError, match="out of range"):
        verify_inclusion_proof(
            leaves[0], log_index=2, tree_size=2,
            audit_path_hex=path, expected_root_hex=root_hex,
        )


def test_merkle_malformed_audit_entry_raises():
    leaves = [b"a", b"b"]
    root_hex, path = _build_tree(leaves, 0)
    bad_path = ["zz" * 32]  # non-hex
    with pytest.raises(InclusionProofError, match="non-hex"):
        verify_inclusion_proof(
            leaves[0], log_index=0, tree_size=2,
            audit_path_hex=bad_path, expected_root_hex=root_hex,
        )


# ---------------------------------------------------------------------------
# SET (Signed Entry Timestamp) verification
# ---------------------------------------------------------------------------

def _ed25519_pem_pair():
    sk = Ed25519PrivateKey.generate()
    pk_pem = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sk, pk_pem


def _ecdsa_p256_pem_pair():
    sk = ec.generate_private_key(ec.SECP256R1())
    pk_pem = sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sk, pk_pem


def test_canonical_set_payload_is_sorted_compact():
    """Pin the canonical-JSON layout Rekor v1's Go side produces.
    A drift in the serializer (e.g. extra whitespace, key reorder)
    breaks SET verification across the wire — guard at the source."""
    payload = canonical_set_payload(
        entry_body_b64="ZHVtbXk=",
        integrated_time=1_700_000_000,
        log_index=42,
        log_id="abc123",
    )
    # Expected: keys alphabetised (body < integratedTime < logID <
    # logIndex), compact separators, no whitespace.
    assert payload == (
        b'{"body":"ZHVtbXk=","integratedTime":1700000000,'
        b'"logID":"abc123","logIndex":42}'
    )


def test_set_ed25519_round_trip():
    sk, pk_pem = _ed25519_pem_pair()
    payload = canonical_set_payload(
        entry_body_b64="QQ==",
        integrated_time=1, log_index=0, log_id="x",
    )
    sig = sk.sign(payload)
    assert (
        verify_set(
            canonical_payload=payload,
            signature=sig,
            log_pubkey_pem=pk_pem,
        )
        is True
    )


def test_set_ecdsa_p256_round_trip():
    sk, pk_pem = _ecdsa_p256_pem_pair()
    payload = canonical_set_payload(
        entry_body_b64="QQ==",
        integrated_time=1, log_index=0, log_id="x",
    )
    from cryptography.hazmat.primitives import hashes
    sig = sk.sign(payload, ec.ECDSA(hashes.SHA256()))
    assert (
        verify_set(
            canonical_payload=payload,
            signature=sig,
            log_pubkey_pem=pk_pem,
        )
        is True
    )


def test_set_rejects_wrong_pubkey():
    sk_a, _ = _ed25519_pem_pair()
    _, pk_b_pem = _ed25519_pem_pair()
    payload = canonical_set_payload(
        entry_body_b64="QQ==",
        integrated_time=1, log_index=0, log_id="x",
    )
    sig = sk_a.sign(payload)
    assert (
        verify_set(
            canonical_payload=payload,
            signature=sig,
            log_pubkey_pem=pk_b_pem,
        )
        is False
    )


def test_set_rejects_tampered_payload():
    sk, pk_pem = _ed25519_pem_pair()
    original = canonical_set_payload(
        entry_body_b64="QQ==",
        integrated_time=1, log_index=0, log_id="x",
    )
    sig = sk.sign(original)
    tampered = canonical_set_payload(
        entry_body_b64="QQ==",
        integrated_time=2, log_index=0, log_id="x",
    )
    assert (
        verify_set(
            canonical_payload=tampered,
            signature=sig,
            log_pubkey_pem=pk_pem,
        )
        is False
    )


def test_set_unsupported_key_type_raises():
    """RSA keys aren't in Rekor v1's algorithm set — caller gets a
    structurally-distinct error rather than False (which would conflate
    "wrong algorithm" with "wrong signer")."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    rsa_sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_sk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = canonical_set_payload(
        entry_body_b64="QQ==",
        integrated_time=1, log_index=0, log_id="x",
    )
    with pytest.raises(SignatureError, match="unsupported"):
        verify_set(
            canonical_payload=payload,
            signature=b"\x00" * 64,
            log_pubkey_pem=rsa_pem,
        )
