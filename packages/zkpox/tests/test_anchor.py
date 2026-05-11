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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from packages.zkpox import (
    Bundle,
    BUNDLE_VERSION,
    Ed25519Keypair,
    Envelope,
    HarnessRef,
    Proof,
    Target,
    VendorEnvelope,
    Vulnerability,
    anchor_bundle,
    bundle_hash_pre_timestamp,
    confirm_anchor_matches,
    gen_ed25519_keypair,
    sha256_bytes,
    vendor_envelope_from,
)


def _fresh_bundle() -> Bundle:
    env = Envelope(
        aes_blob=secrets.token_bytes(60),
        ct_K_age=secrets.token_bytes(232),
        ct_K_tlock=secrets.token_bytes(391),
    )
    return Bundle(
        version=BUNDLE_VERSION,
        target=Target(kind="elf", hash=sha256_bytes(b"binary"), metadata={}),
        vulnerability=Vulnerability(
            cls="memory-safety",
            gadget_id="memory-safety::oob-write@0.1.0",
            gadget_hash=sha256_bytes(b"gadget"),
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
