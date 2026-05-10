"""Tests for packages.zkpox.envelope.

The AES round-trip is exercised offline (no network, no external tools).
The age round-trip uses the real `age`/`age-keygen` binaries from the
host. The tle / Drand round-trip hits `api.drand.sh` and is skipped
unless the test runner opts into network tests via RAPTOR_NET_TESTS=1.
"""

from __future__ import annotations

import os
import secrets
import shutil

import pytest

from packages.zkpox import envelope


# ---------------------------------------------------------------------------
# AES — pure-Python crypto, no external deps
# ---------------------------------------------------------------------------

def test_aes_round_trips_random_payloads():
    key = secrets.token_bytes(32)
    for size in (0, 1, 16, 32, 100, 4096):
        payload = secrets.token_bytes(size)
        ct = envelope.aes_encrypt(payload, key)
        assert envelope.aes_decrypt(ct, key) == payload


def test_aes_rejects_short_key():
    with pytest.raises(ValueError):
        envelope.aes_encrypt(b"hi", b"\x00" * 16)


def test_aes_rejects_truncated_blob():
    key = secrets.token_bytes(32)
    with pytest.raises(ValueError):
        envelope.aes_decrypt(b"\x00" * 5, key)


def test_aes_aad_binding():
    """A ciphertext from a different protocol must not decrypt as a
    zkpox witness — that's why we set associated data."""
    key = secrets.token_bytes(32)
    blob = envelope.aes_encrypt(b"witness", key)
    # Splice a wrong-AAD plaintext using the same key+nonce. We rebuild
    # the encryption with a different AAD by going under the hood:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = blob[:12]
    bad = nonce + AESGCM(key).encrypt(nonce, b"witness", b"OTHER-PROTO-AAD")
    with pytest.raises(Exception):
        envelope.aes_decrypt(bad, key)


# ---------------------------------------------------------------------------
# age — needs `age`/`age-keygen` on PATH
# ---------------------------------------------------------------------------

age_required = pytest.mark.skipif(
    not (shutil.which("age") and shutil.which("age-keygen")),
    reason="age/age-keygen not installed",
)


@age_required
def test_age_round_trip_via_keypair():
    pair = envelope.gen_age_keypair()
    try:
        secret = b"K" * 32
        ct = envelope.age_encrypt_to(secret, pair.public_key)
        assert envelope.age_decrypt_with(ct, pair.secret_key_path) == secret
    finally:
        try:
            pair.secret_key_path.unlink()
            pair.secret_key_path.parent.rmdir()
        except OSError:
            pass


@age_required
def test_age_decrypt_with_wrong_key_fails():
    pair_a = envelope.gen_age_keypair()
    pair_b = envelope.gen_age_keypair()
    try:
        ct = envelope.age_encrypt_to(b"K" * 32, pair_a.public_key)
        with pytest.raises(Exception):
            envelope.age_decrypt_with(ct, pair_b.secret_key_path)
    finally:
        for pair in (pair_a, pair_b):
            try:
                pair.secret_key_path.unlink()
                pair.secret_key_path.parent.rmdir()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Full envelope (seal + both decrypt paths) — gated on tle + network
# ---------------------------------------------------------------------------

net_envelope_required = pytest.mark.skipif(
    not (
        os.environ.get("RAPTOR_NET_TESTS") == "1"
        and (shutil.which("tle") or shutil.which(os.path.expanduser("~/go/bin/tle")))
        and shutil.which("age")
    ),
    reason="set RAPTOR_NET_TESTS=1 and install age + tle to run network tests",
)


@net_envelope_required
def test_seal_round_trips_both_paths():
    """End-to-end: seal a witness, recover via both decrypt paths.

    Uses an 8-second tlock duration so the test terminates promptly.
    Phase 1's real bundle uses the proposal's 90-day default.
    """
    import time

    pair = envelope.gen_age_keypair()
    try:
        witness = b"\xCC" * 64
        env = envelope.seal(witness, pair.public_key, duration="8s")

        # Vendor path is immediate.
        assert envelope.open_via_vendor(env, pair.secret_key_path) == witness

        # Time-lock path: wait past the duration so the round finalises.
        time.sleep(12)
        assert envelope.open_via_tlock(env) == witness
    finally:
        try:
            pair.secret_key_path.unlink()
            pair.secret_key_path.parent.rmdir()
        except OSError:
            pass
