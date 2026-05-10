"""Tests for packages.zkpox.bundle.

CBOR round-trip + schema-shape coverage. The full prove → wrap →
envelope → bundle → verify integration test lives in the SP1-marked
suite (Phase 1.5 will land it once the RAPTOR command surface is
wired); for 1.3 we just confirm the bundle producer/parser is faithful.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import cbor2
import pytest

from packages.zkpox import (
    Bundle,
    BUNDLE_VERSION,
    Envelope,
    HarnessRef,
    Proof,
    Researcher,
    Target,
    VendorEnvelope,
    Vulnerability,
    from_cbor,
    sha256_bytes,
    sha256_file,
    to_cbor,
    vendor_envelope_from,
)


def _fresh_envelope() -> Envelope:
    """Synthetic envelope with random bytes — no external tools called."""
    return Envelope(
        aes_blob=secrets.token_bytes(60),
        ct_K_age=secrets.token_bytes(232),
        ct_K_tlock=secrets.token_bytes(391),
    )


def _fresh_bundle(*, with_researcher: bool = False) -> Bundle:
    env = _fresh_envelope()
    vendor_env = vendor_envelope_from(
        env,
        vendor_pubkey="age1exampleexampleexampleexampleexampleexamplekjzqplexample",
        drand_round_min=12345678,
    )
    bundle = Bundle(
        version=BUNDLE_VERSION,
        target=Target(
            kind="elf",
            hash=sha256_bytes(b"target-binary-bytes"),
            url="https://example.invalid/target.elf",
            metadata={"arch": "riscv64", "loc_hint": "1k"},
        ),
        vulnerability=Vulnerability(
            cls="memory-safety",
            gadget_id="memory-safety::oob-write@0.1.0",
            gadget_hash=sha256_bytes(b"gadget-source"),
            leaked_fields=["function_name"],
        ),
        proof=Proof(
            system="sp1-stark-core/v6.1.0",
            bytes=secrets.token_bytes(2048),
            verifier_key_hash=sha256_bytes(b"vk"),
        ),
        harness=HarnessRef(
            git_url="https://github.com/example/raptor",
            rev="deadbeef",
            hash=sha256_bytes(b"harness-binary"),
        ),
        vendor_envelope=vendor_env,
        researcher=(
            Researcher(
                pubkey="ed25519:...",
                signature_over_bundle=secrets.token_bytes(64),
                contact="researcher@example.invalid",
            )
            if with_researcher
            else None
        ),
    )
    return bundle


def test_round_trip_minimal_bundle():
    bundle = _fresh_bundle()
    blob = to_cbor(bundle)
    parsed = from_cbor(blob)
    assert parsed == bundle


def test_round_trip_with_researcher():
    bundle = _fresh_bundle(with_researcher=True)
    parsed = from_cbor(to_cbor(bundle))
    assert parsed.researcher is not None
    assert parsed.researcher.contact == "researcher@example.invalid"
    assert len(parsed.researcher.signature_over_bundle) == 64


def test_blob_top_level_keys_match_proposal():
    """Bundle binary form must include the §8-spec'd top-level fields,
    so external CBOR-only verifiers can be written without our types."""
    bundle = _fresh_bundle()
    decoded = cbor2.loads(to_cbor(bundle))
    expected = {
        "version", "target", "vulnerability", "proof",
        "harness", "vendor_envelope",
    }
    assert expected <= set(decoded.keys())
    assert decoded["version"] == "zkpox-1.0"


def test_envelope_substructure_exposes_layered_blobs():
    """Phase 1.3 chose to surface the three ciphertexts directly rather
    than collapse them into a single opaque `ciphertext` (per docstring
    in bundle.py). Verifiers depend on this shape."""
    bundle = _fresh_bundle()
    decoded = cbor2.loads(to_cbor(bundle))
    env = decoded["vendor_envelope"]
    assert {"aes_blob", "ct_K_age", "ct_K_tlock"} <= set(env.keys())
    for k in ("aes_blob", "ct_K_age", "ct_K_tlock"):
        assert isinstance(env[k], (bytes, bytearray)), f"{k} must be bytes, got {type(env[k])}"


def test_proof_bytes_round_trip_byte_exact():
    """The proof bytes are the load-bearing artefact; verify they
    survive CBOR's bstr encoding without truncation or re-encoding."""
    bundle = _fresh_bundle()
    parsed = from_cbor(to_cbor(bundle))
    assert parsed.proof.bytes == bundle.proof.bytes
    assert parsed.proof.system == bundle.proof.system


def test_sha256_file_matches_known_value(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello")
    expected = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert sha256_file(p) == expected


def test_timestamp_field_omitted_when_none():
    """Phase 1.4 will fill `timestamp`; Phase 1.3 must NOT emit a
    placeholder (would fingerprint our bundles as pre-1.4 vs post-1.4
    in unhelpful ways). Field is structurally absent."""
    bundle = _fresh_bundle()
    blob = to_cbor(bundle)
    decoded = cbor2.loads(blob)
    assert "timestamp" not in decoded
