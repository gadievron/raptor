"""
zkpox — Python orchestration for RAPTOR's zero-knowledge proof of
exploit feature.

The Rust workspace at `core/zkpox/` does the actual SP1 proving and
bundle verification; this package wraps it for /prove-exploit and
/verify-exploit-proof, plus the layered envelope encryption.

Phase 1.1 surface (this module):
  - envelope: AES-256-GCM + age + Drand tlock layered encryption.
  - prove:    locate / drive the Rust prover binary against a witness.
  - bundle:   CBOR disclosure-bundle producer/consumer (Phase 1.3).
  - verify:   high-level bundle verification (delegates to the Rust
              `zkpox-verify` binary; this is the Python convenience
              wrapper that RAPTOR commands import).

Most operators won't import this directly — RAPTOR's `/prove-exploit`
and `/verify-exploit-proof` commands handle invocation. The public
surface here is for `packages/exploitation/` integration and tests.

Design proposal: docs/proposals/raptor-zkpox-design.md
Phase 0 spike findings: docs/research/zkpox-phase0-findings.md
"""

# Optional dependencies: cryptography and cbor2 are commented out in
# requirements.txt by default (the Rust workspace at core/zkpox/ is what
# does the real work). The Python wrappers below need them, but we don't
# want plain `import packages.zkpox` to explode at collection time when
# the deps aren't installed — that traps pytest before any path filter
# can skip the suite. So: re-exports are guarded, AVAILABLE reflects
# whether the wrappers are usable, and require() gives a one-line install
# hint when callers actually need them.
AVAILABLE = False
_IMPORT_ERROR: Exception | None = None

try:
    from .anchor import (
        AnchorError,
        Ed25519Keypair,
        anchor_bundle,
        confirm_anchor_matches,
        fetch_log_entry,
        gen_ed25519_keypair,
        load_ed25519_secret_pem,
        rekor_url,
    )
    from .bundle import (
        BUNDLE_VERSION,
        Bundle,
        HarnessRef,
        Proof,
        Researcher,
        Target,
        Timestamp,
        VendorEnvelope,
        Vulnerability,
        bundle_hash_pre_timestamp,
        from_cbor,
        sha256_bytes,
        sha256_file,
        to_cbor,
        vendor_envelope_from,
        with_timestamp,
    )
    from .envelope import (
        AgeKeypair,
        Envelope,
        EnvelopeError,
        EnvelopeRoundTripError,
        EnvelopeToolError,
        aes_decrypt,
        aes_encrypt,
        age_decrypt_with,
        age_encrypt_to,
        gen_age_keypair,
        open_via_tlock,
        open_via_vendor,
        seal,
        tle_decrypt,
        tle_encrypt,
    )
    AVAILABLE = True
except ImportError as exc:
    _IMPORT_ERROR = exc


def require() -> None:
    """Raise with an install hint if zkpox's optional deps aren't present.

    Production entry points (raptor_zkpox.main) call this so a missing
    dep surfaces as a single actionable line instead of an import traceback.
    """
    if not AVAILABLE:
        raise RuntimeError(
            "zkpox needs cryptography and cbor2. "
            "pip install cryptography==45.0.4 cbor2==6.0.1 "
            f"(or uncomment them in requirements.txt). {_IMPORT_ERROR}"
        )

__all__ = [
    "AgeKeypair",
    "AnchorError",
    "BUNDLE_VERSION",
    "Bundle",
    "Ed25519Keypair",
    "Envelope",
    "EnvelopeError",
    "EnvelopeRoundTripError",
    "EnvelopeToolError",
    "HarnessRef",
    "Proof",
    "Researcher",
    "Target",
    "Timestamp",
    "VendorEnvelope",
    "Vulnerability",
    "aes_decrypt",
    "aes_encrypt",
    "age_decrypt_with",
    "age_encrypt_to",
    "anchor_bundle",
    "bundle_hash_pre_timestamp",
    "confirm_anchor_matches",
    "fetch_log_entry",
    "from_cbor",
    "gen_age_keypair",
    "gen_ed25519_keypair",
    "load_ed25519_secret_pem",
    "open_via_tlock",
    "open_via_vendor",
    "rekor_url",
    "seal",
    "sha256_bytes",
    "sha256_file",
    "tle_decrypt",
    "tle_encrypt",
    "to_cbor",
    "vendor_envelope_from",
    "with_timestamp",
]
