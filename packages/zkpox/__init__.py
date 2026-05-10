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

from .bundle import (
    BUNDLE_VERSION,
    Bundle,
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

__all__ = [
    "AgeKeypair",
    "BUNDLE_VERSION",
    "Bundle",
    "Envelope",
    "EnvelopeError",
    "EnvelopeRoundTripError",
    "EnvelopeToolError",
    "HarnessRef",
    "Proof",
    "Researcher",
    "Target",
    "VendorEnvelope",
    "Vulnerability",
    "aes_decrypt",
    "aes_encrypt",
    "age_decrypt_with",
    "age_encrypt_to",
    "from_cbor",
    "gen_age_keypair",
    "open_via_tlock",
    "open_via_vendor",
    "seal",
    "sha256_bytes",
    "sha256_file",
    "tle_decrypt",
    "tle_encrypt",
    "to_cbor",
    "vendor_envelope_from",
]
