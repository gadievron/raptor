"""ZKPoX witness evidence and optional curated-source SP1 disclosures.

Generic capture/storage lives in core.witness. This package provides free
eligibility, private Tier 0/1 bundle assembly and sandboxed native reproduction.
The optional native/ workspace and cli module add SP1 6.5.0 Groth16 disclosures
for three exact curated C sources. Arbitrary native binaries remain supported
by reproduction, not by this guest's cryptographic statement.

See README.md and docs/zkpox-scope.md for the statement, build requirements,
encrypted-delivery checks and optional pinned-root Rekor v2 inclusion policy.
Lightweight witness operations remain usable without optional crypto packages
or a proving toolchain. CLI operations import optional dependencies lazily.
"""

from packages.zkpox.bundle import (
    ZKPoXBundle,
    ZKPoXBundleError,
    assemble_bundle,
    render_bundle,
    write_bundle,
)
from packages.zkpox.eligibility import (
    ZKPoXEligibility,
    is_zkpox_eligible,
    render_eligibility_summary,
    summarize_eligibility,
)
from packages.zkpox.proving_deps import (
    ProvingStackUnavailable,
    proving_stack_available,
    require_proving_stack,
)
from packages.zkpox.reproduce import (
    ReproductionResult,
    attach_reproduction,
    reproduce_witness,
)
from packages.zkpox.surfacing import render_run_eligibility

__all__ = [
    "ProvingStackUnavailable",
    "ReproductionResult",
    "ZKPoXBundle",
    "ZKPoXBundleError",
    "ZKPoXEligibility",
    "assemble_bundle",
    "attach_reproduction",
    "is_zkpox_eligible",
    "proving_stack_available",
    "render_bundle",
    "render_eligibility_summary",
    "render_run_eligibility",
    "reproduce_witness",
    "require_proving_stack",
    "summarize_eligibility",
    "write_bundle",
    "Bundle",
    "BUNDLE_VERSION",
    "DisclosureBundle",
    "Envelope",
    "HarnessRef",
    "InclusionProofError",
    "Proof",
    "SignatureError",
    "Target",
    "Vulnerability",
    "anchor_bundle",
    "bundle_hash_pre_timestamp",
    "canonical_set_payload",
    "confirm_anchor_matches",
    "gen_ed25519_keypair",
    "sha256_bytes",
    "vendor_envelope_from",
    "verify_inclusion_proof",
    "verify_set",
]

# Tier 2/3 disclosure bundle + Sigstore anchor — optional deps
# (cbor2, cryptography). Re-exported so tests can import from the
# package root; guarded so Tier 0/1 callers aren't broken.
try:
    from packages.zkpox.disclosure import (
        BUNDLE_VERSION,
        DisclosureBundle,
        HarnessRef,
        Proof,
        Target,
        Vulnerability,
        sha256_bytes,
        vendor_envelope_from,
    )
    # Convenience alias — test_anchor.py and early code use "Bundle"
    Bundle = DisclosureBundle
except ImportError:
    pass

try:
    from packages.zkpox.anchor import (
        InclusionProofError,
        SignatureError,
        anchor_bundle,
        bundle_hash_pre_timestamp,
        canonical_set_payload,
        confirm_anchor_matches,
        gen_ed25519_keypair,
        verify_inclusion_proof,
        verify_set,
    )
except ImportError:
    pass

try:
    from packages.zkpox.envelope import Envelope
except ImportError:
    pass
