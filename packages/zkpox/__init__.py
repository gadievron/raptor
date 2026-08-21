"""ZKPoX — Zero-Knowledge Proof of Exploit (tiered proving).

Downstream consumer of the ``core.witness`` substrate. Proves the
statement "I possess an input that makes binary H exhibit outcome
O" *without revealing the input*. The verifier learns a working,
reproducing exploit exists; they do not learn the exploit bytes.
Use cases: coordinated disclosure (prove capability before a patch
lands), bug-bounty triage, escrowing exploit existence.

## Tiers

Proving is staged so it degrades gracefully by dependency weight.
Each tier is a strictly stronger claim than the one below; each
runs when only its own (and lower tiers') dependencies are present.

  Tier 0/1 — attestation   "I assert W produced O against H",
                           carried by provenance hashes. No deps,
                           no crypto. IMPLEMENTED HERE.
  Tier 1.5* — synthetic    Dry-run of the proving pipeline with no
                           real prover / no optional deps. Plumbing
                           proof only. (not yet implemented)
  Tier 1.5 — reproduction  Re-execute W against H N times in the
                           sandbox; confirm O reproduces. Sandbox
                           dep only; reproducibility, not ZK.
                           IMPLEMENTED HERE (on request).
  Tier 2 — RISC-V          Execute the target in a RISC-V emulator
                           for a deterministic trace. Needs a RISC-V
                           toolchain. (not yet implemented)
  Tier 3 — SP1             Full STARK proof via the SP1 zkVM: the ZK
                           statement above, input hidden. Heavy
                           proving stack. (not yet implemented)

## Trigger model (free vs on-request)

Mirrors the witness arc's cost-based split (witness recording is
default-on because cheap; running code is opt-in):

  - FREE: eligibility classification. Pure field-reading — surfaced
    in end-of-run summaries ("N of M witnesses are ZKPoX-eligible")
    with no flag, no execution, no artifacts.
  - ON REQUEST: bundle assembly (produces persistent prover-ready
    artifacts), reproduction (Tier 1.5 — N× sandbox execution), and
    everything above.

## This package today

Everything achievable *without* the heavyweight proving stack —
Tiers 0/1 and 1.5:

  * :mod:`packages.zkpox.eligibility` — candidacy classification
    (free) + the free end-of-run summary.
  * :mod:`packages.zkpox.bundle` — prover-ready bundle assembly
    (on request); the stable hand-off shape every higher tier
    consumes.
  * :mod:`packages.zkpox.reproduce` — Tier 1.5 native reproduction
    (on request): re-run the witness N times, confirm the outcome
    reproduces, fold the result into the bundle.

The point: the real ZK tiers (2 RISC-V, 3 SP1) pull a large
dependency chain. An operator who wants them installs those deps
themselves — but they shouldn't have to install anything to learn
*whether it's worth it*. The free eligibility surfacing is that
pre-flight signal: "you have N witnesses that could be proven" (or
"zero — don't bother"). Tiers 1.5 / 2 / 3 layer on the bundle shape
defined here once the operator opts in.
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

# ---------------------------------------------------------------------------
# Tier 2/3 lazy re-exports (PEP 562 ``__getattr__``)
# ---------------------------------------------------------------------------
#
# The CBOR disclosure schema (``disclosure``), Sigstore anchoring
# (``anchor``), and the layered envelope (``envelope``) are the heavy
# Tier 2/3 surface: they import ``cbor2`` / ``cryptography`` at module
# load. ``cbor2`` is an OPTIONAL dependency (commented out in
# requirements.txt), so importing them eagerly here would break the
# dependency-free Tier 0/1 import contract — and the
# ``test_zkpox_import_pulls_no_heavy_deps`` invariant. PEP 562 defers
# each submodule import until a caller actually touches one of these
# names (``zkpox.Bundle``, ``zkpox.anchor_bundle``, ``zkpox.seal``, …),
# keeping ``import packages.zkpox`` cheap while preserving the
# top-level access pattern that ``raptor_zkpox.py`` and the tests use.
_LAZY_EXPORTS: dict[str, str] = {
    # CBOR disclosure schema — packages.zkpox.disclosure
    "DisclosureBundle": "disclosure",
    "disclosure_from_manifest": "disclosure",
    "manifest_target_bare_hex": "disclosure",
    "target_hash_matches": "disclosure",
    "BUNDLE_VERSION": "disclosure",
    "ENVELOPE_SCHEME": "disclosure",
    "Target": "disclosure",
    "Vulnerability": "disclosure",
    "Proof": "disclosure",
    "HarnessRef": "disclosure",
    "VendorEnvelope": "disclosure",
    "Researcher": "disclosure",
    "Timestamp": "disclosure",
    "sha256_file": "disclosure",
    "sha256_bytes": "disclosure",
    "vendor_envelope_from": "disclosure",
    "to_cbor": "disclosure",
    "from_cbor": "disclosure",
    "bundle_hash_pre_timestamp": "disclosure",
    "with_timestamp": "disclosure",
    # Sigstore Rekor anchoring — packages.zkpox.anchor
    "Ed25519Keypair": "anchor",
    "AnchorError": "anchor",
    "anchor_bundle": "anchor",
    "fetch_log_entry": "anchor",
    "confirm_anchor_matches": "anchor",
    "gen_ed25519_keypair": "anchor",
    "load_ed25519_secret_pem": "anchor",
    # Phase 1.5.3 Rekor verification primitives
    "verify_inclusion_proof": "anchor",
    "verify_set": "anchor",
    "canonical_set_payload": "anchor",
    "InclusionProofError": "anchor",
    "SignatureError": "anchor",
    "LEGACY_V1_REKOR_URL": "anchor",
    # Layered envelope — packages.zkpox.envelope
    "Envelope": "envelope",
    "AgeKeypair": "envelope",
    "EnvelopeError": "envelope",
    "EnvelopeToolError": "envelope",
    "EnvelopeRoundTripError": "envelope",
    "seal": "envelope",
    "open_via_vendor": "envelope",
    "open_via_tlock": "envelope",
    "gen_age_keypair": "envelope",
    "age_encrypt_to": "envelope",
    "age_decrypt_with": "envelope",
    "tle_encrypt": "envelope",
    "tle_decrypt": "envelope",
    "aes_encrypt": "envelope",
    "aes_decrypt": "envelope",
}


def __getattr__(name: str):
    submodule = _LAZY_EXPORTS.get(name)
    if submodule is None:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        )
    import importlib

    mod = importlib.import_module(f"{__name__}.{submodule}")
    return getattr(mod, name)


def __dir__() -> list:
    return sorted([*globals(), *_LAZY_EXPORTS])


__all__ = [
    "ZKPoXEligibility",
    "is_zkpox_eligible",
    "summarize_eligibility",
    "render_eligibility_summary",
    "render_run_eligibility",
    "ZKPoXBundle",
    "ZKPoXBundleError",
    "assemble_bundle",
    "write_bundle",
    "render_bundle",
    "ReproductionResult",
    "reproduce_witness",
    "attach_reproduction",
    "ProvingStackUnavailable",
    "proving_stack_available",
    "require_proving_stack",
    # Tier 2/3 lazy re-exports (see _LAZY_EXPORTS / __getattr__)
    *sorted(_LAZY_EXPORTS),
]
