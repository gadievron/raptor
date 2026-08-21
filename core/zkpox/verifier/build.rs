//! Phase 1.5.2 — feature-gated guest build for the verifier.
//!
//! When ``full-verify`` is enabled, the verifier embeds the same guest
//! ELF the prover does (via ``include_elf!`` from sp1-sdk). That
//! requires the guest crate to be compiled by sp1-build first, which
//! is what this script triggers. The structural-only feature path
//! does not embed the ELF and so doesn't need the build step —
//! cargo sets ``CARGO_FEATURE_FULL_VERIFY=1`` exactly when the
//! feature is on, so the keyed-on check skips the SP1 build chain
//! entirely for CI fast-tier builds.

fn main() {
    if std::env::var("CARGO_FEATURE_FULL_VERIFY").is_ok() {
        sp1_build::build_program_with_args("../guest", Default::default());
    }
}
