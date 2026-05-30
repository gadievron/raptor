//! `zkpox-verify` — standalone CBOR bundle verifier.
//!
//! Two build modes, gated by Cargo features:
//!
//! - **`full-verify`** (default): the structural pass below plus the
//!   Phase 1.5.2 SP1 STARK verification. The verifier embeds the
//!   same guest ELF the prover uses (via ``include_elf!``), re-derives
//!   the verifying key, hashes it, compares against the bundle's
//!   ``proof.verifier_key_hash``, hashes the embedded ELF and
//!   compares against ``harness.hash``, then runs sp1-sdk's
//!   ``client.verify`` on the bundle's ``proof.bytes``. Tampering
//!   with any of the three (proof, vkey hash, harness hash) produces
//!   a clean non-zero exit. The trust root is the verifier binary
//!   itself — see ``docs/proposals/zkpox-phase-1.5.x.md`` §7 (Option A).
//!
//! - **`structural`** (``--no-default-features --features structural``):
//!   the 1.3/1.5 behaviour — CBOR shape, envelope fingerprint, version
//!   binding, and a deferred ``stark_verification`` field. Used by
//!   CI's fast tier and any environment without the SP1 build chain.
//!
//! Structural checks that BOTH features run:
//!   - Bundle parses as CBOR with the expected top-level fields.
//!   - `version` matches a supported value (``zkpox-1.0`` or
//!     ``zkpox-1.1``).
//!   - `vendor_envelope.vendor_pubkey_fingerprint` is the sha256 of
//!     `vendor_envelope.vendor_pubkey`.
//!   - `proof.bytes` is non-empty and `proof.verifier_key_hash` is a
//!     well-formed sha256 marker.
//!
//! Still deferred at Phase 1.5.2 (lands in 1.5.3):
//!   - The Sigstore Rekor inclusion proof (Merkle path + STH signature).
//!   - The vendor envelope round-trip (the verifier doesn't have the
//!     vendor's age secret key; it can only check the wrapping is
//!     well-formed, which is what the structural pass does).

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Bundle versions this verifier accepts. ``zkpox-1.0`` is the
/// Phase 1.5 (placeholder-hashes) shape; ``zkpox-1.1`` adds the
/// ``vulnerability.gadget_code_hash`` field from Phase 1.5.1. The
/// verifier reads both — strict-mode enforcement of the new field
/// lands in Phase 1.5.4.
const SUPPORTED_VERSIONS: &[&str] = &["zkpox-1.0", "zkpox-1.1"];

/// The current envelope scheme; bundles whose `vendor_envelope.scheme`
/// starts with anything else MUST be rejected by a v1 verifier. Without
/// this check a future v2 envelope could be replayed under v1 framing
/// (the AAD mismatch would surface as an AES-GCM authentication failure
/// but only on decrypt — too late for the structural pass).
const SUPPORTED_ENVELOPE_PREFIX: &str = "zkpox-aes256gcm+age+tlock-drand-quicknet/v1";
/// "No envelope" sentinel — Phase 1.5 `cmd_prove` writes this when the
/// caller omits `--vendor-pubkey`. Structurally distinct from a real v1
/// envelope and from a future v2.
const SENTINEL_ENVELOPE_NONE: &str = "zkpox-none/v1";

#[derive(Parser, Debug)]
#[command(about = "Verify a zkpox CBOR disclosure bundle (structural; STARK verification is Phase 1.5.x)")]
struct Args {
    /// Path to the CBOR bundle.
    bundle: PathBuf,

    /// Print JSON output (machine-readable) instead of human-readable.
    #[arg(long)]
    json: bool,

    /// Exit non-zero on any DEFERRED check (STARK, Rekor inclusion).
    /// Default off in Phase 1.5; becomes the default once 1.5.x lands
    /// the deferred checks. Use this in CI / automated disclosure
    /// pipelines so a structural-only pass is not silently treated as
    /// "the bundle is verified."
    #[arg(long)]
    strict: bool,
}

#[derive(Serialize)]
struct Summary {
    version: String,
    // Beta-feature marker. The Python producer always writes True;
    // an absent field is treated as True so a future post-stable
    // verifier looking at an old bundle doesn't silently drop the
    // marker. See bundle.py for the producer-side rationale.
    experimental: bool,
    target_kind: String,
    target_hash: String,
    target_url: Option<String>,
    vulnerability_class: String,
    gadget_id: String,
    gadget_id_hash: String,
    // Phase 1.5.1's gadget_code_hash field; absent in zkpox-1.0
    // bundles, present in 1.1+. Surfaced for transparency even though
    // the verifier doesn't independently recompute it (the gadget
    // file manifest lives in the RAPTOR Python tree, not the
    // standalone verifier's scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    gadget_code_hash: Option<String>,
    proof_system: String,
    proof_bytes_len: usize,
    verifier_key_hash: String,
    // Phase 1.5.2: ``harness.hash`` is now load-bearing under
    // ``full-verify`` (compared to sha256 of the embedded GUEST_ELF).
    harness_hash: String,
    envelope_scheme: String,
    envelope_aes_blob_len: usize,
    envelope_ct_k_age_len: usize,
    envelope_ct_k_tlock_len: usize,
    drand_round_min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<TimestampSummary>,
    structural_checks_passed: bool,
    // Phase 1.5.2: ``String`` so a ``full-verify`` build can surface
    // dynamic OK / FAIL messages (e.g. with the verifier's expected
    // vkey hash). The structural-only build still emits a fixed
    // ``DEFERRED ...`` string here.
    stark_verification: String,
    rekor_inclusion_verification: String,
}

#[derive(Serialize)]
struct TimestampSummary {
    rekor_log_index: i64,
    rekor_log_id: String,
    integrated_time: i64,
    entry_uuid: String,
    inclusion_proof_root_hash: String,
    inclusion_proof_tree_size: i64,
    inclusion_proof_path_len: usize,
}

// ---------------------------------------------------------------------------
// Phase 1.5.2 — full-verify backend (sp1-sdk)
// ---------------------------------------------------------------------------
//
// All sp1-sdk interaction is sequestered here so the structural-only
// build doesn't pay the compile cost. The module exposes three pure
// entry points the rest of ``inspect`` calls when the feature is on:
//
//   - ``guest_elf_hash()``     → sha256(GUEST_ELF) bare hex
//   - ``verifying_key_hash()`` → ``HashableKey::bytes32`` (sans 0x)
//   - ``verify_proof(bytes)``  → bincode-deserialise + sp1-sdk verify
//
// The verifier's trust root under ``full-verify`` is the embedded
// guest ELF (see docs/proposals/zkpox-phase-1.5.x.md §7 Option A):
// the same ``include_elf!("zkpox-guest")`` macro the prover uses,
// resolved via the verifier's build.rs (Phase 1.5.2 §2) → sp1-build
// → the guest crate sitting next to the verifier in the workspace.

#[cfg(feature = "full-verify")]
mod full_verify {
    use anyhow::{anyhow, Result};
    use sha2::{Digest, Sha256};
    use sp1_sdk::{
        blocking::{Prover, ProverClient},
        include_elf, Elf, HashableKey, SP1ProofWithPublicValues,
    };

    /// Same artefact the prover embeds, resolved by build.rs +
    /// sp1-build. Hashing it gives the verifier's expected
    /// ``harness.hash``; setting up against it derives the expected
    /// verifying key.
    const GUEST_ELF: Elf = include_elf!("zkpox-guest");

    /// sha256 of the embedded guest ELF — bare hex (no ``sha256:``
    /// prefix). Compared against the bundle's ``harness.hash`` after
    /// the ``sha256:`` prefix is stripped.
    pub fn guest_elf_hash() -> String {
        format!("{:x}", Sha256::digest(&GUEST_ELF[..]))
    }

    /// Verifying-key digest in the same form the prover wrote: the
    /// ``HashableKey::bytes32`` value with the ``0x`` prefix stripped.
    /// Setup is fast (~ms) — it doesn't run the proving stack, just
    /// derives the vkey from the ELF.
    pub fn verifying_key_hash() -> Result<String> {
        let client = ProverClient::from_env();
        let pk = client
            .setup(GUEST_ELF)
            .map_err(|e| anyhow!("sp1-sdk setup against embedded GUEST_ELF failed: {e:?}"))?;
        Ok(pk
            .verifying_key()
            .bytes32()
            .trim_start_matches("0x")
            .to_string())
    }

    /// Deserialise the bundle's ``proof.bytes`` (bincode, matches what
    /// ``SP1ProofWithPublicValues::save`` writes) and run sp1-sdk's
    /// ``verify`` against the embedded ELF's verifying key. Returns
    /// ``Ok(())`` iff the STARK proof verifies.
    pub fn verify_proof(proof_bytes: &[u8]) -> Result<()> {
        let proof: SP1ProofWithPublicValues = bincode::deserialize(proof_bytes)
            .map_err(|e| anyhow!("failed to deserialise proof.bytes (bincode): {e}"))?;
        let client = ProverClient::from_env();
        let pk = client
            .setup(GUEST_ELF)
            .map_err(|e| anyhow!("sp1-sdk setup against embedded GUEST_ELF failed: {e:?}"))?;
        client
            .verify(&proof, pk.verifying_key(), None)
            .map_err(|e| anyhow!("STARK verification failed: {e:?}"))
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let blob = std::fs::read(&args.bundle)
        .with_context(|| format!("reading bundle {}", args.bundle.display()))?;

    // Parse top-level value.
    let value: ciborium::Value =
        ciborium::de::from_reader(blob.as_slice()).context("parsing CBOR")?;
    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => bail!("bundle is not a CBOR map"),
    };

    let summary = inspect(&map)?;

    if args.json {
        let out = serde_json::to_string_pretty(&summary)?;
        println!("{out}");
    } else {
        print_human(&summary);
        if summary.experimental {
            // Always-on beta marker — fires even with --strict so an
            // operator running a strict pipeline still sees "this
            // bundle was produced by an experimental version of the
            // toolchain." Suppressed in --json so automated consumers
            // parse the `experimental` field instead.
            eprintln!();
            eprintln!(
                "  EXPERIMENTAL BUNDLE — produced by Phase 1.5 (beta) zkpox."
            );
            eprintln!(
                "  Bundle format and verifier semantics are subject to change."
            );
            eprintln!(
                "  Do NOT use this bundle for real CVE disclosure."
            );
            eprintln!(
                "  Scope: docs/zkpox-scope.md"
            );
        }
        if !args.strict {
            // Loud banner so a casual reader doesn't mistake exit 0
            // for "the bundle is verified." Suppressed in --json so
            // automated consumers parse the verdict fields instead.
            eprintln!();
            eprintln!(
                "  MODE: structural-only — STARK proof and Rekor inclusion checks are DEFERRED."
            );
            eprintln!(
                "        Pass --strict to fail on any deferred check."
            );
        }
    }

    if !summary.structural_checks_passed {
        std::process::exit(1);
    }
    // --strict treats any DEFERRED check as a hard failure. Phase 1.5
    // ships with both STARK and Rekor inclusion deferred; in 1.5.x the
    // strict path narrows as each lands.
    if args.strict {
        let stark_done = !summary.stark_verification.starts_with("DEFERRED");
        let rekor_done = summary.timestamp.is_none()
            || !summary.rekor_inclusion_verification.starts_with("DEFERRED");
        if !stark_done || !rekor_done {
            eprintln!();
            eprintln!("FAIL (--strict): deferred checks are present:");
            if !stark_done {
                eprintln!("  - stark_verification: {}", summary.stark_verification);
            }
            if !rekor_done {
                eprintln!(
                    "  - rekor_inclusion_verification: {}",
                    summary.rekor_inclusion_verification,
                );
            }
            std::process::exit(2);
        }
    }
    Ok(())
}

fn inspect(map: &[(ciborium::Value, ciborium::Value)]) -> Result<Summary> {
    let version = string_at(map, "version")?;
    if !SUPPORTED_VERSIONS.contains(&version.as_str()) {
        bail!(
            "unsupported bundle version: got {version:?}, expected one of {SUPPORTED_VERSIONS:?}",
        );
    }

    let target = submap(map, "target")?;
    let vuln = submap(map, "vulnerability")?;
    let proof = submap(map, "proof")?;
    let envelope = submap(map, "vendor_envelope")?;
    // ``harness`` is the existing structural section the verifier
    // never read before Phase 1.5.2 — it's where ``harness.hash``
    // lives (and what ``full-verify`` checks against the embedded
    // guest ELF).
    let harness = submap(map, "harness")?;

    let target_hash = string_at(target, "hash")?;
    let proof_bytes = bytes_at(proof, "bytes")?;
    let verifier_key_hash = string_at(proof, "verifier_key_hash")?;
    let harness_hash = string_at(harness, "hash")?;
    let envelope_scheme = string_at(envelope, "scheme")?;
    let aes_blob = bytes_at(envelope, "aes_blob")?;
    let ct_age = bytes_at(envelope, "ct_K_age")?;
    let ct_tlock = bytes_at(envelope, "ct_K_tlock")?;
    let vendor_pubkey = string_at(envelope, "vendor_pubkey")?;
    let vendor_fingerprint = string_at(envelope, "vendor_pubkey_fingerprint")?;

    // Structural check: vendor_pubkey_fingerprint == sha256(vendor_pubkey).
    let expected_fp = sha256_hex(vendor_pubkey.as_bytes());
    let mut checks_passed = true;
    if vendor_fingerprint != format!("sha256:{expected_fp}") {
        eprintln!(
            "FAIL: vendor_pubkey_fingerprint {vendor_fingerprint:?} != sha256(vendor_pubkey) (computed sha256:{expected_fp})"
        );
        checks_passed = false;
    }

    // Version-binding check: envelope scheme must match a scheme this
    // verifier understands for the current bundle version. Otherwise a
    // future v2 envelope could be replayed under v1 framing — the AAD
    // mismatch would only surface on the decrypt path, far too late for
    // the structural pass to catch.
    let envelope_ok = envelope_scheme.starts_with(SUPPORTED_ENVELOPE_PREFIX)
        || envelope_scheme == SENTINEL_ENVELOPE_NONE;
    if !envelope_ok {
        eprintln!(
            "FAIL: vendor_envelope.scheme {envelope_scheme:?} not supported by this verifier (expected prefix {SUPPORTED_ENVELOPE_PREFIX:?} or sentinel {SENTINEL_ENVELOPE_NONE:?})"
        );
        checks_passed = false;
    }

    // Sanity: proof bytes non-empty.
    if proof_bytes.is_empty() {
        eprintln!("FAIL: proof.bytes is empty");
        checks_passed = false;
    }
    // Sanity: verifier_key_hash starts with the sha256: prefix.
    if !verifier_key_hash.starts_with("sha256:") {
        eprintln!("FAIL: proof.verifier_key_hash missing sha256: prefix");
        checks_passed = false;
    }

    // Optional Phase 1.4 timestamp field. Structural read only; full
    // Merkle inclusion verification + Rekor STH validation is 1.4.x.
    let timestamp = optional_submap(map, "timestamp")
        .map(|ts_map| -> Result<TimestampSummary> {
            Ok(TimestampSummary {
                rekor_log_index: required_int_at(ts_map, "rekor_log_index")?,
                rekor_log_id: string_at(ts_map, "rekor_log_id")?,
                integrated_time: required_int_at(ts_map, "integrated_time")?,
                entry_uuid: string_at(ts_map, "entry_uuid")?,
                inclusion_proof_root_hash: string_at(ts_map, "inclusion_proof_root_hash")?,
                inclusion_proof_tree_size: required_int_at(ts_map, "inclusion_proof_tree_size")?,
                inclusion_proof_path_len: count_strings_at(ts_map, "inclusion_proof_hashes"),
            })
        })
        .transpose()?;

    // experimental: default True on absent (mirrors producer-side default).
    let experimental = optional_bool_at(map, "experimental").unwrap_or(true);

    // ----- Phase 1.5.2 — STARK verification (full-verify only) ------
    //
    // The structural checks above produced ``checks_passed``; the
    // ``full-verify`` build now additionally:
    //   1. Hashes the embedded guest ELF and compares to
    //      ``harness.hash`` (rejects a bundle that claims a different
    //      harness than this verifier supports).
    //   2. Derives the verifying key from the embedded ELF, hashes
    //      it, and compares to ``proof.verifier_key_hash`` (rejects
    //      a bundle whose proof was made against a different vkey).
    //   3. Bincode-deserialises ``proof.bytes`` and runs the SP1 SDK
    //      verify (the actual cryptographic check).
    // Any of the three failing turns ``stark_verification`` into a
    // ``FAIL (reason)`` string and clears ``structural_checks_passed``.
    // ``--strict`` (in main) then exits non-zero.
    let stark_verification = stark_verification_outcome(
        &harness_hash,
        &verifier_key_hash,
        proof_bytes,
        &mut checks_passed,
    );

    Ok(Summary {
        version,
        experimental,
        target_kind: string_at(target, "kind")?,
        target_hash,
        target_url: optional_string_at(target, "url"),
        vulnerability_class: string_at(vuln, "class")?,
        gadget_id: string_at(vuln, "gadget_id")?,
        gadget_id_hash: string_at(vuln, "gadget_id_hash")?,
        gadget_code_hash: optional_string_at(vuln, "gadget_code_hash"),
        proof_system: string_at(proof, "system")?,
        proof_bytes_len: proof_bytes.len(),
        verifier_key_hash,
        harness_hash,
        envelope_scheme,
        envelope_aes_blob_len: aes_blob.len(),
        envelope_ct_k_age_len: ct_age.len(),
        envelope_ct_k_tlock_len: ct_tlock.len(),
        drand_round_min: optional_int_at(envelope, "drand_round_min"),
        timestamp,
        structural_checks_passed: checks_passed,
        stark_verification,
        rekor_inclusion_verification:
            "DEFERRED — Phase 1.5.3 wires Merkle path + STH validation".to_string(),
    })
}

/// Phase 1.5.2 STARK-verification dispatch. Returns the string that
/// goes into ``summary.stark_verification``; updates
/// ``checks_passed`` (cleared on any FAIL so non-strict mode still
/// exits non-zero — a structurally-OK bundle whose vkey/harness/proof
/// fails is NOT a pass).
///
/// ``--no-default-features --features structural`` collapses this to
/// the original ``DEFERRED`` string; the body runs only under the
/// default ``full-verify`` feature.
#[cfg(feature = "full-verify")]
fn stark_verification_outcome(
    harness_hash: &str,
    verifier_key_hash: &str,
    proof_bytes: &[u8],
    checks_passed: &mut bool,
) -> String {
    // 1. ``harness.hash`` MUST match the embedded ELF.
    let expected_elf = full_verify::guest_elf_hash();
    let supplied_elf = harness_hash.strip_prefix("sha256:").unwrap_or(harness_hash);
    if supplied_elf != expected_elf {
        *checks_passed = false;
        return format!(
            "FAIL: harness.hash sha256:{supplied_elf} does not match the \
             verifier's embedded guest ELF (sha256:{expected_elf}). The \
             bundle was produced against a different harness; verify \
             with the verifier matching the bundle's harness version.",
        );
    }
    // 2. ``proof.verifier_key_hash`` MUST match the vkey derived from
    //    the embedded ELF.
    let expected_vk = match full_verify::verifying_key_hash() {
        Ok(s) => s,
        Err(e) => {
            *checks_passed = false;
            return format!("FAIL: could not derive verifying key from embedded ELF: {e}");
        }
    };
    let supplied_vk = verifier_key_hash
        .strip_prefix("sha256:")
        .unwrap_or(verifier_key_hash);
    if supplied_vk != expected_vk {
        *checks_passed = false;
        return format!(
            "FAIL: proof.verifier_key_hash sha256:{supplied_vk} does \
             not match the verifier's derived vkey (sha256:{expected_vk}).",
        );
    }
    // 3. The actual cryptographic STARK verification.
    if let Err(e) = full_verify::verify_proof(proof_bytes) {
        *checks_passed = false;
        return format!("FAIL: {e}");
    }
    format!(
        "OK — sp1-sdk verified against embedded guest ELF (sha256:{expected_elf}, \
         vkey sha256:{expected_vk})",
    )
}

#[cfg(not(feature = "full-verify"))]
fn stark_verification_outcome(
    _harness_hash: &str,
    _verifier_key_hash: &str,
    _proof_bytes: &[u8],
    _checks_passed: &mut bool,
) -> String {
    // Structural-only build: no sp1-sdk linked, no embedded ELF. The
    // bundle's proof / harness hashes are reported back but not
    // independently checked. ``--strict`` (main) treats the DEFERRED
    // prefix as a hard failure.
    "DEFERRED — verifier built with --features structural; STARK check not run".to_string()
}

fn print_human(s: &Summary) {
    println!(
        "zkpox bundle: version {} ({}){}",
        s.version,
        if s.structural_checks_passed { "OK" } else { "INVALID" },
        if s.experimental { " [EXPERIMENTAL]" } else { "" },
    );
    println!("  target:        {} hash={}", s.target_kind, s.target_hash);
    if let Some(url) = &s.target_url {
        println!("                 {url}");
    }
    println!("  vulnerability: {} :: {}", s.vulnerability_class, s.gadget_id);
    println!("                 gadget_id_hash   {}", s.gadget_id_hash);
    if let Some(g) = &s.gadget_code_hash {
        println!("                 gadget_code_hash {g}");
    }
    println!("  proof:         {} ({} bytes)", s.proof_system, s.proof_bytes_len);
    println!("                 vk      {}", s.verifier_key_hash);
    println!("                 harness {}", s.harness_hash);
    println!("  envelope:      {}", s.envelope_scheme);
    println!(
        "                 aes={}B  age={}B  tlock={}B  round_min={:?}",
        s.envelope_aes_blob_len,
        s.envelope_ct_k_age_len,
        s.envelope_ct_k_tlock_len,
        s.drand_round_min,
    );
    println!("  STARK:         {}", s.stark_verification);
    if let Some(ts) = &s.timestamp {
        println!("  rekor anchor:  log_index={} log_id={}", ts.rekor_log_index, ts.rekor_log_id);
        println!(
            "                 entry={}  integrated={}  tree_size={}  path_len={}",
            ts.entry_uuid,
            ts.integrated_time,
            ts.inclusion_proof_tree_size,
            ts.inclusion_proof_path_len,
        );
        println!("  rekor incl.:   {}", s.rekor_inclusion_verification);
    } else {
        println!("  rekor anchor:  (none)");
    }
}

// ---------- ciborium accessor helpers ---------- //

fn submap<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<&'a [(ciborium::Value, ciborium::Value)]> {
    let v = lookup(map, key)?;
    match v {
        ciborium::Value::Map(m) => Ok(m.as_slice()),
        _ => Err(anyhow!("field {key:?} is not a map")),
    }
}

fn string_at(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Result<String> {
    match lookup(map, key)? {
        ciborium::Value::Text(s) => Ok(s.clone()),
        _ => Err(anyhow!("field {key:?} is not a string")),
    }
}

fn optional_string_at(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<String> {
    for (k, v) in map {
        if let ciborium::Value::Text(t) = k {
            if t == key {
                if let ciborium::Value::Text(s) = v {
                    return Some(s.clone());
                }
                return None;
            }
        }
    }
    None
}

fn optional_bool_at(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<bool> {
    for (k, v) in map {
        if let ciborium::Value::Text(t) = k {
            if t == key {
                if let ciborium::Value::Bool(b) = v {
                    return Some(*b);
                }
                return None;
            }
        }
    }
    None
}

fn optional_int_at(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<i64> {
    for (k, v) in map {
        if let ciborium::Value::Text(t) = k {
            if t == key {
                if let ciborium::Value::Integer(i) = v {
                    return i64::try_from(*i).ok();
                }
                return None;
            }
        }
    }
    None
}

fn bytes_at<'a>(map: &'a [(ciborium::Value, ciborium::Value)], key: &str) -> Result<&'a [u8]> {
    match lookup(map, key)? {
        ciborium::Value::Bytes(b) => Ok(b.as_slice()),
        _ => Err(anyhow!("field {key:?} is not bytes")),
    }
}

fn optional_submap<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [(ciborium::Value, ciborium::Value)]> {
    for (k, v) in map {
        if let ciborium::Value::Text(t) = k {
            if t == key {
                if let ciborium::Value::Map(m) = v {
                    return Some(m.as_slice());
                }
                return None;
            }
        }
    }
    None
}

fn required_int_at(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<i64> {
    match lookup(map, key)? {
        ciborium::Value::Integer(i) => i64::try_from(*i)
            .map_err(|_| anyhow!("field {key:?} integer does not fit i64")),
        _ => Err(anyhow!("field {key:?} is not an integer")),
    }
}

fn count_strings_at(
    map: &[(ciborium::Value, ciborium::Value)],
    key: &str,
) -> usize {
    for (k, v) in map {
        if let ciborium::Value::Text(t) = k {
            if t == key {
                if let ciborium::Value::Array(items) = v {
                    return items.len();
                }
            }
        }
    }
    0
}

fn lookup<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Result<&'a ciborium::Value> {
    for (k, v) in map {
        if let ciborium::Value::Text(t) = k {
            if t == key {
                return Ok(v);
            }
        }
    }
    Err(anyhow!("missing required field: {key:?}"))
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
