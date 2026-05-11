//! `zkpox-prove` — native CLI that loads a witness, runs the SP1 guest
//! in execute or prove mode against target #1, and emits a JSON record
//! with both the `crash_only` and `oob_write` gadgets' verdicts (one
//! invocation yields both — see core/zkpox/guest/src/main.rs).
//!
//! Usage:
//!   zkpox-prove --witness <FILE> --execute
//!   zkpox-prove --witness <FILE> --prove [--wrap=core|groth16]
//!
//! Wrap modes:
//!   core    (default) — raw STARK proof, ~2.65 MB. Verifier-friendly
//!                       in-process; impractical to ship in a CBOR bundle.
//!   groth16          — STARK + Groth16 wrap, ~256 B. Suitable for the
//!                       disclosure bundle. Adds ~5–10 min on the first
//!                       invocation (downloads SP1's ~few-GB Groth16
//!                       circuit artifacts) and ~1–3 min per proof on
//!                       CPU thereafter.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const GUEST_ELF: Elf = include_elf!("zkpox-guest");

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
enum Wrap {
    /// Raw STARK proof (~2.65 MB). Default; fastest end-to-end.
    Core,
    /// STARK + Groth16 wrap (~256 B). Disclosure-bundle ready.
    Groth16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
enum TargetSel {
    /// Target 01 — stack BOF (no bound check at all).
    #[clap(name = "01")]
    #[serde(rename = "01")]
    T01,
    /// Target 02 — off-by-one (i <= buf_size).
    #[clap(name = "02")]
    #[serde(rename = "02")]
    T02,
    /// Target 03 — CVE-2017-9047 (libxml2 xmlSnprintfElementContent
    /// stale-len; freestanding extraction). Uses a 32-byte buffer.
    #[clap(name = "03")]
    #[serde(rename = "03")]
    T03,
}

impl TargetSel {
    fn id_byte(self) -> u8 {
        match self {
            TargetSel::T01 => 0x01,
            TargetSel::T02 => 0x02,
            TargetSel::T03 => 0x03,
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "zkpox-prove — SP1 driver for the multi-target guest")]
struct Args {
    #[arg(long, value_name = "FILE")]
    witness: PathBuf,

    /// Which C target the witness belongs to. The prover prepends a
    /// one-byte selector to the witness bytes; the guest dispatches on
    /// it (see core/zkpox/guest/src/main.rs).
    #[arg(long, value_enum, default_value_t = TargetSel::T01)]
    target: TargetSel,

    #[arg(long, conflicts_with = "prove")]
    execute: bool,

    #[arg(long, conflicts_with = "execute")]
    prove: bool,

    /// Proof wrap (only meaningful with --prove).
    #[arg(long, value_enum, default_value_t = Wrap::Core)]
    wrap: Wrap,

    /// Path to write the proof artifact. If unset, the proof is
    /// generated, measured, then dropped (no on-disk artifact).
    #[arg(long, value_name = "FILE")]
    proof_out: Option<PathBuf>,

    /// Path to dump the bench JSON record. Defaults to stdout.
    #[arg(long, value_name = "FILE")]
    record: Option<PathBuf>,

    /// Tag for the bench record (e.g. "01-stack-bof:crash").
    #[arg(long, default_value = "01-stack-bof")]
    tag: String,
}

#[derive(Serialize)]
struct Verdicts {
    target_id: u32,
    crash_only_crashed: bool,
    oob_detected: bool,
    oob_count: u32,
    oob_first_offset: i32,
}

#[derive(Serialize)]
struct BenchRecord<'a> {
    tag: &'a str,
    witness: String,
    witness_bytes: u64,
    mode: &'a str,
    /// "core" or "groth16" when mode == "prove"; absent when mode == "execute".
    #[serde(skip_serializing_if = "Option::is_none")]
    wrap: Option<Wrap>,
    verdicts: Verdicts,
    cycles: Option<u64>,
    wall_secs: f64,
    proof_bytes: Option<usize>,
    verified: Option<bool>,
}

fn read_verdicts(public_values: &mut sp1_sdk::SP1PublicValues) -> Verdicts {
    // Order must match the five `commit(...)` calls in the guest
    // (core/zkpox/guest/src/main.rs).
    let target_id: u32 = public_values.read::<u32>();
    let crash_only_crashed: bool = public_values.read::<bool>();
    let oob_detected: bool = public_values.read::<bool>();
    let oob_count: u32 = public_values.read::<u32>();
    let oob_first_offset: i32 = public_values.read::<i32>();
    Verdicts {
        target_id,
        crash_only_crashed,
        oob_detected,
        oob_count,
        oob_first_offset,
    }
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();

    let args = Args::parse();
    if !args.execute && !args.prove {
        return Err(anyhow!("specify either --execute or --prove"));
    }

    // For Groth16 wrap, ensure SP1's circuit artifacts are present *before*
    // we burn STARK cycles. Without this, the first invocation crashes at
    // the final wrap step with "artifact not found" after ~20 minutes of
    // upstream proving — discovered during Phase 1.2 bench. The download
    // is ~6 GB compressed (~15 GB extracted); subsequent runs hit the cache
    // and skip silently.
    if args.prove && args.wrap == Wrap::Groth16 {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("spinning a tokio runtime for artifact install")?;
        rt.block_on(sp1_sdk::install::try_install_circuit_artifacts("groth16"))
            .context("installing SP1 groth16 circuit artifacts")?;
    }

    let witness = std::fs::read(&args.witness)
        .with_context(|| format!("reading witness {}", args.witness.display()))?;
    let witness_bytes = witness.len() as u64;

    // Prepend the target-id byte so the guest's dispatch picks the
    // right C victim binding. Phase 1.6+ schema: [target_id: u8] || witness.
    let mut framed = Vec::with_capacity(witness.len() + 1);
    framed.push(args.target.id_byte());
    framed.extend_from_slice(&witness);

    let mut stdin = SP1Stdin::new();
    stdin.write(&framed);

    let client = ProverClient::from_env();

    let record = if args.execute {
        let start = Instant::now();
        let (mut output, report) = client
            .execute(GUEST_ELF, stdin)
            .run()
            .map_err(|e| anyhow!("execute failed: {e}"))?;
        let wall = start.elapsed().as_secs_f64();
        let verdicts = read_verdicts(&mut output);

        BenchRecord {
            tag: &args.tag,
            witness: args.witness.display().to_string(),
            witness_bytes,
            mode: "execute",
            wrap: None,
            verdicts,
            cycles: Some(report.total_instruction_count()),
            wall_secs: wall,
            proof_bytes: None,
            verified: None,
        }
    } else {
        let pk = client.setup(GUEST_ELF).expect("failed to setup guest ELF");

        let start = Instant::now();
        let proof = match args.wrap {
            Wrap::Core => client.prove(&pk, stdin).run(),
            Wrap::Groth16 => client.prove(&pk, stdin).groth16().run(),
        }
        .map_err(|e| anyhow!("prove ({:?}) failed: {e}", args.wrap))?;
        let wall = start.elapsed().as_secs_f64();

        let mut public_values = proof.public_values.clone();
        let verdicts = read_verdicts(&mut public_values);

        // Persist the proof so we can measure size. If --proof-out was
        // given, keep it; otherwise write to a temp path and unlink.
        let (proof_path, persistent) = match &args.proof_out {
            Some(p) => (p.clone(), true),
            None => (
                std::env::temp_dir()
                    .join(format!("zkpox-{}.proof", std::process::id())),
                false,
            ),
        };
        let proof_bytes = match proof.save(&proof_path) {
            Ok(()) => std::fs::metadata(&proof_path).ok().map(|m| m.len() as usize),
            Err(_) => None,
        };
        if !persistent {
            let _ = std::fs::remove_file(&proof_path);
        }

        let verified = client.verify(&proof, pk.verifying_key(), None).is_ok();

        BenchRecord {
            tag: &args.tag,
            witness: args.witness.display().to_string(),
            witness_bytes,
            mode: "prove",
            wrap: Some(args.wrap),
            verdicts,
            cycles: None,
            wall_secs: wall,
            proof_bytes,
            verified: Some(verified),
        }
    };

    let json = serde_json::to_string_pretty(&record)?;
    match args.record {
        Some(p) => std::fs::write(&p, json + "\n")?,
        None => println!("{json}"),
    }
    Ok(())
}
