//! Phase 0 host driver: load a witness, run the SP1 guest in execute or
//! prove mode against target #1, and emit a JSON record with the verdicts
//! of *both* the `crash_only` and `oob_write` gadgets (one prove run
//! yields both — see harness/guest/src/main.rs).
//!
//! Usage:
//!   prove-bof --witness ../witnesses/01-crash.bin --execute
//!   prove-bof --witness ../witnesses/01-crash.bin --prove
//!   prove-bof --witness ../witnesses/01-canarymatch-overflow1-fn.bin --execute
//!     # → crash_only=false (gadget blind spot), oob_write=true (closes it)

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Serialize;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const GUEST_ELF: Elf = include_elf!("zkpox-phase0-guest");

#[derive(Parser, Debug)]
#[command(about = "Phase 0 SP1 driver for target #1 (stack BOF)")]
struct Args {
    #[arg(long, value_name = "FILE")]
    witness: PathBuf,

    #[arg(long, conflicts_with = "prove")]
    execute: bool,

    #[arg(long, conflicts_with = "execute")]
    prove: bool,

    /// Path to dump the bench JSON record. Defaults to stdout.
    #[arg(long, value_name = "FILE")]
    record: Option<PathBuf>,

    /// Tag for the bench record (e.g. "01-stack-bof:crash").
    #[arg(long, default_value = "01-stack-bof")]
    tag: String,
}

#[derive(Serialize)]
struct Verdicts {
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
    verdicts: Verdicts,
    cycles: Option<u64>,
    wall_secs: f64,
    proof_bytes: Option<usize>,
    verified: Option<bool>,
}

fn read_verdicts(public_values: &mut sp1_sdk::SP1PublicValues) -> Verdicts {
    // Order must match the four `commit(...)` calls in the guest.
    let crash_only_crashed: bool = public_values.read::<bool>();
    let oob_detected: bool = public_values.read::<bool>();
    let oob_count: u32 = public_values.read::<u32>();
    let oob_first_offset: i32 = public_values.read::<i32>();
    Verdicts {
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

    let witness = std::fs::read(&args.witness)
        .with_context(|| format!("reading witness {}", args.witness.display()))?;
    let witness_bytes = witness.len() as u64;

    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);

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
            verdicts,
            cycles: Some(report.total_instruction_count()),
            wall_secs: wall,
            proof_bytes: None,
            verified: None,
        }
    } else {
        let pk = client.setup(GUEST_ELF).expect("failed to setup guest ELF");

        let start = Instant::now();
        let proof = client
            .prove(&pk, stdin)
            .run()
            .map_err(|e| anyhow!("prove failed: {e}"))?;
        let wall = start.elapsed().as_secs_f64();

        let mut public_values = proof.public_values.clone();
        let verdicts = read_verdicts(&mut public_values);

        // SP1's SP1ProofWithPublicValues::save uses bincode internally.
        let proof_path = std::env::temp_dir().join(format!(
            "zkpox-phase0-{}.proof",
            std::process::id()
        ));
        let proof_bytes = match proof.save(&proof_path) {
            Ok(()) => std::fs::metadata(&proof_path).ok().map(|m| m.len() as usize),
            Err(_) => None,
        };
        let _ = std::fs::remove_file(&proof_path);

        let verified = client.verify(&proof, pk.verifying_key(), None).is_ok();

        BenchRecord {
            tag: &args.tag,
            witness: args.witness.display().to_string(),
            witness_bytes,
            mode: "prove",
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
