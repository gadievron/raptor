//! `zkpox-prove` — native CLI that loads a witness, runs the SP1 guest
//! in execute or prove mode against target #1, and emits a JSON record
//! with both the `crash_only` and `oob_write` gadgets' verdicts (one
//! invocation yields both — see packages/zkpox/native/guest/src/main.rs).
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
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};

use sha2::{Digest, Sha256};
use zkpox_statement::{Statement, INPUT_HEADER_LEN, MAX_WITNESS, VERSION};

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
    #[arg(long, value_name = "FILE", required_unless_present_any = ["install_artifacts", "check_runtime"])]
    witness: Option<PathBuf>,

    /// Provision public SP1 circuit files before sandboxed proving (no witness is read).
    #[arg(long, conflicts_with_all = ["execute", "prove", "witness"])]
    install_artifacts: bool,

    /// Check sparse shared-memory file limits before initializing SP1.
    #[arg(long, conflicts_with_all = ["execute", "prove", "witness", "install_artifacts"])]
    check_runtime: bool,

    /// Which C target the witness belongs to. The prover prepends a
    /// one-byte selector to the witness bytes; the guest dispatches on
    /// it (see packages/zkpox/native/guest/src/main.rs).
    #[arg(long, value_enum, default_value_t = TargetSel::T01)]
    target: TargetSel,

    #[arg(long, conflicts_with = "prove")]
    execute: bool,

    #[arg(long, conflicts_with = "execute")]
    prove: bool,

    /// Selected violation predicate: 1 = uniform canary, 2 = varying canary.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=2))]
    gadget: u32,

    /// Private, random 32-byte salt; required when generating a proof.
    #[arg(long, value_name = "FILE", required_if_eq("prove", "true"))]
    salt: Option<PathBuf>,

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
    statement: serde_json::Value,
    harness_hash: String,
    verifier_key_hash: Option<String>,
    cycles: Option<u64>,
    wall_secs: f64,
    proof_bytes: Option<usize>,
    verified: Option<bool>,
}

fn read_statement(public_values: &sp1_sdk::SP1PublicValues) -> Result<(Verdicts, serde_json::Value)> {
    let s = Statement::decode(public_values.as_slice()).map_err(|e| anyhow!(e))?;
    let verdicts = Verdicts {
        target_id: s.target, crash_only_crashed: s.flags & 1 != 0,
        oob_detected: s.flags & 2 != 0, oob_count: s.count,
        oob_first_offset: s.first_offset,
    };
    let statement = serde_json::json!({
        "version": VERSION, "target_id": s.target, "gadget_id": s.gadget,
        "flags": s.flags, "oob_count": s.count, "oob_first_offset": s.first_offset,
        "witness_commitment": format!("sha256:{}", hex::encode(s.witness_commitment)),
        "target_source_hash": format!("sha256:{}", hex::encode(s.target_hash)),
    });
    Ok((verdicts, statement))
}

// SP1 6.5 uses MAX_JIT_LOG_ADDR=40 and a twice-address-space sparse backing.
// Keep the Python proving-job file-size allowance in sync.
const JIT_SHARED_MEMORY_BYTES: u64 = 1u64 << 41;

fn check_runtime() -> Result<()> {
    #[cfg(unix)] {
        let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // getrlimit initializes both fields on success.
        anyhow::ensure!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, limits.as_mut_ptr()) } == 0,
                        "could not inspect the file-size resource limit");
        let limits = unsafe { limits.assume_init() };
        anyhow::ensure!(limits.rlim_cur == libc::RLIM_INFINITY || limits.rlim_cur as u64 >= JIT_SHARED_MEMORY_BYTES,
            "SP1 6.5 needs a 2 TiB sparse shared-memory object; this job's max_file_mb must be at least 2097152 (logical size, not disk allocation)");
    }
    Ok(())
}

fn main() -> Result<()> {
    // A worker panic can otherwise leave its async caller waiting forever.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        std::process::exit(1);
    }));
    sp1_sdk::utils::setup_logger();

    let args = Args::parse();
    if args.check_runtime {
        check_runtime()?;
        println!("{{\"runtime_ready\":true,\"jit_shared_memory_bytes\":{JIT_SHARED_MEMORY_BYTES}}}");
        return Ok(());
    }
    if args.prove { check_runtime()?; }
    if !args.execute && !args.prove && !args.install_artifacts {
        return Err(anyhow!("specify either --execute or --prove"));
    }

    // For Groth16 wrap, ensure SP1's circuit artifacts are present *before*
    // we burn STARK cycles. Without this, the first invocation crashes at
    // the final wrap step with "artifact not found" after ~20 minutes of
    // upstream proving — discovered during Phase 1.2 bench. The download
    // is ~6 GB compressed (~15 GB extracted); subsequent runs hit the cache
    // and skip silently.
    if args.install_artifacts {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("spinning a tokio runtime for artifact install")?;
        rt.block_on(sp1_sdk::install::try_install_circuit_artifacts("groth16"))
            .context("installing SP1 groth16 circuit artifacts")?;
        return Ok(());
    }

    let witness_path = args.witness.as_ref().context("--witness is required")?;
    use std::io::Read;
    let mut witness = Vec::new();
    std::fs::File::open(witness_path)?.take(MAX_WITNESS as u64 + 1).read_to_end(&mut witness)?;
    let witness_bytes = witness.len() as u64;

    anyhow::ensure!(witness.len() <= MAX_WITNESS, "witness exceeds supported size");
    let salt: [u8; 32] = match &args.salt {
        Some(path) => std::fs::read(path)?.try_into()
            .map_err(|_| anyhow!("salt must contain exactly 32 bytes"))?,
        None if args.prove => return Err(anyhow!("--salt is required for proof generation")),
        None => [0; 32], // Execute-only diagnostics never produce a disclosure proof.
    };
    let mut framed = Vec::with_capacity(INPUT_HEADER_LEN + witness.len());
    for value in [VERSION, u32::from(args.target.id_byte()), args.gadget] {
        framed.extend_from_slice(&value.to_le_bytes());
    }
    framed.extend_from_slice(&salt);
    framed.extend_from_slice(&witness);
    let mut stdin = SP1Stdin::new();
    stdin.write(&framed);
    // Never select a remote or mock prover implicitly from the environment.
    let harness_hash = format!("sha256:{}", hex::encode(Sha256::digest(&GUEST_ELF[..])));

    let record = if args.execute {
        let client = ProverClient::builder().light().build();
        let start = Instant::now();
        let (output, report) = client
            .execute(GUEST_ELF, stdin)
            .run()
            .map_err(|e| anyhow!("execute failed: {e}"))?;
        let wall = start.elapsed().as_secs_f64();
        let (verdicts, statement) = read_statement(&output)?;

        BenchRecord {
            tag: &args.tag,
            witness: witness_path.display().to_string(),
            witness_bytes,
            mode: "execute",
            wrap: None,
            verdicts,
            statement,
            harness_hash,
            verifier_key_hash: None,
            cycles: Some(report.total_instruction_count()),
            wall_secs: wall,
            proof_bytes: None,
            verified: None,
        }
    } else {
        let client = ProverClient::builder().cpu().build();
        let pk = client.setup(GUEST_ELF).context("setting up guest ELF")?;
        let verifier_key_hash = format!("sp1-vk:{}", pk.verifying_key().bytes32().trim_start_matches("0x"));

        let start = Instant::now();
        let proof = match args.wrap {
            Wrap::Core => client.prove(&pk, stdin).run(),
            Wrap::Groth16 => client.prove(&pk, stdin).groth16().run(),
        }
        .map_err(|e| anyhow!("prove ({:?}) failed: {e}", args.wrap))?;
        let wall = start.elapsed().as_secs_f64();

        let (verdicts, statement) = read_statement(&proof.public_values)?;

        client.verify(&proof, pk.verifying_key(), None)
            .map_err(|e| anyhow!("in-process verification failed: {e:?}"))?;
        let proof_bytes = Some(bincode::serialized_size(&proof)? as usize);
        if let Some(path) = &args.proof_out {
            proof.save(path).context("saving proof artifact")?;
        }
        let verified = true;

        BenchRecord {
            tag: &args.tag,
            witness: witness_path.display().to_string(),
            witness_bytes,
            mode: "prove",
            wrap: Some(args.wrap),
            verdicts,
            statement,
            harness_hash,
            verifier_key_hash: Some(verifier_key_hash),
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
