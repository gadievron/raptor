//! Compile the freestanding C target into a static lib that the SP1
//! guest links via `extern "C"`. SP1's `cargo prove build` cross-
//! compiles the Rust crate to its custom RISC-V triple
//! (`riscv64im-succinct-zkvm-elf`); we have to bring our own clang for
//! the C side because:
//!
//!   - Apple clang lacks the RISC-V backend.
//!   - SP1's "succinct-zkvm" triple isn't a real LLVM platform — it's an
//!     SP1-internal label. The C just needs vanilla bare-metal RISC-V64
//!     ABI to be link-compatible with whatever the Rust side emits.
//!
//! We therefore use a separately-installed clang with full backends
//! (Homebrew LLVM on macOS, distro clang on Linux) and pass an explicit
//! `--target=riscv64-unknown-none-elf -march=rv64im -mabi=lp64` so the
//! emitted code speaks the same ABI as SP1's RISC-V emission.
//!
//! Override the clang path via `ZKPOX_CLANG` env var if defaults are wrong.
//!
//! `-fno-stack-protector` is deliberate: we want the BOF to actually
//! corrupt memory inside the zkVM so the Rust gadget wrapper's shadow
//! canaries fire. `__stack_chk_fail`/`abort` don't exist in the
//! freestanding SP1 environment regardless.

use std::path::PathBuf;
use std::process::Command;

fn pick_clang() -> String {
    if let Ok(p) = std::env::var("ZKPOX_CLANG") {
        return p;
    }
    if cfg!(target_os = "macos") {
        let brew_llvm = "/opt/homebrew/opt/llvm/bin/clang";
        if PathBuf::from(brew_llvm).exists() {
            return brew_llvm.to_string();
        }
    }
    // Linux / fallback: rely on a clang on PATH that has the RISC-V backend
    // (true for distro clang from llvm-15+ on Ubuntu/Debian).
    "clang".to_string()
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_c = manifest_dir.join("../../targets/01-stack-bof.c");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let obj_path = out_dir.join("01-stack-bof.o");
    let archive_path = out_dir.join("libzkpox_target_01.a");

    let clang = pick_clang();

    // Compile C → object
    let status = Command::new(&clang)
        .args([
            "--target=riscv64-unknown-none-elf",
            "-march=rv64im",
            "-mabi=lp64",
            "-mcmodel=medany",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fno-pic",
            "-O0",
            "-Wall",
            "-Wextra",
            "-c",
        ])
        .arg(&target_c)
        .args(["-o"])
        .arg(&obj_path)
        .status()
        .expect("failed to invoke clang");
    if !status.success() {
        panic!("clang failed compiling {}", target_c.display());
    }

    // Wrap as static archive so cargo can link it. We use whichever `ar`
    // we can find — llvm-ar shipped with the same Homebrew LLVM is ideal,
    // GNU ar / Apple ar also fine because the format is portable.
    let archiver_candidates = [
        std::env::var("ZKPOX_AR").unwrap_or_default(),
        "/opt/homebrew/opt/llvm/bin/llvm-ar".to_string(),
        "llvm-ar".to_string(),
        "ar".to_string(),
    ];
    let mut last_err = None;
    for ar in archiver_candidates.iter().filter(|s| !s.is_empty()) {
        let r = Command::new(ar)
            .arg("rcs")
            .arg(&archive_path)
            .arg(&obj_path)
            .status();
        match r {
            Ok(s) if s.success() => {
                last_err = None;
                break;
            }
            Ok(s) => last_err = Some(format!("{} returned {s}", ar)),
            Err(e) => last_err = Some(format!("{} not runnable: {e}", ar)),
        }
    }
    if let Some(msg) = last_err {
        panic!("no archiver succeeded: {msg}");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=zkpox_target_01");
    println!("cargo:rerun-if-changed={}", target_c.display());
    println!("cargo:rerun-if-env-changed=ZKPOX_CLANG");
    println!("cargo:rerun-if-env-changed=ZKPOX_AR");
}
