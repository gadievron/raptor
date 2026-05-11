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

fn compile_c(clang: &str, src: &PathBuf, obj: &PathBuf) {
    let status = Command::new(clang)
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
        .arg(src)
        .args(["-o"])
        .arg(obj)
        .status()
        .expect("failed to invoke clang");
    if !status.success() {
        panic!("clang failed compiling {}", src.display());
    }
}

fn archive_objects(out_dir: &PathBuf, archive: &PathBuf, objs: &[PathBuf]) {
    // llvm-ar shipped with Homebrew LLVM, GNU ar, and Apple ar all work —
    // the archive format is portable. Pick the first one that succeeds.
    let archiver_candidates = [
        std::env::var("ZKPOX_AR").unwrap_or_default(),
        "/opt/homebrew/opt/llvm/bin/llvm-ar".to_string(),
        "llvm-ar".to_string(),
        "ar".to_string(),
    ];
    let mut last_err = None;
    for ar in archiver_candidates.iter().filter(|s| !s.is_empty()) {
        let mut cmd = Command::new(ar);
        cmd.arg("rcs").arg(archive);
        for obj in objs {
            cmd.arg(obj);
        }
        match cmd.status() {
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
    let _ = out_dir;
}

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let clang = pick_clang();

    // Per-target sources kept in a list so adding target #N is a single
    // line change. The static archive bundles every target object — the
    // guest's `extern "C"` bindings resolve against whichever symbol the
    // dispatch picks per invocation.
    let targets: Vec<(&str, &str)> = vec![
        ("01-stack-bof.c",  "01-stack-bof.o"),
        ("02-off-by-one.c", "02-off-by-one.o"),
    ];

    let mut obj_paths = Vec::with_capacity(targets.len());
    for (src_name, obj_name) in &targets {
        let src = manifest_dir.join("../targets").join(src_name);
        let obj = out_dir.join(obj_name);
        compile_c(&clang, &src, &obj);
        println!("cargo:rerun-if-changed={}", src.display());
        obj_paths.push(obj);
    }

    let archive_path = out_dir.join("libzkpox_targets.a");
    archive_objects(&out_dir, &archive_path, &obj_paths);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=zkpox_targets");
    println!("cargo:rerun-if-env-changed=ZKPOX_CLANG");
    println!("cargo:rerun-if-env-changed=ZKPOX_AR");
}
