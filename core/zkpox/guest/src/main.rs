//! SP1 guest — target dispatch + gadget invocations.
//!
//! ## Witness layout
//!
//! Witnesses sent into the guest are bytes prefixed by a 1-byte
//! `target_id`. The host (`zkpox-prove --target {01,02}`) prepends
//! this byte; `core/zkpox/test/run-tests.sh` and `raptor_zkpox.py`
//! both go through the host so the prepend stays in one place.
//!
//! `target_id == 0x01`  →  target #1 (stack BOF)
//! `target_id == 0x02`  →  target #2 (off-by-one)
//! any other value (including empty witness) → falls back to target 01
//! for backward compatibility with pre-1.6 callers.
//!
//! ## Adding target #N
//!
//! 1. Drop the freestanding C at `targets/0N-<shape>.c`.
//! 2. Add an entry to `targets: Vec<...>` in `guest/build.rs`.
//! 3. Add an `extern "C"` binding here and a match arm in `dispatch()`.
//! 4. Bump the witness corpus.
//!
//! ## Public-values schema (5 fields, in commit order)
//!
//! ```text
//! target_id              : u32   (cast from u8, see TargetId enum)
//! crash_only_crashed     : bool
//! oob_detected           : bool
//! oob_count              : u32
//! oob_first_offset       : i32
//! ```

#![no_main]
sp1_zkvm::entrypoint!(main);

mod redzone;

use core::ffi::c_char;
use redzone::{pattern_byte_uniform, pattern_byte_varying, scan_around, Scan};

extern "C" {
    fn zkpox_target_01_victim(
        buf: *mut c_char,
        buf_size: usize,
        input: *const c_char,
        n: usize,
    ) -> c_char;

    fn zkpox_target_02_victim(
        buf: *mut c_char,
        buf_size: usize,
        input: *const c_char,
        n: usize,
    ) -> c_char;
}

/// Both targets currently share these buffer parameters. Phase 1.7+
/// targets that bring their own buffer geometry override locally.
const BUF_SIZE: usize = 16;
const LEADING: usize = 16;
const MIN_TRAILING: usize = 16;

#[derive(Copy, Clone, PartialEq, Eq)]
enum TargetId {
    T01 = 0x01,
    T02 = 0x02,
}

impl TargetId {
    fn from_byte(b: u8) -> Self {
        match b {
            0x02 => TargetId::T02,
            // Default to T01 on 0x01 or any unknown value. Pre-1.6
            // bench witnesses lacked the prefix byte — those streams
            // saw witness[0] = first overflow byte, which is unlikely
            // but possible to alias 0x02; reproducibility of pre-1.6
            // numbers ships via the prover's --target=01 default.
            _ => TargetId::T01,
        }
    }
}

fn dispatch(target: TargetId, witness: &[u8]) -> (Scan, Scan) {
    let victim = match target {
        TargetId::T01 => zkpox_target_01_victim,
        TargetId::T02 => zkpox_target_02_victim,
    };
    let crash_only = scan_around(
        witness, BUF_SIZE, LEADING, MIN_TRAILING, pattern_byte_uniform, victim,
    );
    let oob_write = scan_around(
        witness, BUF_SIZE, LEADING, MIN_TRAILING, pattern_byte_varying, victim,
    );
    (crash_only, oob_write)
}

pub fn main() {
    let raw: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let (target_id, witness) = match raw.split_first() {
        Some((head, tail)) => (TargetId::from_byte(*head), tail.to_vec()),
        None => (TargetId::T01, raw),
    };

    let (crash_only, oob_write) = dispatch(target_id, &witness);

    // Public-values layout (host reads in the same order). target_id
    // is committed as u32 so SP1's u8-as-public-value handling stays
    // out of the schema's load path.
    sp1_zkvm::io::commit(&(target_id as u32));
    sp1_zkvm::io::commit(&crash_only.dirty);
    sp1_zkvm::io::commit(&oob_write.dirty);
    sp1_zkvm::io::commit(&oob_write.count);
    sp1_zkvm::io::commit(&oob_write.first_offset);
}
