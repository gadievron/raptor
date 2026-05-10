//! Phase 0 SP1 guest — target binding + gadget invocations.
//!
//! Adding a new target is mechanical. To bind target #N (a hypothetical
//! `02-heap-oob.c`, for example):
//!   1. drop `targets/02-heap-oob.c` next to `01-stack-bof.c` with the
//!      same `(buf, buf_size, input, n)` signature
//!   2. add a `clang ... 02-heap-oob.c ...` invocation in `build.rs`
//!   3. add an `extern "C" fn zkpox_target_02_victim(...)` binding here
//!   4. mirror the `crash_only` + `oob_write` pair below for it
//!
//! The redzone primitive itself (`scan_around`) is unchanged. That's the
//! "gadget abstraction stable across bug shapes" claim from the Phase 0
//! plan's go/no-go question 4.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod redzone;

use core::ffi::{c_char, c_uchar};
use redzone::{pattern_byte_uniform, pattern_byte_varying, scan_around};

extern "C" {
    fn zkpox_target_01_victim(
        buf: *mut c_char,
        buf_size: usize,
        input: *const c_char,
        n: usize,
    ) -> c_char;
}

const TARGET_01_BUF_SIZE: usize = 16;
const TARGET_01_LEADING: usize = 16;
const TARGET_01_MIN_TRAILING: usize = 16;

pub fn main() {
    let witness: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();

    // crash_only: uniform 0xA5 canary. Cheap, naive, vulnerable to
    // canarymatch witnesses (kept as the baseline gadget).
    let crash_only = scan_around(
        &witness,
        TARGET_01_BUF_SIZE,
        TARGET_01_LEADING,
        TARGET_01_MIN_TRAILING,
        pattern_byte_uniform,
        zkpox_target_01_victim,
    );

    // oob_write: position-varying pattern, structured outputs. Catches
    // canarymatch attempts that defeat crash_only.
    let oob_write = scan_around(
        &witness,
        TARGET_01_BUF_SIZE,
        TARGET_01_LEADING,
        TARGET_01_MIN_TRAILING,
        pattern_byte_varying,
        zkpox_target_01_victim,
    );

    // Public-values layout (host reads in the same order):
    sp1_zkvm::io::commit(&crash_only.dirty);
    sp1_zkvm::io::commit(&oob_write.dirty);
    sp1_zkvm::io::commit(&oob_write.count);
    sp1_zkvm::io::commit(&oob_write.first_offset);
}
