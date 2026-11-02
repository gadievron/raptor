//! SP1 guest — target dispatch + gadget invocations.
//!
//! Private input: version/target/gadget (u32 little-endian), random salt
//! (32 bytes), then witness. Unsupported selectors are rejected.
//! Public output: the fixed 88-byte v2 statement from zkpox-statement.
//! It commits to the source, predicate, verdict and salted witness digest.
//! The verifier must require a positive selected verdict; valid execution
//! proofs of benign inputs are intentionally possible for negative tests.

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

    fn zkpox_target_03_victim(
        buf: *mut c_char,
        buf_size: usize,
        input: *const c_char,
        n: usize,
    ) -> c_char;
}

/// Default buffer geometry for targets 01/02. Target 03 overrides
/// `buf_size` locally — its CVE-shape (xmlSnprintfElementContent's
/// stale-len bug) needs `prefix_len > 8` to bypass the size check,
/// which doesn't fit a 16-byte buffer.
const BUF_SIZE_DEFAULT: usize = 16;
const BUF_SIZE_T03: usize = 32;
const LEADING: usize = 16;
const MIN_TRAILING: usize = 16;

#[derive(Copy, Clone, PartialEq, Eq)]
enum TargetId {
    T01 = 0x01,
    T02 = 0x02,
    T03 = 0x03,
}

impl TargetId {
    fn from_byte(b: u8) -> Self {
        match b {
            0x02 => TargetId::T02,
            0x03 => TargetId::T03,
            // Default to T01 on 0x01 or any unknown value. Pre-1.6
            // bench witnesses lacked the prefix byte — those streams
            // saw witness[0] = first overflow byte, which is unlikely
            // but possible to alias 0x02 or 0x03; reproducibility of
            // pre-1.6 numbers ships via the prover's --target=01 default.
            _ => TargetId::T01,
        }
    }
}

fn dispatch(target: TargetId, witness: &[u8]) -> (Scan, Scan) {
    let (victim, buf_size): (
        unsafe extern "C" fn(*mut c_char, usize, *const c_char, usize) -> c_char,
        usize,
    ) = match target {
        TargetId::T01 => (zkpox_target_01_victim, BUF_SIZE_DEFAULT),
        TargetId::T02 => (zkpox_target_02_victim, BUF_SIZE_DEFAULT),
        TargetId::T03 => (zkpox_target_03_victim, BUF_SIZE_T03),
    };
    let crash_only = scan_around(
        witness, buf_size, LEADING, MIN_TRAILING, pattern_byte_uniform, victim,
    );
    let oob_write = scan_around(
        witness, buf_size, LEADING, MIN_TRAILING, pattern_byte_varying, victim,
    );
    (crash_only, oob_write)
}

pub fn main() {
    use zkpox_statement::{commitment, target_hash, Statement, VERSION, MAX_WITNESS, INPUT_HEADER_LEN};
    let raw: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    assert!(raw.len() >= INPUT_HEADER_LEN && raw.len() <= INPUT_HEADER_LEN + MAX_WITNESS);
    let word = |i: usize| u32::from_le_bytes(raw[i*4..i*4+4].try_into().unwrap());
    assert_eq!(word(0), VERSION);
    let target = word(1);
    let gadget = word(2);
    assert!((1..=3).contains(&target));
    assert!((1..=2).contains(&gadget));
    let salt: [u8;32] = raw[12..44].try_into().unwrap();
    let witness = &raw[44..];
    let target_id = TargetId::from_byte(target as u8);
    let (crash_only, oob_write) = dispatch(target_id, witness);
    let statement = Statement {
        target, gadget, flags: (crash_only.dirty as u32) | ((oob_write.dirty as u32) << 1),
        count: oob_write.count, first_offset: oob_write.first_offset,
        witness_commitment: commitment(target, gadget, &salt, witness),
        target_hash: target_hash(target).unwrap(),
    };
    sp1_zkvm::io::commit_slice(&statement.encode());
}
