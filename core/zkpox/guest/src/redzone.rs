//! Target-agnostic redzone scanning primitive.
//!
//! Every Phase-0 gadget shape (`crash_only`, `oob_write`) reduces to:
//! "fill the memory around the C-supplied buffer with a known pattern,
//! call the C, scan for bytes that no longer match the pattern."
//!
//! Adding a new target therefore requires only:
//!   - a freestanding C with the bug pattern (in `targets/`),
//!   - a `build.rs` line that cross-compiles it,
//!   - one `extern "C"` binding,
//!   - a one-line call to `scan_around(...)` in the guest's `main`.
//!
//! Phase 1 will replace the probabilistic redzone with a true shadow
//! allocation table; the function signature here is stable across that
//! swap (callers keep their pattern-fn callback shape).

use core::ffi::{c_char, c_uchar};

pub const UNIFORM_CANARY: c_uchar = 0xA5;

#[inline]
pub fn pattern_byte_uniform(_pos: usize) -> c_uchar {
    UNIFORM_CANARY
}

#[inline]
pub fn pattern_byte_varying(pos: usize) -> c_uchar {
    let mix = (pos as u32).wrapping_mul(0x9E37_79B1u32);
    UNIFORM_CANARY ^ ((mix >> 24) as u8)
}

/// One observed redzone-scan result. `dirty == false` ⇔
/// `count == 0` ⇔ `first_offset == i32::MIN`.
#[derive(Default)]
pub struct Scan {
    pub dirty: bool,
    pub count: u32,
    pub first_offset: i32,
}

/// Run the supplied `victim` C function with a buffer surrounded by the
/// given pattern in both leading and trailing redzones. Trailing redzone
/// is sized to absorb any input length so a deep overrun never escapes
/// into memory SP1's executor doesn't track.
pub fn scan_around<F>(
    input: &[u8],
    buf_size: usize,
    leading_redzone: usize,
    min_trailing_redzone: usize,
    pattern: F,
    victim: unsafe extern "C" fn(*mut c_char, usize, *const c_char, usize) -> c_char,
) -> Scan
where
    F: Fn(usize) -> c_uchar,
{
    let trailing = min_trailing_redzone.max(input.len().saturating_sub(buf_size) + 8);
    let total = leading_redzone + buf_size + trailing;

    let mut window: Vec<c_uchar> = (0..total).map(&pattern).collect();

    let buf_ptr = unsafe { window.as_mut_ptr().add(leading_redzone) as *mut c_char };
    let _sentinel = unsafe {
        victim(
            buf_ptr,
            buf_size,
            input.as_ptr() as *const c_char,
            input.len(),
        )
    };

    let mut scan = Scan {
        first_offset: i32::MIN,
        ..Scan::default()
    };
    for (i, &b) in window.iter().enumerate() {
        if i >= leading_redzone && i < leading_redzone + buf_size {
            continue;
        }
        if b != pattern(i) {
            scan.dirty = true;
            scan.count = scan.count.saturating_add(1);
            if scan.first_offset == i32::MIN {
                let signed = i as i64 - leading_redzone as i64;
                scan.first_offset = signed as i32;
            }
        }
    }
    scan
}
