# Rust Vulnerability Patterns

Rust's ownership system prevents many C-class bugs, but these patterns
remain. Language-agnostic patterns (injection, path traversal, etc.)
are in `common.md` and always apply alongside these.

---

## 1. Unsafe Block Soundness

`unsafe` blocks bypass the borrow checker. Any unsound `unsafe` use
can produce memory corruption — use-after-free, data races, aliased
`&mut`, dangling pointers.

```rust
// BUG: creates two &mut references to the same data
unsafe {
    let p1 = &mut *ptr;
    let p2 = &mut *ptr;  // UB: aliased &mut
    p1.field = 1;
    p2.field = 2;
}

// FIX: ensure unique &mut access; prefer safe abstractions
let p1 = &mut *ptr;
p1.field = 1;
```

Key checks: Does the `unsafe` block uphold the invariants documented
in its safety comment? If there's no safety comment, that's a finding.

---

## 2. Integer Overflow in Release Mode

In debug mode, integer overflow panics. In release mode, it wraps
silently. Code relying on debug-mode panics for safety is vulnerable
in production.

```rust
// BUG: wraps in release, undersized allocation
let total: u32 = width * height * 4;  // wraps silently in release
let buf = vec![0u8; total as usize];

// FIX: use checked arithmetic
let total = width.checked_mul(height)
    .and_then(|v| v.checked_mul(4))
    .ok_or(Error::Overflow)?;
```

---

## 3. Panic in FFI Boundary

Panicking across an FFI boundary (unwinding through C frames) is
undefined behaviour.

```rust
// BUG: panic unwinds through C caller
#[no_mangle]
pub extern "C" fn callback(data: *const u8) -> i32 {
    let s = std::str::from_utf8(slice).unwrap();  // panics on invalid UTF-8
    process(s)
}

// FIX: catch_unwind at the FFI boundary
#[no_mangle]
pub extern "C" fn callback(data: *const u8) -> i32 {
    std::panic::catch_unwind(|| {
        // ... inner logic
    }).unwrap_or(-1)
}
```

---

## 4. Interior Mutability Misuse

`RefCell` defers borrow rules to runtime: conflicting borrows panic
(DoS if unrecovered). `UnsafeCell` in `unsafe` code can produce real
data races when shared across threads.

```rust
// BUG: runtime panic (DoS) — conflicting borrow_mut
let cell = RefCell::new(vec![1, 2, 3]);
let borrow1 = cell.borrow_mut();
let borrow2 = cell.borrow_mut();  // panics

// BUG: real data race — UnsafeCell shared across threads
struct Shared(UnsafeCell<u64>);
unsafe impl Sync for Shared {}  // unsound: no synchronization

// FIX (RefCell): scope borrows carefully
{
    let mut b = cell.borrow_mut();
    b.push(4);
}  // borrow dropped
let b2 = cell.borrow_mut();  // OK
```

---

## 5. Use-After-Free via Raw Pointer

Safe Rust prevents UAF, but raw pointers in `unsafe` blocks can
dereference freed memory.

```rust
// BUG: box freed when dropped, raw pointer dangles
let b = Box::new(42);
let ptr = &*b as *const i32;
drop(b);
unsafe { println!("{}", *ptr); }  // UAF

// FIX: ensure lifetime of pointer does not exceed allocation
let b = Box::new(42);
let val = unsafe { *(&*b as *const i32) };
drop(b);
println!("{}", val);  // val is a copy
```

---

## 6. Incorrect Send/Sync Implementation

Manually implementing `Send` or `Sync` for a type that is not
thread-safe enables data races in safe code.

```rust
// BUG: T contains a raw pointer; declaring Send is unsound
struct Wrapper(*mut Data);
unsafe impl Send for Wrapper {}  // other threads can now access *mut Data

// FIX: only implement Send/Sync when the invariants genuinely hold
// Use PhantomData to opt out: PhantomData<*mut ()> → !Send, !Sync
```

---

## 7. Unvalidated Index / Slice Panic

Indexing a slice or vec with an unchecked index panics on out-of-bounds.
In a server, this crashes the handler (or the process if unrecovered).

```rust
// BUG: panics if idx >= data.len()
let val = data[idx];

// FIX: use .get() and handle None
let val = data.get(idx).ok_or(Error::OutOfBounds)?;
```

---

## 8. Path Traversal via Path::join

`std::path::Path::join` replaces the base when the argument is absolute.
`..` components are not resolved.

```rust
// BUG: user_path = "/etc/passwd" or "../../etc/passwd"
let path = base_dir.join(user_path);

// FIX: canonicalize and check prefix
let path = base_dir.join(user_path).canonicalize()?;
if !path.starts_with(base_dir.canonicalize()?) {
    return Err(Error::Traversal);
}
```

---

## 9. Denial of Service via Unbounded collect

Collecting an iterator of attacker-controlled length into a Vec.
Allocates unbounded memory.

```rust
// BUG: n from attacker
let items: Vec<_> = (0..n).map(|_| parse_item(&mut reader)?).collect();

// FIX: cap before collecting
if n > MAX_ITEMS { return Err(Error::TooMany); }
```

---

## 10. Regex Denial of Service

User-controlled regex patterns compiled without size or complexity
limits. Catastrophic backtracking or excessive compilation time.

```rust
// BUG: user-supplied pattern
let re = Regex::new(&user_pattern)?;

// FIX: use regex with size limit
let re = RegexBuilder::new(&user_pattern)
    .size_limit(1 << 20)  // 1MB compiled limit
    .build()?;
```

---

## 11. Unvalidated Transmute

`std::mem::transmute` reinterprets bits as a different type. Invalid
values for the target type are immediate UB.

```rust
// BUG: not all u8 values are valid bool (only 0 and 1)
let b: bool = unsafe { std::mem::transmute(byte) };

// FIX: validate before transmuting
let b = match byte {
    0 => false,
    1 => true,
    _ => return Err(Error::InvalidBool),
};
```

---

## 12. Incorrect Lifetime Annotation

Lifetime annotations that are too broad, allowing references to outlive
their data. The borrow checker trusts the annotations.

```rust
// BUG: 'a ties output lifetime to input, but data is allocated inside
fn get_ref<'a>(input: &'a str) -> &'a str {
    let owned = format!("processed: {}", input);
    &owned  // ERROR: owned dropped, but in unsafe code this compiles
}
```

In safe code the compiler catches this. In `unsafe` code with manual
lifetime annotations, the programmer must ensure correctness.

---

## 13. Command Injection via std::process::Command

`Command::new("sh").arg("-c").arg(user_input)` passes through shell.

```rust
// BUG: shell injection
Command::new("sh")
    .arg("-c")
    .arg(format!("convert {} output.png", filename))
    .status()?;

// FIX: direct execution, no shell
Command::new("convert")
    .arg(filename)
    .arg("output.png")
    .status()?;
```
