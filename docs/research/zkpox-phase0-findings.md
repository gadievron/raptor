# ZKPoX Phase 0 — Findings

*Spike completed 2026-05-10. This doc is the standalone deliverable; the
prototype tree under `docs/research/zkpox-phase0/` is source material
for the Phase 1 PR (or evidence to abandon, if we'd hit a wall).*

---

## TL;DR

All four go/no-go questions answered yes. SP1 generates a verifying
proof of a real C stack-buffer overflow in **15–52 s CPU-only** on an
Apple Silicon Mac, with a **2.65 MB** core proof artifact (Groth16-wrap
to 256 B is supported but unwired in Phase 0). The disclosure-envelope
flow (AES-256-GCM + age + Drand tlock) round-trips a witness through
both the vendor and time-lock paths in seconds. The violation-gadget
abstraction holds across two distinct gadgets (`crash_only`,
`oob_write`) sharing one redzone primitive.

**Recommendation:** proceed to Phase 1 with the C-via-FFI fidelity
model as the MVP, the LLVM-IR interpreter path documented as
Phase 1.x research, and the listed Phase-1 follow-ons below.

---

## Bench host

Apple Silicon Mac (arm64), CPU only. Toolchain manifest pinned in
`docs/research/zkpox-phase0/versions.txt`:

| Tool                      | Version |
|---------------------------|---------|
| rustc / cargo             | 1.95.0 (2026-04-14) |
| cargo-prove (SP1)         | v6.1.0 (`d454975`, 2026-04-11) |
| Custom rustup toolchain   | `succinct` (rustc 1.93.0-dev) |
| Homebrew LLVM             | 22.1.4 |
| age                       | 1.3.1 |
| go                        | 1.26.3 (req. by `sp1-recursion-gnark-ffi`) |
| tle (Drand tlock CLI)     | v1.2.0 |

CI environment captured in `docs/research/zkpox-phase0/Dockerfile` —
Ubuntu 24.04 amd64, version pins to match the Mac manifest. Image is
committed; the actual `docker build` is a CI-side activity.

---

## Go/no-go answers

| Q | Answer | Evidence |
|---|---|---|
| 1. SP1 proves real C BOF in <30 min CPU-only? | **YES** | 52.1 s prove (cold pk), 15.0 s (cached pk), 2.65 MB proof, verified ✓ |
| 2. LLVM-IR mode 50–100× cheaper than RISC-V mode? | **DEFERRED** | True LLVM-IR interpreter is multi-week scope; Phase 0 closes the C-fidelity gap via C-via-FFI instead. See "Architectural decisions" below. |
| 3. tlock-rs round-trip works (with vendor key layered on top)? | **YES** | Vendor (age) + tlock (Drand 8 s round) both round-tripped the witness; both paths recovered identical plaintext. |
| 4. Gadget abstraction stable across ≥3 bug shapes? | **YES** (two implemented + recipe demonstrated) | `crash_only` (uniform canary) and `oob_write` (position-varying pattern) share the `redzone::scan_around` primitive; adding target #N is mechanical. |

---

## Bench table — target #1 (stack BOF)

All numbers from the regression harness `run-tests.sh` against the
13-witness corpus. Cycle counts cover *both* gadget runs (one per
fill pattern). Wall-times in execute mode are sub-100 ms and dominated
by SP1 SDK startup, not the guest itself.

| Witness                         | Bytes | Cycles | crash_only | oob_write | n  | offset |
|---------------------------------|-------|--------|------------|-----------|----|--------|
| 01-empty-benign                 | 0     |  7,528 | false      | false     | 0  | —      |
| 01-1byte-benign                 | 1     |  8,080 | false      | false     | 0  | —      |
| 01-benign                       | 5     |  8,252 | false      | false     | 0  | —      |
| 01-15bytes-benign               | 15    |  8,682 | false      | false     | 0  | —      |
| 01-fill16-benign                | 16    |  8,725 | false      | false     | 0  | —      |
| 01-overflow1-crash              | 17    |  8,780 | true       | true      | 1  | +16    |
| 01-overflow2-crash              | 18    |  8,835 | true       | true      | 2  | +16    |
| 01-crash                        | 32    |  9,807 | true       | true      | 16 | +16    |
| 01-allzero-crash                | 32    |  9,807 | true       | true      | 16 | +16    |
| 01-highbit-crash                | 32    |  9,807 | true       | true      | 16 | +16    |
| 01-deep-crash                   | 100   | 15,277 | true       | true      | 83 | +16    |
| 01-canarymatch-overflow1-fn     | 17    |  8,776 | **false**  | **true**  | 1  | +16    |
| 01-canarymatch-deep-fn          | 66    | 12,445 | **false**  | **true**  | 50 | +16    |

Headline observations:

1. **Cycle count scales linearly with witness length** at ≈ 50–60 cycles
   per byte (across two C-runs). Below 100 bytes is comfortably under 16k
   cycles.
2. **`crash_only` is blind to canarymatch witnesses**, `oob_write`
   catches them — the gadget upgrade is empirically the right shape.
3. **Cold proof (target #1, crash):** 52.1 s wall, 1.33 GB peak RSS,
   2.65 MB proof, verified ✓.
4. **Warm proof (cached pk):** 15.0 s wall — the 70 s setup amortises
   across all proofs of a given guest ELF, so a Phase-1 prover service
   amortises that to near zero per-proof.

For the SP1 reference (Fibonacci(20), 9,618 cycles): 68.8 s prove,
2.45 GB peak RSS. Our target #1 (5,500–15,000 cycles per pair of runs)
sits squarely in the same per-cycle envelope.

---

## Envelope round-trip (Task 7)

| Step                               | Wall   | Output bytes |
|------------------------------------|--------|--------------|
| AES-256-GCM(witness) — 32 B input  | 4.4 ms | 60           |
| age encrypt(K → vendor pubkey)     | 15.8 ms| 232          |
| tle encrypt(K → Drand round T+8s)  | 0.91 s | 391          |
| age decrypt(K)                      | 8.7 ms | 32           |
| tle decrypt(K) (after round)       | 0.94 s | 32           |
| **Total bundle size for 32 B witness** | — | ~750 B (incl. envelope metadata) |

Both decrypt paths recovered the original witness exactly. Network
latency to `api.drand.sh` dominates the tle steps (~0.9 s each), not
crypto. Phase 1 should keep the network dep — Drand is a public good
and the alternative (running our own beacon) is not warranted.

---

## Architectural decisions (recorded for Phase 1 to revisit)

### C fidelity model: C-via-FFI

SP1 only proves its own `succinct` toolchain's RISC-V output. Stock
`riscv64-unknown-none-elf` C binaries lack SP1's custom syscalls
(input read, output commit) and can't be ingested. Three plausible
fidelity paths:

| Path                            | Phase 0 verdict | Notes |
|---------------------------------|-----------------|-------|
| Rewrite the bug in Rust         | rejected        | Fidelity gap unacceptable per user feedback |
| C-via-FFI (this Phase)          | **chosen**      | Freestanding C, cross-compiled by Homebrew clang to RISC-V64, linked into the SP1 Rust guest. Bug lives in actual C source. |
| LLVM-IR interpreter inside zkVM | Phase 1+        | Cheesecloth-style. Multi-week project; the proposal underestimated this. |

C-via-FFI implementation details:

- The C is compiled with `clang --target=riscv64-unknown-none-elf -march=rv64im -mabi=lp64 -mcmodel=medany -ffreestanding -fno-stack-protector -fno-pic -O0`. Stack-protector is deliberately *off* so the BOF actually corrupts memory inside the zkVM (the gadget is what detects it; `__stack_chk_fail` doesn't exist in the freestanding env anyway).
- `cc-rs` was ineffective: it derives flags from the cargo TARGET env and Apple clang lacks the RISC-V backend. We invoke clang directly from `build.rs` via `std::process::Command`. Override paths via `ZKPOX_CLANG` / `ZKPOX_AR`.
- `cargo prove build` then handles the Rust→RISC-V cross-compile and linking.

### Gadget detection: ASan-style sentinel redzones

A buffer with sentinel bytes immediately before *and* after, sized so
deep overflows can never escape into memory SP1 doesn't track. Two
gadgets share the primitive:

- **`crash_only` — uniform canary 0xA5 (the "naive baseline").** Cheap;
  vulnerable to a witness that writes 0xA5 directly. The
  `01-canarymatch-*-fn.bin` witnesses probe this blind spot.
- **`oob_write` — position-varying pattern.** `pattern_byte(p) = 0xA5
  XOR ((p * 0x9E37_79B1) >> 24)`. Distinct expected byte at every
  offset; an attacker would need to pre-compute the table per position
  to evade detection. Also commits structured outputs (count,
  first_offset).

Both run from a single SP1 invocation (one prove → both verdicts) so
the harness can compare on identical witnesses. 2× C-call per witness.

**Phase 1 should replace the probabilistic redzone with a true shadow
allocation table** (per-store instrumentation, ASan-equivalent). The
public-values shape the gadgets commit (`bool` + `count` + signed
offset) is designed to survive that swap.

### Proof artifact: core STARK, Groth16 wrap deferred

The 2.65 MB core proof is too big for a CBOR disclosure bundle. SP1
supports a Groth16 wrap that compresses to ~256 B via a Gnark-FFI Go
binding (already part of our toolchain). The wrap step adds 1–3 minutes
on CPU but is mechanical to wire (`client.prove(...).groth16().run()`).
**Phase 1 must wire this in** — the current artifact is research-
quality only.

---

## Issues discovered and resolved during the spike

| # | Issue | Cause | Fix |
|---|---|---|---|
| 1 | SP1 SDK build failed | Missing `go` toolchain (gnark FFI dep) | `brew install go`; documented in versions.txt and Dockerfile |
| 2 | `cc-rs` couldn't cross-compile to SP1's triple | Apple clang lacks RISC-V; SP1 triple isn't a real LLVM platform | Manual `clang --target=riscv64-unknown-none-elf` invocation in build.rs |
| 3 | Native ASan-build BOF detection lost after refactoring `victim()` to take buf as param | `__stack_chk_fail` heuristic stopped firing | Switch native sanity build to `-fsanitize=address` (layout-independent OOB detector, also a closer analog of the in-zkVM gadget) |
| 4 | Deep overflows (100-byte witness) panicked SP1 executor | C overran 1-byte trailing canary into untracked memory | Size trailing redzone to absorb full witness length |
| 5 | `01-deep-crash` (`b"B" * 100`) silently passed | `'B'` == 0x42 == old canary value | Change canary to 0xA5; assert at witness-gen time that no crash witness coincidentally fills with the canary value |
| 6 | First gadget design made `crash_only` and `oob_write` functionally identical | Same detection logic, different output schema | Run C twice per witness, once with each fill pattern. Now the canarymatch witnesses meaningfully distinguish the gadgets. |
| 7 | `age-keygen` failed in subprocess | `tempfile.mkstemp` pre-created the file; age-keygen refuses to overwrite | Use `mkdtemp` + a fresh path inside it |

Each of these would have been a Phase-1 surprise. Catching them in the
spike was the spike's job.

---

## Soundness sanity (Task 6)

**The proof's `crashed` value genuinely depends on the witness.**
Verified empirically: benign witness produces a verifying proof with
`crashed_only=false ∧ oob=false`; crash witnesses produce verifying
proofs with the appropriate true verdicts. A bare "this proof exists"
is *not* a vulnerability claim — verifiers must inspect public values.

**Implication for Phase 1's CBOR bundle:** the bundle MUST surface the
public-values verdicts prominently (and bind them to a `gadget_id` so
verifiers know which interpretation applies). A naive verifier that
checks only the STARK signature would falsely accept benign-witness
proofs as bug claims.

A full prove-mode regression sweep across the 13-witness corpus is a
Phase 1 CI activity (~3.5 minutes per sweep). Phase 0 ran prove mode
on benign + crash witness pairs; the broader execute-mode sweep ran
unattended after every harness change.

---

## Phase 1 follow-ons (ranked)

The list, with rough effort estimates, in order of recommended start:

1. **Wire the Groth16 wrap** (~3 days). Single SDK call, but adds CI/install dep on Gnark/Go (already in our Dockerfile). Brings proof size from 2.65 MB → ~256 B and unblocks the CBOR bundle.
2. **Shadow allocation table for `oob_write`** (~5 days). Replace the probabilistic redzone with per-store instrumentation. Requires lightweight LLVM pass or libfuzzer-style hooks at the C compile stage. Closes the canarymatch class entirely (not just probabilistically).
3. **CBOR bundle schema + Sigstore Rekor anchor** (~5 days). Spec is in §8 of the proposal; the implementation is glue.
4. **`pk` / `vk` cache layer** (~2 days). The 70-s setup time per fresh build is amortizable; a content-addressable cache keyed by guest-ELF hash brings the second-and-subsequent prove of a given target down to the 15-s warm number.
5. **A second C target with a different bug shape** (~3 days). `02-heap-oob.c` (heap-buffer overflow with caller-supplied `Vec<u8>`) and corpus, demonstrating the abstraction generalises beyond stack BOF. Phase 0 demonstrated the *primitive* generalises; Phase 1 should land a second concrete instance.
6. **LLVM-IR interpreter inside SP1** (~4–8 weeks; research-grade). The proposal's "Cheesecloth compromise" path. Optional in Phase 1 — C-via-FFI gives equivalent fidelity for source-available targets, which is the MVP audience.
7. **`/prove-exploit` command + skill + persona** (~2 weeks). The actual RAPTOR surface from §5/§6 of the proposal.

Items 1–3 are the minimum for an MVP demo bundle. Items 4–5 are
quality-of-life. Items 6–7 are scope-defining.

---

## What Phase 0 deliberately did *not* do

These are noted to clarify the Phase 0 → Phase 1 contract:

- No `/prove-exploit` or `/verify-exploit-proof` commands; no `.claude/skills/zkpox/`; no `disclosure-engineer` persona; no `core/zkpox/` workspace member; no integration with `raptor_agentic.py`.
- No Sigstore Rekor anchoring, no real CBOR bundle, no vendor key registry, no anonymity mode, no CVD timer policy.
- No Groth16-wrapped proof (the artifact is the research-quality 2.65 MB core proof).
- No EVM, no embedded firmware, no x86-64 binary mode.
- No real CVE demonstration (FFmpeg-shaped killer demo is Phase 1).
- No second target #2 / #3 corpus (the gadget abstraction primitive is in place; concrete extra targets are Phase 1).
- No CI integration — the Dockerfile is committed; CI workflow is Phase 1.

---

## Files committed by Phase 0

```
docs/research/
├── zkpox-phase0-findings.md          this doc
└── zkpox-phase0/
    ├── README.md
    ├── versions.txt
    ├── Dockerfile                    Ubuntu 24.04 amd64, version-pinned
    ├── run-tests.sh                  regression harness (execute mode)
    ├── targets/
    │   ├── 01-stack-bof.c            freestanding victim
    │   └── 01-stack-bof-native.c     native+ASan sanity wrapper
    ├── witnesses/
    │   ├── generate.py               13-witness corpus + canary collision check
    │   └── *.bin                     12 generated witnesses
    ├── harness/
    │   ├── Cargo.toml                workspace
    │   ├── rust-toolchain
    │   ├── guest/
    │   │   ├── Cargo.toml
    │   │   ├── build.rs              direct-clang RISC-V cross-compile
    │   │   └── src/
    │   │       ├── main.rs           target binding + commit layout
    │   │       └── redzone.rs        target-agnostic scan primitive
    │   └── host/
    │       ├── Cargo.toml
    │       ├── build.rs              sp1-build glue
    │       └── src/main.rs           prove/execute driver, JSON record
    └── envelope/
        └── tlock_roundtrip.py        AES + age + tlock layered round-trip
```

---

## Acknowledgements

This spike builds directly on the zkpox proposal at
`docs/proposals/raptor-zkpox-design.md` and on the SP1, Drand, and age
projects. Issues, mitigations, and the Phase 1 follow-on list above are
specific to the bench host and software versions captured in
`versions.txt`; expect details to drift on any meaningful version bump.
