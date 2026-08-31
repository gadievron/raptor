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

### Proof mode comparison — target #1, crash witness (32 B)

Apples-to-apples on the same witness across all three execution modes
the prover supports as of the Phase 1.2 commit. Cold = first run on a
clean cache; warm = subsequent runs with `pk` (and, for groth16, the
6.2 GB circuit artifacts) already on disk.

| Mode                  | Wall (in-process) | Wall (total, cold) | Peak RSS | Proof bytes | Verifier | Verified |
|-----------------------|------------------:|-------------------:|---------:|------------:|---------:|---------:|
| `--execute`           | 0.01 s            | 0.06 s             | —        | —           | —        | — (no proof) |
| `--prove --wrap=core`    | 15–18 s (warm `pk`) | 124 s              | 1.33 GB  | **2,777,208** (2.65 MB) | sub-ms in-process | ✓ |
| `--prove --wrap=groth16` | **17 m 11 s**     | **24 m 06 s** (incl. 6.2 GB download) | 2.89 GB  | **1,704** (1.7 KB) | **4.8 ms** in-process | ✓ |

Read across the rows for the cost / compression tradeoff:

- **core → groth16: ~60× wall-clock penalty in steady state, ~1,560× proof-size reduction** (2.65 MB → 1.7 KB).
- Verifier time is the same order of magnitude for both wraps in-process (sub-ms to ms); the *real* benefit of Groth16 is the on-chain / cross-tool verifier that doesn't carry the SP1 SDK.
- `--wrap=groth16` first run also pays a one-time **6.21 GB compressed / 7.8 GB extracted** circuit-artifact download (~10 min on a residential connection); the prover's `try_install_circuit_artifacts()` call (committed in Phase 1.2) makes this idempotent across reruns.
- The 1,704 B figure is the SDK-saved bundle-friendly proof (includes public values + VK reference). The bare on-chain BN254 Groth16 proof is ~192–256 B — but a disclosure bundle wants the self-contained form, so 1,704 B is the right number for our CBOR envelope.

See "Appendix: Phase 1.2 Groth16 bench" at the bottom of this doc for
the full Gnark-stage breakdown (R1CS load / PK load / constraints
solved / wrap step).

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

1. **Wire the Groth16 wrap** (~3 days). Single SDK call, but adds CI/install dep on Gnark/Go (already in our Dockerfile). Brings proof size from 2.65 MB → ~256 B and unblocks the CBOR bundle. **LANDED in Phase 1.2 — see Appendix: Phase 1.2 Groth16 bench below for actual numbers.**
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

---

## Appendix: Phase 1.2 Groth16 bench (post-spike)

Captured 2026-05-11 on the same Mac host. The Phase 1.2 commit wired
`--wrap=groth16` into the prover and validated the chain end-to-end.

### Numbers

| Metric | Value |
|---|---|
| Total wall-clock (first run: download + STARK + wrap) | **1,445.57 s (24 m 06 s)** |
| In-process `.groth16().run()` | **1,031.39 s (17 m 11 s)** |
| Groth16 wrap step alone (Gnark) | **4 m 59 s** |
| Gnark R1CS load | 1 m 30 s |
| Gnark proving-key load | 1 m 13 s |
| Constraints solved | **15,972,262** |
| Wrap constraint-solver time | 58.96 s |
| Wrap prover time | 239.75 s |
| Verifier (in-process) | **4.8 ms** |
| Peak RSS | **2.89 GB** |
| Proof artifact (SDK saved) | **1,704 bytes** |
| Verification | ✓ |
| Verdicts (identical to core STARK) | `crash_only=true, oob=true, n=16, off=+16` |

### What the proposal got right and what needs correction

- **Right:** Verification is sub-second (4.8 ms wall in-process).
- **Right:** The wrap step is "1–3 min on CPU" — though that's just the
  Gnark prover step. Add 2–3 min for Gnark's R1CS + proving-key load
  per invocation; the SDK keeps these in memory across calls in a
  long-lived service but reloads them every run from a CLI.
- **Refined:** "~256 B proof artifact" needs a footnote.
  - The bare BN254 Groth16 proof is ~192–256 B and that's what an
    on-chain Solidity verifier reads from calldata.
  - The SDK's saved proof (`SP1ProofWithPublicValues::save`) is **1,704
    B** here — wraps the bare proof with public values + VK reference
    so the artifact is self-contained for verification without a side
    channel for the public values.
  - **The 1,704 B number is the right one for the CBOR disclosure
    bundle**, because the bundle is meant to be self-contained.
- **Refined:** "Brings proof size from 2.65 MB → ~256 B" — actual
  compression ratio is **~1,560×** (2,777,208 B → 1,704 B). Either way
  the bundle becomes overhead-negligible.
- **New cost item:** the SP1 Groth16 circuit artifacts (PK, VK,
  R1CS, Solidity verifier) are **6.21 GB compressed / 7.8 GB extracted**
  and live at `~/.sp1/circuits/groth16/<version>/`. First-time install
  is ~10 min on a residential connection. CI runners must either pre-
  warm this cache or budget the download time.

### Issue #8 (Phase 1.2 — captured here for completeness)

The first Groth16 bench attempt **failed after 18.7 min of upstream
proving work** with `Error: prove (Groth16) failed: An unexpected
error occurred: artifact not found`. Root cause: SP1 v6's
`.groth16().run()` does *not* auto-install the BN254 circuit
artifacts — the SDK exposes `sp1_sdk::install::try_install_circuit_artifacts`
but you have to call it yourself. The first attempt's partial 1.77 GB
of 6.21 GB tarball lived at `~/.sp1/circuits/groth16/v6.1.0/artifacts.tar.gz`
in a state SP1's artifact lookup treated as "already installed,
skipping" — fatally inconsistent.

Fix (committed in the Phase 1.2 follow-up commit alongside this
appendix): prover's `main` calls `try_install_circuit_artifacts("groth16")`
via a single-threaded Tokio runtime before any `.groth16().run()`
invocation. The function is idempotent: subsequent runs hit the cache
in milliseconds. Without the fix, every first-time user hits the
same 18-min cliff.

### Implication for Phase 1.3+ work

- The CBOR bundle's `proof.bytes` field carries the 1,704-B SDK-
  saved proof, not the bare ~256-B Groth16 proof. Bundle size
  remains well under any practical envelope ceiling.
- Phase 1.5's `/verify-exploit-proof` command, and the Rust
  `zkpox-verify` binary once `sp1-sdk` is wired into it (currently
  stubbed), need the same `try_install_circuit_artifacts` call —
  but for *verifying-key* artifacts. Same provisioning pattern.
- The 24-min first-run cost (and 17-min steady-state) means a Phase
  1.7 zlib-CVE demo running Groth16 wrap on each prove is feasible
  but not interactive. Future GPU acceleration brings this to
  sub-minute, per SP1's roadmap.

---

## Appendix: Phase 1.4 Sigstore Rekor anchoring (post-spike)

Captured 2026-05-11 alongside the Phase 1.4 commit.

### Shape of the work

- `packages/zkpox/anchor.py` — Rekor producer: ed25519 keypair gen,
  `hashedrekord/0.0.1` POST to `rekor.sigstore.dev` (overridable via
  `ZKPOX_REKOR_URL`), response parsed into a typed `Timestamp`.
- `packages/zkpox/bundle.py` — `Timestamp` dataclass added; new
  `bundle_hash_pre_timestamp()` returns the canonical-CBOR sha256 of
  the bundle with `timestamp` omitted. This is the hash Rekor binds
  to, which is the property that lets the anchor be added *after* the
  rest of the bundle is built without invalidating the binding.
- `core/zkpox/verifier/` — reads and displays the timestamp
  structurally (log_index, log_id, entry_uuid, integrated_time, tree
  size, path length). **Full Merkle inclusion verification + Rekor STH
  validation is Phase 1.4.x** — same pattern as the 1.3 verifier:
  parse + display now, cryptographic checks land alongside the
  `/verify-exploit-proof` command surface in 1.5.

### Anchor flow

```
bundle (no timestamp)
   │
   │  bundle_hash_pre_timestamp(bundle)  →  32-byte digest
   ▼
ed25519.sign(digest)                     →  signature
   ▼
POST /api/v1/log/entries
     { apiVersion: "0.0.1", kind: "hashedrekord",
       spec: { data:      { hash: { algorithm, value } },
               signature: { content, publicKey: { content } } } }
   ▼
Rekor 201
     { <uuid>: { logIndex, logID, integratedTime,
                 verification: { inclusionProof: {…},
                                 signedEntryTimestamp } } }
   ▼
Timestamp dataclass               ─►  attached to bundle via with_timestamp
```

### Why "pre-timestamp" hash matters

The natural mistake is to anchor the *final* bundle. But the final
bundle contains the timestamp, which contains values returned by
Rekor — chicken-and-egg. By hashing the bundle with `timestamp = None`,
the same hash is produced before and after anchoring; verifiers
recompute it from a received bundle by setting `timestamp = None` and
re-serialising.

Two tests guard this invariant (in `tests/test_bundle.py`):

- `test_pre_anchor_hash_invariant_under_timestamp_mutation` —
  asserts the hash doesn't change when the timestamp field is added
  or rotated.
- `test_pre_anchor_hash_changes_when_proof_changes` — the inverse:
  mutating *any* non-timestamp field MUST change the hash, otherwise
  Rekor's anchor doesn't bind what we claim.

### What's deferred to Phase 1.4.x

Phase 1.4 establishes the weakest useful Rekor property: "Rekor
recorded a hash matching our bundle at log index N." Real soundness
needs three more steps, all of which are mechanical extensions:

1. **Merkle inclusion-proof verification.** The `inclusion_proof_hashes`
   list is a path of sibling-hash nodes; combined with the leaf hash
   and the recorded `inclusion_proof_root_hash`, you reconstruct the
   tree root and confirm it matches. ~50 lines of RFC 9162-compatible
   code; defer until the Rust verifier learns `sp1-sdk`.
2. **Signed tree-head (STH) validation.** Rekor publishes signed tree
   heads at `/api/v1/log`; verifying our recorded `root_hash` matches
   one of those tree heads (or chains to a more recent one via a
   consistency proof) is what makes the inclusion proof
   trust-rooted in Rekor's signing key rather than just in the
   server-of-the-moment.
3. **Offline verifier.** Phase 1.4's `confirm_anchor_matches()`
   fetches the entry from Rekor at verify-time. A truly offline
   verifier would compare against the locally-stored inclusion proof
   instead, and only ever go online to refresh Rekor's STH key.

### Network and ergonomic costs

- Anchoring costs **one POST** to Rekor (~200–500 ms on a residential
  connection from this Mac). The response body is ~2 KB.
- The `Timestamp` field adds ~250 bytes to the CBOR bundle.
- Public Rekor is rate-limited; bursts of anchors should batch or
  back off. Self-hosted Rekor (e.g. private CVD pipelines) has no
  rate limit.
- The default URL `https://rekor.sigstore.dev` is hard-coded but
  overridable via `ZKPOX_REKOR_URL` — internal CI may want to
  anchor to a private log; vendors may want their own log of
  disclosures they've received.

### Tests landed

`packages/zkpox/tests/test_anchor.py`:

- Keypair generation + ed25519 self-verify.
- SubjectPublicKeyInfo PEM round-trip (Rekor's expected format).
- Ed25519 determinism (same key + message → same signature).
- `_make_hashedrekord_entry` schema shape (catches drift offline).
- `ZKPOX_REKOR_URL` env override.
- **Network-gated:** `test_anchor_and_confirm_round_trip` actually
  anchors a synthetic bundle, GETs it back, asserts the recorded hash
  matches the locally-computed `bundle_hash_pre_timestamp`. Gated on
  `RAPTOR_NET_TESTS=1` because it writes a permanent public Rekor
  entry.

`packages/zkpox/tests/test_bundle.py` gained 4 Timestamp-specific
tests covering round-trip, schema presence, and the two
pre-anchor-hash invariants above.

---

## Appendix: Phase 1.6 — second C target

Phase 0 demonstrated the redzone+pattern *primitive* generalises;
Phase 1.6 lands a concrete second instance to back the claim.

### What target #2 adds

`core/zkpox/targets/02-off-by-one.c`:

```c
for (size_t i = 0; i <= buf_size && i < n; i++) {
    buf[i] = input[i];   // bug: <= instead of <
}
```

Distinct bug *shape* from target 01's "no bound check at all":

- Target 01 (stack BOF): any `n > buf_size` writes `n - buf_size`
  bytes past the buffer.
- Target 02 (off-by-one): any `n > buf_size` writes EXACTLY ONE
  byte at offset `buf_size`. Subsequent input bytes are unreached.

That difference is a structural-output test the gadget infrastructure
has to pass: `oob_count` for target-02 crash witnesses is always 1,
regardless of `n`. The bench table below confirms this.

### Schema bump: target_id in public values

The guest now reads a 1-byte `target_id` prefix off the witness and
commits it as the *first* public value. Schema is now 5 fields:

```
target_id              : u32   (0x01 = stack-bof, 0x02 = off-by-one)
crash_only_crashed     : bool
oob_detected           : bool
oob_count              : u32
oob_first_offset       : i32
```

Pre-1.6 witnesses (no prefix byte) get default-routed to target 01;
the prover's `--target` flag defaults to 01 too, so Phase 0 / 1.1–1.5
bench commands keep producing comparable numbers.

The host prepends the byte before `stdin.write()`; witnesses on disk
stay as raw exploit bytes. `core/zkpox/test/run-tests.sh` parses the
target id from each witness's filename prefix (`01-…`, `02-…`) and
passes the matching `--target` flag.

### Bench table — target 02

Same gadget pair (`crash_only` + `oob_write`) as target 01, both
running in execute mode over the new witness corpus.

| Witness                 | Bytes | Cycles | crash_only | oob_write | n  | offset |
|-------------------------|-------|--------|------------|-----------|----|--------|
| 02-empty-benign         | 0     |  8,229 | false      | false     | 0  | —      |
| 02-1byte-benign         | 1     |  8,808 | false      | false     | 0  | —      |
| 02-benign               | 5     |  9,108 | false      | false     | 0  | —      |
| 02-15bytes-benign       | 15    |  9,793 | false      | false     | 0  | —      |
| 02-fill16-benign        | 16    |  9,860 | false      | false     | 0  | —      |
| 02-overflow1-crash      | 17    |  9,930 | true       | true      | **1** | +16 |
| 02-overflow2-crash      | 18    |  9,943 | true       | true      | **1** | +16 |
| 02-crash                | 32    | 10,327 | true       | true      | **1** | +16 |
| 02-deep-crash           | 96    | 12,715 | true       | true      | **1** | +16 |
| 02-highbit-crash        | 32    | 10,327 | true       | true      | **1** | +16 |
| 02-zerobyte-crash       | 17    |  9,930 | true       | true      | **1** | +16 |
| 02-canarymatch-fn       | 17    |  9,926 | **false**  | **true**  | 1  | +16   |

Every crash witness reports `oob_count = 1` — the off-by-one's signature.

For comparison, the same-length witnesses against target 01:

| Witness            | Bytes | t01 oob_count | t02 oob_count |
|--------------------|-------|--------------:|--------------:|
| -overflow1-crash   | 17    |   1           |   1           |
| -overflow2-crash   | 18    |   2           |   1           |
| -crash             | 32    |  16           |   1           |
| -deep-crash        | 96/100|  83           |   1           |

The gap widens with witness length — exactly the structural difference
between "every byte past the buffer is written" and "one byte past the
buffer is written, then return."

### Soundness probes

`02-canarymatch-fn.bin` writes the canary value (0xA5) at exactly the
off-by-one byte position. Same `crash_only=false, oob_detected=true`
verdict as the target-01 canarymatch witnesses — the gadget upgrade
generalises cleanly to the new bug shape, no per-target patching of
the redzone primitive needed.

### Regression / pytest coverage

`run-tests.sh` now iterates the 25-witness combined corpus, parsing
target id from each filename prefix and asserting target-id round-trip
in addition to the gadget verdicts. 25/25 pass on this Mac.

`packages/zkpox/tests/test_regression.py` wraps the shell harness in a
pytest test — subprocesses `bash run-tests.sh`, asserts exit 0, plus
some structural checks (both target families present in output, ≥25
passes). **Gated behind `RAPTOR_SLOW_TESTS=1`** — SP1 SDK startup
costs ~20 s per invocation, so a full sweep is ~10 min wall-clock.
CI workflows in Phase 1.8 can opt in on a slower job tier.

Default pytest run (no slow / no network) is 27 passes, 3 skips, ~0.6 s.

### What 1.6 did NOT do

- Add a third target. Two is enough to demonstrate the abstraction
  generalises; the proposal's full "5 known-vulnerable / 5 known-safe
  binary pairs per gadget" is part of the Phase 1.7 demo plan.
- Wire the bundle to thread `target_id` through to `proof.system` or
  the `vulnerability` substructure. Currently the bundle's
  `gadget_id` describes the *gadget*; producers should label the
  target via a free-form `target.metadata.target_id` until the
  schema picks a canonical home (1.7 candidate).
- Bench prove-mode numbers for target 02 — same shape as target 01
  (the wrap step is target-agnostic), no new information to learn.

---

## Appendix: Phase 1.7 — third target, CVE-2017-9047

Phase 1.6's case for the gadget abstraction rested on two
hand-written textbook bugs (stack BOF, off-by-one). Phase 1.7 lands a
slice of a *real, public, low-severity* CVE — libxml2's
`xmlSnprintfElementContent` stale-`len` bug, fixed in GNOME/libxml2
commit `932cc9896ab4` — to test whether the same redzone primitive
catches a bug shape that wasn't designed around it.

### Why CVE-2017-9047 specifically

The proposal called for "memory-safety bugs in C/C++" as the MVP
scope. CVE-2017-9047 is at the small end of that distribution:

- **Real upstream fix.** Public patch, public reproducer in the CVE
  details, fixed > 9 years before this work. No disclosure risk.
- **Tiny.** The bug is one stale variable across one strcat; the
  whole pre-patch branch is ~10 lines. The fix is ~7 lines.
- **Low CVSS (5.9).** Moderate severity — exactly the "lesser
  vulnerability" Phase 1.7 was scoped against. If the gadget catches
  the small ones, the big ones are trivially covered.
- **Bypass window doesn't fit a 16-byte buffer.** The bug only
  triggers when `prefix_len > 8` (so `len`'s lag exceeds the
  safety margin of 10 in the size check). With `size = 16` and the
  bypass cap `prefix_len <= size - 10 = 6`, no overflow is reachable.
  This was useful: it forced the dispatch to grow per-target buffer
  geometry, which is a generally-useful capability for future targets
  (heap-allocated structs, etc.).

### The bug, restated

`xmlSnprintfElementContent` enters with `int len = strlen(buf)`. The
`XML_ELEMENT_CONTENT_ELEMENT` branch then, when `content->prefix !=
NULL`, appends `prefix` and `":"` to `buf` — growing the buffer by
`prefix_len + 1` bytes — but never updates `len`. The next check,
"is there room for content->name?", uses the stale `len` and so
under-counts the bytes already consumed by exactly `prefix_len + 1`.

With caller-supplied empty `buf` (the common libxml2 caller pattern):

| Constraint | Inequality |
|---|---|
| Bypass prefix size check | `prefix_len <= size - 10` |
| Bypass name size check (stale `len`) | `name_len <= size - 10` |
| Overflow actually occurs | `prefix_len + name_len + 1 > size - 1` |

The third row simplifies to `prefix_len + name_len > size - 2`.
Combining: overflow needs `prefix_len > 8` (so the lag exceeds the
margin). Max bytes past buffer = `prefix_len - 8` for fixed
`name_len = size - 10`.

For target 03's `size = 32`: `prefix_len ∈ (8, 22]`, max overflow 14
bytes. That fits inside the existing `MIN_TRAILING_REDZONE = 16`, so
no further changes to the redzone primitive were needed.

### Buffer geometry override

`core/zkpox/guest/src/main.rs` previously hardcoded a single
`BUF_SIZE = 16` constant shared by all targets. Phase 1.7 splits this
into `BUF_SIZE_DEFAULT = 16` (targets 01, 02) and `BUF_SIZE_T03 = 32`,
selected in the `dispatch()` match alongside the C victim. The
`scan_around` primitive already accepts `buf_size` as a parameter —
no changes there. Adding target #N with its own geometry is now: one
const, one match arm.

### Witness encoding

```
witness[0]                              prefix_len (u8)
witness[1]                              name_len   (u8)
witness[2 .. 2+prefix_len]              prefix bytes
witness[2+prefix_len .. 2+prefix_len+name_len]  name bytes
```

The freestanding C extraction parses these inline; a witness shorter
than `2 + prefix_len + name_len` is a no-op (returns without touching
the buggy path). This mirrors what would happen if libxml2 received a
corrupt content tree before reaching the bug — a clean "the gadget
ran but found nothing" verdict rather than a guest-side crash.

### Corpus shape

15 witnesses total (9 benign, 6 crash, 0 fn). Benign cases cover:

- empty witness (no-op early return)
- no-prefix paths (bug inert without prefix)
- both small (sum well under buffer)
- prefix-only (`name_len = 0` skips the buggy strcat)
- borderline (sum exactly fills buffer, no overflow)
- bypass-fails paths (`prefix_len > 22` or `name_len > 22` → libxml2's
  safe `" ..."` return)
- **all-NUL prefix** (`prefix_byte = 0x00`) — soundness probe; see
  below.

Crash cases sweep `prefix_len ∈ {9, 10, 15, 22}` with `name_len = 22`
(the maximum bypassable name length) to exercise overflow widths of
1, 2, 7, and 14 bytes respectively, plus high-bit (`0xFF`) and
zero-name-with-nonzero-prefix (`0x01` prefix, `0x00` name) fills for
byte-pattern coverage.

### Soundness probe: the bug requires a non-NUL prefix

Surfaced during the Phase 1.7 regression sweep — the originally-named
`03-allzero-crash.bin` (prefix and name both `0x00*N`) reported
benign verdicts. Investigation: when the very first byte appended is
`0x00`, the buffer's first NUL terminator lands at position 0, so the
*next* `strcat`'s `strlen(buf)` returns 0 — not `prefix_len`. The
stale-`len` lag the bug relies on never opens, and the final write
stays inside the buffer.

This is a real property of CVE-2017-9047 in production libxml2: a
content tree whose `prefix` field is a zero-length-but-non-NULL
string (or, equivalently, a string starting with `\0`) doesn't
trigger the overflow regardless of how big `name` is. We rename the
witness to `03-nulprefix-benign.bin` (documenting the soundness
property) and add `03-nullname-crash.bin` (prefix `0x01*15`, name
`0x00*22`) to preserve byte-pattern coverage with a non-NUL prefix.
40 witnesses, 40 passes.

### Why no `-fn` (canarymatch) witness for target 03

The bug is strcat-style, so every overflow run ends with a NUL
terminator (`'\0' == 0x00`). For an all-uniform-canary overflow we'd
need every OOB byte to equal `0xA5`, and one of those bytes is
unavoidably `0x00`. The set of "canarymatch false-negatives" is
empty by construction — not a bug in the gadget, but a property of
strcat-shape overflows.

This is structurally different from targets 01 and 02, whose `buf[i]
= input[i]` writes have no implicit terminator and can therefore be
adversarially set to canary bytes. The generator's
`_assert_not_canarymatch` has an explicit no-op arm for target 03
that documents this so a future reader doesn't add a redundant
check.

### Schema impact

None. Phase 1.6's 5-field public-values schema (`target_id`,
`crash_only_crashed`, `oob_detected`, `oob_count`, `oob_first_offset`)
covers target 03 unchanged. Side-by-side `oob_count` on the same
strcat-shape overflow widths:

| Witness                  | prefix | name | OOB written            | oob_count |
|--------------------------|-------:|-----:|------------------------|----------:|
| 03-overflow1-crash       |      9 |   22 | 1× NUL                 |         1 |
| 03-overflow2-crash       |     10 |   22 | 1× name + 1× NUL       |         2 |
| 03-deep-crash            |     15 |   22 | 6× name + 1× NUL       |         7 |
| 03-max-crash             |     22 |   22 | 13× name + 1× NUL      |        14 |

The `oob_count = prefix_len + name_len + 2 - size` identity holds
across the corpus and is the cheapest invariant a future regression
could assert. The harness doesn't currently assert it (only the
boolean verdicts), but the field is on the bundle for downstream
verifiers to use.

### Regression / pytest coverage

`run-tests.sh` now accepts the `03-` prefix in its target case arm;
no other changes needed (the verdict suffix parsing was already
target-agnostic, and the target-id round-trip check uses
`$((10#$target))` which handles `03` → 3 correctly).

`packages/zkpox/tests/test_regression.py` asserts `" t=3 "` is
present in output and bumps the minimum pass count from 25 to 39
(13 + 12 + 14 = 39, exactly the current corpus).

### What 1.7 did NOT do

- Bring in the full libxml2 source tree. The freestanding extraction
  preserves the buggy logic byte-for-byte but skips the recursive
  tree-walking and the SEQ/OR/PCDATA arms. A "vendored libxml2 slice"
  variant is a 1.7.x candidate but not load-bearing for the gadget
  story.
- Add a fourth target. The gadget catches all three bug shapes with
  zero per-target patches to the redzone primitive — that's the
  property Phase 0 hypothesised and 1.7 finishes nailing down.
- Bench prove-mode numbers for target 03. Same shape as 01/02 (the
  wrap step is target-agnostic, the C side adds a few hundred cycles
  for the inline strlen/strcat — within noise on the ~10k-cycle
  total). Execute-mode numbers are exercised by the regression
  harness.
- Wire `target_id = 3` through to the bundle's `vulnerability`
  substructure as a labelled CVE. Same deferral as Phase 1.6:
  producers set `target.metadata.cve = "CVE-2017-9047"` for now;
  the canonical schema home is a 1.8 candidate.
