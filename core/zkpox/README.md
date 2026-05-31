# core/zkpox — Zero-Knowledge Proof of Exploit (Rust workspace)

The Rust portion of RAPTOR's zkpox feature: SP1-backed proofs of
memory-safety violation predicates, with a layered disclosure envelope.
**Read `docs/zkpox-scope.md` first** for an honest statement of what
the MVP actually proves (and what it does NOT prove — "exploit" in the
operational sense is broader than what the redzone gadget catches).

Companion Python orchestration lives at `packages/zkpox/`.
Design proposal: `docs/proposals/raptor-zkpox-design.md`.
Phase 0 spike findings: `docs/research/zkpox-phase0-findings.md`.

## Workspace members

| Crate     | Purpose                                                      |
|-----------|--------------------------------------------------------------|
| `guest/`  | The SP1 guest program. Cross-compiled to RISC-V; runs inside the zkVM. Embeds the freestanding C target via clang + linker. |
| `prover/` | Native CLI (`zkpox-prove`) that loads a witness, drives `client.prove()` / `client.execute()`, and emits a JSON record. |
| `verifier/` | Standalone CLI (`zkpox-verify`) that validates a disclosure bundle. Designed to install and run **without** RAPTOR. |

## Build

```sh
# Guest (cross-compile to SP1's custom RISC-V target).
cd core/zkpox/guest && cargo prove build

# Prover + verifier (native).
cd core/zkpox && cargo build --release
```

### Fast local build (no SP1 toolchain)

The verifier's `full-verify` feature (default) links `sp1-sdk`, which
roughly doubles its build time. Contributors who aren't touching the
crypto layer can skip it entirely and build the structural verifier:

```sh
# Structural checks only — CBOR shape, envelope fingerprint, version
# binding. No sp1-sdk, no proving toolchain.
cd core/zkpox && cargo build --release \
  -p zkpox-verify --no-default-features --features structural
```

### Optional: faster local linking / caching (opt-in)

Not committed to the repo because they hard-break any machine missing
the tool. If you have them installed, drop a `core/zkpox/.cargo/config.toml`
of your own:

```toml
# lld host linker — typically much faster than the default on this
# dep-heavy workspace. Needs clang + lld on PATH.
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=lld"]

# sccache — compile cache that survives `cargo clean`. Needs sccache on PATH.
[build]
rustc-wrapper = "sccache"
```

## Test

```sh
# Regression sweep across the 40-witness corpus (execute mode, fast).
cd core/zkpox/test && ./run-tests.sh

# PR-tier subset (8 witnesses) — what CI runs.
cd core/zkpox/test && ./run-tests.sh --ci-subset

# Full prove-mode sweep (slow — ~10 min on warm cache).
cd core/zkpox/test && ./run-tests.sh --prove
```

## Toolchain

Pinned versions in `versions.txt`. Reproducible CI environment in
`Dockerfile`. On macOS, see `versions.txt` for Homebrew clang +
`go install github.com/drand/tlock/cmd/tle@latest` (the latter is
required by `packages/zkpox/envelope.py`, not by this Rust workspace).
