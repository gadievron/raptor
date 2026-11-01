# ZKPoX

ZKPoX has one implementation under `packages/zkpox`. Generic witness capture
and storage belong to `core/witness`; the optional Rust/SP1 backend belongs to
`packages/zkpox/native`. `libexec/raptor-zkpox`, `raptor.py zkpox` and the legacy
`raptor_zkpox.py` entry point delegate to the package CLI.

## Supported claims

Eligibility, private bundle assembly and sandboxed native reproduction support
the existing witness substrate without installing SP1.

The SP1 backend supports **three curated freestanding C sources**, identified
by their exact source hashes. A disclosure proves that a private input caused
the selected uniform or varying canary predicate to detect an out-of-buffer
write in that source, under the embedded guest. It does not prove exploitation
of an arbitrary native binary or an entire upstream project. In particular,
target 03 is an extraction of a libxml2 bug shape, not the full library.

Public disclosures require **SP1 6.5.0 Groth16**. Core proofs remain a diagnostic
backend format and are rejected as disclosures even when relabeled Groth16.
Verification checks the actual proof variant, guest/verifying-key identities,
positive predicate and exact public statement. See [scope](docs/zkpox-scope.md).

The public statement includes a salted witness commitment. Public output omits
the private witness, salt, unsalted witness hash and private bench record.
Encrypted delivery is explicitly `encrypted_unchecked` until a recipient opens
it and verifies its commitment. Public verification cannot establish encryption
consistency or guarantee eventual delivery.

## Build

The host toolchain is Rust **1.95.0**; install `cargo-prove` **6.5.0** from
[the official SP1 release](https://github.com/succinctlabs/sp1/releases/tag/v6.5.0)
and run its `install-toolchain` command. Install clang with RISC-V support,
a C archiver, Go and protobuf `protoc` (validated with 29.3). Install the RAPTOR
Python environment plus `cbor2` and `cryptography`.

```sh
cargo build --release --locked --manifest-path packages/zkpox/native/Cargo.toml
```

Provision the public circuit cache before sandboxed proving:

```sh
export SP1_GROTH16_CIRCUIT_PATH=/path/to/scratch/sp1-groth16
packages/zkpox/native/target/release/zkpox-prove --install-artifacts
```

Use `CARGO_TARGET_DIR`, `CARGO_HOME`, `RUSTUP_HOME`, `TMPDIR`, `GOPATH`,
`GOMODCACHE` and `GOCACHE` to place builds and caches on a sufficiently large disk.
SP1's compiler installation also uses `~/.sp1`. The proving process needs access
to the prepared circuit path, not the operator's home directory. Put the built
`zkpox-prove` and `zkpox-verify` on PATH when using a custom Cargo target directory.

Envelope support additionally needs `age`, `age-keygen` (validated with 1.3.2)
and `tle` (drand/tlock 1.2.0). The tools run through RAPTOR's sandbox. Proving and
verification block network access; Drand operations use a pinned egress host.
A working mount-namespace sandbox is required by the production CLI.

## Commands

Invoke through `bin/raptor zkpox` or the `/zkpox` command. For trusted development
invocations of the internal dispatcher, set `_RAPTOR_TRUSTED=1`.

```sh
libexec/raptor-zkpox bundle /path/to/witness-store WITNESS_SHA256 --out /private/bundle
libexec/raptor-zkpox reproduce /private/bundle --binary /path/to/target --n 3 --timeout 5
libexec/raptor-zkpox prove /private/bundle --target 01 --gadget oob_write --out /public/disclosure
libexec/raptor-zkpox verify /public/disclosure/bundle.cbor --json
libexec/raptor-zkpox inspect /public/disclosure/bundle.cbor
```

`prove` requires the manifest's `target_source_hash` to match the selected
curated source. Private input and public output directories must be separate.
`--threads` bounds Rust/Go proving parallelism (default 8); `--timeout` bounds
wall time (default 7200 seconds), with a matching aggregate CPU-time limit.
Publish `bundle.cbor`; keep the original private bundle private.

Pass `--vendor-pubkey AGE_RECIPIENT --tlock-duration 90d` to seal a delivery.
The vendor can open it with:

```sh
libexec/raptor-zkpox open /public/disclosure/bundle.cbor --identity /private/age-identity --out /private/recovered-witness
```

After release, use `--after-release` instead of `--identity`. Opening verifies
the proof, authenticates the statement as AES-GCM associated data and checks the
recovered salt/witness commitment. It creates a new private file with mode 0600.

Anchoring is opt-in: `prove --anchor` additionally requires `--rekor-url`,
`--rekor-key` (a pinned P-256 log public key PEM), and `--rekor-origin` (the exact
checkpoint origin). Obtain those through a trusted operator channel; bundle
contents cannot supply a trust root. Verify that inclusion with
`verify --require-anchor --rekor-key ... --rekor-origin ...`.
The v2 adapter persists the original log entry and signed checkpoint, verifies
the artifact signature and Merkle inclusion, and reports **inclusion, not a
timestamp**. RFC3161 timestamps and automatic TUF service discovery are not
implemented. Annual log shard names are never guessed. The legacy v1 helpers
require an explicit compatible endpoint for writes.

## Validation

```sh
python3 -m pytest packages/zkpox/tests
cargo test --locked --manifest-path packages/zkpox/native/Cargo.toml -p zkpox-statement
cargo test --locked --manifest-path packages/zkpox/native/Cargo.toml -p zkpox-verify --no-default-features --features structural
```

The structural verifier succeeds only with explicit `--inspect`; normal verify
fails when the crypto backend is absent. Inspection never verifies a proof.

Real proof tests require built binaries and provisioned circuits. Set
`ZKPOX_FULL_PROOFS=1` and run `test_full_verify_e2e.py` with `-m slow`.
Set `ZKPOX_CLI_ROUNDTRIP=1` as well to require the production sandbox roundtrip.
The `ZKPoX native checks` workflow runs fast statement/parser checks on changes;
its explicit full-proof dispatch requires a runner labeled `sp1`, at least
32 GB RAM, adequate free scratch storage and a working production sandbox.

## Runtime and worker configuration

SP1 6.5 needs a 2 TiB sparse shared-memory mapping, a logical size rather than
a disk allocation. The per-proving-job file limit accommodates it;
`zkpox-prove --check-runtime` fails before initialization if the limit is too low.
SDK worker panics terminate the job promptly. The executor and validated witness
are staged only in private writable job scratch.

`prove --circuit-cache DIR` selects prepared public circuits. The unified
launcher forwards the configured or standard cache through argv without widening
the global safe-environment allowlist. Public bundle factories require a v2
statement and omit private witness manifests, unsalted hashes and attestations.
