# packages/zkpox — Python orchestration for ZKPoX

Companion to the `core/zkpox/` Rust workspace. Provides:

| Module       | Purpose                                                                          |
|--------------|----------------------------------------------------------------------------------|
| `envelope`   | AES-256-GCM + age + Drand tlock layered encryption. Vendor + time-lock paths.    |
| `prove`      | Locate and drive the `zkpox-prove` binary; parse its JSON record.                |
| `bundle`     | CBOR disclosure-bundle producer/consumer (Phase 1.3 — not yet present).          |
| `verify`     | High-level bundle verification — delegates to `zkpox-verify` (Phase 1.3).        |

## External binary dependencies

The envelope module shells out to two tools that don't have stable Python
bindings:

- **`age` + `age-keygen`** (Homebrew: `brew install age`; apt: `age`)
- **`tle`** (Drand time-lock CLI): `go install github.com/drand/tlock/cmd/tle@latest`

The prove module shells out to the Rust prover:

- **`zkpox-prove`** (this repo): `cargo build --release --manifest-path core/zkpox/Cargo.toml`

## Pip dependencies

- `cryptography` — AES-GCM
- `cbor2` — bundle encoding

## Tests

```sh
pytest packages/zkpox/tests/
```

Network-dependent tests (anything touching `tle`) hit `api.drand.sh` and
are gated on the `RAPTOR_NET_TESTS` env var so offline CI doesn't fail
on them.
