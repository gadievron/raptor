#!/usr/bin/env bash
#
# Phase 1.5.2 §6 — feature-gate smoke test.
#
# Builds the verifier under both Cargo feature configurations and runs
# ``--help`` on each. Fast (no SP1 prove cycles), and the cheapest
# possible check that the structural / full-verify split compiles
# cleanly on this host. Real end-to-end prove → verify coverage lives
# in ``packages/zkpox/tests/test_full_verify_e2e.py`` (slow tier,
# gated on the SP1 toolchain).
#
# Usage:
#   ./build-verifier-both-features.sh
#
# Exit codes:
#   0   both features build + run --help OK
#   1   structural feature build / help failed
#   2   full-verify feature build / help failed (likely SP1 toolchain absent)

set -euo pipefail

cd "$(dirname "$0")/.."   # core/zkpox

echo "==> structural-only build (no sp1-sdk)"
if ! cargo build --release \
        --manifest-path verifier/Cargo.toml \
        --no-default-features --features structural; then
    echo "FAIL: structural build broken" >&2
    exit 1
fi
if ! ./target/release/zkpox-verify --help >/dev/null; then
    echo "FAIL: structural --help did not run" >&2
    exit 1
fi
echo "  OK"

echo "==> full-verify build (links sp1-sdk + embeds guest ELF)"
# This requires the SP1 toolchain (cargo-prove). If absent, exit 2 so
# CI's fast tier (which won't have SP1) can treat this as expected.
if ! cargo build --release \
        --manifest-path verifier/Cargo.toml \
        --features full-verify; then
    echo "FAIL: full-verify build broken (SP1 toolchain present?)" >&2
    exit 2
fi
if ! ./target/release/zkpox-verify --help >/dev/null; then
    echo "FAIL: full-verify --help did not run" >&2
    exit 2
fi
echo "  OK"

echo "both features built + ran --help"
