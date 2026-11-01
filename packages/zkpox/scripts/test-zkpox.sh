#!/usr/bin/env bash
# Independent verification walk-through for the curated libxml2 bug extraction.
# Prerequisites and pinned toolchain: packages/zkpox/README.md.
# This generates a real Groth16 proof and may take tens of minutes on CPU.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
umask 077

NATIVE="$PWD/packages/zkpox/native"
TARGET_DIR="${CARGO_TARGET_DIR:-$NATIVE/target}"
if [[ "$TARGET_DIR" != /* ]]; then
    TARGET_DIR="$PWD/$TARGET_DIR"
fi
BIN_DIR="$TARGET_DIR/release"
export PATH="$BIN_DIR:$PATH"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/zkpox-demo-XXXXXX")
PRIVATE="$WORK/private"
PUBLIC="$WORK/public"
mkdir "$PRIVATE"
echo "== working directory: $WORK =="

echo "== building prover + full-verify verifier =="
cargo build --release --locked --features full-verify \
    --manifest-path "$NATIVE/Cargo.toml"

python3 "$NATIVE/test/witnesses/generate.py"
WITNESS="$NATIVE/test/witnesses/03-overflow1-crash.bin"

echo "== prover sees the curated overflow =="
"$BIN_DIR/zkpox-prove" --witness "$WITNESS" --execute --target 03 \
    | jq -e '.verdicts | select(.oob_detected == true and .oob_count > 0)'

cp "$WITNESS" "$PRIVATE/witness.bin"
python3 - "$PRIVATE" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
from packages.zkpox import ZKPoXBundle
from packages.zkpox.statement import source_hash

work = Path(sys.argv[1])
witness = (work / "witness.bin").read_bytes()
manifest = ZKPoXBundle(
    witness_hash=hashlib.sha256(witness).hexdigest(),
    witness_len=len(witness),
    source="fuzz", observed_outcome="unknown", outcome_detail={},
    target_binary_hash=None, target_source_hash=source_hash(3).hex(),
    produced_by="curated-source-demo", timestamp=None,
    attestation={"scope": "freestanding libxml2 bug extraction, not the full library"},
    tier="0/1", reproduction=None,
)
(work / "manifest.json").write_text(json.dumps(manifest.as_dict(), indent=2))
PY

echo "== producing a Groth16 disclosure for curated target 03 =="
# Anchoring is opt-in; this command does not publish to a transparency log.
python3 raptor.py zkpox prove "$PRIVATE" \
    --target 03 --gadget oob_write --out "$PUBLIC"

echo "== verifying proof, statement and guest/key identities =="
"$BIN_DIR/zkpox-verify" "$PUBLIC/bundle.cbor"

echo "== tamper test: change the proof bytes, preserving canonical CBOR =="
python3 - "$PUBLIC/bundle.cbor" "$WORK/tampered.cbor" <<'PY'
from dataclasses import replace
from pathlib import Path
import sys
from packages.zkpox.disclosure import from_cbor, to_cbor

bundle = from_cbor(Path(sys.argv[1]).read_bytes())
proof = bytearray(bundle.proof.bytes)
assert proof, "the real prover must produce nonempty proof bytes"
proof[len(proof) // 2] ^= 1
changed = replace(bundle, proof=replace(bundle.proof, bytes=bytes(proof)))
Path(sys.argv[2]).write_bytes(to_cbor(changed))
PY

if "$BIN_DIR/zkpox-verify" "$WORK/tampered.cbor"; then
    echo "REGRESSION: tampered proof passed verification." >&2
    exit 1
fi

echo "== independent verification complete; tampered proof rejected =="
echo "Public disclosure: $PUBLIC/bundle.cbor"
echo "Keep the private input directory private: $PRIVATE"
