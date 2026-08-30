#!/usr/bin/env bash
# zkpox-cve-2017-9047-demo.sh — independent verification walk-through.
# Prereqs: SP1 toolchain (`curl -L https://sp1up.succinct.xyz | bash; sp1up`)
#          + Python 3.12+ + `pip install -r requirements-dev.txt`.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# 1. Build prover + the full-verify verifier. ~20 min cold cache.
echo "== building prover + full-verify verifier =="
cargo build --release --features full-verify \
    --manifest-path core/zkpox/Cargo.toml

# 2. Regenerate the witness corpus (includes the CVE-2017-9047
#    trigger at witnesses/03-overflow1-crash.bin).
python3 core/zkpox/test/witnesses/generate.py

# 3. Confirm the prover finds the bug in execute mode (no STARK
#    wrap — fast). The verdicts the guest publishes include
#    `oob_detected=true`, `oob_count`, `oob_first_offset` — that's
#    the proof's binding to the bug.
echo "== prover sees the overflow =="
./core/zkpox/target/release/zkpox-prove \
    --witness core/zkpox/test/witnesses/03-overflow1-crash.bin \
    --execute --target 3 \
    | jq '.verdicts'   # expect oob_detected:true, oob_count > 0

# 4. Produce a real ZK proof + a CBOR disclosure bundle.
#    --wrap core is the fast wrap (~5 min); --wrap groth16 is the
#    shippable form (~17 min on CPU).
WORK=$(mktemp -d)
cp core/zkpox/test/witnesses/03-overflow1-crash.bin "$WORK/witness.bin"

python3 - "$WORK" <<'PY'
"""Build a minimal Tier 0/1 bundle dir cmd_prove will read."""
import hashlib, json, sys
from pathlib import Path
from packages.zkpox import ZKPoXBundle
from core.hash import sha256_file

work = Path(sys.argv[1])
w = (work / "witness.bin").read_bytes()
# The bundle binds to *some* target artefact's hash; for the demo
# we hash the SP1 guest ELF as the witnessed artefact (its bytes
# are what the proof actually runs against).
elf_path = next(Path("core/zkpox/target/release/build").rglob("zkpox-guest"))
manifest = ZKPoXBundle(
    witness_hash=hashlib.sha256(w).hexdigest(),
    witness_len=len(w),
    source="fuzz", observed_outcome="exit_signal",
    outcome_detail={"finding_id": "CVE-2017-9047"},
    target_binary_hash=sha256_file(elf_path),
    target_source_hash=None,
    produced_by="cve-demo-script", timestamp=None,
    attestation={"claim": "input triggers CVE-2017-9047 in target 03"},
    tier="0/1", reproduction=None,
)
(work / "manifest.json").write_text(json.dumps(manifest.as_dict(), indent=2))
print(f"bundle dir prepared at {work}")
PY

echo "== producing the disclosure bundle (real STARK + real hashes) =="
python3 raptor.py zkpox prove "$WORK" \
    --wrap core \
    --gadget-id "memory-safety::oob-write@0.1.0" \
    --no-anchor

# 5. The headline check — Phase 1.5.4 strict mode (default).
#    Exit 0 means: STARK verified against the embedded guest ELF AND
#    the bundle's vkey/harness hashes match the verifier's derivation.
echo "== verifying under default strict =="
./core/zkpox/target/release/zkpox-verify "$WORK/bundle.cbor"
echo "verify exit: $?  (0 = pass; non-zero would be a FAIL)"

# 6. Tamper test — flip one bit in the proof bytes. Strict must fail.
echo "== tamper test: flip a bit in proof.bytes =="
cp "$WORK/bundle.cbor" "$WORK/tampered.cbor"
python3 - <<PY
from pathlib import Path
p = Path("$WORK/tampered.cbor")
b = bytearray(p.read_bytes())
# Flip a byte near the middle (proof.bytes region — large CBOR bstr).
b[len(b)//2] ^= 0x01
p.write_bytes(b)
PY

if ./core/zkpox/target/release/zkpox-verify "$WORK/tampered.cbor"; then
    echo "REGRESSION: tampered bundle passed strict — investigate."
    exit 1
fi
echo "OK: tampered bundle correctly rejected under default strict"

# 7. Confirm the rejection is precise — the verifier prints which
#    check failed (STARK / harness hash / vkey hash). Useful for
#    proving to a reviewer that the failure isn't generic.
./core/zkpox/target/release/zkpox-verify "$WORK/tampered.cbor" 2>&1 \
    | grep -E "FAIL|stark_verification|harness|verifier_key_hash" || true

echo "== independent verification complete =="

