"""Phase 1.5.2 §6 — full-verify end-to-end coverage.

A real prove → bundle → verify round-trip: invoke ``zkpox-prove``
against a minimal witness, drive the Python ``cmd_prove`` flow (which
reads the prover record, computes the gadget code hash, projects a
DisclosureBundle, writes ``bundle.cbor``), then invoke
``zkpox-verify --strict`` against the produced bundle. Strict mode
requires:

  - ``harness.hash`` matching the verifier's embedded guest ELF hash;
  - ``proof.verifier_key_hash`` matching the verifier's derived vkey;
  - the SP1 STARK proof verifying against that vkey.

Gates:

  - ``@pytest.mark.slow`` — SP1 + Groth16 wrap is ~15+ minutes.
  - Skip when ``zkpox-prove`` / ``zkpox-verify`` aren't built.
  - Skip when the SP1 / RISC-V proving stack isn't installed.

CI's ``zkpox-regression`` tier runs the slow marker and has the
toolchain; local runs skip cleanly without it.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from packages.zkpox import proving_stack_available


REPO_ROOT = Path(__file__).resolve().parents[3]
PROVE_BIN = REPO_ROOT / "core" / "zkpox" / "target" / "release" / "zkpox-prove"
VERIFY_BIN = REPO_ROOT / "core" / "zkpox" / "target" / "release" / "zkpox-verify"
ZKPOX_DISPATCHER = REPO_ROOT / "libexec" / "raptor-zkpox"
# A small known witness from the regression corpus. Picked because it's
# the canonical T01 stack-BOF crash — fast to prove, and the entry that
# exercises every step of the pipeline.
CORPUS_WITNESS = (
    REPO_ROOT / "core" / "zkpox" / "test" / "witnesses" / "01-overflow1-crash.bin"
)


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not proving_stack_available(),
        reason="SP1/RISC-V proving stack not installed",
    ),
    pytest.mark.skipif(
        not (PROVE_BIN.exists() and VERIFY_BIN.exists()),
        reason=(
            f"zkpox-prove or zkpox-verify not built. Build with: "
            f"cargo build --release "
            f"--manifest-path core/zkpox/Cargo.toml --features full-verify"
        ),
    ),
    pytest.mark.skipif(
        not CORPUS_WITNESS.is_file(),
        reason=f"corpus witness not found: {CORPUS_WITNESS}",
    ),
]


def _build_tier01_bundle(tmp_path: Path) -> Path:
    """Lay out a minimum Tier 0/1 bundle dir the way ``cmd_prove``
    expects it: a manifest.json (matching the ZKPoXBundle schema) plus
    a witness.bin copy. Avoids spinning up the full ``zkpox bundle``
    flow since the corpus witnesses already carry their own framing."""
    from core.hash import sha256_file
    from packages.zkpox import ZKPoXBundle

    witness_bytes = CORPUS_WITNESS.read_bytes()
    bundle_dir = tmp_path / "tier01"
    bundle_dir.mkdir()
    (bundle_dir / "witness.bin").write_bytes(witness_bytes)
    bundle = ZKPoXBundle(
        witness_hash=__import__("hashlib").sha256(witness_bytes).hexdigest(),
        witness_len=len(witness_bytes),
        source="fuzz",
        observed_outcome="exit_signal",
        outcome_detail={"finding_id": "F1.5.2-e2e"},
        # No real target binary in this test — point at the prover
        # binary itself as a stand-in artefact (its hash is stable).
        target_binary_hash=sha256_file(PROVE_BIN),
        target_source_hash=None,
        produced_by="test_full_verify_e2e",
        timestamp=None,
        attestation={"claim": "phase 1.5.2 end-to-end exercise"},
        tier="0/1",
        reproduction=None,
    )
    (bundle_dir / "manifest.json").write_text(
        json.dumps(bundle.as_dict(), indent=2), encoding="utf-8",
    )
    return bundle_dir


def test_prove_bundle_verify_round_trip_under_strict(tmp_path):
    """The headline Phase 1.5.2 exit-criterion test: a producer-side
    prove → bundle → verify chain returns 0 under ``--strict``.

    A failing strict run means one of: the harness.hash doesn't match
    the verifier's embedded ELF, the proof's vkey doesn't match the
    derived vkey, or the STARK doesn't verify — all of which are
    real regressions worth catching."""
    bundle_dir = _build_tier01_bundle(tmp_path)

    # Drive cmd_prove via the dispatcher so the full operator path
    # (including the proving-stack gate + manifest read + projection)
    # is exercised. core mode picked for speed (still verifiable;
    # Groth16 only adds the wrap and bumps the wall time ~10x).
    env = {**os.environ, "_RAPTOR_TRUSTED": "1", "RAPTOR_DIR": str(REPO_ROOT)}
    out_dir = bundle_dir
    r = subprocess.run(
        [
            str(ZKPOX_DISPATCHER), "prove", str(bundle_dir),
            "--wrap", "core",
            "--gadget-id", "crash-only@0.1.0",
            "--no-anchor",
            "--out", str(out_dir),
        ],
        env=env, capture_output=True, text=True, timeout=2400,  # 40 min ceiling
    )
    assert r.returncode == 0, (
        f"cmd_prove failed (rc={r.returncode})\n"
        f"stdout: {r.stdout}\n"
        f"stderr: {r.stderr[-2000:]}"
    )

    bundle_cbor = out_dir / "bundle.cbor"
    assert bundle_cbor.is_file(), (
        f"bundle.cbor not produced: {out_dir.iterdir()}"
    )

    # Phase 1.5.2 strict: the verifier MUST exit 0. Any of the three
    # failure modes (harness mismatch / vkey mismatch / STARK fail)
    # produces a clean non-zero with a precise message.
    r = subprocess.run(
        [str(VERIFY_BIN), "--strict", str(bundle_cbor)],
        capture_output=True, text=True, timeout=600,
    )
    assert r.returncode == 0, (
        f"zkpox-verify --strict failed (rc={r.returncode})\n"
        f"stdout: {r.stdout}\n"
        f"stderr: {r.stderr}"
    )
    # And the JSON form should report stark_verification: OK ... (not
    # a DEFERRED string and not a FAIL string).
    r = subprocess.run(
        [str(VERIFY_BIN), "--strict", "--json", str(bundle_cbor)],
        capture_output=True, text=True, timeout=600,
    )
    assert r.returncode == 0
    summary = json.loads(r.stdout)
    assert summary["stark_verification"].startswith("OK"), summary
    assert "DEFERRED" not in summary["stark_verification"], summary
