#!/usr/bin/env python3
"""
Phase 0 envelope round-trip — answers go/no-go question 3.

Demonstrates the layered disclosure-bundle encryption flow:

    plaintext_witness                       (the AFL crash bytes)
       │
       │  AES-256-GCM(K)
       ▼
    ciphertext  +  nonce  +  tag
       │
       └── K is encrypted *twice*, in parallel:
              ▶ to a Drand future round via tle  (time-lock)
              ▶ to the vendor's age public key   (vendor-decryptable)

Two decrypt paths must round-trip the original plaintext:
  1. Vendor path: age decrypt with vendor private key → K → AES decrypt.
  2. Time-lock path: tle decrypt (waits for round) → K → AES decrypt.

For Phase 0 we exercise both with a brief future round (~5–10 s) so the
test completes in a reasonable wall-clock. Phase 1's real envelope uses
a 90-day round (Project Zero norm), which the tle CLI handles
identically — only the round number changes.

Outputs a JSON record describing what was encrypted, what reversed, and
the timing of each step. No Sigstore in Phase 0 (deferred to Phase 1).
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HERE = Path(__file__).resolve().parent
DEFAULT_WITNESS = HERE.parent / "witnesses" / "01-crash.bin"
TLE = shutil.which("tle") or os.path.expanduser("~/go/bin/tle")
AGE = shutil.which("age")
AGE_KEYGEN = shutil.which("age-keygen")


def require(binary: str, name: str) -> str:
    if not binary or not Path(binary).exists():
        raise SystemExit(
            f"required binary not found: {name}. "
            f"Install it before running this script."
        )
    return binary


@dataclass
class StepTiming:
    name: str
    seconds: float
    bytes_out: int = 0


def _run(cmd: list[str], stdin_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        cmd,
        input=stdin_bytes,
        capture_output=True,
        check=True,
    )
    return result.stdout


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM. Returns (nonce_concat_ciphertext_with_tag, key)."""
    nonce = secrets.token_bytes(12)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, associated_data=b"zkpox-phase0-v0")
    return nonce + ct, key


def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    aead = AESGCM(key)
    return aead.decrypt(nonce, ct, associated_data=b"zkpox-phase0-v0")


def gen_age_keypair() -> tuple[Path, str]:
    """Returns (path_to_secret_key_file, public_key_string)."""
    age_keygen = require(AGE_KEYGEN, "age-keygen")
    # Use mkdtemp + a fresh path inside it; age-keygen refuses to
    # overwrite an existing file, which mkstemp would have pre-created.
    tmpdir = Path(tempfile.mkdtemp(prefix="zkpox-age-"))
    sk_path = tmpdir / "secret.txt"
    out = subprocess.run(
        [age_keygen, "-o", str(sk_path)],
        capture_output=True, check=True, text=True,
    )
    # age-keygen prints "Public key: age1..." to stderr.
    pub = ""
    for line in out.stderr.splitlines():
        if line.startswith("Public key: "):
            pub = line.removeprefix("Public key: ").strip()
            break
    if not pub:
        raise RuntimeError(f"could not parse age public key from: {out.stderr!r}")
    return sk_path, pub


def age_encrypt(plaintext: bytes, recipient: str) -> bytes:
    age = require(AGE, "age")
    return _run([age, "-e", "-r", recipient, "-o", "-"], stdin_bytes=plaintext)


def age_decrypt(ciphertext: bytes, identity_file: Path) -> bytes:
    age = require(AGE, "age")
    return _run([age, "-d", "-i", str(identity_file), "-o", "-"], stdin_bytes=ciphertext)


def tle_encrypt(plaintext: bytes, duration: str = "8s") -> bytes:
    tle = require(TLE, "tle")
    return _run([tle, "-e", "-D", duration, "-o", "-"], stdin_bytes=plaintext)


def tle_decrypt(ciphertext: bytes) -> bytes:
    tle = require(TLE, "tle")
    return _run([tle, "-d", "-o", "-"], stdin_bytes=ciphertext)


def main() -> int:
    witness_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WITNESS
    witness = witness_path.read_bytes()
    record: dict = {
        "witness": str(witness_path),
        "witness_bytes": len(witness),
        "steps": [],
        "round_trip": {},
    }

    timings: list[StepTiming] = []

    # --- Step 1: AES-256-GCM the witness with a random key ---
    t = time.perf_counter()
    K = secrets.token_bytes(32)
    ct_witness, _ = aes_encrypt(witness, K)
    timings.append(StepTiming("aes_encrypt_witness", time.perf_counter() - t, len(ct_witness)))

    # --- Step 2: encrypt K to vendor's age pubkey ---
    sk_path, vendor_pub = gen_age_keypair()
    try:
        t = time.perf_counter()
        ct_K_age = age_encrypt(K, vendor_pub)
        timings.append(StepTiming("age_encrypt_key", time.perf_counter() - t, len(ct_K_age)))

        # --- Step 3: encrypt K to a Drand future round (8 seconds out) ---
        t = time.perf_counter()
        ct_K_tlock = tle_encrypt(K, duration="8s")
        timings.append(StepTiming("tle_encrypt_key", time.perf_counter() - t, len(ct_K_tlock)))

        # --- Decrypt path A: vendor (age) ---
        t = time.perf_counter()
        K_via_age = age_decrypt(ct_K_age, sk_path)
        timings.append(StepTiming("age_decrypt_key", time.perf_counter() - t))
        recovered_a = aes_decrypt(ct_witness, K_via_age)
        record["round_trip"]["vendor_path_ok"] = (recovered_a == witness)

        # --- Decrypt path B: time-lock (waits for round) ---
        # Sleep slightly past the duration so the round has finalized.
        wait_secs = 12
        record["round_trip"]["tlock_wait_seconds"] = wait_secs
        time.sleep(wait_secs)
        t = time.perf_counter()
        K_via_tlock = tle_decrypt(ct_K_tlock)
        timings.append(StepTiming("tle_decrypt_key", time.perf_counter() - t))
        recovered_b = aes_decrypt(ct_witness, K_via_tlock)
        record["round_trip"]["tlock_path_ok"] = (recovered_b == witness)
    finally:
        try:
            sk_path.unlink()
            sk_path.parent.rmdir()
        except OSError:
            pass

    record["steps"] = [asdict(t) for t in timings]
    record["round_trip"]["both_paths_ok"] = (
        record["round_trip"].get("vendor_path_ok", False)
        and record["round_trip"].get("tlock_path_ok", False)
    )

    print(json.dumps(record, indent=2))
    return 0 if record["round_trip"]["both_paths_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
