"""
Layered envelope encryption for zkpox disclosure bundles.

The bundle's witness payload is encrypted with AES-256-GCM under a fresh
random key K; K is then encrypted *twice*, in parallel:

  * to a Drand future round via tle (time-lock)        → public after T
  * to the vendor's age public key                     → vendor-readable now

Two decrypt paths must therefore round-trip the original plaintext:

  1. Vendor path: age -d -i <vendor.sk> < ct_K_age → K → AES decrypt.
  2. Time-lock path: tle -d < ct_K_tlock (waits for round) → K → AES decrypt.

Phase 1.3's CBOR bundle stores `ct_K_age` and `ct_K_tlock` as the
`vendor_envelope` field's `ciphertext` (per proposal §8 — both blobs are
present so the bundle is self-contained for either decrypt path).

External binaries: `tle` (`go install github.com/drand/tlock/cmd/tle`)
and `age` + `age-keygen` (Homebrew / apt). Neither has stable Python
bindings; subprocess is the pragmatic interop. Every invocation goes
through `core.sandbox.run_untrusted` — Landlock + namespace network
block + env hygiene; the tle paths additionally pin the egress proxy
to `api.drand.sh` so attacker-crafted ciphertext can't smuggle the
binary into reaching arbitrary hosts.
"""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.sandbox import run_untrusted

# Drand mainnet API — the only hostname `tle` reaches for the time-lock
# rounds. Egress proxy is pinned to this host so a compromised `tle`
# binary can't reach arbitrary network endpoints.
_DRAND_HOST = "api.drand.sh"


# Wide associated data so an attacker can't take a ciphertext from a
# different protocol and feed it to a zkpox verifier as if it were a
# bundle witness. Bumped on any breaking change to the envelope layout.
_AAD = b"zkpox-envelope-v1"


def _which_tle() -> str | None:
    return shutil.which("tle") or _expand_or_none("~/go/bin/tle")


def _which_age() -> str | None:
    return shutil.which("age")


def _which_age_keygen() -> str | None:
    return shutil.which("age-keygen")


def _expand_or_none(path: str) -> str | None:
    p = os.path.expanduser(path)
    return p if Path(p).exists() else None


def require(binary: str | None, name: str) -> str:
    if not binary:
        raise EnvelopeToolError(
            f"required binary not found: {name}. "
            f"See packages/zkpox/README.md for install instructions."
        )
    return binary


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class Envelope:
    """Layered ciphertexts for a single witness payload."""

    aes_blob: bytes      # nonce(12) || AES-GCM(witness, key=K)
    ct_K_age: bytes      # age-encrypted K (vendor path)
    ct_K_tlock: bytes    # tle-encrypted K (time-lock path)


@dataclass(frozen=True)
class AgeKeypair:
    """Vendor's age keypair. Phase-1 vendor registry will publish only
    the public key; the secret key never leaves the vendor's machine.
    For Phase 1.1 tests we generate ephemeral pairs."""

    secret_key_path: Path  # caller is responsible for cleanup
    public_key: str


class EnvelopeError(Exception):
    """Base for envelope-layer errors."""


class EnvelopeToolError(EnvelopeError):
    """Required external tool (tle, age, age-keygen) missing."""


class EnvelopeRoundTripError(EnvelopeError):
    """A decrypt path failed to recover the original plaintext."""


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-256-GCM. Returns nonce || ciphertext-with-tag.

    Caller manages key lifecycle; this function does not retain it.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key (got {len(key)})")
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, _AAD)


def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    """Inverse of :func:`aes_encrypt`."""
    if len(blob) < 12:
        raise ValueError("blob too short to contain a nonce")
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, _AAD)


def gen_age_keypair() -> AgeKeypair:
    """Generate a fresh age keypair via the system `age-keygen` binary.

    Returns the path to the secret-key file (a 0600 temp file the caller
    is responsible for unlinking) and the public key string. age-keygen
    refuses to overwrite existing files, so we use a fresh path inside
    a fresh tempdir.
    """
    keygen = require(_which_age_keygen(), "age-keygen")
    tmpdir = Path(tempfile.mkdtemp(prefix="zkpox-age-"))
    sk_path = tmpdir / "secret.txt"
    # Sandboxed: Landlock-scope the writable area to ``tmpdir`` so a
    # compromised age-keygen can only land its output file in this
    # per-call temp dir. No network. ``tool_paths`` makes the keygen
    # binary's parent dir readable in mount-ns hosts where Homebrew /
    # /opt/homebrew/bin aren't on the default safe-bin path.
    out = run_untrusted(
        [keygen, "-o", str(sk_path)],
        output=str(tmpdir),
        tool_paths=[str(Path(keygen).parent)],
        caller_label="zkpox-age-keygen",
        capture_output=True, check=True, text=True,
    )
    pub = ""
    for line in out.stderr.splitlines():
        if line.startswith("Public key: "):
            pub = line.removeprefix("Public key: ").strip()
            break
    if not pub:
        raise EnvelopeError(f"could not parse age public key from: {out.stderr!r}")
    return AgeKeypair(secret_key_path=sk_path, public_key=pub)


def age_encrypt_to(plaintext: bytes, recipient_pubkey: str) -> bytes:
    age = require(_which_age(), "age")
    # age is local-only — no network.
    return _run([age, "-e", "-r", recipient_pubkey, "-o", "-"], plaintext)


def age_decrypt_with(ciphertext: bytes, identity_file: Path) -> bytes:
    age = require(_which_age(), "age")
    # age is local-only — no network. ``identity_file`` is the most
    # attacker-facing input (vendor secret key paired with attacker-
    # crafted ciphertext), so it's read-only-scoped via ``readable_paths``.
    return _run(
        [age, "-d", "-i", str(identity_file), "-o", "-"],
        ciphertext,
        readable_paths=[str(Path(identity_file).parent)],
    )


def tle_encrypt(plaintext: bytes, duration: str = "90d") -> bytes:
    """Time-lock encrypt to a Drand future round.

    `duration` is a Go-style duration string (e.g. ``"90d"``, ``"30m"``,
    ``"8s"``). Default 90 days mirrors the Project Zero CVD norm; tests
    pass a short ``"8s"`` so the round-trip terminates in the test's
    wall-clock budget.
    """
    tle = require(_which_tle(), "tle")
    # tle needs api.drand.sh to fetch the chain info; egress proxy
    # pins it to that host only.
    return _run([tle, "-e", "-D", duration, "-o", "-"], plaintext,
                proxy_hosts=[_DRAND_HOST])


def tle_decrypt(ciphertext: bytes) -> bytes:
    """Decrypt a tle blob. Blocks until the encrypted-to round finalises.

    Caller is responsible for sleeping past the duration before invoking
    this — tle itself will retry-poll the Drand network.
    """
    tle = require(_which_tle(), "tle")
    # tle polls Drand for the finalised round; egress proxy pins to
    # api.drand.sh so attacker-crafted ciphertext can't be used to
    # smuggle the binary into reaching arbitrary endpoints.
    return _run([tle, "-d", "-o", "-"], ciphertext,
                proxy_hosts=[_DRAND_HOST])


def seal(witness: bytes, vendor_pubkey: str, *, duration: str = "90d") -> Envelope:
    """High-level: produce the three layered ciphertexts for a witness.

    Generates a fresh AES key K, encrypts the witness under it, then
    encrypts K to both the vendor pubkey (age) and a Drand future round
    (tle). Returns the bundle-ready :class:`Envelope`.
    """
    K = secrets.token_bytes(32)
    aes_blob = aes_encrypt(witness, K)
    ct_K_age = age_encrypt_to(K, vendor_pubkey)
    ct_K_tlock = tle_encrypt(K, duration=duration)
    return Envelope(aes_blob=aes_blob, ct_K_age=ct_K_age, ct_K_tlock=ct_K_tlock)


def open_via_vendor(envelope: Envelope, vendor_key_path: Path) -> bytes:
    """Open an envelope by the vendor path: age decrypt K, then AES."""
    K = age_decrypt_with(envelope.ct_K_age, vendor_key_path)
    return aes_decrypt(envelope.aes_blob, K)


def open_via_tlock(envelope: Envelope) -> bytes:
    """Open an envelope by the time-lock path: tle decrypt K, then AES.

    Blocks until the Drand round finalises.
    """
    K = tle_decrypt(envelope.ct_K_tlock)
    return aes_decrypt(envelope.aes_blob, K)


# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------

def _run(
    cmd: list[str],
    stdin_bytes: bytes | None = None,
    *,
    proxy_hosts: list[str] | None = None,
    readable_paths: list[str] | None = None,
) -> bytes:
    """Route the age / tle invocation through ``core.sandbox.run_untrusted``.

    These binaries process attacker-crafted ciphertext and (for the
    vendor path) attacker-crafted age identity files. Plain
    ``subprocess.run`` with ``get_safe_env()`` only sanitises env vars
    — it doesn't isolate the filesystem or pin egress. ``run_untrusted``
    adds Landlock (so the binary can only touch the per-call temp dir
    plus any ``readable_paths``), namespace-level network block, and
    optional hostname-allowlisted egress for the tle / Drand path.

    ``proxy_hosts`` engages the egress proxy for tle's Drand fetch;
    ``readable_paths`` extends the read allowlist when callers pass
    file inputs (e.g. age identity file). With neither, the child sees
    only system bins / libs, the per-call temp output dir, and stdin.
    """
    tmpdir = tempfile.mkdtemp(prefix="zkpox-sb-")
    try:
        kwargs = dict(
            output=tmpdir,
            tool_paths=[str(Path(cmd[0]).parent)],
            caller_label="zkpox-envelope",
            input=stdin_bytes,
            capture_output=True, check=True,
        )
        if proxy_hosts:
            kwargs["use_egress_proxy"] = True
            kwargs["proxy_hosts"] = list(proxy_hosts)
        if readable_paths:
            kwargs["readable_paths"] = list(readable_paths)
        return run_untrusted(cmd, **kwargs).stdout
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
