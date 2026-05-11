"""
Sigstore Rekor anchor for zkpox disclosure bundles.

Rekor is an append-only transparency log run by Sigstore. Anchoring a
bundle here gives anyone a cryptographic proof that the bundle existed
by a specific time, without trusting a single notary. The proposal §9
spells out the trust model: verifiers trust the Rekor log for the
timestamp, or another transparency log of their choice — we make the
log URL overridable via ZKPOX_REKOR_URL so private instances drop in.

Flow:
    1. Producer builds a Bundle (without a timestamp).
    2. Producer generates (or supplies) an ed25519 keypair.
    3. Producer signs `bundle_hash_pre_timestamp(bundle)`.
    4. Producer POSTs a `hashedrekord/0.0.1` entry to Rekor with the
       hash + signature + PEM-encoded public key.
    5. Rekor returns the log index, entry UUID, inclusion proof, and
       integrated time.
    6. Producer wraps the response into a :class:`Timestamp` and
       attaches it to the bundle via :func:`bundle.with_timestamp`.

Verifier side (Phase 1.4c — structural; Phase 1.4.x — full Merkle):
    1. Read the bundle; extract the Timestamp field.
    2. Recompute `bundle_hash_pre_timestamp` from the bundle WITHOUT
       its timestamp.
    3. Confirm Rekor's recorded hash matches our computed hash
       (either by GETing the entry by log index from Rekor, or by
       reconstructing it locally from the bundle).
    4. Validate the Merkle inclusion proof against Rekor's current
       (or embedded) signed tree head.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .bundle import Bundle, Timestamp, bundle_hash_pre_timestamp, with_timestamp


# The public Rekor log. Overridable so private/self-hosted instances
# work without code changes — RAPTOR-internal CI may want to anchor
# elsewhere, vendors with an internal CVD pipeline may have their own.
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"


def rekor_url() -> str:
    return os.environ.get("ZKPOX_REKOR_URL", DEFAULT_REKOR_URL).rstrip("/")


# ---------------------------------------------------------------------------
# Keypair helpers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Ed25519Keypair:
    """Caller-managed ed25519 keypair. For test/spike use we generate
    ephemeral keys; in production a researcher key (or an offline
    signing service) provides one."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def pem_public(self) -> bytes:
        """SubjectPublicKeyInfo PEM — the format Rekor's
        hashedrekord/0.0.1 schema expects in its `publicKey.content`."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


def gen_ed25519_keypair() -> Ed25519Keypair:
    sk = Ed25519PrivateKey.generate()
    return Ed25519Keypair(private_key=sk, public_key=sk.public_key())


def load_ed25519_secret_pem(pem_path: Path) -> Ed25519Keypair:
    """Load a PEM-encoded ed25519 private key from disk."""
    data = Path(pem_path).read_bytes()
    sk = serialization.load_pem_private_key(data, password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise ValueError(f"{pem_path} is not an ed25519 private key")
    return Ed25519Keypair(private_key=sk, public_key=sk.public_key())


# ---------------------------------------------------------------------------
# Rekor REST client (just the slice we need)
# ---------------------------------------------------------------------------

class AnchorError(Exception):
    """Base for anchoring/verification errors."""


def _make_hashedrekord_entry(
    *,
    bundle_hash_hex: str,
    signature_b64: str,
    pubkey_pem_b64: str,
) -> dict:
    """Build the Rekor proposed-entry body. The hashedrekord/0.0.1
    schema is the simplest Rekor type that accepts a precomputed hash
    plus a signature over it."""
    return {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": bundle_hash_hex,
                },
            },
            "signature": {
                "content": signature_b64,
                "publicKey": {
                    "content": pubkey_pem_b64,
                },
            },
        },
    }


def _parse_rekor_response(entry_response: dict) -> Timestamp:
    """Extract our :class:`Timestamp` shape from Rekor's response.

    Rekor returns a dict keyed by the entry UUID with a value containing
    `logIndex`, `logID`, `integratedTime`, and `verification`
    (which holds the inclusion proof).
    """
    if not entry_response:
        raise AnchorError("empty response from Rekor")
    (uuid, body), = entry_response.items()
    verification = body.get("verification") or {}
    inc = verification.get("inclusionProof") or {}
    return Timestamp(
        rekor_log_index=int(body["logIndex"]),
        rekor_log_id=str(body["logID"]),
        integrated_time=int(body.get("integratedTime") or time.time()),
        entry_uuid=uuid,
        inclusion_proof_root_hash=str(inc.get("rootHash", "")),
        inclusion_proof_tree_size=int(inc.get("treeSize", 0)),
        inclusion_proof_hashes=[str(h) for h in inc.get("hashes", [])],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def anchor_bundle(
    bundle: Bundle,
    *,
    keypair: Ed25519Keypair | None = None,
    rekor: str | None = None,
    timeout_s: float = 30.0,
) -> tuple[Bundle, Ed25519Keypair]:
    """Anchor `bundle` to Sigstore Rekor; return (bundle-with-timestamp,
    keypair-used).

    If `keypair` is None, generates a fresh ephemeral ed25519 keypair.
    The caller decides whether to keep or discard it; for one-shot
    disclosure runs you typically discard, since the proof of "this
    bundle existed by time T" is in Rekor's log, not in any local key.

    `rekor` overrides the log URL; default is `ZKPOX_REKOR_URL` env var
    or the public Sigstore Rekor instance.
    """
    kp = keypair or gen_ed25519_keypair()
    log_url = (rekor or rekor_url()).rstrip("/")

    digest = bundle_hash_pre_timestamp(bundle)
    bundle_hash_hex = digest.hex()
    signature = kp.sign(digest)

    entry_body = _make_hashedrekord_entry(
        bundle_hash_hex=bundle_hash_hex,
        signature_b64=base64.b64encode(signature).decode("ascii"),
        pubkey_pem_b64=base64.b64encode(kp.pem_public()).decode("ascii"),
    )

    resp = requests.post(
        f"{log_url}/api/v1/log/entries",
        json=entry_body,
        headers={"Content-Type": "application/json"},
        timeout=timeout_s,
    )
    if resp.status_code != 201:
        raise AnchorError(
            f"Rekor returned {resp.status_code}: {resp.text[:512]}"
        )
    ts = _parse_rekor_response(resp.json())
    return with_timestamp(bundle, ts), kp


def fetch_log_entry(
    log_index: int,
    *,
    rekor: str | None = None,
    timeout_s: float = 15.0,
) -> dict:
    """Fetch a Rekor log entry by its index. Returns Rekor's raw JSON.
    Useful for the verifier path: GET an entry, compare its body's
    hashedrekord.data.hash to a locally-computed bundle hash.
    """
    log_url = (rekor or rekor_url()).rstrip("/")
    resp = requests.get(
        f"{log_url}/api/v1/log/entries",
        params={"logIndex": log_index},
        timeout=timeout_s,
    )
    if resp.status_code != 200:
        raise AnchorError(
            f"Rekor GET {log_index} returned {resp.status_code}: {resp.text[:512]}"
        )
    return resp.json()


def confirm_anchor_matches(
    bundle: Bundle,
    *,
    rekor: str | None = None,
    timeout_s: float = 15.0,
) -> bool:
    """Verifier-side structural check: does Rekor's recorded entry for
    `bundle.timestamp.rekor_log_index` match `bundle_hash_pre_timestamp`?

    Fetches the entry from Rekor, parses the embedded hashedrekord
    body, and compares the data hash.

    Phase 1.4 does NOT verify the Merkle inclusion proof or Rekor's
    signed tree head — that's 1.4.x. This pass establishes the
    "weakest useful thing": Rekor records a hash that matches what we
    would have produced from the bundle, at the index the bundle
    claims.
    """
    if bundle.timestamp is None:
        raise AnchorError("bundle has no timestamp to confirm")

    response = fetch_log_entry(
        bundle.timestamp.rekor_log_index, rekor=rekor, timeout_s=timeout_s
    )
    if not response:
        return False
    _, body = next(iter(response.items()))
    entry_body_b64 = body.get("body")
    if not entry_body_b64:
        return False

    entry_body = json.loads(base64.b64decode(entry_body_b64))
    rekor_hash = (
        entry_body.get("spec", {}).get("data", {}).get("hash", {}).get("value")
    )
    return rekor_hash == bundle_hash_pre_timestamp(bundle).hex()
