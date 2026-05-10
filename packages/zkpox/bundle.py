"""
CBOR disclosure bundle producer + parser.

Schema follows proposal §8 (`docs/proposals/raptor-zkpox-design.md`)
with one deliberate deviation: the `vendor_envelope` substructure
exposes our three layered ciphertexts directly (`aes_blob`, `ct_K_age`,
`ct_K_tlock`) rather than collapsing them into a single opaque
`ciphertext` field. The proposal's "ciphertext: <bstr>" framing was
abstract; we make the layering visible so verifiers can reason about
which decrypt path was used.

Sigstore Rekor anchoring (the `timestamp` field) is Phase 1.4. In 1.3
the field is omitted entirely from the bundle; producers and parsers
treat it as optional.

Every bytestring field is encoded as CBOR major type 2 (bstr). Hashes
are stored as the `sha256:HEX` string convention from the proposal
rather than raw 32-byte bstr — easier to log, copy-paste, and grep.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import cbor2  # type: ignore[import-untyped]

from .envelope import Envelope


BUNDLE_VERSION = "zkpox-1.0"
ENVELOPE_SCHEME = "zkpox-aes256gcm+age+tlock-drand-quicknet/v1"


# ---------------------------------------------------------------------------
# Dataclasses mirroring the schema
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    kind: str           # "elf" | "wasm" | "evm" | "llvm-ir"
    hash: str           # "sha256:HEX"
    url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Vulnerability:
    cls: str            # "memory-safety" | "cfi" | "info-leak" | "evm-*"
    gadget_id: str      # e.g. "memory-safety::oob-write@1.0.0"
    gadget_hash: str    # "sha256:HEX" — commits to the gadget code
    leaked_fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Proof:
    system: str         # e.g. "sp1-stark-core/v6.1.0", "sp1-groth16-bn254/v6.1.0"
    bytes: bytes        # raw proof artefact (the SP1 SDK's saved proof bytes)
    verifier_key_hash: str  # "sha256:HEX"


@dataclass(frozen=True)
class HarnessRef:
    git_url: str | None
    rev: str | None
    hash: str           # "sha256:HEX" — locks the harness binary


@dataclass(frozen=True)
class VendorEnvelope:
    """Layered vendor + time-lock envelope. Three ciphertexts:

    - aes_blob:    nonce || AES-256-GCM(witness, K)        (see envelope.aes_*)
    - ct_K_age:    K encrypted to the vendor's age pubkey  (vendor decrypt path)
    - ct_K_tlock:  K encrypted to a Drand future round     (time-lock decrypt path)
    """

    scheme: str
    aes_blob: bytes
    ct_K_age: bytes
    ct_K_tlock: bytes
    drand_round_min: int | None
    vendor_pubkey: str
    vendor_pubkey_fingerprint: str  # sha256 hex of the pubkey string


@dataclass(frozen=True)
class Researcher:
    pubkey: str | None              # researcher's signing pubkey
    signature_over_bundle: bytes | None
    contact: str | None             # email / link; can be None for anonymity


@dataclass(frozen=True)
class Bundle:
    version: str
    target: Target
    vulnerability: Vulnerability
    proof: Proof
    harness: HarnessRef
    vendor_envelope: VendorEnvelope
    researcher: Researcher | None = None
    # Phase 1.4 fills `timestamp`; absent in 1.3.
    timestamp: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    """Stream-hash a file; return the proposal's `sha256:HEX` form."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


# ---------------------------------------------------------------------------
# Producer
# ---------------------------------------------------------------------------

def vendor_envelope_from(
    envelope: Envelope,
    *,
    vendor_pubkey: str,
    drand_round_min: int | None = None,
) -> VendorEnvelope:
    """Wrap a raw :class:`Envelope` into the bundle's typed substructure.

    Computes the vendor pubkey fingerprint (sha256 of the public-key
    string). drand_round_min is informational; the tle blob already
    binds the actual round.
    """
    return VendorEnvelope(
        scheme=ENVELOPE_SCHEME,
        aes_blob=envelope.aes_blob,
        ct_K_age=envelope.ct_K_age,
        ct_K_tlock=envelope.ct_K_tlock,
        drand_round_min=drand_round_min,
        vendor_pubkey=vendor_pubkey,
        vendor_pubkey_fingerprint=sha256_bytes(vendor_pubkey.encode()),
    )


# ---------------------------------------------------------------------------
# CBOR encode / decode
# ---------------------------------------------------------------------------

def to_cbor(bundle: Bundle) -> bytes:
    return cbor2.dumps(_to_dict(bundle))


def from_cbor(blob: bytes) -> Bundle:
    return _from_dict(cbor2.loads(blob))


def _to_dict(bundle: Bundle) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "version": bundle.version,
        "target": {
            "kind": bundle.target.kind,
            "hash": bundle.target.hash,
            "metadata": dict(bundle.target.metadata),
        },
        "vulnerability": {
            "class": bundle.vulnerability.cls,
            "gadget_id": bundle.vulnerability.gadget_id,
            "gadget_hash": bundle.vulnerability.gadget_hash,
            "leaked_fields": list(bundle.vulnerability.leaked_fields),
        },
        "proof": {
            "system": bundle.proof.system,
            "bytes": bundle.proof.bytes,
            "verifier_key_hash": bundle.proof.verifier_key_hash,
        },
        "harness": {
            "git_url": bundle.harness.git_url,
            "rev": bundle.harness.rev,
            "hash": bundle.harness.hash,
        },
        "vendor_envelope": {
            "scheme": bundle.vendor_envelope.scheme,
            "aes_blob": bundle.vendor_envelope.aes_blob,
            "ct_K_age": bundle.vendor_envelope.ct_K_age,
            "ct_K_tlock": bundle.vendor_envelope.ct_K_tlock,
            "drand_round_min": bundle.vendor_envelope.drand_round_min,
            "vendor_pubkey": bundle.vendor_envelope.vendor_pubkey,
            "vendor_pubkey_fingerprint": bundle.vendor_envelope.vendor_pubkey_fingerprint,
        },
    }
    if bundle.target.url is not None:
        payload["target"]["url"] = bundle.target.url
    if bundle.researcher is not None:
        payload["researcher"] = {
            "pubkey": bundle.researcher.pubkey,
            "signature_over_bundle": bundle.researcher.signature_over_bundle,
            "contact": bundle.researcher.contact,
        }
    if bundle.timestamp is not None:
        payload["timestamp"] = bundle.timestamp
    return payload


def _from_dict(d: dict[str, Any]) -> Bundle:
    target_d = d["target"]
    vuln_d = d["vulnerability"]
    proof_d = d["proof"]
    harness_d = d["harness"]
    env_d = d["vendor_envelope"]
    researcher_d = d.get("researcher")
    timestamp_d = d.get("timestamp")
    return Bundle(
        version=d["version"],
        target=Target(
            kind=target_d["kind"],
            hash=target_d["hash"],
            url=target_d.get("url"),
            metadata=dict(target_d.get("metadata", {})),
        ),
        vulnerability=Vulnerability(
            cls=vuln_d["class"],
            gadget_id=vuln_d["gadget_id"],
            gadget_hash=vuln_d["gadget_hash"],
            leaked_fields=list(vuln_d.get("leaked_fields", [])),
        ),
        proof=Proof(
            system=proof_d["system"],
            bytes=proof_d["bytes"],
            verifier_key_hash=proof_d["verifier_key_hash"],
        ),
        harness=HarnessRef(
            git_url=harness_d.get("git_url"),
            rev=harness_d.get("rev"),
            hash=harness_d["hash"],
        ),
        vendor_envelope=VendorEnvelope(
            scheme=env_d["scheme"],
            aes_blob=env_d["aes_blob"],
            ct_K_age=env_d["ct_K_age"],
            ct_K_tlock=env_d["ct_K_tlock"],
            drand_round_min=env_d.get("drand_round_min"),
            vendor_pubkey=env_d["vendor_pubkey"],
            vendor_pubkey_fingerprint=env_d["vendor_pubkey_fingerprint"],
        ),
        researcher=(
            None
            if researcher_d is None
            else Researcher(
                pubkey=researcher_d.get("pubkey"),
                signature_over_bundle=researcher_d.get("signature_over_bundle"),
                contact=researcher_d.get("contact"),
            )
        ),
        timestamp=timestamp_d,
    )
