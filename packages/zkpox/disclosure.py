"""
CBOR disclosure bundle producer + parser (Tier 2/3 schema).

This is the heavyweight zero-knowledge *disclosure* bundle — distinct
from the dependency-free Tier 0/1 attestation bundle in ``bundle.py``
(``ZKPoXBundle``). The two briefly shared the filename ``bundle.py``;
#625's Tier 0/1 rewrite won a later merge and clobbered this schema,
leaving ``anchor.py`` / ``raptor_zkpox.py`` / ``test_anchor.py`` with
dangling imports. It now lives in its own module so both coexist, and
so the ``cbor2`` import below (an OPTIONAL dependency — commented out
in requirements.txt) is only paid when a caller touches the Tier 2/3
path, never at ``import packages.zkpox`` time.

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

from .bundle import ZKPoXBundle
from .statement import Statement
from .envelope import Envelope


BUNDLE_VERSION = "zkpox-2.0"
ENVELOPE_SCHEME = "zkpox-aes256gcm+age+tlock-drand-quicknet/v2"


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
    gadget_id_hash: str # "sha256:HEX" — commits to the gadget IDENTIFIER
                        # (string). Independent of the implementation
                        # binding below.
    leaked_fields: list[str] = field(default_factory=list)
    # Phase 1.5.1: ``sha256:HEX`` over the gadget's declared file
    # manifest (markdown spec + guest implementation files). Optional
    # for wire-format compatibility — Phase 1.5 / ``zkpox-1.0`` bundles
    # omit it and the verifier accepts that in non-strict mode. Phase
    # 1.5.4 makes ``--strict`` the default, at which point a None here
    # is a hard fail. New bundles produced by ``cmd_prove`` always
    # populate this via :func:`packages.zkpox.gadget.compute_gadget_code_hash`.
    gadget_code_hash: str | None = None


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
class DisclosureBundle:
    version: str
    target: Target
    vulnerability: Vulnerability
    proof: Proof
    harness: HarnessRef
    vendor_envelope: VendorEnvelope
    researcher: Researcher | None = None
    timestamp: "Timestamp | None" = None
    # Optional caller-supplied public context; canonical factories omit private manifests.
    provenance: dict[str, Any] | None = None
    experimental: bool = True
    statement: dict[str, Any] | None = None
    transparency: dict[str, Any] | None = None


@dataclass(frozen=True)
class Timestamp:
    """Sigstore Rekor anchor binding the bundle hash to a moment in time.

    The bundle hash this binds to is `bundle_hash_pre_timestamp(bundle)` —
    a canonical-CBOR hash of the bundle with `timestamp` omitted. That
    lets the Timestamp be added *after* signing/serialising the rest of
    the bundle without invalidating the binding.

    Field semantics mirror Rekor's response shape (the `verification`
    block of POST /api/v1/log/entries). `inclusion_proof_hashes` is the
    Merkle path from our entry up to the tree root; combined with
    `inclusion_proof_root_hash` + `inclusion_proof_tree_size` it lets a
    verifier reconstruct and check the path.
    """

    rekor_log_index: int
    rekor_log_id: str            # sha256 hex of Rekor's log public key
    integrated_time: int          # Unix seconds the entry was integrated
    entry_uuid: str               # Rekor's per-entry UUID
    inclusion_proof_root_hash: str  # hex of the tree root at integration
    inclusion_proof_tree_size: int
    inclusion_proof_hashes: list[str]  # Merkle path, hex per node


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


def manifest_target_bare_hex(manifest: ZKPoXBundle) -> str | None:
    """The manifest's authoritative target hash as bare hex (no
    ``sha256:`` prefix), binary preferred over source. ``None`` when the
    manifest records neither — caller decides whether that's fatal."""
    recorded = manifest.target_binary_hash or manifest.target_source_hash
    if recorded is None:
        return None
    return recorded.split(":", 1)[-1]


def target_hash_matches(manifest: ZKPoXBundle, supplied_bare_hex: str) -> bool:
    """Does an operator-supplied target's bare-hex sha256 match the
    manifest's recorded target hash?

    Used to reject the "re-keying" failure: proving against a different
    artifact than the one the manifest was triaged/reproduced against.
    A manifest with no recorded target hash matches anything (nothing to
    reconcile against) — the caller treats a missing hash as its own
    error in the projection.
    """
    recorded_bare = manifest_target_bare_hex(manifest)
    return recorded_bare is None or supplied_bare_hex == recorded_bare


def _normalize_sha256(h: str | None) -> str | None:
    """Normalise a hash to the proposal's ``sha256:HEX`` form.

    Manifest hashes come from ``core.hash.sha256_file``, which returns
    bare hex; the CBOR schema uses the ``sha256:HEX`` convention. Tolerate
    an already-prefixed value so the projection is idempotent.
    """
    if h is None:
        return None
    return h if h.startswith("sha256:") else f"sha256:{h}"


def disclosure_from_statement(statement: Statement, *, proof: Proof,
    vendor_envelope: VendorEnvelope, harness: HarnessRef,
    target_url: str | None = None, researcher: Researcher | None = None) -> DisclosureBundle:
    """Assemble public v2 fields; verification is separate. Private provenance stays private."""
    from .statement import SYSTEM
    statement.validate()
    if proof.system != SYSTEM:
        raise ValueError("v2 disclosure requires the supported Groth16 proof system")
    gadget_id = {1: "crash_only", 2: "oob_write"}[statement.gadget_id]
    return DisclosureBundle(version=BUNDLE_VERSION,
        target=Target("source", "sha256:" + statement.target_source_hash.hex(), url=target_url),
        vulnerability=Vulnerability("memory-safety", gadget_id, sha256_bytes(gadget_id.encode())),
        proof=proof, harness=harness, vendor_envelope=vendor_envelope, researcher=researcher,
        statement=statement.to_dict())


def disclosure_from_manifest(manifest: ZKPoXBundle, *, statement: Statement,
    proof: Proof, vendor_envelope: VendorEnvelope, harness: HarnessRef,
    vuln_class: str, gadget_id: str, gadget_id_hash: str,
    gadget_code_hash: str | None = None, leaked_fields: list[str] | None = None,
    target_kind: str = "source", target_url: str | None = None,
    researcher: Researcher | None = None) -> DisclosureBundle:
    """Bind the recorded source to a v2 statement without exporting the private manifest."""
    if _normalize_sha256(manifest.target_source_hash) != "sha256:" + statement.target_source_hash.hex():
        raise ValueError("manifest source hash does not match the proven source")
    result = disclosure_from_statement(statement, proof=proof, vendor_envelope=vendor_envelope,
        harness=harness, target_url=target_url, researcher=researcher)
    if (target_kind != "source" or vuln_class != result.vulnerability.cls
            or gadget_id != result.vulnerability.gadget_id
            or gadget_id_hash != result.vulnerability.gadget_id_hash
            or gadget_code_hash is not None or leaked_fields):
        raise ValueError("supplied claim metadata does not match the v2 statement")
    return result


# ---------------------------------------------------------------------------
# CBOR encode / decode
# ---------------------------------------------------------------------------

def to_cbor(bundle: DisclosureBundle) -> bytes:
    payload = _to_dict(bundle)
    _validate_profile(payload)
    encoded = cbor2.dumps(payload, canonical=True)
    if len(encoded) > 64 * 1024 * 1024:
        raise ValueError("bundle exceeds CBOR size limit")
    return encoded


def from_cbor(blob: bytes) -> DisclosureBundle:
    if type(blob) is not bytes or len(blob) > 64 * 1024 * 1024:
        raise ValueError("bundle exceeds CBOR size limit")
    _scan_cbor_profile(blob)
    payload = cbor2.loads(blob)
    _validate_profile(payload)
    if cbor2.dumps(payload, canonical=True) != blob:
        raise ValueError("bundle must use canonical CBOR without duplicates or trailing data")
    if type(payload) is not dict:
        raise ValueError("bundle must be a CBOR map")
    result = _from_dict(payload)
    if result.version == BUNDLE_VERSION and cbor2.dumps(_to_dict(result), canonical=True) != blob:
        raise ValueError("unsupported or non-normalized disclosure fields")
    return result


def bundle_hash_pre_timestamp(bundle: DisclosureBundle) -> bytes:
    """Canonical-CBOR sha256 of the bundle with timestamp set to None.

    This is the hash a Sigstore Rekor anchor binds: anchoring happens
    AFTER everything else but BEFORE the timestamp field is filled, so
    we compute the hash with timestamp excluded. The producer
    (anchor.py) signs this hash; the verifier checks
    sha256(canonical_cbor(bundle with timestamp=None)) matches what
    Rekor recorded.

    Uses cbor2's `canonical=True` encoder for deterministic
    serialisation: map keys sorted by length-then-bytewise per
    RFC 8949 §4.2.1.
    """
    pre = bundle if bundle.timestamp is None else _replace_timestamp(bundle, None)
    return hashlib.sha256(cbor2.dumps(_to_dict(pre), canonical=True)).digest()


def _replace_timestamp(bundle: DisclosureBundle, ts: "Timestamp | None") -> DisclosureBundle:
    """Functional update — `dataclasses.replace` would also work, but
    DisclosureBundle is frozen so we go the long way for clarity."""
    return DisclosureBundle(
        version=bundle.version,
        target=bundle.target,
        vulnerability=bundle.vulnerability,
        proof=bundle.proof,
        harness=bundle.harness,
        vendor_envelope=bundle.vendor_envelope,
        researcher=bundle.researcher,
        timestamp=ts,
        provenance=bundle.provenance,
        experimental=bundle.experimental,
        statement=bundle.statement,
        transparency=bundle.transparency,
    )


def with_timestamp(bundle: DisclosureBundle, ts: "Timestamp") -> DisclosureBundle:
    """Return a copy of `bundle` with its timestamp field set. Useful
    after anchor.anchor_bundle(...) returns a Timestamp."""
    return _replace_timestamp(bundle, ts)


def _vulnerability_to_dict(v: Vulnerability) -> dict[str, Any]:
    """Per-field serializer for Vulnerability — keeps ``gadget_code_hash``
    omitted when None (1.0-style bundle) so the encoded shape stays
    minimal. New 1.1 bundles always carry a real value."""
    payload: dict[str, Any] = {
        "class": v.cls,
        "gadget_id": v.gadget_id,
        "gadget_id_hash": v.gadget_id_hash,
        "leaked_fields": list(v.leaked_fields),
    }
    if v.gadget_code_hash is not None:
        payload["gadget_code_hash"] = v.gadget_code_hash
    return payload


def _to_dict(bundle: DisclosureBundle) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "version": bundle.version,
        "target": {
            "kind": bundle.target.kind,
            "hash": bundle.target.hash,
            "metadata": dict(bundle.target.metadata),
        },
        "vulnerability": _vulnerability_to_dict(bundle.vulnerability),
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
        ts = bundle.timestamp
        payload["timestamp"] = {
            "rekor_log_index": ts.rekor_log_index,
            "rekor_log_id": ts.rekor_log_id,
            "integrated_time": ts.integrated_time,
            "entry_uuid": ts.entry_uuid,
            "inclusion_proof_root_hash": ts.inclusion_proof_root_hash,
            "inclusion_proof_tree_size": ts.inclusion_proof_tree_size,
            "inclusion_proof_hashes": list(ts.inclusion_proof_hashes),
        }
    # Provenance is bundle CONTENT (not post-hoc like the timestamp), so
    # it stays inside ``bundle_hash_pre_timestamp`` — the proof's anchor
    # binds the Tier 0/1 + 1.5 evidence too, not just the proof bytes.
    if bundle.provenance is not None:
        payload["provenance"] = dict(bundle.provenance)
    if bundle.statement is not None:
        payload["statement"] = dict(bundle.statement)
    if bundle.transparency is not None:
        payload["transparency"] = dict(bundle.transparency)
    payload["experimental"] = bundle.experimental
    return payload


def _from_dict(d: dict[str, Any]) -> DisclosureBundle:
    target_d = d["target"]
    vuln_d = d["vulnerability"]
    proof_d = d["proof"]
    harness_d = d["harness"]
    env_d = d["vendor_envelope"]
    researcher_d = d.get("researcher")
    timestamp_d = d.get("timestamp")
    provenance_d = d.get("provenance")
    experimental = d.get("experimental", True)
    return DisclosureBundle(
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
            gadget_id_hash=vuln_d["gadget_id_hash"],
            gadget_code_hash=vuln_d.get("gadget_code_hash"),
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
        timestamp=(
            None
            if timestamp_d is None
            else Timestamp(
                rekor_log_index=int(timestamp_d["rekor_log_index"]),
                rekor_log_id=timestamp_d["rekor_log_id"],
                integrated_time=int(timestamp_d["integrated_time"]),
                entry_uuid=timestamp_d["entry_uuid"],
                inclusion_proof_root_hash=timestamp_d["inclusion_proof_root_hash"],
                inclusion_proof_tree_size=int(timestamp_d["inclusion_proof_tree_size"]),
                inclusion_proof_hashes=list(timestamp_d.get("inclusion_proof_hashes", [])),
            )
        ),
        provenance=(None if provenance_d is None else dict(provenance_d)),
        experimental=experimental,
        statement=d.get("statement"),
        transparency=d.get("transparency"),
    )


def _validate_profile(value: Any, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("CBOR nesting exceeds limit")
    kind = type(value)
    if kind is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise ValueError("CBOR map keys must be text")
            _validate_profile(child, depth + 1)
    elif kind in (list, tuple):
        for child in value:
            _validate_profile(child, depth + 1)
    elif kind is int:
        if not -(2**64) <= value < 2**64:
            raise ValueError("CBOR integer exceeds profile")
    elif kind not in (str, bytes, bool, type(None)):
        raise ValueError("unsupported CBOR disclosure type")


def _scan_cbor_profile(blob: bytes) -> None:
    """Bound framing and reject semantic tags before cbor2 constructs objects."""
    size = len(blob)
    def walk(offset: int, depth: int) -> int:
        if depth > 64:
            raise ValueError("CBOR nesting exceeds limit")
        if offset >= size:
            raise ValueError("truncated CBOR value")
        header = blob[offset]
        offset += 1
        major, extra = header >> 5, header & 31
        if major == 6:
            raise ValueError("CBOR semantic tags are not permitted")
        if major == 7:
            if extra not in (20, 21, 22):
                raise ValueError("unsupported CBOR simple/float value")
            return offset
        if extra < 24:
            argument = extra
        elif extra <= 27:
            width = 1 << (extra - 24)
            if offset + width > size:
                raise ValueError("truncated CBOR argument")
            argument = int.from_bytes(blob[offset:offset + width], "big")
            offset += width
            if argument < (24,256,65536,4294967296)[extra-24]:
                raise ValueError("nonminimal CBOR argument")
        else:
            raise ValueError("indefinite/reserved CBOR framing is not permitted")
        if major <= 1:
            return offset
        if major in (2,3):
            if argument > size-offset:
                raise ValueError("truncated CBOR string")
            return offset+argument
        count = argument*(2 if major == 5 else 1)
        if count > size-offset:
            raise ValueError("CBOR container count exceeds available input")
        for _ in range(count):
            offset=walk(offset,depth+1)
        return offset
    if walk(0,0) != size:
        raise ValueError("trailing CBOR data")
