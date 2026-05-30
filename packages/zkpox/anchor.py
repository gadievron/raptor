"""
Sigstore Rekor anchor for zkpox disclosure bundles.

Rekor is an append-only transparency log run by Sigstore. Anchoring a
bundle here gives anyone a cryptographic proof that the bundle existed
by a specific time, without trusting a single notary. The proposal §9
spells out the trust model: verifiers trust the Rekor log for the
timestamp, or another transparency log of their choice — we make the
log URL overridable via ZKPOX_REKOR_URL so private instances drop in.

Flow:
    1. Producer builds a DisclosureBundle (without a timestamp).
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
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.http import HttpClient, HttpError, default_client

from .disclosure import (
    DisclosureBundle,
    Timestamp,
    bundle_hash_pre_timestamp,
    with_timestamp,
)


# Default Rekor log target. Phase 1.5.3 migrates this to the v2
# annual-shard convention (``log2026-1.rekor.sigstore.dev`` at write
# time — current shard rolls each year, see
# https://docs.sigstore.dev/logging/overview/). Verifiers reading
# legacy v1 bundles still find them via ``ZKPOX_REKOR_URL`` =
# ``https://rekor.sigstore.dev`` (Sigstore keeps v1 running in
# parallel for the read path).
#
# Overridable so private / self-hosted instances drop in —
# RAPTOR-internal CI may want to anchor elsewhere; vendors with an
# internal CVD pipeline may have their own log.
DEFAULT_REKOR_URL = "https://log2026-1.rekor.sigstore.dev"

# Phase 1.5.3 — read path for legacy v1 anchors. Kept available as
# an explicit override for verifiers reconciling old bundles whose
# ``timestamp`` field references the v1 instance.
LEGACY_V1_REKOR_URL = "https://rekor.sigstore.dev"


def rekor_url() -> str:
    return os.environ.get("ZKPOX_REKOR_URL", DEFAULT_REKOR_URL).rstrip("/")


def _rekor_host(log_url: str) -> str:
    """Extract the hostname from a Rekor base URL for the egress allowlist.

    Rekor URLs are always ``https://<host>[/path]``; the egress proxy's
    allowlist is hostname-only. Parsing centrally keeps the public /
    self-hosted / test-stub cases all going through the same shape.
    """
    host = urlparse(log_url).hostname
    if not host:
        raise AnchorError(f"could not parse hostname from rekor URL: {log_url!r}")
    return host


def _default_http_for(log_url: str) -> HttpClient:
    """Build an egress-allowlisted HttpClient for a given Rekor URL.

    Production path: every Rekor call goes through ``core.http`` with
    the proxy backend constrained to the single hostname we're talking
    to. Tests inject their own ``HttpClient`` stub via the ``http=``
    kwarg on the public functions and never hit this.
    """
    return default_client(allowed_hosts=[_rekor_host(log_url)])


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
    # `integratedTime` is the canonical "Rekor recorded this hash at" time.
    # We MUST NOT substitute a local-clock fallback — doing so would make
    # the bundle's timestamp.integrated_time disagree with what's actually
    # in Rekor's log, breaking the anchor verification path. Raise instead.
    if "integratedTime" not in body:
        raise AnchorError(
            f"Rekor response for entry {uuid} omits integratedTime; "
            "cannot anchor without it. Body keys: "
            f"{sorted(body.keys())}"
        )
    return Timestamp(
        rekor_log_index=int(body["logIndex"]),
        rekor_log_id=str(body["logID"]),
        integrated_time=int(body["integratedTime"]),
        entry_uuid=uuid,
        inclusion_proof_root_hash=str(inc.get("rootHash", "")),
        inclusion_proof_tree_size=int(inc.get("treeSize", 0)),
        inclusion_proof_hashes=[str(h) for h in inc.get("hashes", [])],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def anchor_bundle(
    bundle: DisclosureBundle,
    *,
    keypair: Ed25519Keypair | None = None,
    rekor: str | None = None,
    timeout_s: float = 30.0,
    http: HttpClient | None = None,
) -> tuple[DisclosureBundle, Ed25519Keypair]:
    """Anchor `bundle` to Sigstore Rekor; return (bundle-with-timestamp,
    keypair-used).

    If `keypair` is None, generates a fresh ephemeral ed25519 keypair.
    The caller decides whether to keep or discard it; for one-shot
    disclosure runs you typically discard, since the proof of "this
    bundle existed by time T" is in Rekor's log, not in any local key.

    `rekor` overrides the log URL; default is `ZKPOX_REKOR_URL` env var
    or the public Sigstore Rekor instance.

    `http` overrides the HTTP client; default builds an egress-proxied
    client allowlisted to the Rekor host. Tests inject a stub here.
    """
    kp = keypair or gen_ed25519_keypair()
    log_url = (rekor or rekor_url()).rstrip("/")
    client = http or _default_http_for(log_url)

    digest = bundle_hash_pre_timestamp(bundle)
    bundle_hash_hex = digest.hex()
    signature = kp.sign(digest)

    entry_body = _make_hashedrekord_entry(
        bundle_hash_hex=bundle_hash_hex,
        signature_b64=base64.b64encode(signature).decode("ascii"),
        pubkey_pem_b64=base64.b64encode(kp.pem_public()).decode("ascii"),
    )

    # ``retries=0``: posting an entry is not idempotent — a 5xx after
    # partial server-side processing could double-anchor the bundle.
    try:
        body = client.post_json(
            f"{log_url}/api/v1/log/entries",
            entry_body,
            timeout=int(timeout_s),
            retries=0,
        )
    except HttpError as exc:
        raise AnchorError(f"Rekor POST failed: {exc}") from exc

    ts = _parse_rekor_response(body)
    return with_timestamp(bundle, ts), kp


def fetch_log_entry(
    log_index: int,
    *,
    rekor: str | None = None,
    timeout_s: float = 15.0,
    http: HttpClient | None = None,
) -> dict:
    """Fetch a Rekor log entry by its index. Returns Rekor's raw JSON.
    Useful for the verifier path: GET an entry, compare its body's
    hashedrekord.data.hash to a locally-computed bundle hash.

    `http` overrides the HTTP client; default builds an egress-proxied
    client allowlisted to the Rekor host.
    """
    log_url = (rekor or rekor_url()).rstrip("/")
    client = http or _default_http_for(log_url)
    # HttpClient API doesn't take params= directly — encode the
    # logIndex query manually. Rekor's GET endpoint is idempotent so
    # the default retry budget is fine.
    url = f"{log_url}/api/v1/log/entries?{urlencode({'logIndex': log_index})}"
    try:
        return client.get_json(url, timeout=int(timeout_s))
    except HttpError as exc:
        raise AnchorError(f"Rekor GET {log_index} failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Phase 1.5.3 — Merkle inclusion verification (RFC 6962 §2.1.1)
# ---------------------------------------------------------------------------

import hashlib as _hashlib  # local: avoids touching the module docstring above

# RFC 6962 §2.1: hash domain separation prevents 2nd-preimage attacks
# between leaf and inner node hashes (a node hash could otherwise look
# like a leaf hash by accident, letting an attacker swap a tree slice).
_RFC6962_LEAF_PREFIX = b"\x00"
_RFC6962_NODE_PREFIX = b"\x01"


def _rfc6962_leaf_hash(leaf_bytes: bytes) -> bytes:
    """sha256(0x00 || leaf_bytes) — the RFC 6962 leaf-hash domain."""
    h = _hashlib.sha256()
    h.update(_RFC6962_LEAF_PREFIX)
    h.update(leaf_bytes)
    return h.digest()


def _rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """sha256(0x01 || left || right) — the RFC 6962 inner-node domain."""
    h = _hashlib.sha256()
    h.update(_RFC6962_NODE_PREFIX)
    h.update(left)
    h.update(right)
    return h.digest()


class InclusionProofError(AnchorError):
    """Raised when a Merkle inclusion proof is malformed (wrong path
    length for the claimed tree size, hex parse failure, etc.). A
    proof that parses correctly but doesn't verify against the
    recorded root returns ``False`` from
    :func:`verify_inclusion_proof` rather than raising — that's the
    "Rekor lied to us / the bundle was tampered with" case the caller
    needs to distinguish."""


def verify_inclusion_proof(
    leaf_bytes: bytes,
    *,
    log_index: int,
    tree_size: int,
    audit_path_hex: list[str],
    expected_root_hex: str,
) -> bool:
    """Verify an RFC 6962 Merkle audit path.

    Reconstructs the root from ``leaf_bytes`` and ``audit_path_hex``,
    walking up the tree per RFC 6962 §2.1.1, and returns ``True`` iff
    the computed root equals ``expected_root_hex``.

    Inputs:
      ``leaf_bytes``       — raw bytes the log committed (NOT pre-hashed;
                              the leaf-hash step happens here so callers
                              can't forget the ``0x00`` domain prefix).
      ``log_index``        — 0-based leaf index in the tree.
      ``tree_size``        — number of leaves the audit path was built
                              against (the STH's tree size at the time).
      ``audit_path_hex``   — sibling hashes bottom-up, hex-encoded.
      ``expected_root_hex``— claimed Merkle root, hex-encoded.

    Raises :class:`InclusionProofError` on a structurally-invalid
    proof (wrong path length, hex parse fail, out-of-range index).
    Returns ``False`` on a structurally-valid but non-matching path.
    """
    if log_index < 0 or log_index >= tree_size:
        raise InclusionProofError(
            f"log_index {log_index} out of range for tree_size {tree_size}",
        )
    try:
        audit_path = [bytes.fromhex(h) for h in audit_path_hex]
        expected_root = bytes.fromhex(expected_root_hex)
    except ValueError as e:
        raise InclusionProofError(f"non-hex audit-path entry: {e}") from e
    for blob in audit_path:
        if len(blob) != 32:
            raise InclusionProofError(
                f"audit-path entry is not a 32-byte sha256: len={len(blob)}",
            )
    if len(expected_root) != 32:
        raise InclusionProofError(
            f"expected_root is not a 32-byte sha256: len={len(expected_root)}",
        )

    # RFC 6962 §2.1.1 — bottom-up walk (Trillian / google.com/trillian
    # ``verifyInclusionProof`` shape).
    #
    # ``fn`` is the current node's index at the current level (the
    # path we're walking from the leaf); ``sn`` is the last index at
    # the same level (so ``sn`` reveals where the rightmost frontier
    # is). The "promote frontier" inner loop after a left-sibling
    # consume handles odd-sized subtrees where the just-computed
    # node has no sibling at the next level up and propagates
    # unchanged.
    fn = log_index
    sn = tree_size - 1
    current = _rfc6962_leaf_hash(leaf_bytes)
    consumed = 0
    for sibling in audit_path:
        if sn == 0:
            raise InclusionProofError(
                f"audit path longer than tree depth for log_index={log_index} "
                f"tree_size={tree_size} ({len(audit_path)} entries, "
                f"consumed {consumed} before exhaustion)",
            )
        if (fn & 1) == 1 or fn == sn:
            # Sibling is on the left; promote any further "we have no
            # right sibling" frontier nodes that follow.
            current = _rfc6962_node_hash(sibling, current)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            current = _rfc6962_node_hash(current, sibling)
        fn >>= 1
        sn >>= 1
        consumed += 1
    if sn != 0:
        raise InclusionProofError(
            f"audit path shorter than tree depth (sn={sn} after "
            f"consuming {consumed} of {len(audit_path)})",
        )
    return current == expected_root


# ---------------------------------------------------------------------------
# Phase 1.5.3 — Rekor SET (Signed Entry Timestamp) verification
# ---------------------------------------------------------------------------
#
# Rekor v1 returns a ``signedEntryTimestamp`` (SET) in each response's
# ``verification`` block: a signature, from the log's own keypair,
# over a canonical JSON of the entry's ``body`` + ``integratedTime`` +
# ``logIndex`` + ``logID``. The SET is the "did the log endorse this
# entry?" check; combined with the Merkle inclusion proof above, it
# rules out a Rekor instance that's lying about what's in its tree
# (the log would have to forge the signature too).
#
# Rekor v2 carries the same intent via a signed *checkpoint* with
# integrated witness cosignatures; that path lands in a follow-up
# alongside the Sigstore TUF integration that provides the witness
# pubkey set.


class SignatureError(AnchorError):
    """Raised on a malformed signed payload (unsupported key type,
    bad PEM). A signature that's structurally fine but verifies as
    invalid returns ``False`` from :func:`verify_set` — that's the
    "log signed something else" case the caller needs to surface
    distinctly from a malformed proof."""


def canonical_set_payload(
    *,
    entry_body_b64: str,
    integrated_time: int,
    log_index: int,
    log_id: str,
) -> bytes:
    """Build the canonical JSON payload Rekor v1 signs.

    Per the Sigstore Rekor v1 SET spec, the signed bytes are:

        json_canonical({
          "body":           <base64 of the entry's canonical body>,
          "integratedTime": <Unix seconds when the log integrated it>,
          "logIndex":       <0-based leaf index>,
          "logID":          <sha256 hex of the log's pubkey>,
        })

    "Canonical" here is sorted keys + compact separators. That matches
    what Rekor's Go side produces (no whitespace, alphabetically
    ordered keys, no escaping beyond standard JSON). Tests pin a
    golden payload to catch any silent drift if Sigstore changes the
    serializer.
    """
    return json.dumps(
        {
            "body": entry_body_b64,
            "integratedTime": int(integrated_time),
            "logIndex": int(log_index),
            "logID": log_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def verify_set(
    *,
    canonical_payload: bytes,
    signature: bytes,
    log_pubkey_pem: bytes,
) -> bool:
    """Verify a Rekor v1 SET (Signed Entry Timestamp) signature.

    Accepts both algorithm families Sigstore Rekor v1 actually uses:

      - Ed25519 (some self-hosted deployments / older keys);
      - ECDSA P-256 with SHA-256 (the public ``rekor.sigstore.dev``).

    The PEM type drives the dispatch; an unsupported key type raises
    :class:`SignatureError` (a malformed input — distinct from
    "signature verifies as invalid", which returns ``False``).

    ``log_pubkey_pem`` is operator-supplied: the trust anchor for the
    log. For Sigstore Rekor v1 the public key is published via the
    Sigstore TUF root; the Phase 1.5.3 producer flow doesn't yet
    auto-fetch it (that's the v2-TUF follow-up), so the caller must
    pass the PEM they want to trust.
    """
    try:
        pubkey = serialization.load_pem_public_key(log_pubkey_pem)
    except (ValueError, TypeError) as e:
        raise SignatureError(f"could not parse log_pubkey_pem: {e}") from e

    if isinstance(pubkey, Ed25519PublicKey):
        try:
            pubkey.verify(signature, canonical_payload)
        except InvalidSignature:
            return False
        return True

    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        # ECDSA over SHA-256 — what the public Sigstore Rekor uses on
        # the secp256r1 (P-256) curve. The verify call hashes the
        # payload internally per the SHA256() argument.
        try:
            pubkey.verify(signature, canonical_payload, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True

    raise SignatureError(
        f"unsupported log public key type: {type(pubkey).__name__}; "
        f"Rekor v1 uses Ed25519 or ECDSA P-256",
    )


def confirm_anchor_matches(
    bundle: DisclosureBundle,
    *,
    rekor: str | None = None,
    timeout_s: float = 15.0,
    http: HttpClient | None = None,
    log_pubkey_pem: bytes | None = None,
) -> bool:
    """Validate a bundle's Rekor anchor end-to-end.

    Phase 1.5.3 raises the bar from "the recorded hash matches" to
    actually verifying the Merkle inclusion proof, and (when the
    operator supplies ``log_pubkey_pem``) the SET signature. All
    three layers must agree for the anchor to pass:

      1. Hash match — the entry Rekor recorded hashes the same bytes
         as ``bundle_hash_pre_timestamp(bundle)``. Same check the
         1.4 path performed.
      2. Merkle inclusion — the audit path in the bundle's
         ``Timestamp`` walks the leaf up to the recorded
         ``inclusion_proof_root_hash`` (RFC 6962 §2.1.1). A tampered
         path / wrong root / wrong leaf returns ``False``.
      3. SET signature (optional but recommended) — if
         ``log_pubkey_pem`` is supplied, verify the Rekor v1
         ``signedEntryTimestamp`` against the operator-trusted log
         pubkey. Without it this check is skipped; the function still
         returns ``True`` on (1) + (2) alone, which is strictly more
         than the 1.4 path performed.

    The Rekor v2 witness-cosignature check is reserved for the
    Sigstore TUF integration follow-up; pass ``log_pubkey_pem`` to
    pin the trust anchor explicitly in the meantime.

    Inputs: ``log_pubkey_pem`` — the trusted log's public key in PEM.
    ``http`` / ``rekor`` / ``timeout_s`` — as before.
    """
    if bundle.timestamp is None:
        raise AnchorError("bundle has no timestamp to confirm")

    response = fetch_log_entry(
        bundle.timestamp.rekor_log_index,
        rekor=rekor, timeout_s=timeout_s, http=http,
    )
    if not response:
        return False
    _, body = next(iter(response.items()))
    entry_body_b64 = body.get("body")
    if not entry_body_b64:
        return False

    # (1) Hash match — same shape as 1.4.
    entry_body = json.loads(base64.b64decode(entry_body_b64))
    rekor_hash = (
        entry_body.get("spec", {}).get("data", {}).get("hash", {}).get("value")
    )
    if rekor_hash != bundle_hash_pre_timestamp(bundle).hex():
        return False

    # (2) Merkle inclusion proof — the bundle's Timestamp carries
    # ``inclusion_proof_root_hash`` + ``tree_size`` + ``hashes``; the
    # leaf bytes Rekor hashed are the base64-decoded entry body. A
    # structurally-malformed proof raises InclusionProofError; a
    # well-formed but non-matching proof returns False.
    leaf_bytes = base64.b64decode(entry_body_b64)
    ts = bundle.timestamp
    if not verify_inclusion_proof(
        leaf_bytes,
        log_index=ts.rekor_log_index,
        tree_size=ts.inclusion_proof_tree_size,
        audit_path_hex=list(ts.inclusion_proof_hashes),
        expected_root_hex=ts.inclusion_proof_root_hash,
    ):
        return False

    # (3) SET signature — only when the operator pinned a log pubkey.
    # Without it, the inclusion proof's authenticity rests on the
    # Rekor host the verifier talks to (egress-allowlisted to the
    # operator-chosen URL via ``rekor``). Supply ``log_pubkey_pem``
    # to remove that trust assumption.
    if log_pubkey_pem is not None:
        verification = body.get("verification") or {}
        set_b64 = verification.get("signedEntryTimestamp")
        if not set_b64:
            # Operator asked for SET verification but Rekor didn't
            # return one — caller distinguishes this from a forged
            # signature via the AnchorError. Either way the anchor
            # cannot satisfy strict mode.
            raise AnchorError(
                "log_pubkey_pem supplied but Rekor response carries no "
                "signedEntryTimestamp",
            )
        try:
            signature = base64.b64decode(set_b64)
        except (ValueError, TypeError) as e:
            raise SignatureError(
                f"signedEntryTimestamp is not valid base64: {e}",
            ) from e
        canonical = canonical_set_payload(
            entry_body_b64=entry_body_b64,
            integrated_time=ts.integrated_time,
            log_index=ts.rekor_log_index,
            log_id=ts.rekor_log_id,
        )
        if not verify_set(
            canonical_payload=canonical,
            signature=signature,
            log_pubkey_pem=log_pubkey_pem,
        ):
            return False

    return True
