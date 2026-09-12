"""Phase 1.5.1 §6 invariant — no placeholder string survives.

Pinned regression guard against a future rebase / merge that quietly
re-introduces the Phase 1.5 placeholder strings ("placeholder-vk-1.5",
"harness-1.5") into the producer side. The Tier 2/3 layer hashes
those strings into sha256:HEX form, so the *raw* sentinels never
appear in a real bundle's bytes — meaning a literal-substring search
across the producer's source tree + a newly-projected bundle is
sufficient to catch a regression.

Lives in the package's tests/ rather than .github/tests because it's a
substantive invariant about the Tier 2/3 layer's behaviour, not a CI
linter check. CI runs it via the standard pytest path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("cbor2")

from packages.zkpox.bundle import ZKPoXBundle
from packages.zkpox.disclosure import (
    DisclosureBundle,
    HarnessRef,
    Proof,
    VendorEnvelope,
    disclosure_from_manifest,
    to_cbor,
)


_PLACEHOLDER_LITERALS = (
    b"placeholder-vk-1.5",
    b"harness-1.5",
)

# The producer source tree the invariant guards. Excludes tests (which
# legitimately *reference* the strings to assert they don't survive),
# the design docs, and the scope/skill docs (which discuss the
# history). Any other matching file is a regression.
_PRODUCER_PATHS = (
    "raptor_zkpox.py",
    "packages/zkpox/disclosure.py",
    "packages/zkpox/bundle.py",
    "packages/zkpox/anchor.py",
    "packages/zkpox/envelope.py",
    "packages/zkpox/prove.py",
    "packages/zkpox/eligibility.py",
    "packages/zkpox/reproduce.py",
    "packages/zkpox/surfacing.py",
    "packages/zkpox/proving_deps.py",
    "packages/zkpox/gadget.py",
    "libexec/raptor-zkpox",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _repo_root() -> Path:
    # tests/test_no_placeholders.py → parents[3] = repo root
    return Path(__file__).resolve().parents[3]


def _manifest() -> ZKPoXBundle:
    return ZKPoXBundle(
        witness_hash="b" * 64, witness_len=42, source="fuzz",
        observed_outcome="exit_signal", outcome_detail={"finding_id": "F1"},
        target_binary_hash="a" * 64, target_source_hash=None,
        produced_by="raptor", timestamp=None,
        attestation={"claim": "input X makes Y crash"},
        tier="1.5",
        reproduction={"reproduced": True, "runs": 3},
    )


def _projected_bundle() -> DisclosureBundle:
    return disclosure_from_manifest(
        _manifest(),
        proof=Proof(
            # 1.5.1: a *real-shape* vkey digest from the prove record
            # (no placeholder string). 64-hex characters under sha256:.
            system="sp1-groth16/v6.1.0",
            bytes=b"\x00" * 64,
            verifier_key_hash="sha256:" + "0" * 64,
        ),
        vendor_envelope=VendorEnvelope(
            scheme="zkpox-none/v1", aes_blob=b"", ct_K_age=b"", ct_K_tlock=b"",
            drand_round_min=None, vendor_pubkey="",
            vendor_pubkey_fingerprint="sha256:" + "0" * 64,
        ),
        harness=HarnessRef(
            git_url=None, rev=None,
            hash="sha256:" + "0" * 64,
        ),
        vuln_class="memory-safety",
        gadget_id="memory-safety::oob-write@0.1.0",
        gadget_id_hash="sha256:" + "0" * 64,
        gadget_code_hash="sha256:" + "0" * 64,
        leaked_fields=[],
        target_kind="elf",
    )


# ---------------------------------------------------------------------------
# Producer source: no placeholder literal anywhere
# ---------------------------------------------------------------------------

def test_no_placeholder_literal_in_producer_source():
    """If a placeholder string reappears in any producer file, this
    fires. Test files are excluded — they reference the literals on
    purpose to assert their absence."""
    repo = _repo_root()
    offenders: list[str] = []
    for rel in _PRODUCER_PATHS:
        path = repo / rel
        if not path.is_file():
            continue  # tolerate path drift; covered by skill drift tests
        text = path.read_bytes()
        for lit in _PLACEHOLDER_LITERALS:
            if lit in text:
                offenders.append(f"{rel}: contains {lit!r}")
    assert not offenders, (
        "Phase 1.5.1 invariant: placeholder strings must not appear in "
        "the producer source tree.\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# Produced bundle: no placeholder literal in any serialized form
# ---------------------------------------------------------------------------

def test_no_placeholder_literal_in_projected_bundle_repr():
    """A bundle built via the projection — the only producer path —
    must contain no placeholder literal in its dataclass repr."""
    db = _projected_bundle()
    body = repr(db).encode()
    for lit in _PLACEHOLDER_LITERALS:
        assert lit not in body, (
            f"placeholder literal {lit!r} surfaces in DisclosureBundle repr"
        )


def test_no_placeholder_literal_in_cbor_bytes():
    """The encoded CBOR is what reviewers / verifiers ultimately see.
    Search the raw bytes; placeholders must not appear."""
    db = _projected_bundle()
    blob = to_cbor(db)
    for lit in _PLACEHOLDER_LITERALS:
        assert lit not in blob, (
            f"placeholder literal {lit!r} surfaces in CBOR-encoded bundle"
        )


def test_no_placeholder_string_inside_any_sha256_field():
    """The placeholders were originally fed through sha256_bytes to
    produce a hex digest — guarantee that no field is the sha256 of
    a placeholder string, either, by computing those reference digests
    and asserting they're absent."""
    import hashlib
    forbidden_digests = {
        f"sha256:{hashlib.sha256(lit).hexdigest()}"
        for lit in _PLACEHOLDER_LITERALS
    }
    db = _projected_bundle()
    encoded = json.dumps(_dataclass_dict(db), default=_default_for_json)
    for digest in forbidden_digests:
        assert digest not in encoded, (
            f"a field still hashes a placeholder literal "
            f"({digest!r} present in projected bundle)"
        )


# ---------------------------------------------------------------------------
# Helpers for JSON-y traversal of the dataclass
# ---------------------------------------------------------------------------

def _dataclass_dict(obj):
    """Convert any DisclosureBundle (or nested dataclass) to a plain
    dict for JSON serialisation. ``dataclasses.asdict`` would also
    work but the bundle is frozen — explicit recursion keeps the test
    portable across dataclass internals."""
    from dataclasses import asdict
    return asdict(obj)


def _default_for_json(o):
    """Render any bytes as a hex string so JSON serialisation never
    drops a field that could otherwise hide a placeholder literal."""
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, Path):
        return str(o)
    raise TypeError(f"unserialisable: {type(o)!r}")
