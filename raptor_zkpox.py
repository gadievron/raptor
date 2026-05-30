#!/usr/bin/env python3
"""
RAPTOR ZKPoX — Zero-Knowledge Proof of Exploit driver (Tier 2/3).

End-to-end Phase 1.5 orchestration:
  prove                 prove → wrap → envelope → bundle → optional Rekor anchor
  verify                delegate to the standalone zkpox-verify binary

Reached from the operator surface via ``python3 raptor.py zkpox prove``
/ ``python3 raptor.py zkpox verify``, which forward through
``libexec/raptor-zkpox`` to this script (analogous to
``raptor_codeql.py`` / ``raptor_fuzzing.py``).

Companion code:
  core/zkpox/                    Rust workspace: guest / prover / verifier
  packages/zkpox/                Python: envelope / bundle / anchor / prove
  libexec/raptor-zkpox           Operator CLI dispatcher
  docs/proposals/raptor-zkpox-design.md
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Hard-lookup RAPTOR_DIR per the project's sys.path rule (CLAUDE.md):
# the KeyError on an unset env is intentional — fail loudly rather than
# silently falling back to a cwd or __file__-relative walk that breaks
# under symlinks / non-repo cwd. The launcher always sets RAPTOR_DIR.
sys.path.insert(0, os.environ["RAPTOR_DIR"])

from core.logging import get_logger
from core.sandbox import run_untrusted
from packages import zkpox

logger = get_logger()


# ---------------------------------------------------------------------------
# `prove` subcommand
# ---------------------------------------------------------------------------

def _resolve_prover_binary() -> Path:
    """Locate the zkpox-prove binary built by core/zkpox/."""
    root = Path(__file__).resolve().parent
    candidate = root / "core" / "zkpox" / "target" / "release" / "zkpox-prove"
    if not candidate.exists():
        raise SystemExit(
            f"zkpox-prove not built: {candidate}\n"
            f"build it with: cargo build --release "
            f"--manifest-path core/zkpox/Cargo.toml"
        )
    return candidate


# Phase 1.5.1 removed the placeholder constants (`_PLACEHOLDER_VK_DIGEST`,
# `_PLACEHOLDER_HARNESS_DIGEST`) and the matching `_PLACEHOLDER_WARNING`:
# the bundle's ``proof.verifier_key_hash`` and ``harness.hash`` now bind
# to the real SP1 vkey + guest ELF, read out of ``prove-record.json``
# (which the Rust prover emits per Phase 1.5.1 §1). A producer running
# against a pre-1.5.1 prover that omits ``vkey_digest`` /
# ``guest_elf_hash`` fails loudly in ``cmd_prove`` rather than falling
# back to a placeholder.

# Loud always-on banner. This is the meta-level "the whole feature is
# beta" message so an operator who skipped the slash-command help still
# sees it. Printed to stderr so it doesn't pollute stdout JSON output.
_EXPERIMENTAL_BANNER = (
    "[zkpox] ============================================================\n"
    "[zkpox] EXPERIMENTAL — ZKPoX is beta. Phase 1.5.x landed real vkey/\n"
    "[zkpox] harness binding (1.5.1), standalone STARK verification\n"
    "[zkpox] (1.5.2), and Rekor Merkle + SET verify (1.5.3); strict mode\n"
    "[zkpox] is the default verifier behaviour from 1.5.4.\n"
    "[zkpox] Bundle format and verifier semantics may still change as\n"
    "[zkpox] 1.6+ lands (Rust-side offline Rekor wire, multi-gadget\n"
    "[zkpox] dispatch). Scope statement: docs/zkpox-scope.md\n"
    "[zkpox] ============================================================"
)


def _emit_experimental_banner() -> None:
    """Print the always-on experimental banner to stderr.

    Stderr, not stdout, so /zkpox prove's JSON summary on stdout
    stays machine-parseable.
    """
    print(_EXPERIMENTAL_BANNER, file=sys.stderr)


def _load_manifest(bundle_dir: Path):
    """Reconstruct the Tier 0/1 ``ZKPoXBundle`` from
    ``<bundle_dir>/manifest.json``.

    The manifest is exactly ``ZKPoXBundle.as_dict()``; rebuilding via
    the dataclass makes a corrupt / incomplete / schema-drifted manifest
    fail loudly here, rather than producing a half-populated disclosure
    bundle downstream.
    """
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(
            f"[zkpox] no manifest.json in {bundle_dir} — assemble it "
            f"first with: python3 raptor.py zkpox bundle <store> <hash> "
            f"--out <dir>"
        )
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"[zkpox] manifest.json is not valid JSON: {e}")
    if not isinstance(data, dict):
        raise SystemExit("[zkpox] manifest.json is not a JSON object")
    try:
        return zkpox.ZKPoXBundle(**data)
    except TypeError as e:
        raise SystemExit(
            f"[zkpox] manifest.json does not match the ZKPoXBundle "
            f"schema: {e}"
        )


def cmd_prove(args: argparse.Namespace) -> int:
    """End-to-end: read a Tier 0/1 bundle dir → prove → wrap → envelope
    → project to a CBOR DisclosureBundle → anchor.

    The bundle dir (produced by ``zkpox bundle`` and enriched by
    ``zkpox reproduce``) is the single source of truth for the witness,
    the target artefact hash, the observed outcome, the Tier-1 claim,
    and the Tier 1.5 reproduction evidence. Tier 2/3 flags
    (``--vendor-pubkey`` / ``--gadget-id`` / ``--harness-*`` / ``--wrap``
    …) supply only the genuinely-new proving material; nothing the
    manifest already carries is re-derived from flags.
    """
    _emit_experimental_banner()

    bundle_dir = Path(args.bundle_dir).resolve()
    if not bundle_dir.is_dir():
        raise SystemExit(f"[zkpox] bundle dir not found: {bundle_dir}")
    manifest = _load_manifest(bundle_dir)

    witness_path = bundle_dir / "witness.bin"
    if not witness_path.is_file():
        raise SystemExit(
            f"[zkpox] no witness.bin in {bundle_dir} — bundle is "
            f"incomplete (re-run `zkpox bundle`)"
        )

    # Output defaults to the bundle dir itself, so proof.bin /
    # prove-record.json / bundle.cbor land alongside manifest.json (the
    # /zkpox tier-ladder layout). --out overrides.
    out_dir = Path(args.out).resolve() if args.out else bundle_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- Target reconciliation ----------------------------------------
    # The manifest's target hash is authoritative — it is what was
    # triaged and reproduced. If --target is also supplied, hash it and
    # confirm it matches, so the disclosure proof can never silently
    # bind to a different artifact than the manifest attests to.
    if args.target:
        from core.hash import sha256_file as _bare_sha256_file

        supplied = _bare_sha256_file(Path(args.target))
        if not zkpox.target_hash_matches(manifest, supplied):
            recorded_bare = zkpox.manifest_target_bare_hex(manifest)
            raise SystemExit(
                "[zkpox] --target hash does not match the manifest:\n"
                f"    --target  sha256 {supplied}\n"
                f"    manifest  sha256 {recorded_bare}\n"
                "Refusing to prove: the disclosure bundle would bind to "
                "a different artifact than the one triaged/reproduced. "
                "Pass the target that produced this witness, or omit "
                "--target to use the manifest's recorded hash."
            )

    # Phase 1.5.4: ``--allow-placeholder-hashes`` is gone — the flag was
    # removed from the argparse below. If anyone still passes it via a
    # stale wrapper script that constructs args directly, log + ignore;
    # the bundle binds to the real vkey + guest ELF either way.
    if getattr(args, "allow_placeholder_hashes", False):
        logger.warning(
            "[zkpox] --allow-placeholder-hashes has been removed in "
            "Phase 1.5.4 — the placeholders are gone since 1.5.1. "
            "Drop the flag from any wrapper scripts that still pass it."
        )

    # ---- 1. Drive the Rust prover on the bundle's witness -------------
    prover = _resolve_prover_binary()
    proof_artifact = out_dir / "proof.bin"
    record_path = out_dir / "prove-record.json"

    cmd = [
        str(prover),
        "--witness", str(witness_path),
        "--prove",
        f"--wrap={args.wrap}",
        "--proof-out", str(proof_artifact),
        "--record", str(record_path),
        "--tag", args.tag or f"zkpox-{args.wrap}",
    ]
    logger.info(f"[zkpox] proving via {prover.name} (--wrap={args.wrap})")
    # Sandboxed: bundle dir read-only via target=, out_dir writable via
    # output= (proof.bin + prove-record.json land there), tool_paths to
    # make the workspace-local prover binary visible inside mount-ns. No
    # network — Rekor anchoring happens later in step 4 via the HTTPS
    # client, not this subprocess.
    rc = run_untrusted(
        cmd,
        target=str(bundle_dir),
        output=str(out_dir),
        readable_paths=[str(bundle_dir)],
        tool_paths=[str(prover.parent)],
        caller_label="zkpox-prove",
    ).returncode
    if rc != 0:
        return rc
    record = json.loads(record_path.read_text())
    if record.get("verified") is False:
        logger.error("[zkpox] in-process verify failed; refusing to build bundle")
        return 1

    # Phase 1.5.1: the prover now emits ``vkey_digest`` and
    # ``guest_elf_hash`` (bare hex) in the record. A producer running
    # against a pre-1.5.1 prover that omits either field is refused
    # here, before any bundle gets written, so a placeholder can't
    # silently leak into a disclosure artifact.
    vkey_digest_bare = record.get("vkey_digest")
    guest_elf_hash_bare = record.get("guest_elf_hash")
    if not vkey_digest_bare or not guest_elf_hash_bare:
        logger.error(
            "[zkpox] prove-record.json is missing vkey_digest / "
            "guest_elf_hash — the prover is older than Phase 1.5.1. "
            "Rebuild the prover (core/zkpox/) and retry. Refusing to "
            "write a bundle with placeholder hashes."
        )
        return 1
    verifier_key_hash = f"sha256:{vkey_digest_bare}"
    harness_hash = f"sha256:{guest_elf_hash_bare}"

    # Phase 1.5.1: bind to the gadget's declared file manifest
    # (markdown spec + guest impl files). Refuse the bundle on an
    # unknown gadget_id so a typo never produces an under-bound proof.
    from packages.zkpox.gadget import (
        GadgetCodeHashError,
        compute_gadget_code_hash,
    )
    try:
        gadget_code_hash = compute_gadget_code_hash(args.gadget_id)
    except GadgetCodeHashError as exc:
        logger.error(f"[zkpox] {exc}")
        return 1

    # ---- 2. Build envelope (optional) ----------------------------------
    envelope_blobs = None
    if args.vendor_pubkey:
        witness_bytes = witness_path.read_bytes()
        logger.info("[zkpox] sealing vendor envelope")
        envelope_blobs = zkpox.seal(
            witness_bytes,
            args.vendor_pubkey,
            duration=args.tlock_duration,
        )

    # ---- 3. Project manifest → DisclosureBundle ------------------------
    # The projection derives target-hash / outcome / claim / reproduction
    # from the manifest and carries the full Tier 0/1 + 1.5 evidence into
    # the bundle's ``provenance``. We supply only the new Tier 2/3 parts.
    proof_bytes = proof_artifact.read_bytes()
    vendor_envelope = (
        zkpox.vendor_envelope_from(
            envelope_blobs,
            vendor_pubkey=args.vendor_pubkey,
            drand_round_min=None,
        )
        if envelope_blobs is not None
        else zkpox.VendorEnvelope(
            scheme="zkpox-none/v1",
            aes_blob=b"",
            ct_K_age=b"",
            ct_K_tlock=b"",
            drand_round_min=None,
            vendor_pubkey="",
            vendor_pubkey_fingerprint=zkpox.sha256_bytes(b""),
        )
    )
    bundle = zkpox.disclosure_from_manifest(
        manifest,
        proof=zkpox.Proof(
            system=f"sp1-{args.wrap}/v6.1.0",
            bytes=proof_bytes,
            # Phase 1.5.1: real SP1 verifying-key digest from the prove
            # record (the prover computes it via ``HashableKey::bytes32``).
            verifier_key_hash=verifier_key_hash,
        ),
        vendor_envelope=vendor_envelope,
        harness=zkpox.HarnessRef(
            git_url=args.harness_git_url,
            rev=args.harness_rev,
            # Phase 1.5.1: real sha256 of the embedded SP1 guest ELF.
            hash=harness_hash,
        ),
        vuln_class=args.vuln_class,
        gadget_id=args.gadget_id,
        # Hashes the gadget IDENTIFIER string (independent of the code
        # binding, which lives in ``gadget_code_hash`` below).
        gadget_id_hash=zkpox.sha256_bytes(args.gadget_id.encode()),
        # Phase 1.5.1: binds the bundle to the gadget's declared file
        # manifest (markdown spec + guest impl files). See
        # ``packages/zkpox/gadget.py``.
        gadget_code_hash=gadget_code_hash,
        leaked_fields=[f.strip() for f in (args.leaked or "").split(",") if f.strip()],
        target_kind=args.target_kind,
        target_url=args.target_url,
    )

    # ---- 4. Anchor (optional) ------------------------------------------
    if not args.no_anchor:
        try:
            logger.info("[zkpox] anchoring bundle to Rekor")
            bundle, _kp = zkpox.anchor_bundle(bundle, rekor=args.rekor_url)
        except Exception as exc:
            logger.error(f"[zkpox] anchor failed: {exc}")
            if args.require_anchor:
                return 1
            logger.warning("[zkpox] continuing without anchor (--require-anchor not set)")

    # ---- 5. Persist bundle ---------------------------------------------
    bundle_path = out_dir / "bundle.cbor"
    bundle_path.write_bytes(zkpox.to_cbor(bundle))

    summary = {
        "bundle": str(bundle_path),
        "proof_artifact": str(proof_artifact),
        "source_manifest": str(bundle_dir / "manifest.json"),
        "manifest_tier": manifest.tier,
        "reproduction_carried": manifest.reproduction is not None,
        "target_hash": bundle.target.hash,
        "wrap": args.wrap,
        "proof_bytes": len(proof_bytes),
        "verified_in_process": record.get("verified"),
        "envelope": envelope_blobs is not None,
        "anchored": bundle.timestamp is not None,
        "rekor_log_index": (
            bundle.timestamp.rekor_log_index if bundle.timestamp else None
        ),
    }
    print(json.dumps(summary, indent=2))
    return 0


# ---------------------------------------------------------------------------
# `verify` subcommand
# ---------------------------------------------------------------------------

def _resolve_verifier_binary() -> Path:
    root = Path(__file__).resolve().parent
    candidate = root / "core" / "zkpox" / "target" / "release" / "zkpox-verify"
    if not candidate.exists():
        raise SystemExit(
            f"zkpox-verify not built: {candidate}\n"
            f"build it with: cargo build --release "
            f"--manifest-path core/zkpox/Cargo.toml"
        )
    return candidate


def cmd_verify(args: argparse.Namespace) -> int:
    _emit_experimental_banner()
    verifier = _resolve_verifier_binary()
    cmd = [str(verifier), args.bundle]
    if args.json:
        cmd.append("--json")
    # Sandboxed: bundle dir read-only, fresh tempdir for the verifier's
    # scratch (SP1 SDK + Groth16 artifact cache), no network. The
    # verifier emits its result on stdout — no FS writes back to the
    # bundle dir, so the writable scope can be a throwaway tempdir.
    bundle_dir = Path(args.bundle).resolve().parent
    sandbox_workdir = tempfile.mkdtemp(prefix="zkpox-verify-")
    try:
        return run_untrusted(
            cmd,
            target=str(bundle_dir),
            output=sandbox_workdir,
            readable_paths=[str(bundle_dir)],
            tool_paths=[str(verifier.parent)],
            caller_label="zkpox-verify",
        ).returncode
    finally:
        shutil.rmtree(sandbox_workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor_zkpox",
        description="Zero-knowledge proof of exploit driver",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    pp = sub.add_parser(
        "prove",
        help="Generate a ZKPoX disclosure bundle from a Tier 0/1 bundle dir",
    )
    pp.add_argument(
        "bundle_dir",
        help=(
            "Tier 0/1 bundle directory (contains manifest.json + "
            "witness.bin), as produced by `zkpox bundle` and optionally "
            "enriched by `zkpox reproduce`. The witness, target hash, "
            "outcome, claim, and reproduction evidence are read from it."
        ),
    )
    pp.add_argument(
        "--target",
        help=(
            "Optional path to the vulnerable target binary. When given, "
            "its sha256 is reconciled against the manifest's recorded "
            "hash (mismatch is a hard error); the manifest hash is "
            "authoritative either way."
        ),
    )
    pp.add_argument("--target-kind", default="elf",
                    choices=["elf", "wasm", "evm", "llvm-ir"])
    pp.add_argument("--target-url", help="Optional URL the target can be retrieved from")
    pp.add_argument("--vuln-class", default="memory-safety",
                    help="Bundle vulnerability class")
    pp.add_argument("--gadget-id", default="memory-safety::oob-write@0.1.0",
                    help="Violation-gadget identifier (see .claude/skills/zkpox/violation-gadgets/)")
    pp.add_argument("--leaked", default="",
                    help="Comma-separated list of fields the gadget intentionally leaks")
    pp.add_argument("--wrap", default="groth16", choices=["core", "groth16"],
                    help="Proof wrap. groth16 is required for shippable bundles.")
    pp.add_argument("--vendor-pubkey",
                    help="age public key for the vendor envelope (omit to skip envelope)")
    pp.add_argument("--tlock-duration", default="90d",
                    help="Drand tlock duration (Project Zero default 90d)")
    pp.add_argument("--no-anchor", action="store_true",
                    help="Skip Sigstore Rekor anchoring")
    pp.add_argument("--require-anchor", action="store_true",
                    help="If anchoring fails, exit non-zero (default: warn)")
    pp.add_argument("--rekor-url",
                    help="Override the Sigstore Rekor URL (env: ZKPOX_REKOR_URL)")
    pp.add_argument("--harness-git-url",
                    help="Harness source git URL (recorded in bundle)")
    pp.add_argument("--harness-rev",
                    help="Harness source git revision")
    pp.add_argument("--tag", help="Bench tag for the prover record")
    # Phase 1.5.4 removed ``--allow-placeholder-hashes`` from the parser
    # entirely. The Phase 1.5.1 no-op + deprecation cycle is done. A
    # stale wrapper script that still passes the flag now gets an
    # argparse "unrecognised argument" error — intentional, so the
    # caller updates rather than silently flipping into a different
    # bundle shape than they expect.
    pp.add_argument(
        "--out",
        help=(
            "Output directory for bundle.cbor + proof.bin + "
            "prove-record.json. Defaults to the bundle dir itself, "
            "landing the artefacts alongside manifest.json."
        ),
    )
    pp.set_defaults(func=cmd_prove)

    vp = sub.add_parser("verify", help="Verify a ZKPoX disclosure bundle")
    vp.add_argument("bundle", help="Path to the CBOR bundle")
    vp.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    vp.add_argument("--out", help=argparse.SUPPRESS)  # accepted from raptor.py lifecycle
    vp.set_defaults(func=cmd_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    # No blanket dependency gate here: the old ``zkpox.require()`` global
    # was removed when the package was split into dependency-free tiers,
    # and a blanket check would wrongly gate ``verify`` (which needs only
    # the built verifier binary + cbor2, not the SP1 proving toolchain).
    # The operator surface ``libexec/raptor-zkpox`` gates ``prove`` on
    # ``require_proving_stack()`` before delegating here; missing cbor2 /
    # age / tle / the Rust binaries surface as clear point-of-use errors.
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
