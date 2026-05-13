#!/usr/bin/env python3
"""
RAPTOR ZKPoX — Zero-Knowledge Proof of Exploit driver.

End-to-end Phase 1.5 orchestration:
  prove                 prove → wrap → envelope → bundle → optional Rekor anchor
  verify                delegate to the standalone zkpox-verify binary

Most users will invoke this through `python3 raptor.py prove-exploit` or
`python3 raptor.py verify-exploit-proof`; this script is the standalone
backing implementation, analogous to raptor_codeql.py / raptor_fuzzing.py.

Companion code:
  core/zkpox/                    Rust workspace: guest / prover / verifier
  packages/zkpox/                Python: envelope / bundle / anchor / prove
  docs/proposals/raptor-zkpox-design.md
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

# Hard-lookup RAPTOR_DIR per the project's sys.path rule (CLAUDE.md):
# the KeyError on an unset env is intentional — fail loudly rather than
# silently falling back to a cwd or __file__-relative walk that breaks
# under symlinks / non-repo cwd. The launcher always sets RAPTOR_DIR.
sys.path.insert(0, os.environ["RAPTOR_DIR"])

from core.config import RaptorConfig
from core.logging import get_logger
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


_PLACEHOLDER_VK_DIGEST = "placeholder-vk-1.5"
_PLACEHOLDER_HARNESS_DIGEST = "harness-1.5"
_PLACEHOLDER_WARNING = (
    "[zkpox] WARNING: bundle's verifier_key_hash and harness.hash are "
    "Phase 1.5 PLACEHOLDERS. They do NOT bind to the real SP1 verifying "
    "key or the harness binary. Do NOT use this bundle for a real "
    "disclosure until Phase 1.5.x replaces them. See docs/zkpox-scope.md."
)


def cmd_prove(args: argparse.Namespace) -> int:
    """End-to-end prove → wrap → envelope → bundle → anchor."""
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not args.allow_placeholder_hashes:
        raise SystemExit(
            "[zkpox] refusing to write a bundle: Phase 1.5 produces "
            "placeholder verifier_key_hash and harness.hash, which do "
            "not bind to the real SP1 verifying key or the harness. "
            "Re-run with --allow-placeholder-hashes to acknowledge and "
            "proceed; the bundle will print a loud warning on every "
            "verify. Real-disclosure use should wait for Phase 1.5.x. "
            "Background: docs/zkpox-scope.md."
        )
    logger.warning(_PLACEHOLDER_WARNING)

    # ---- 1. Drive the Rust prover --------------------------------------
    prover = _resolve_prover_binary()
    proof_artifact = out_dir / "proof.bin"
    record_path = out_dir / "prove-record.json"

    cmd = [
        str(prover),
        "--witness", str(args.witness),
        "--prove",
        f"--wrap={args.wrap}",
        "--proof-out", str(proof_artifact),
        "--record", str(record_path),
        "--tag", args.tag or f"zkpox-{args.wrap}",
    ]
    logger.info(f"[zkpox] proving via {prover.name} (--wrap={args.wrap})")
    # Explicit get_safe_env() at the subprocess boundary even though
    # raptor.py's lifecycle already sanitised the parent env — convention
    # is "explicit at every spawn site" so a future direct caller can't
    # accidentally leak a dirty env through.
    rc = subprocess.run(
        cmd, check=False, env=RaptorConfig.get_safe_env()
    ).returncode
    if rc != 0:
        return rc
    record = json.loads(record_path.read_text())
    if record.get("verified") is False:
        logger.error("[zkpox] in-process verify failed; refusing to build bundle")
        return 1

    # ---- 2. Build envelope (optional) ----------------------------------
    envelope_blobs = None
    if args.vendor_pubkey:
        witness_bytes = Path(args.witness).read_bytes()
        logger.info("[zkpox] sealing vendor envelope")
        envelope_blobs = zkpox.seal(
            witness_bytes,
            args.vendor_pubkey,
            duration=args.tlock_duration,
        )

    # ---- 3. Assemble bundle --------------------------------------------
    proof_bytes = proof_artifact.read_bytes()
    bundle = zkpox.Bundle(
        version=zkpox.BUNDLE_VERSION,
        target=zkpox.Target(
            kind=args.target_kind,
            hash=zkpox.sha256_file(Path(args.target)) if args.target else "sha256:" + "00" * 32,
            url=args.target_url,
            metadata={"witness_bytes": record["witness_bytes"]},
        ),
        vulnerability=zkpox.Vulnerability(
            cls=args.vuln_class,
            gadget_id=args.gadget_id,
            # Hashes the gadget IDENTIFIER, not its source. The field name
            # was `gadget_hash` pre-Phase-1.5; renamed to make the binding
            # honest (see docs/zkpox-scope.md). Phase 1.5.x will add a
            # separate `gadget_code_hash` over the gadget implementation
            # files.
            gadget_id_hash=zkpox.sha256_bytes(args.gadget_id.encode()),
            leaked_fields=[f.strip() for f in (args.leaked or "").split(",") if f.strip()],
        ),
        proof=zkpox.Proof(
            system=f"sp1-{args.wrap}/v6.1.0",
            bytes=proof_bytes,
            # Placeholder until Phase 1.5.x wires sp1-sdk's real vk digest.
            # cmd_prove refuses to reach this branch without the explicit
            # --allow-placeholder-hashes opt-in (see top of this function).
            verifier_key_hash=zkpox.sha256_bytes(_PLACEHOLDER_VK_DIGEST.encode()),
        ),
        harness=zkpox.HarnessRef(
            git_url=args.harness_git_url,
            rev=args.harness_rev,
            hash=zkpox.sha256_bytes(_PLACEHOLDER_HARNESS_DIGEST.encode()),
        ),
        vendor_envelope=(
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
        ),
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
    verifier = _resolve_verifier_binary()
    cmd = [str(verifier), args.bundle]
    if args.json:
        cmd.append("--json")
    # Explicit get_safe_env() at the subprocess boundary (see cmd_prove).
    return subprocess.run(
        cmd, check=False, env=RaptorConfig.get_safe_env()
    ).returncode


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor_zkpox",
        description="Zero-knowledge proof of exploit driver",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    pp = sub.add_parser("prove", help="Generate a ZKPoX disclosure bundle")
    pp.add_argument("--witness", required=True, help="Path to the exploit witness (raw bytes)")
    pp.add_argument("--target", help="Path to the vulnerable target binary (for hashing)")
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
    pp.add_argument(
        "--allow-placeholder-hashes",
        action="store_true",
        help=(
            "Acknowledge that Phase 1.5 produces a bundle with placeholder "
            "verifier_key_hash and harness.hash that do NOT bind to real "
            "SP1 / harness state. Required until Phase 1.5.x replaces "
            "them. Bundle will print a loud warning; do not use for real "
            "disclosure."
        ),
    )
    pp.add_argument("--out", required=True,
                    help="Output directory (bundle.cbor + proof.bin + prove-record.json)")
    pp.set_defaults(func=cmd_prove)

    vp = sub.add_parser("verify", help="Verify a ZKPoX disclosure bundle")
    vp.add_argument("bundle", help="Path to the CBOR bundle")
    vp.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    vp.add_argument("--out", help=argparse.SUPPRESS)  # accepted from raptor.py lifecycle
    vp.set_defaults(func=cmd_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
