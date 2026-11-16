"""ZKPoX CLI — unified subcommand dispatcher.

Import target for ``raptor_zkpox.py``
(``from packages.zkpox.cli import main``), which ``raptor.py``
mode_zkpox delegates to via ``_run_script`` / ``_run_with_lifecycle``.

Dependency-free tiers (bundle, reproduce) delegate to the package
APIs. SP1 native tiers (prove, verify, inspect, open) require the
native workspace and error cleanly when it is absent.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_MAX_MANIFEST_BYTES = 2 * 1024 * 1024


def _require_native(subcommand: str) -> int:
    native = Path(__file__).parent / "native"
    print(
        f"zkpox {subcommand}: requires the native workspace "
        f"({native / 'Cargo.toml'}).\n"
        f"See packages/zkpox/README.md for build prerequisites.",
        file=sys.stderr,
    )
    return 1


def _cmd_bundle(args) -> int:
    from core.witness import WitnessStore, WitnessStoreError
    from packages.zkpox import (
        ZKPoXBundleError,
        assemble_bundle,
        render_bundle,
        write_bundle,
    )

    store_root = Path(args.witness_store)
    if not (store_root / "manifests").is_dir():
        sys.stderr.write(
            f"not a witness store (no manifests/): {store_root}\n"
        )
        return 2

    store = WitnessStore(store_root)
    try:
        witness = store.get_witness(args.witness_hash)
    except WitnessStoreError as exc:
        sys.stderr.write(f"witness lookup failed: {exc}\n")
        return 2

    try:
        bundle = assemble_bundle(witness, store)
    except ZKPoXBundleError as exc:
        sys.stderr.write(f"bundle assembly refused: {exc}\n")
        return 1

    bundle_dir = write_bundle(bundle, store, Path(args.out))
    print(render_bundle(bundle))
    print(f"  bundle dir: {bundle_dir}")
    return 0


def _cmd_reproduce(args) -> int:
    from core.hash import sha256_bytes
    from packages.zkpox import (
        ZKPoXBundle,
        attach_reproduction,
        render_bundle,
        reproduce_witness,
    )

    bundle_dir = Path(args.bundle_dir)
    manifest_path = bundle_dir / "manifest.json"
    witness_path = bundle_dir / "witness.bin"
    if not manifest_path.is_file():
        sys.stderr.write(f"no manifest.json in {bundle_dir}\n")
        return 2
    if not witness_path.is_file():
        sys.stderr.write(f"no witness.bin in {bundle_dir}\n")
        return 2

    try:
        raw = manifest_path.read_bytes()
        if len(raw) > _MAX_MANIFEST_BYTES:
            sys.stderr.write("manifest.json exceeds size limit\n")
            return 2
        manifest = json.loads(raw)
    except (ValueError, OSError) as exc:
        sys.stderr.write(f"cannot read manifest.json: {exc}\n")
        return 2
    if not isinstance(manifest, dict):
        sys.stderr.write("manifest.json is not a JSON object\n")
        return 2

    required = ("witness_hash", "witness_len", "source", "observed_outcome")
    missing = [k for k in required if k not in manifest]
    if missing:
        sys.stderr.write(
            f"manifest.json missing required field(s): "
            f"{', '.join(missing)}\n"
        )
        return 2

    try:
        witness_bytes = witness_path.read_bytes()
    except OSError as exc:
        sys.stderr.write(f"cannot read witness.bin: {exc}\n")
        return 2
    actual_hash = sha256_bytes(witness_bytes)
    if actual_hash != manifest["witness_hash"]:
        sys.stderr.write(
            f"witness.bin hash mismatch: file {actual_hash[:16]}... "
            f"!= manifest {str(manifest['witness_hash'])[:16]}...\n"
        )
        return 2

    bundle = ZKPoXBundle(
        witness_hash=manifest["witness_hash"],
        witness_len=manifest["witness_len"],
        source=manifest["source"],
        observed_outcome=manifest["observed_outcome"],
        outcome_detail=manifest.get("outcome_detail", {}),
        target_binary_hash=manifest.get("target_binary_hash"),
        target_source_hash=manifest.get("target_source_hash"),
        produced_by=manifest.get("produced_by"),
        timestamp=manifest.get("timestamp"),
        attestation=manifest.get("attestation", {}),
        tier=manifest.get("tier", "0/1"),
        reproduction=manifest.get("reproduction"),
    )

    binary_path = Path(args.binary) if args.binary else None
    result = reproduce_witness(
        bundle, witness_bytes,
        binary_path=binary_path, n=args.n,
        sandbox_timeout=args.timeout,
    )
    attach_reproduction(bundle, result)

    manifest_path.write_text(
        json.dumps(bundle.as_dict(), indent=2) + "\n"
    )

    print(render_bundle(bundle))
    print(f"  reproduced: {result.reproduced} "
          f"(attempted={result.attempted}, {result.reason})")
    if result.reproduced:
        return 0
    return 1 if result.attempted else 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="raptor-zkpox",
        description="ZKPoX zero-knowledge proof of exploit.",
    )
    sub = ap.add_subparsers(dest="cmd")

    # ── Dependency-free tiers ─────────────────────────────────────
    b = sub.add_parser("bundle", help="Tier 0/1: assemble a bundle")
    b.add_argument("witness_store", help="WitnessStore root dir")
    b.add_argument("witness_hash", help="sha256 of the witness bytes")
    b.add_argument("--out", required=True, help="output dir")

    r = sub.add_parser("reproduce", help="Tier 1.5: reproduce a bundle")
    r.add_argument("bundle_dir", help="bundle dir (with manifest.json)")
    r.add_argument("--binary", help="target binary")
    r.add_argument("--n", type=int, default=3, help="consecutive runs")
    r.add_argument("--timeout", type=int, default=5,
                   help="per-run timeout (s)")

    # ── SP1 native tiers (stubs until native workspace lands) ─────
    p = sub.add_parser("prove", help="Tier 2/3: Groth16 disclosure")
    p.add_argument("bundle_dir", help="private bundle dir")
    p.add_argument("--target", required=True,
                   help="curated target id (01/02/03)")
    p.add_argument("--gadget", help="gadget class")
    p.add_argument("--out", required=True, help="public output dir")
    p.add_argument("--anchor", action="store_true",
                   help="anchor to Rekor")
    p.add_argument("--rekor-url", help="Rekor log URL")
    p.add_argument("--rekor-key", help="pinned log public key PEM")
    p.add_argument("--rekor-origin", help="checkpoint origin")
    p.add_argument("--circuit-cache", help="SP1 circuit cache dir")
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--timeout", type=int, default=7200,
                   help="wall-time limit (s)")

    v = sub.add_parser("verify", help="verify a disclosure bundle")
    v.add_argument("bundle", help="path to bundle.cbor")
    v.add_argument("--json", action="store_true", help="JSON output")
    v.add_argument("--require-anchor", action="store_true")
    v.add_argument("--rekor-key", help="pinned log public key PEM")
    v.add_argument("--rekor-origin", help="checkpoint origin")

    i = sub.add_parser("inspect",
                       help="inspect bundle metadata (no verification)")
    i.add_argument("bundle", help="path to bundle.cbor")

    o = sub.add_parser("open", help="decrypt + verify delivery")
    o.add_argument("bundle", help="path to bundle.cbor")
    o.add_argument("--identity", help="age identity file")
    o.add_argument("--after-release", action="store_true")
    o.add_argument("--out", required=True, help="output file")

    args = ap.parse_args(argv)

    if args.cmd is None:
        ap.print_help()
        return 2

    if args.cmd == "bundle":
        return _cmd_bundle(args)
    if args.cmd == "reproduce":
        return _cmd_reproduce(args)
    if args.cmd in ("prove", "verify", "inspect", "open"):
        return _require_native(args.cmd)
    return 2
