"""Canonical ZKPoX CLI. Lightweight operations do not require the SP1 stack."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from core.json import load_json, save_json
from core.security.log_sanitisation import sanitise_for_terminal

# manifest.json is a small bundle descriptor.
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024


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
    except WitnessStoreError as e:
        sys.stderr.write(f"witness lookup failed: {e}\n")
        return 2

    try:
        bundle = assemble_bundle(witness, store)
    except ZKPoXBundleError as e:
        sys.stderr.write(f"bundle assembly refused: {e}\n")
        return 1

    bundle_dir = write_bundle(bundle, store, Path(args.out))
    print(render_bundle(bundle))
    print(f"  bundle dir: {bundle_dir}")
    return 0


def _cmd_reproduce(args) -> int:
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
        manifest = load_json(
            manifest_path, strict=True, max_bytes=_MAX_MANIFEST_BYTES,
        )
    except ValueError as e:
        sys.stderr.write(f"manifest.json is not valid JSON: {e}\n")
        return 2
    except OSError as e:
        # An unreadable manifest (permissions, I/O error) must land on
        # the diagnostic exit-2 path, not escape as a traceback.
        sys.stderr.write(f"cannot read manifest.json: {e}\n")
        return 2
    if not isinstance(manifest, dict):
        sys.stderr.write("manifest.json is not a JSON object\n")
        return 2

    # The four fields reproduce_witness reads are load-bearing; a
    # manifest missing any of them is corrupt, not reproducible.
    required = ("witness_hash", "witness_len", "source", "observed_outcome")
    missing = [k for k in required if k not in manifest]
    if missing:
        sys.stderr.write(
            f"manifest.json missing required field(s): "
            f"{', '.join(missing)}\n"
        )
        return 2

    # Verify witness.bin against the manifest before constructing the
    # bundle — a swapped/truncated witness must not silently drive an
    # N-run reproduction of the wrong bytes.
    try:
        witness_bytes = witness_path.read_bytes()
    except OSError as e:
        # is_file() above doesn't guarantee the read succeeds
        # (permissions, races) — keep the exit-code contract.
        sys.stderr.write(f"cannot read witness.bin: {e}\n")
        return 2
    from core.hash import sha256_bytes
    actual_hash = sha256_bytes(witness_bytes)
    if actual_hash != manifest["witness_hash"]:
        sys.stderr.write(
            f"witness.bin hash mismatch: file {actual_hash[:16]}... "
            f"!= manifest witness_hash "
            f"{str(manifest['witness_hash'])[:16]}...; "
            f"refusing to reproduce a tampered/swapped witness\n"
        )
        return 2
    if manifest.get("witness_len") is not None \
            and len(witness_bytes) != manifest["witness_len"]:
        sys.stderr.write(
            f"witness.bin length mismatch: file is "
            f"{len(witness_bytes)} bytes, manifest witness_len is "
            f"{manifest['witness_len']}; refusing to reproduce\n"
        )
        return 2

    # Reconstruct the bundle dataclass from the manifest. The rest
    # round-trip for re-persistence.
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

    # Re-persist the manifest with the reproduction block + tier bump.
    # save_json writes atomically (tempfile + rename) — no partial
    # writes.
    save_json(manifest_path, bundle.as_dict())

    print(render_bundle(bundle))
    print(f"  reproduced: {result.reproduced} "
          f"(attempted={result.attempted}, {sanitise_for_terminal(result.reason)})")
    # Per-run diagnostics: name the lane and shape of every run so a
    # divergent run (isolation degradation, clean-exit-with-no-input)
    # is diagnosable straight from the report/CI log.
    for rec in result.run_details:
        extras = ", ".join(
            f"{k}={rec[k]!r}" for k in rec if k not in ("run", "outcome")
        )
        line = f"    run {rec.get('run', '?')}: {rec.get('outcome', '?')}"
        if extras:
            line += f" ({extras})"
        print(sanitise_for_terminal(line, max_len=2048))
    # Exit 0 when it reproduced; 1 when attempted-but-not; 2 when
    # not attempted (couldn't run) — so scripts can branch.
    if result.reproduced:
        return 0
    return 1 if result.attempted else 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="raptor-zkpox", description="Witness bundles, reproduction and curated SP1 disclosure proofs.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    eligibility = sub.add_parser("eligible", help="Read witness eligibility without execution or artifacts")
    eligibility.add_argument("--run-dir", required=True)
    eligibility.add_argument("--project-root")
    eligibility.set_defaults(func=_cmd_eligible)
    b = sub.add_parser("bundle", help="Tier 0/1: assemble a private witness bundle")
    b.add_argument("witness_store")
    b.add_argument("witness_hash")
    b.add_argument("--out", required=True)
    b.set_defaults(func=_cmd_bundle)
    r = sub.add_parser("reproduce", help="Tier 1.5: reproduce a private bundle")
    r.add_argument("bundle_dir")
    r.add_argument("--binary")
    r.add_argument("--n", type=int, default=3)
    r.add_argument("--timeout", type=int, default=5)
    r.set_defaults(func=_cmd_reproduce)
    p = sub.add_parser("prove", help="Prove a violation for one of the three curated C sources")
    p.add_argument("bundle_dir", help="Private Tier 0/1 bundle containing witness.bin and manifest.json")
    p.add_argument("--target", choices=("01", "02", "03"), required=True)
    p.add_argument("--gadget", choices=("crash_only", "oob_write"), default="oob_write")
    p.add_argument("--out", required=True, help="Separate public disclosure directory")
    p.add_argument("--circuit-cache", help="Prepared SP1 Groth16 circuit-cache directory")
    p.add_argument("--vendor-pubkey")
    p.add_argument("--tlock-duration", default="90d")
    p.add_argument("--timeout", type=int, default=7200)
    p.add_argument("--threads", type=int, default=8, help="CPU parallelism for Rust and Go proving (1..64)")
    p.add_argument("--anchor", action="store_true", help="Publish an inclusion entry to the specified Rekor v2 service")
    p.add_argument("--rekor-url", help="Explicit Rekor v2 HTTPS URL; never inferred from a year")
    p.add_argument("--rekor-key", help="Pinned log ECDSA P-256 public key PEM")
    p.add_argument("--rekor-origin", help="Pinned checkpoint origin")
    p.set_defaults(func=_cmd_prove)
    for command in ("verify", "inspect"):
        v = sub.add_parser(command, help="Verify cryptography" if command == "verify" else "Inspect metadata without verification")
        v.add_argument("bundle")
        v.add_argument("--json", action="store_true")
        v.add_argument("--require-anchor", action="store_true")
        v.add_argument("--rekor-key", help="Pinned log public key PEM")
        v.add_argument("--rekor-origin", help="Pinned checkpoint origin")
        v.set_defaults(func=_cmd_verify if command == "verify" else _cmd_inspect)
    opening = sub.add_parser("open", help="Decrypt a delivery and check the proven witness commitment")
    opening.add_argument("bundle")
    route = opening.add_mutually_exclusive_group(required=True)
    route.add_argument("--identity", help="Vendor age identity file")
    route.add_argument("--after-release", action="store_true")
    opening.add_argument("--out", required=True, help="New private witness file (mode 0600)")
    opening.set_defaults(func=_cmd_open)
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError, KeyError, ImportError, RuntimeError) as exc:
        print(f"zkpox: {exc}", file=sys.stderr)
        return 2


def _read_bounded(path: Path, limit: int) -> bytes:
    # Nonblocking open avoids hanging on FIFOs supplied as bundles/manifests.
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f"expected a regular file: {path.name}")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"file exceeds size limit: {path.name}")
    return data


def _native(name: str) -> Path:
    import shutil
    found = shutil.which(name)
    candidate = Path(found) if found else Path(__file__).parent / "native" / "target" / "release" / name
    if not candidate.is_file():
        raise ValueError(f"{name} is not installed; build packages/zkpox/native with the pinned SP1 toolchain")
    return candidate.resolve()


def _cmd_prove(args) -> int:
    from core.config import RaptorConfig
    from core.atomic_fs import write_bytes_atomically
    from .proving_deps import SP1_JIT_FILE_LIMIT_MB
    from core.sandbox import run_untrusted
    from .disclosure import (Proof, HarnessRef, VendorEnvelope, to_cbor,
                             vendor_envelope_from, disclosure_from_statement)
    from .statement import Statement, SYSTEM, MAX_WITNESS, source_hash, commitment
    if args.anchor and not all((args.rekor_url, args.rekor_key, args.rekor_origin)):
        raise ValueError("--anchor requires --rekor-url, --rekor-key and --rekor-origin")
    private_dir = Path(args.bundle_dir).resolve()
    out = Path(args.out).resolve()
    if out == private_dir or out in private_dir.parents or private_dir in out.parents:
        raise ValueError("public output must be separate from the private witness bundle")
    manifest = json.loads(_read_bounded(private_dir / "manifest.json", _MAX_MANIFEST_BYTES))
    witness = _read_bounded(private_dir / "witness.bin", MAX_WITNESS)
    if type(manifest.get("witness_len")) is not int or len(witness) != manifest["witness_len"] or hashlib.sha256(witness).hexdigest() != manifest.get("witness_hash"):
        raise ValueError("private witness does not match its manifest")
    target = int(args.target)
    expected_source = source_hash(target)
    if manifest.get("target_source_hash") != expected_source.hex():
        raise ValueError("SP1 currently supports only the three curated sources; the manifest source hash must match --target. Use reproduce for arbitrary native binaries.")
    gadget = {"crash_only": 1, "oob_write": 2}[args.gadget]
    if args.timeout <= 0 or not 1 <= args.threads <= 64:
        raise ValueError("timeout must be positive and threads must be in 1..64")
    prover = _native("zkpox-prove")
    if args.vendor_pubkey:
        from .envelope import require_sealing_tools
        if not args.vendor_pubkey.startswith("age1") or len(args.vendor_pubkey) > 200:
            raise ValueError("vendor recipient must be an age public key")
        require_sealing_tools()
    salt = os.urandom(32)
    with tempfile.TemporaryDirectory(prefix="zkpox-private-") as tmp:
        work = Path(tmp)
        witness_path = work / "witness.bin"
        witness_path.write_bytes(witness)
        witness_path.chmod(0o600)
        salt_path = work / "salt.bin"
        salt_path.write_bytes(salt)
        salt_path.chmod(0o600)
        record_path, proof_path = work / "record.json", work / "proof.bin"
        env = RaptorConfig.get_safe_env()
        env["RAYON_NUM_THREADS"] = str(args.threads)
        env["GOMAXPROCS"] = str(args.threads)
        readable = []
        circuit = args.circuit_cache or os.environ.get("SP1_GROTH16_CIRCUIT_PATH") or str(Path.home() / ".sp1/circuits/groth16")
        if circuit:
            circuit = str(Path(circuit).resolve())
            if not Path(circuit).is_dir():
                raise ValueError("prepared Groth16 circuit-cache directory does not exist")
            env["SP1_GROTH16_CIRCUIT_PATH"] = circuit
            readable.append(circuit)
        result = run_untrusted([
            "/usr/bin/env", f"TMPDIR={work}", str(prover), "--witness", str(witness_path), "--target", args.target,
            "--gadget", str(gadget), "--salt", str(salt_path), "--prove", "--wrap", "groth16",
            "--proof-out", str(proof_path), "--record", str(record_path),
        ], output=str(work), readable_paths=readable,
            tool_paths=[str(prover.parent)], caller_label="zkpox-prove", env=env, timeout=args.timeout,
            limits={"cpu_seconds": args.timeout * args.threads, "max_file_mb": SP1_JIT_FILE_LIMIT_MB})
        if result.returncode:
            return result.returncode
        record = json.loads(_read_bounded(record_path, 1024 * 1024))
        statement = Statement.from_dict(record["statement"])
        statement.validate()
        if record.get("mode") != "prove" or record.get("wrap") != "groth16" or record.get("verified") is not True:
            raise ValueError("prover did not verify a Groth16 proof")
        if statement.target_id != target or statement.gadget_id != gadget or statement.witness_commitment != commitment(target, gadget, salt, witness):
            raise ValueError("prover returned a statement for a different witness/target/predicate")
        proof = _read_bounded(proof_path, 64 * 1024 * 1024)
        vk, harness = record["verifier_key_hash"], record["harness_hash"]
        for value, prefix in ((vk, "sp1-vk:"), (harness, "sha256:")):
            if type(value) is not str or not value.startswith(prefix) or len(value[len(prefix):]) != 64:
                raise ValueError("prover returned invalid artifact identity")
            bytes.fromhex(value[len(prefix):])
        if args.vendor_pubkey:
            from .envelope import seal
            encrypted = seal(salt + witness, args.vendor_pubkey, duration=args.tlock_duration,
                             aad=b"raptor-zkpox-delivery-v2\0" + statement.encode())
            envelope = vendor_envelope_from(encrypted, vendor_pubkey=args.vendor_pubkey, drand_round_min=None)
        else:
            envelope = VendorEnvelope("zkpox-none/v2", b"", b"", b"", None, "", "sha256:" + hashlib.sha256(b"").hexdigest())
        bundle = disclosure_from_statement(statement, proof=Proof(SYSTEM, proof, vk),
            harness=HarnessRef(None,None,harness), vendor_envelope=envelope)
        if args.anchor:
            from .rekor_v2 import anchor
            bundle = anchor(bundle, url=args.rekor_url,
                            trusted_key=_read_bounded(Path(args.rekor_key), 64 * 1024), origin=args.rekor_origin)
        # Public output contains neither witness, salt, raw witness digest nor private bench record.
        out.mkdir(parents=True, exist_ok=True)
        write_bytes_atomically(out / "bundle.cbor", to_cbor(bundle))
        summary = {"bundle": str(out / "bundle.cbor"), "verified_in_process": True,
                   "target_scope": "curated-source", "anchored": bundle.transparency is not None,
                   "timestamp": "absent",
                   "delivery": "encrypted-unchecked" if args.vendor_pubkey else "absent"}
        save_json(out / "verification.json", summary)
        print(json.dumps(summary, indent=2))
    return 0


def _cmd_verify(args) -> int:
    from core.sandbox import run_untrusted
    verifier = _native("zkpox-verify")
    blob = _read_bounded(Path(args.bundle), 64 * 1024 * 1024)
    anchor_status = {"status": "not_checked"}
    if getattr(args, "require_anchor", False):
        from .disclosure import from_cbor
        from .rekor_v2 import verify
        if not args.rekor_key or not args.rekor_origin:
            raise ValueError("--require-anchor needs a pinned --rekor-key and --rekor-origin")
        anchor_status = verify(from_cbor(blob), trusted_key=_read_bounded(Path(args.rekor_key), 64 * 1024), origin=args.rekor_origin)
    with tempfile.TemporaryDirectory(prefix="zkpox-verify-") as tmp:
        work = Path(tmp)
        snapshot = work / "bundle.cbor"
        snapshot.write_bytes(blob)
        scratch = work / "scratch"
        scratch.mkdir()
        command = [str(verifier), str(snapshot)] + (["--json"] if args.json else [])
        result = run_untrusted(command, target=str(work), output=str(scratch),
                               readable_paths=[str(work)], tool_paths=[str(verifier.parent)],
                               caller_label="zkpox-verify", timeout=300,
                               capture_output=args.json, text=args.json)
        if args.json:
            if result.returncode == 0:
                summary = json.loads(result.stdout)
                summary["transparency_verification"] = anchor_status
                print(json.dumps(summary, indent=2))
            else:
                sys.stderr.write(sanitise_for_terminal(result.stderr, max_len=8192) + "\n")
        elif anchor_status["status"] == "verified_inclusion":
            print("Rekor v2 inclusion verified against pinned log key; no timestamp asserted.")
        return result.returncode


def _cmd_inspect(args) -> int:
    from .disclosure import from_cbor
    bundle = from_cbor(_read_bounded(Path(args.bundle), 64 * 1024 * 1024))
    if getattr(args, "require_anchor", False):
        raise ValueError("use verify --require-anchor to authenticate log inclusion; inspect only reads metadata")
    print(json.dumps({"status": "not_verified", "version": bundle.version,
                      "target_kind": bundle.target.kind, "target_hash": bundle.target.hash,
                      "statement": bundle.statement, "proof_system": bundle.proof.system,
                      "delivery": "encrypted-unchecked" if bundle.vendor_envelope.aes_blob else "absent"}, indent=2))
    return 0


def _cmd_open(args) -> int:
    import hmac
    from .disclosure import from_cbor
    from .statement import Statement, commitment, MAX_WITNESS
    from .envelope import Envelope, open_via_vendor, open_via_tlock
    from cryptography.exceptions import InvalidTag
    # Verify exactly the bytes later decrypted, even if the caller replaces its file.
    blob = _read_bounded(Path(args.bundle), 64 * 1024 * 1024)
    with tempfile.TemporaryDirectory(prefix="zkpox-opening-") as tmp:
        snapshot = Path(tmp) / "bundle.cbor"
        snapshot.write_bytes(blob)
        if _cmd_verify(argparse.Namespace(bundle=str(snapshot), json=False)):
            return 1
    bundle = from_cbor(blob)
    statement = Statement.from_dict(bundle.statement)
    statement.validate()
    env = bundle.vendor_envelope
    envelope = Envelope(env.aes_blob, env.ct_K_age, env.ct_K_tlock)
    aad = b"raptor-zkpox-delivery-v2\0" + statement.encode()
    try:
        if args.identity:
            payload = open_via_vendor(envelope, Path(args.identity), aad=aad)
        elif args.after_release:
            payload = open_via_tlock(envelope, aad=aad)
        else:
            raise ValueError("select vendor identity or time-lock opening")
    except InvalidTag as exc:
        raise ValueError("delivery authentication failed for the proven statement") from exc
    if not 32 <= len(payload) <= MAX_WITNESS + 32:
        raise ValueError("invalid private delivery payload size")
    salt, witness = payload[:32], payload[32:]
    if not hmac.compare_digest(commitment(statement.target_id, statement.gadget_id, salt, witness), statement.witness_commitment):
        raise ValueError("delivered witness does not match the proven commitment")
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(witness)
    print(json.dumps({"delivery": "commitment_verified", "witness": args.out}))
    return 0


def _cmd_eligible(args) -> int:
    from .surfacing import render_run_eligibility
    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        raise ValueError("run directory does not exist")
    summary = render_run_eligibility(run_dir, project_root=Path(args.project_root) if args.project_root else None)
    print(summary or "No recorded witnesses found.")
    return 0
