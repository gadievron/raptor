#!/usr/bin/env python3
"""Fetch Semgrep registry packs for airgapped RAPTOR installations.

Run this on a machine with internet access to download packs, then
transfer the resulting bundle across the airgap and import it.

Usage
-----
  # List what RAPTOR expects and current cache status:
  python3 engine/semgrep/tools/cache-packs.py list

  # Update the local cache directly (connected machine):
  python3 engine/semgrep/tools/cache-packs.py update
  python3 engine/semgrep/tools/cache-packs.py update --packs security-audit,owasp-top-ten

  # Fetch into a zip bundle (for airgap transfer):
  python3 engine/semgrep/tools/cache-packs.py fetch
  python3 engine/semgrep/tools/cache-packs.py fetch --packs security-audit,owasp-top-ten

  # Import a bundle on the airgapped machine:
  python3 engine/semgrep/tools/cache-packs.py import semgrep-cache-2026-07-16.zip --sha256 <retained-sha256>
  python3 engine/semgrep/tools/cache-packs.py check
  export RAPTOR_SEMGREP_OFFLINE=1
"""
from __future__ import annotations

import argparse
import io
import hashlib
import stat
import json
import os
import re
import tempfile
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

SEMGREP_ENGINE_DIR = Path(__file__).resolve().parents[1]
CACHE_DIR = SEMGREP_ENGINE_DIR / "rules" / "registry-cache"

REGISTRY_URL = "https://semgrep.dev/c/p/{pack_id}"
FETCH_TIMEOUT = 30

# Cap on a single registry response, enforced at the socket read —
# never buffer more than this no matter what the server streams.
# Real packs are ~1-5 MB of YAML/JSON; 32 MiB is a generous ceiling.
MAX_PACK_BYTES = 32 * 1024 * 1024

# Every pack RAPTOR may request at scan time.  Derived from
# RaptorConfig.BASELINE_SEMGREP_PACKS + POLICY_GROUP_TO_SEMGREP_PACK
# + the target-type catalog's semgrep_packs lists
# (core/run/target_types/*.yml — the scanner's baseline resolver takes
# a matched catalog entry's default packs over the config baseline).
# The list is intentionally duplicated here so the script is
# standalone (no RAPTOR imports needed on the connected side);
# tests/test_cache_packs.py holds it in sync against all three
# sources so drift fails CI instead of shipping an airgap bundle
# missing a pack the scanner requests.
DEFAULT_PACKS = [
    "security-audit",
    "owasp-top-ten",
    "secrets",
    "command-injection",
    "jwt",
    "default",
    "xss",
    "0xdea",
    "trailofbits",
    "django",
    "flask",
]

# Registry pack ids are flat lowercase names. The id is spliced into
# both the registry URL path and the cache filename, so anything with
# a separator (or any other unexpected character) is rejected at
# parse — a pid like `../../x` must never reach
# `CACHE_DIR / cache_filename(pid)` or the URL.
_PACK_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")


def parse_pack_ids(packs_arg: str) -> list[str]:
    """Split and validate a ``--packs`` argument."""
    pack_ids = []
    for raw in packs_arg.split(","):
        pid = raw.strip().removeprefix("p/")
        if not _PACK_ID_RE.fullmatch(pid):
            msg = (
                f"invalid pack id {pid!r} — expected a flat lowercase "
                f"registry name ([a-z0-9][a-z0-9._-]*)"
            )
            raise SystemExit(msg)
        pack_ids.append(pid)
    return list(dict.fromkeys(pack_ids))


def cache_filename(pack_id: str) -> str:
    return f"c.p.{pack_id}.json"


def _write_atomic(dest: Path, data: bytes) -> None:
    """Write a cache file via tempfile + rename (repo idiom).

    The cache is read by concurrent scans; an in-place write_bytes
    leaves a torn half-written pack visible during the write. The
    rename is atomic on the same filesystem, and a failed write never
    replaces the previous content or leaks the temp file.
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=str(dest.parent), prefix=dest.name + ".", suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def fetch_pack(pack_id: str) -> bytes:
    """Fetch a pack from the Semgrep registry, return JSON bytes."""
    if os.environ.get("RAPTOR_SEMGREP_OFFLINE", "").lower() in {"1", "true", "yes"}:
        raise SystemExit("Offline Semgrep: fetching registry packs is disabled")
    url = REGISTRY_URL.format(pack_id=pack_id)
    req = Request(url, headers={"Accept": "application/json"})
    try:
        resp = urlopen(req, timeout=FETCH_TIMEOUT)
        try:
            # Bounded read: one extra byte past the cap detects "too
            # large" without ever buffering an unbounded response.
            data = resp.read(MAX_PACK_BYTES + 1)
        finally:
            resp.close()
    except OSError as exc:
        # OSError covers URLError/HTTPError plus the socket-level
        # timeouts and resets that resp.read() raises directly —
        # all of them are one pack's fetch failing, reported the
        # same way (callers print the per-pack FAILED line and
        # continue with the remaining packs).
        msg = f"  FAILED: {pack_id} — {exc}"
        raise SystemExit(msg) from exc
    if len(data) > MAX_PACK_BYTES:
        msg = (
            f"  FAILED: {pack_id} — registry response exceeds the "
            f"{MAX_PACK_BYTES}-byte cap; refusing oversize pack"
        )
        raise SystemExit(msg)

    # Registry may return YAML; normalise to JSON.
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        try:
            import yaml
            parsed = yaml.safe_load(data)
        except ImportError:
            msg = (
                f"  FAILED: {pack_id} — response is YAML but PyYAML "
                f"is not installed on this machine"
            )
            raise SystemExit(msg) from None
        except Exception as exc:
            msg = f"  FAILED: {pack_id} — could not parse response: {exc}"
            raise SystemExit(msg) from exc

    # YAML scalars with no JSON twin (unquoted ISO dates in rule
    # metadata: parse as datetime.date) render as strings — the shape
    # a JSON registry response carries. Anything default=str cannot
    # rescue (e.g. a non-string mapping key) is that one pack's
    # failure, reported inside the per-pack contract like every other
    # arm above — never an escaping traceback that aborts the whole
    # fetch/update on pack 1 of N.
    try:
        return json.dumps(
            parsed, separators=(",", ":"), default=str,
        ).encode()
    except (TypeError, ValueError) as exc:
        msg = (
            f"  FAILED: {pack_id} — response not JSON-serialisable: "
            f"{exc}"
        )
        raise SystemExit(msg) from exc


def cmd_list(args: argparse.Namespace) -> None:
    """List packs RAPTOR uses and their cache status."""
    print("Semgrep registry packs used by RAPTOR:\n")
    print(f"  {'Pack ID':<25} {'Cached?':<10} {'Rules':<8} {'License'}")
    print(f"  {'─' * 25} {'─' * 10} {'─' * 8} {'─' * 30}")
    for pid in DEFAULT_PACKS:
        cached_path = CACHE_DIR / cache_filename(pid)
        if cached_path.exists():
            try:
                # Bounded read, mirroring the fetch/import caps — the
                # listing must not buffer an unbounded cache file.
                with cached_path.open("rb") as fh:
                    raw = fh.read(MAX_PACK_BYTES + 1)
                if len(raw) > MAX_PACK_BYTES:
                    print(
                        f"  p/{pid:<23} {'yes':<10} {'?':<8} "
                        f"oversize (exceeds pack cap)"
                    )
                    continue
                d = json.loads(raw)
                rules = d.get("rules", d) if isinstance(d, dict) else d
                count = len(rules) if isinstance(rules, list) else "?"
                lics = set()
                items = rules if isinstance(rules, list) else []
                for r in items:
                    if isinstance(r, dict):
                        meta = r.get("metadata")
                        lic = meta.get("license", "") if isinstance(meta, dict) else ""
                        if lic and isinstance(lic, str):
                            lics.add(lic[:40])
                lic_str = "; ".join(sorted(lics)) if lics else "unknown"
            except (OSError, ValueError):
                # Unreadable or invalid-JSON cache file — report and
                # keep listing the rest.
                count = "?"
                lic_str = "error reading"
            print(f"  p/{pid:<23} {'yes':<10} {count!s:<8} {lic_str}")
        else:
            print(f"  p/{pid:<23} {'no':<10} {'—':<8} —")

    # Show any extra cached packs not in DEFAULT_PACKS
    extras = []
    if CACHE_DIR.exists():
        for f in sorted(CACHE_DIR.glob("c.p.*.json")):
            pid = f.stem.removeprefix("c.p.")
            if pid not in DEFAULT_PACKS:
                extras.append(pid)
    if extras:
        print("\n  Additional cached packs (not in default set):")
        for pid in extras:
            print(f"    p/{pid}")


def cmd_fetch(args: argparse.Namespace) -> None:
    """Fetch packs and bundle into a zip."""
    if args.packs:
        pack_ids = parse_pack_ids(args.packs)
    else:
        pack_ids = list(DEFAULT_PACKS)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    zip_name = args.output or f"semgrep-cache-{stamp}.zip"

    buf = io.BytesIO()
    fetched = 0
    inventory = {}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for pid in pack_ids:
            print(f"  fetching p/{pid} ... ", end="", flush=True)
            try:
                data = fetch_pack(pid)
            except SystemExit as exc:
                print(str(exc).removeprefix("  "))
                continue
            fname = cache_filename(pid)
            zf.writestr(fname, data)
            inventory[fname] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            # Count rules for feedback
            try:
                parsed = json.loads(data)
                rules = parsed.get("rules", parsed) if isinstance(parsed, dict) else parsed
                count = len(rules) if isinstance(rules, list) else "?"
            except ValueError:
                # Registry returned non-JSON — count is cosmetic.
                count = "?"
            print(f"ok ({count} rules)")
            fetched += 1

        # Add a manifest so import can verify
        manifest = {
            "schema": 1,
            "files": inventory,
            "fetched_utc": datetime.now(timezone.utc).isoformat(),
            "packs": pack_ids,
            "fetched_count": fetched,
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    if fetched == 0:
        print("\nNo packs fetched — not writing zip.")
        raise SystemExit(1)

    Path(zip_name).write_bytes(buf.getvalue())
    size_kb = len(buf.getvalue()) / 1024
    print(f"\n  {fetched}/{len(pack_ids)} packs → {zip_name} ({size_kb:.0f} KB)")
    digest = hashlib.sha256(buf.getvalue()).hexdigest()
    print(f"  SHA256 (retain separately): {digest}")
    print("  Transfer this file to the airgapped machine and run:")
    print(f"    python3 engine/semgrep/tools/cache-packs.py import {zip_name} --sha256 {digest}")
    if fetched < len(pack_ids):
        # The partial bundle is still written (the fetched packs are
        # useful) but the build must not report success: an airgap
        # bundle silently missing packs is a coverage loss on exactly
        # the machine that cannot fetch them later.
        print(
            f"  WARNING: bundle is INCOMPLETE — "
            f"{len(pack_ids) - fetched} pack(s) failed (see FAILED "
            f"lines above)"
        )
        raise SystemExit(1)


def _read_member_bounded(zf: zipfile.ZipFile, name: str) -> bytes | None:
    """Decompress one bundle member with a hard size cap.

    ``zf.read()`` inflates the whole member into memory with no bound,
    so a small bundle carrying one high-ratio DEFLATE member could
    exhaust memory. Read in chunks and stop one byte past
    MAX_PACK_BYTES (the same ceiling the network fetch enforces);
    return None when the cap is exceeded.
    """
    chunks: list[bytes] = []
    total = 0
    with zf.open(name) as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PACK_BYTES:
                return None
            chunks.append(chunk)
    return b"".join(chunks)


def _validate_rules(data: bytes, name: str) -> None:
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise SystemExit(f"Invalid pack JSON: {name}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list) or not doc["rules"]:
        raise SystemExit(f"Pack {name} must contain a nonempty rules list")
    if any(not isinstance(rule, dict) or not isinstance(rule.get("id"), str)
           for rule in doc["rules"]):
        raise SystemExit(f"Invalid rule entries in {name}")


def _verified_import(zip_path: Path, expected: str) -> None:
    """Verify a private snapshot completely before touching the live cache."""
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise SystemExit("--sha256 must be the retained 64-character SHA256")
    fd = os.open(zip_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source, tempfile.TemporaryFile() as snapshot:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise SystemExit("Bundle must be a regular file")
        digest = hashlib.sha256()
        total = 0
        while chunk := source.read(65536):
            total += len(chunk)
            if total > 512 * 1024 * 1024:
                raise SystemExit("Bundle exceeds 512 MiB")
            digest.update(chunk)
            snapshot.write(chunk)
        if digest.hexdigest() != expected:
            raise SystemExit("Bundle SHA256 mismatch; cache unchanged")
        snapshot.seek(0)
        with zipfile.ZipFile(snapshot) as zf:
            names = zf.namelist()
            if len(names) != len(set(names)) or len(names) > 65:
                raise SystemExit("Duplicate members or too many packs")
            if "manifest.json" not in names:
                raise SystemExit("Bundle manifest missing; re-fetch using this tool")
            raw = _read_member_bounded(zf, "manifest.json")
            manifest = json.loads(raw) if raw else None
            if not isinstance(manifest, dict) or manifest.get("schema") != 1:
                raise SystemExit("Unsupported bundle manifest; re-fetch using this tool")
            packs = manifest.get("packs")
            if (not isinstance(packs, list) or not packs or len(packs) != len(set(packs))
                    or any(not isinstance(p, str) or not _PACK_ID_RE.fullmatch(p) for p in packs)):
                raise SystemExit("Invalid manifest pack list")
            expected_names = {cache_filename(p) for p in packs}
            files = manifest.get("files")
            if (manifest.get("fetched_count") != len(packs) or not isinstance(files, dict)
                    or set(files) != expected_names or set(names) != expected_names | {"manifest.json"}):
                raise SystemExit("Incomplete bundle or unexpected members; cache unchanged")
            contents = {}
            expanded = 0
            for name in sorted(expected_names):
                data = _read_member_bounded(zf, name)
                if data is None:
                    raise SystemExit(f"Oversize pack: {name}")
                expanded += len(data)
                if expanded > 512 * 1024 * 1024:
                    raise SystemExit("Expanded bundle exceeds 512 MiB")
                if files[name] != {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}:
                    raise SystemExit(f"Pack digest/size mismatch: {name}")
                _validate_rules(data, name)
                contents[name] = data
            # Refuse redirected cache roots. Individual files are atomically replaced.
            for parent in (CACHE_DIR, *CACHE_DIR.parents):
                if parent.is_symlink():
                    raise SystemExit(f"Cache directory is a symlink: {parent}")
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            for name, data in contents.items():
                _write_atomic(CACHE_DIR / name, data)
            print(f"{len(contents)} verified pack(s) imported into {CACHE_DIR}")
            print("Run cache-packs.py check, then export RAPTOR_SEMGREP_OFFLINE=1 before scanning.")


def cmd_check(args: argparse.Namespace) -> None:
    """Validate selected cached packs with Semgrep inside a network-denied sandbox."""
    import sys
    import shutil
    sys.path.insert(0, str(SEMGREP_ENGINE_DIR.parents[1]))
    from core.config import RaptorConfig, pin_raptor_dir_in_environ
    from core.security.capped_read import read_capped
    from core.sandbox import run
    from core.sandbox.python_paths import python_runtime_tool_paths
    pin_raptor_dir_in_environ()
    packs = parse_pack_ids(args.packs) if args.packs else DEFAULT_PACKS
    binary = shutil.which("semgrep")
    if not binary:
        raise SystemExit("Install Semgrep before validating the offline cache")
    configs = []
    for pack in packs:
        path = CACHE_DIR / cache_filename(pack)
        raw = read_capped(path, MAX_PACK_BYTES, raise_on_refusal=True)
        _validate_rules(raw, pack)
        configs.extend(["--config", str(path)])
    with tempfile.TemporaryDirectory(prefix="raptor-semgrep-check-") as tmp:
        # --validate unconditionally fetches p/semgrep-rule-lints upstream.
        # A strict scan loads the local rule schema without that registry call.
        target = Path(tmp) / "probe"
        target.mkdir()
        (target / "probe.py").write_text("pass\n")
        result = run(
            [str(Path(binary).resolve()), "scan", "--strict", "--json", "--metrics", "off",
             "--disable-version-check", "--no-git-ignore", *configs, str(target)],
            block_network=True, output=tmp, fake_home=True,
            tool_paths=[str(CACHE_DIR), str(Path(binary).resolve().parent), *python_runtime_tool_paths()],
            env=RaptorConfig.get_safe_env(), env_caller_filtered=True, timeout=300,
            capture_output=True, text=True,
        )
        if result.returncode:
            raise SystemExit(f"Offline Semgrep validation failed ({result.returncode}): {result.stderr[-4000:]}")
        report = json.loads(result.stdout)
        if report.get("errors"):
            raise SystemExit(f"Offline Semgrep reported rule errors: {report['errors']!r}")
    print(f"{len(packs)} cached pack(s) validated with network connections denied")


def cmd_import(args: argparse.Namespace) -> None:
    """Import a cache bundle into RAPTOR's registry-cache directory."""
    zip_path = Path(args.zipfile)
    if getattr(args, "sha256", None):
        _verified_import(zip_path, args.sha256)
        return
    if not zip_path.exists():
        msg = f"File not found: {zip_path}"
        raise SystemExit(msg)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    imported = 0
    skipped = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in sorted(zf.namelist()):
            if name == "manifest.json":
                continue
            # Flat namespace is the bundle contract (cmd_fetch writes
            # cache_filename() members only): any separator or '..'
            # segment is a traversal-shaped name that could escape
            # CACHE_DIR — reject, never join it onto the cache dir.
            if (
                "/" in name
                or "\\" in name
                or ".." in name
                or not name.startswith("c.p.")
                or not name.endswith(".json")
            ):
                print(f"  skip: {name} (unexpected filename)")
                skipped += 1
                continue
            dest = CACHE_DIR / name
            data = _read_member_bounded(zf, name)
            if data is None:
                print(
                    f"  skip: {name} (exceeds the "
                    f"{MAX_PACK_BYTES}-byte pack cap)"
                )
                skipped += 1
                continue
            # Validate it's parseable JSON
            try:
                json.loads(data)
            except json.JSONDecodeError:
                print(f"  skip: {name} (invalid JSON)")
                skipped += 1
                continue
            existed = dest.exists()
            _write_atomic(dest, data)
            status = "updated" if existed else "added"
            print(f"  {status}: {name}")
            imported += 1

        # Show manifest info if present
        if "manifest.json" in zf.namelist():
            # Cosmetic manifest display: a corrupt bundle member
            # (BadZipFile / zlib.error), undecodable or invalid JSON
            # (ValueError) or a read error (OSError) shouldn't fail
            # the import.
            try:
                raw = _read_member_bounded(zf, "manifest.json")
                m = json.loads(raw) if raw is not None else None
                if isinstance(m, dict):
                    print(f"\n  Bundle fetched: {m.get('fetched_utc', 'unknown')}")
            except (OSError, ValueError, zipfile.BadZipFile, zlib.error):
                pass

    print(f"\n  {imported} pack(s) imported, {skipped} skipped")
    if imported:
        print(f"  Cache dir: {CACHE_DIR}")


def cmd_update(args: argparse.Namespace) -> None:
    """Fetch packs and write directly to the local cache (requires connectivity)."""
    if args.packs:
        pack_ids = parse_pack_ids(args.packs)
    else:
        pack_ids = list(DEFAULT_PACKS)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    updated = 0
    for pid in pack_ids:
        print(f"  fetching p/{pid} ... ", end="", flush=True)
        try:
            data = fetch_pack(pid)
        except SystemExit as exc:
            print(str(exc).removeprefix("  "))
            continue
        dest = CACHE_DIR / cache_filename(pid)
        existed = dest.exists()
        _write_atomic(dest, data)
        try:
            parsed = json.loads(data)
            rules = parsed.get("rules", parsed) if isinstance(parsed, dict) else parsed
            count = len(rules) if isinstance(rules, list) else "?"
        except ValueError:
            # Registry returned non-JSON — count is cosmetic.
            count = "?"
        status = "updated" if existed else "added"
        print(f"ok ({count} rules, {status})")
        updated += 1

    print(f"\n  {updated}/{len(pack_ids)} packs written to {CACHE_DIR}")
    if updated < len(pack_ids):
        # Operators and CI key off the exit code; a silent 0/N (or
        # k/N) success code leaves the cache stale with no signal.
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="raptor-semgrep-cache",
        description="Manage Semgrep registry pack cache for airgapped use.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List packs and cache status")
    p_check = sub.add_parser("check", help="Validate cached packs with network connections denied")
    p_check.add_argument("--packs", help="Comma-separated pack IDs (default: all RAPTOR packs)")

    p_update = sub.add_parser("update", help="Fetch and write packs directly to the local cache")
    p_update.add_argument(
        "--packs",
        help="Comma-separated pack IDs (default: all RAPTOR packs)",
    )

    p_fetch = sub.add_parser("fetch", help="Fetch packs into a zip bundle for airgap transfer")
    p_fetch.add_argument(
        "--packs",
        help="Comma-separated pack IDs (default: all RAPTOR packs)",
    )
    p_fetch.add_argument(
        "-o", "--output",
        help="Output zip filename (default: semgrep-cache-YYYY-MM-DD.zip)",
    )

    p_import = sub.add_parser("import", help="Import a zip bundle into the cache")
    p_import.add_argument("zipfile", help="Path to the cache zip")
    p_import.add_argument("--sha256", required=True, help="Bundle SHA256 retained on the connected host")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        raise SystemExit(1)

    cmds = {"list": cmd_list, "update": cmd_update, "fetch": cmd_fetch, "import": cmd_import, "check": cmd_check}
    cmds[args.command](args)


if __name__ == "__main__":
    main()
