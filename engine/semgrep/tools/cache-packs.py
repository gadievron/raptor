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
  python3 engine/semgrep/tools/cache-packs.py import semgrep-cache-2026-07-16.zip
"""
from __future__ import annotations

import argparse
import io
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
    "python-django",
    "python-flask",
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
    return pack_ids


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
    print("  Transfer this file to the airgapped machine and run:")
    print(f"    python3 engine/semgrep/tools/cache-packs.py import {zip_name}")
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


def cmd_import(args: argparse.Namespace) -> None:
    """Import a cache bundle into RAPTOR's registry-cache directory."""
    zip_path = Path(args.zipfile)
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

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        raise SystemExit(1)

    cmds = {"list": cmd_list, "update": cmd_update, "fetch": cmd_fetch, "import": cmd_import}
    cmds[args.command](args)


if __name__ == "__main__":
    main()
