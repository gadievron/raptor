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
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen, Request

SEMGREP_ENGINE_DIR = Path(__file__).resolve().parents[1]
CACHE_DIR = SEMGREP_ENGINE_DIR / "rules" / "registry-cache"

REGISTRY_URL = "https://semgrep.dev/c/p/{pack_id}"
FETCH_TIMEOUT = 30

# Every pack RAPTOR may request at scan time.  Derived from
# RaptorConfig.BASELINE_SEMGREP_PACKS + POLICY_GROUP_TO_SEMGREP_PACK
# + target-type catalog entries.  Keep in sync manually — the list
# is intentionally duplicated here so the script is standalone
# (no RAPTOR imports needed on the connected side).
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
]


def cache_filename(pack_id: str) -> str:
    return f"c.p.{pack_id}.json"


def fetch_pack(pack_id: str) -> bytes:
    """Fetch a pack from the Semgrep registry, return JSON bytes."""
    url = REGISTRY_URL.format(pack_id=pack_id)
    req = Request(url, headers={"Accept": "application/json"})
    try:
        resp = urlopen(req, timeout=FETCH_TIMEOUT)  # noqa: S310
        data = resp.read()
    except URLError as exc:
        raise SystemExit(
            f"  FAILED: {pack_id} — {exc}"
        ) from exc

    # Registry may return YAML; normalise to JSON.
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        try:
            import yaml
            parsed = yaml.safe_load(data)
        except ImportError:
            raise SystemExit(
                f"  FAILED: {pack_id} — response is YAML but PyYAML "
                f"is not installed on this machine"
            ) from None
        except Exception as exc:
            raise SystemExit(
                f"  FAILED: {pack_id} — could not parse response: {exc}"
            ) from exc

    return json.dumps(parsed, separators=(",", ":")).encode()


def cmd_list(args: argparse.Namespace) -> None:
    """List packs RAPTOR uses and their cache status."""
    print("Semgrep registry packs used by RAPTOR:\n")
    print(f"  {'Pack ID':<25} {'Cached?':<10} {'Rules':<8} {'License'}")
    print(f"  {'─' * 25} {'─' * 10} {'─' * 8} {'─' * 30}")
    for pid in DEFAULT_PACKS:
        cached_path = CACHE_DIR / cache_filename(pid)
        if cached_path.exists():
            try:
                d = json.loads(cached_path.read_bytes())
                rules = d.get("rules", d) if isinstance(d, dict) else d
                count = len(rules) if isinstance(rules, list) else "?"
                lics = set()
                items = rules if isinstance(rules, list) else []
                for r in items:
                    if isinstance(r, dict):
                        lic = r.get("metadata", {}).get("license", "")
                        if lic:
                            lics.add(lic[:40])
                lic_str = "; ".join(sorted(lics)) if lics else "unknown"
            except Exception:
                count = "?"
                lic_str = "error reading"
            print(f"  p/{pid:<23} {'yes':<10} {str(count):<8} {lic_str}")
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
        pack_ids = [p.strip().removeprefix("p/") for p in args.packs.split(",")]
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
            except Exception:
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


def cmd_import(args: argparse.Namespace) -> None:
    """Import a cache bundle into RAPTOR's registry-cache directory."""
    zip_path = Path(args.zipfile)
    if not zip_path.exists():
        raise SystemExit(f"File not found: {zip_path}")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    imported = 0
    skipped = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in sorted(zf.namelist()):
            if name == "manifest.json":
                continue
            if not name.startswith("c.p.") or not name.endswith(".json"):
                print(f"  skip: {name} (unexpected filename)")
                skipped += 1
                continue
            dest = CACHE_DIR / name
            data = zf.read(name)
            # Validate it's parseable JSON
            try:
                json.loads(data)
            except json.JSONDecodeError:
                print(f"  skip: {name} (invalid JSON)")
                skipped += 1
                continue
            existed = dest.exists()
            dest.write_bytes(data)
            status = "updated" if existed else "added"
            print(f"  {status}: {name}")
            imported += 1

        # Show manifest info if present
        if "manifest.json" in zf.namelist():
            try:
                m = json.loads(zf.read("manifest.json"))
                print(f"\n  Bundle fetched: {m.get('fetched_utc', 'unknown')}")
            except Exception:
                pass

    print(f"\n  {imported} pack(s) imported, {skipped} skipped")
    if imported:
        print(f"  Cache dir: {CACHE_DIR}")


def cmd_update(args: argparse.Namespace) -> None:
    """Fetch packs and write directly to the local cache (requires connectivity)."""
    if args.packs:
        pack_ids = [p.strip().removeprefix("p/") for p in args.packs.split(",")]
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
        dest.write_bytes(data)
        try:
            parsed = json.loads(data)
            rules = parsed.get("rules", parsed) if isinstance(parsed, dict) else parsed
            count = len(rules) if isinstance(rules, list) else "?"
        except Exception:
            count = "?"
        status = "updated" if existed else "added"
        print(f"ok ({count} rules, {status})")
        updated += 1

    print(f"\n  {updated}/{len(pack_ids)} packs written to {CACHE_DIR}")


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
