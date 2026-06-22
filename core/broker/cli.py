"""``raptor broker`` — manage the remote system fleet.

Subcommands:
    add       — register a remote system
    remove    — unregister a system
    list      — show all registered systems
    probe     — re-probe a system and refresh cached capabilities
    check     — check if a mode can run locally or needs brokering
    provision — install missing tools on a remote system (dry-run default)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Optional

from core.broker.broker import Broker, BrokerError, LocalExecution, RemoteExecution
from core.broker.capabilities import (
    MODE_REQUIREMENTS,
    ModeRequirements,
    OperatingSystem,
    SystemCapabilities,
)
from core.broker.inventory import Inventory
from core.broker.probe import probe_system
from core.broker.provision import provision_tools
from core.broker.transport import RemoteSystemEntry, TransportKind

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raptor broker",
        description="Manage the remote system fleet for cross-platform execution",
    )
    sub = parser.add_subparsers(dest="subcommand")

    # -- add ---------------------------------------------------------------
    add_p = sub.add_parser("add", help="Register a remote system")
    add_p.add_argument("alias", help="Friendly name for this system")
    add_p.add_argument("host", help="Hostname or IP address")
    add_p.add_argument("--port", type=int, default=22, help="SSH/WinRM port (default: 22)")
    add_p.add_argument("--user", default="root", help="Remote username (default: root)")
    add_p.add_argument("--transport", choices=["ssh", "winrm"], default="ssh")
    add_p.add_argument("--key", dest="key_path", help="Path to SSH private key")
    add_p.add_argument("--labels", help="Comma-separated labels (e.g. gpu,high-mem)")
    add_p.add_argument("--no-probe", action="store_true", help="Skip capability probing")

    # -- remove ------------------------------------------------------------
    rm_p = sub.add_parser("remove", help="Unregister a system")
    rm_p.add_argument("alias", help="System alias to remove")

    # -- list --------------------------------------------------------------
    sub.add_parser("list", help="Show all registered systems and capabilities")

    # -- probe -------------------------------------------------------------
    pr_p = sub.add_parser("probe", help="Re-probe a system and refresh capabilities")
    pr_p.add_argument("alias", help="System alias to probe")

    # -- check -------------------------------------------------------------
    ck_p = sub.add_parser(
        "check",
        help="Check if a mode can run locally or needs brokering",
    )
    ck_p.add_argument("mode", help="RAPTOR mode (scan, fuzz, codeql, etc.)")

    # -- provision ---------------------------------------------------------
    pv_p = sub.add_parser(
        "provision",
        help="Install missing tools on a remote system",
    )
    pv_p.add_argument("alias", help="System alias to provision")
    pv_p.add_argument("mode", help="RAPTOR mode whose tools to install")
    pv_p.add_argument(
        "--apply", action="store_true",
        help="Actually install (default is dry-run)",
    )

    return parser


def main(args: list[str]) -> int:
    parser = _build_parser()
    try:
        parsed = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code or 0)

    if not parsed.subcommand:
        parser.print_help()
        return 0

    handlers = {
        "add": _cmd_add,
        "remove": _cmd_remove,
        "list": _cmd_list,
        "probe": _cmd_probe,
        "check": _cmd_check,
        "provision": _cmd_provision,
    }
    return handlers[parsed.subcommand](parsed)


def _cmd_add(parsed: argparse.Namespace) -> int:
    labels = frozenset(parsed.labels.split(",")) if parsed.labels else frozenset()

    entry = RemoteSystemEntry(
        alias=parsed.alias,
        host=parsed.host,
        port=parsed.port,
        user=parsed.user,
        transport=TransportKind(parsed.transport),
        key_path=parsed.key_path,
        labels=labels,
    )

    broker = Broker()

    if parsed.no_probe:
        broker.inventory.add(entry)
        print(f"[+] Registered {parsed.alias} ({parsed.host}) — skipped probe")
        return 0

    print(f"[*] Probing {parsed.host}...")
    try:
        caps = broker.probe_and_register(entry)
    except Exception as exc:
        print(f"[!] Probe failed: {exc}", file=sys.stderr)
        print(f"    System registered without capabilities — run 'raptor broker probe {parsed.alias}' later")
        broker.inventory.add(entry)
        return 0

    _print_capabilities(caps)
    print(f"[+] Registered {parsed.alias}")
    return 0


def _cmd_remove(parsed: argparse.Namespace) -> int:
    inv = Inventory()
    if inv.remove(parsed.alias):
        print(f"[-] Removed {parsed.alias}")
        return 0
    print(f"[!] No system named '{parsed.alias}' in inventory", file=sys.stderr)
    return 1


def _cmd_list(parsed: argparse.Namespace) -> int:
    inv = Inventory()
    systems = inv.list_all()
    if not systems:
        print("No systems registered. Use 'raptor broker add' to register one.")
        return 0

    print(f"\n{'Alias':<16} {'Host':<24} {'Transport':<8} {'OS':<10} {'Arch':<10} {'Tools'}")
    print("-" * 90)
    for entry in systems:
        caps = inv.get_capabilities(entry.alias)
        os_str = caps.os.value if caps else "?"
        arch_str = caps.arch.value if caps else "?"
        tools_str = ", ".join(sorted(caps.tools)) if caps else "not probed"
        print(
            f"{entry.alias:<16} {entry.host:<24} {entry.transport.value:<8} "
            f"{os_str:<10} {arch_str:<10} {tools_str}"
        )

    local = SystemCapabilities.detect_local()
    print(f"\n{'localhost':<16} {'127.0.0.1':<24} {'local':<8} {local.os.value:<10} {local.arch.value:<10} {', '.join(sorted(local.tools))}")
    print()
    return 0


def _cmd_probe(parsed: argparse.Namespace) -> int:
    broker = Broker()
    entry = broker.inventory.get(parsed.alias)
    if not entry:
        print(f"[!] No system named '{parsed.alias}' in inventory", file=sys.stderr)
        return 1

    print(f"[*] Probing {entry.host}...")
    try:
        caps = broker.refresh(parsed.alias)
    except Exception as exc:
        print(f"[!] Probe failed: {exc}", file=sys.stderr)
        return 1

    _print_capabilities(caps)
    return 0


def _cmd_check(parsed: argparse.Namespace) -> int:
    mode = parsed.mode
    reqs = MODE_REQUIREMENTS.get(mode, ModeRequirements(mode=mode))
    local = SystemCapabilities.detect_local()
    verdict = local.satisfies(reqs)

    print(f"\nMode: {mode}")
    print(f"Local system: {local.os.value}/{local.arch.value}")
    print(f"Requirements: {_format_requirements(reqs)}")

    if verdict.met:
        print(f"\n[+] Mode '{mode}' can run locally — no brokering needed")
        return 0

    print(f"\n[!] Local system cannot run '{mode}': {verdict.summary()}")

    inv = Inventory()
    candidates = inv.find_capable(reqs)
    if candidates:
        print(f"\n[+] {len(candidates)} remote system(s) available:")
        for entry, caps in candidates:
            print(f"    - {entry.alias} ({entry.host}) — {caps.os.value}/{caps.arch.value}")
    else:
        print("\n[-] No registered systems can satisfy these requirements")
        print("    Register a compatible system with 'raptor broker add'")

    return 0


def _cmd_provision(parsed: argparse.Namespace) -> int:
    inv = Inventory()
    entry = inv.get(parsed.alias)
    if not entry:
        print(f"[!] No system named '{parsed.alias}' in inventory", file=sys.stderr)
        return 1

    reqs = MODE_REQUIREMENTS.get(parsed.mode, ModeRequirements(mode=parsed.mode))
    caps = inv.get_capabilities(parsed.alias)
    if not caps:
        print(f"[!] No cached capabilities for '{parsed.alias}' — run probe first", file=sys.stderr)
        return 1

    verdict = caps.satisfies(reqs)
    if verdict.met:
        print(f"[+] {parsed.alias} already satisfies all requirements for '{parsed.mode}'")
        return 0

    if not verdict.missing_tools:
        print(f"[!] Cannot auto-provision: {verdict.summary()}", file=sys.stderr)
        return 1

    from core.broker.broker import _build_transport

    transport = _build_transport(entry)
    dry_run = not parsed.apply
    label = "[dry-run] " if dry_run else ""

    print(f"\n{label}Provisioning {parsed.alias} for mode '{parsed.mode}':")
    print(f"  Missing tools: {', '.join(sorted(verdict.missing_tools))}")

    with transport:
        results = provision_tools(transport, caps.os, verdict.missing_tools, dry_run=dry_run)

    for r in results:
        status = "OK" if r.success else "FAIL"
        print(f"  [{status}] {r.tool}: {r.message}")

    if dry_run:
        print(f"\nRe-run with --apply to install: raptor broker provision {parsed.alias} {parsed.mode} --apply")

    return 0


def _print_capabilities(caps: SystemCapabilities) -> None:
    print(f"  OS:        {caps.os.value}")
    print(f"  Arch:      {caps.arch.value}")
    print(f"  RAM:       {caps.ram_mb} MB")
    print(f"  Cores:     {caps.cores}")
    print(f"  Free disk: {caps.free_disk_mb} MB")
    print(f"  Tools:     {', '.join(sorted(caps.tools)) or 'none'}")
    if caps.labels:
        print(f"  Labels:    {', '.join(sorted(caps.labels))}")


def _format_requirements(reqs: ModeRequirements) -> str:
    parts: list[str] = []
    if reqs.os:
        parts.append(f"OS={reqs.os.value}")
    if reqs.arch:
        parts.append(f"arch={reqs.arch.value}")
    if reqs.tools:
        parts.append(f"tools=[{', '.join(sorted(reqs.tools))}]")
    if reqs.min_ram_mb:
        parts.append(f"RAM>={reqs.min_ram_mb}MB")
    if reqs.min_cores:
        parts.append(f"cores>={reqs.min_cores}")
    return ", ".join(parts) if parts else "none (runs anywhere)"
