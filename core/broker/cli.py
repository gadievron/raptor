"""``raptor broker`` — manage the remote system fleet.

Subcommands:
    add       — register a remote system
    remove    — unregister a system
    list      — show all registered systems
    probe     — re-probe a system and refresh cached capabilities
    check     — check if a mode can run locally or needs brokering
    provision — install missing tools on a remote system (dry-run default)
    task      — route a task to the best fleet member and execute it
    rank      — score fleet members for a mode (dry-run routing)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from typing import Optional

from core.broker.broker import Broker, BrokerError, LocalExecution, RemoteExecution
from core.broker.capabilities import (
    MODE_REQUIREMENTS,
    Architecture,
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
    add_p.add_argument("--transport", choices=["ssh", "winrm", "adb"], default="ssh")
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

    # -- store-cred --------------------------------------------------------
    sc_p = sub.add_parser(
        "store-cred",
        help="Store a system's password in the OS keyring (macOS Keychain / GNOME Keyring / Windows Credential Manager)",
    )
    sc_p.add_argument("alias", help="System alias to store credentials for")
    sc_p.add_argument(
        "--keypass", action="store_true",
        help="Store an SSH key passphrase instead of a login password",
    )

    # -- deps --------------------------------------------------------------
    deps_p = sub.add_parser(
        "deps",
        help="Show the full dependency satisfaction matrix for this system",
    )
    deps_p.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON",
    )
    deps_p.add_argument(
        "--platform",
        help="Override detected platform (e.g. linux-x86_64, macos-arm64, windows-x86_64)",
    )

    # -- rank --------------------------------------------------------------
    rk_p = sub.add_parser(
        "rank",
        help="Score fleet members for a mode (dry-run routing)",
    )
    rk_p.add_argument("mode", help="RAPTOR mode to score for")
    rk_p.add_argument(
        "--labels", help="Comma-separated required labels (e.g. gpu,high-mem)",
    )

    # -- task --------------------------------------------------------------
    tk_p = sub.add_parser(
        "task",
        help="Route a task to the best fleet member and execute it",
    )
    tk_p.add_argument("mode", help="RAPTOR mode to run")
    tk_p.add_argument("target", help="Target path or URL")
    tk_p.add_argument(
        "--prefer", dest="prefer_alias",
        help="Soft preference for a system alias",
    )
    tk_p.add_argument(
        "--labels", help="Comma-separated required labels",
    )
    tk_p.add_argument(
        "--timeout", type=int, default=3600,
        help="Execution timeout in seconds (default: 3600)",
    )
    tk_p.add_argument(
        "--dry-run", action="store_true",
        help="Show routing decision without executing",
    )
    tk_p.add_argument(
        "--detach", action="store_true",
        help="Run in detached tmux/screen session (survives disconnects)",
    )
    tk_p.add_argument(
        "--os",
        choices=["linux", "darwin", "windows", "android"],
        help="Require target system OS",
    )
    tk_p.add_argument(
        "--arch",
        choices=["x86_64", "aarch64", "armv7"],
        help="Require target system architecture",
    )
    tk_p.add_argument(
        "--transport",
        dest="require_transport",
        choices=["ssh", "winrm", "adb"],
        help="Require transport kind",
    )
    tk_p.add_argument(
        "--require-tools",
        help="Comma-separated tools the target must have (e.g. gdb,afl++)",
    )
    tk_p.add_argument(
        "extra_args", nargs="*",
        help="Additional arguments passed to the remote command",
    )

    # -- task-status -------------------------------------------------------
    ts_p = sub.add_parser(
        "task-status",
        help="Check status of a detached task",
    )
    ts_p.add_argument("task_id", help="Task ID to check")

    # -- task-collect ------------------------------------------------------
    tc_p = sub.add_parser(
        "task-collect",
        help="Download results from a completed detached task",
    )
    tc_p.add_argument("task_id", help="Task ID to collect")
    tc_p.add_argument(
        "--no-cleanup", action="store_true",
        help="Keep remote workspace after collecting",
    )

    # -- task-cancel -------------------------------------------------------
    tx_p = sub.add_parser(
        "task-cancel",
        help="Kill a running detached task",
    )
    tx_p.add_argument("task_id", help="Task ID to cancel")

    # -- task-list ---------------------------------------------------------
    sub.add_parser(
        "task-list",
        help="List all tracked detached tasks",
    )

    # -- lift --------------------------------------------------------------
    lf_p = sub.add_parser(
        "lift",
        help="Pull a binary from a fleet member to local staging",
    )
    lf_p.add_argument(
        "source",
        help="alias:/remote/path (e.g. pixel-7:/data/app/com.example/base.apk)",
    )
    lf_p.add_argument(
        "--no-unpack", action="store_true",
        help="Skip automatic unpacking (APK, PE)",
    )
    lf_p.add_argument(
        "--staging-dir",
        help="Override local staging directory",
    )

    # -- lift-and-route ----------------------------------------------------
    lr_p = sub.add_parser(
        "lift-and-route",
        help="Pull a binary from one system, route analysis to the best other",
    )
    lr_p.add_argument(
        "source",
        help="alias:/remote/path (e.g. pixel-7:/data/app/com.example/base.apk)",
    )
    lr_p.add_argument("mode", help="RAPTOR mode for analysis (fuzz, scan, etc.)")
    lr_p.add_argument(
        "--no-unpack", action="store_true",
        help="Skip automatic unpacking (APK, PE)",
    )
    lr_p.add_argument(
        "--prefer", dest="prefer_alias",
        help="Soft preference for analysis system alias",
    )
    lr_p.add_argument(
        "--labels", help="Comma-separated required labels",
    )
    lr_p.add_argument(
        "--timeout", type=int, default=3600,
        help="Execution timeout in seconds (default: 3600)",
    )
    lr_p.add_argument(
        "--detach", action="store_true",
        help="Run analysis in detached session",
    )
    lr_p.add_argument(
        "--os",
        choices=["linux", "darwin", "windows", "android"],
        help="Require analysis system OS",
    )
    lr_p.add_argument(
        "--arch",
        choices=["x86_64", "aarch64", "armv7"],
        help="Require analysis system architecture",
    )
    lr_p.add_argument(
        "--dry-run", action="store_true",
        help="Lift the binary but only show routing — don't execute",
    )
    lr_p.add_argument(
        "extra_args", nargs="*",
        help="Additional arguments passed to the remote command",
    )

    # -- engage ------------------------------------------------------------
    eg_p = sub.add_parser(
        "engage",
        help="Plan fleet deployment for an engagement",
    )
    eg_p.add_argument(
        "action",
        choices=["propose", "confirm", "show", "clear", "override"],
        help="Engagement action",
    )
    eg_p.add_argument(
        "--scope",
        choices=["full", "source-audit", "binary", "web-assessment", "mobile", "reversing"],
        help="Predefined scope (sets of modes)",
    )
    eg_p.add_argument(
        "--modes",
        help="Comma-separated modes (overrides --scope)",
    )
    eg_p.add_argument(
        "--target", dest="target_desc", default="",
        help="Target description for the engagement",
    )
    eg_p.add_argument(
        "--exclude",
        help="Comma-separated aliases to exclude",
    )
    eg_p.add_argument(
        "--set",
        dest="override_pairs",
        action="append",
        help="mode=alias override (repeatable, e.g. --set fuzz=linux-arm)",
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
        "store-cred": _cmd_store_cred,
        "deps": _cmd_deps,
        "rank": _cmd_rank,
        "task": _cmd_task,
        "task-status": _cmd_task_status,
        "task-collect": _cmd_task_collect,
        "task-cancel": _cmd_task_cancel,
        "task-list": _cmd_task_list,
        "lift": _cmd_lift,
        "lift-and-route": _cmd_lift_and_route,
        "engage": _cmd_engage,
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


def _cmd_store_cred(parsed: argparse.Namespace) -> int:
    import getpass as _getpass

    from core.broker.creds import store_in_keyring

    purpose = "SSH key passphrase" if parsed.keypass else "password"
    try:
        pw = _getpass.getpass(f"Enter {purpose} for {parsed.alias}: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled")
        return 1

    if not pw:
        print("[!] Empty credential — nothing stored", file=sys.stderr)
        return 1

    if store_in_keyring(parsed.alias, pw, is_keypass=parsed.keypass):
        print(f"[+] Stored {purpose} for {parsed.alias} in OS keyring")
        return 0

    print(
        f"[!] Failed to store in keyring — install 'keyring' package "
        f"or use RAPTOR_BROKER_PASS_{parsed.alias.upper().replace('-', '_')} env var instead",
        file=sys.stderr,
    )
    return 1


def _cmd_deps(parsed: argparse.Namespace) -> int:
    from core.broker.deps import Platform, check_all, format_matrix

    plat = None
    if parsed.platform:
        try:
            plat = Platform(parsed.platform)
        except ValueError:
            valid = ", ".join(p.value for p in Platform)
            print(f"[!] Unknown platform '{parsed.platform}'", file=sys.stderr)
            print(f"    Valid: {valid}", file=sys.stderr)
            return 1

    result = check_all(platform=plat)

    if parsed.json:
        import json as _json

        data = {
            "platform": result.platform.value,
            "score": f"{result.met_count}/{result.total_count}",
            "required_score": f"{result.required_met}/{result.required_total}",
            "dependencies": [
                {
                    "name": r.dep.name,
                    "tier": r.dep.tier.value,
                    "met": r.met,
                    "required": r.dep.required,
                    "affects": r.dep.affects,
                    "install": r.guide.command if r.guide else None,
                    "url": r.guide.url if r.guide else None,
                    "notes": r.guide.notes if r.guide else None,
                }
                for r in result.results
            ],
        }
        print(_json.dumps(data, indent=2))
    else:
        print(format_matrix(result))

    return 0


def _cmd_rank(parsed: argparse.Namespace) -> int:
    from core.broker.scoring import rank_fleet

    inv = Inventory()
    fleet = inv.list_all_with_capabilities()
    if not fleet:
        print("No systems with cached capabilities. Probe them first.")
        return 0

    labels = frozenset(parsed.labels.split(",")) if parsed.labels else frozenset()
    ranked = rank_fleet(fleet, parsed.mode, require_capable=False, labels=labels)

    if not ranked:
        print(f"No systems match the label filter.")
        return 0

    print(f"\nFleet ranking for mode '{parsed.mode}':")
    print(f"{'#':<4} {'Alias':<16} {'Score':>8} {'Capable':>8} {'OS':<10} {'Cores':>6} {'RAM MB':>8}")
    print("-" * 70)

    for i, s in enumerate(ranked, 1):
        capable = "yes" if s.verdict.met else "NO"
        print(
            f"{i:<4} {s.entry.alias:<16} {s.score:>8.1f} {capable:>8} "
            f"{s.capabilities.os.value:<10} {s.capabilities.cores:>6} "
            f"{s.capabilities.ram_mb:>8}"
        )

    print()
    return 0


def _cmd_task(parsed: argparse.Namespace) -> int:
    from core.broker.scoring import TaskConstraints
    from core.broker.tasks import (
        TaskExecutor,
        TaskRouter,
        TaskRoutingError,
        TaskSpec,
    )

    labels = frozenset(parsed.labels.split(",")) if parsed.labels else frozenset()

    req_os = OperatingSystem(parsed.os) if parsed.os else None
    req_arch = Architecture(parsed.arch) if parsed.arch else None
    req_transport = TransportKind(parsed.require_transport) if parsed.require_transport else None
    req_tools = frozenset(parsed.require_tools.split(",")) if parsed.require_tools else frozenset()

    constraints = None
    if any((req_os, req_arch, req_transport, req_tools)):
        constraints = TaskConstraints(
            require_os=req_os,
            require_arch=req_arch,
            require_transport=req_transport,
            require_tools=req_tools,
        )

    spec = TaskSpec(
        mode=parsed.mode,
        target_path=parsed.target,
        args=tuple(parsed.extra_args),
        labels=labels,
        prefer_alias=parsed.prefer_alias,
        timeout=parsed.timeout,
        constraints=constraints,
    )

    from core.broker.engage import load_engagement

    inv = Inventory()
    engagement = load_engagement()
    router = TaskRouter(inv, engagement=engagement)

    try:
        assignment = router.route(spec)
    except TaskRoutingError as exc:
        print(f"[!] Routing failed: {exc}", file=sys.stderr)
        return 1

    s = assignment.system
    print(f"\n[*] Task {assignment.task_id}")
    print(f"    Mode:   {spec.mode}")
    print(f"    Target: {spec.target_path}")
    print(f"    Routed: {s.entry.alias} ({s.entry.host}) — score {s.score:.1f}")
    print(f"    Reason: {assignment.reason}")
    if engagement:
        print(f"    Plan:   {engagement.target_description or 'active'}")

    if assignment.alternatives:
        print(f"    Alternatives: {', '.join(a.entry.alias for a in assignment.alternatives)}")

    if parsed.dry_run:
        print(f"\n    [dry-run] Would execute on {s.entry.alias}")
        return 0

    executor = TaskExecutor()

    if parsed.detach:
        print(f"\n[*] Launching detached on {s.entry.alias}...")
        handle = executor.launch(assignment)
        print(f"\n[+] Task {handle.task_id} running in {handle.backend} session")
        print(f"    Check:   raptor broker task-status {handle.task_id}")
        print(f"    Collect: raptor broker task-collect {handle.task_id}")
        print(f"    Cancel:  raptor broker task-cancel {handle.task_id}")
        return 0

    print(f"\n[*] Executing on {s.entry.alias}...")
    result = executor.execute(assignment)

    print(f"\n[{'+'if result.state.value == 'completed' else '!'}] {result.state.value}")
    if result.duration_secs is not None:
        print(f"    Duration: {result.duration_secs}s")
    if result.output_dir:
        print(f"    Results:  {result.output_dir}")
    if result.error:
        print(f"    Error:    {result.error}")
    if result.exit_code is not None:
        print(f"    Exit:     {result.exit_code}")

    return 0 if result.state.value == "completed" else 1


def _cmd_task_status(parsed: argparse.Namespace) -> int:
    from core.broker.tasks import TaskExecutor, _load_task_handle

    handle = _load_task_handle(parsed.task_id)
    if not handle:
        print(f"[!] No tracked task '{parsed.task_id}'", file=sys.stderr)
        return 1

    inv = Inventory()
    executor = TaskExecutor()

    try:
        state = executor.poll_task(handle, inv)
    except Exception as exc:
        print(f"[!] Poll failed: {exc}", file=sys.stderr)
        return 1

    elapsed = time.time() - handle.started_at
    status = "RUNNING" if state.running else f"FINISHED (exit {state.exit_code})"

    print(f"\n[*] Task {handle.task_id}")
    print(f"    Mode:    {handle.spec_mode}")
    print(f"    System:  {handle.system_alias}")
    print(f"    Backend: {handle.backend}")
    print(f"    Status:  {status}")
    print(f"    Elapsed: {elapsed:.0f}s")
    if state.pid:
        print(f"    PID:     {state.pid}")
    if state.tail_stdout:
        print(f"\n--- stdout (last 20 lines) ---")
        print(state.tail_stdout)
    if state.tail_stderr:
        print(f"--- stderr (last 20 lines) ---")
        print(state.tail_stderr)

    return 0


def _cmd_task_collect(parsed: argparse.Namespace) -> int:
    from core.broker.tasks import TaskExecutor, _load_task_handle

    handle = _load_task_handle(parsed.task_id)
    if not handle:
        print(f"[!] No tracked task '{parsed.task_id}'", file=sys.stderr)
        return 1

    inv = Inventory()
    executor = TaskExecutor()
    result = executor.collect(
        handle, inv, cleanup=not parsed.no_cleanup,
    )

    if result.state.value == "running":
        print(f"[*] Task {handle.task_id} is still running — cannot collect yet")
        return 1

    print(f"\n[{'+'if result.state.value == 'completed' else '!'}] {result.state.value}")
    if result.duration_secs is not None:
        print(f"    Duration: {result.duration_secs:.0f}s")
    if result.output_dir:
        print(f"    Results:  {result.output_dir}")
    if result.error:
        print(f"    Error:    {result.error}")

    return 0 if result.state.value == "completed" else 1


def _cmd_task_cancel(parsed: argparse.Namespace) -> int:
    from core.broker.tasks import TaskExecutor, _load_task_handle

    handle = _load_task_handle(parsed.task_id)
    if not handle:
        print(f"[!] No tracked task '{parsed.task_id}'", file=sys.stderr)
        return 1

    inv = Inventory()
    executor = TaskExecutor()
    killed = executor.cancel(handle, inv)

    if killed:
        print(f"[-] Task {handle.task_id} cancelled on {handle.system_alias}")
    else:
        print(f"[!] Could not cancel task {handle.task_id}", file=sys.stderr)

    return 0 if killed else 1


def _cmd_task_list(parsed: argparse.Namespace) -> int:
    from core.broker.tasks import list_active_tasks

    tasks = list_active_tasks()
    if not tasks:
        print("No tracked tasks.")
        return 0

    print(f"\n{'Task ID':<14} {'Mode':<10} {'System':<16} {'Backend':<8} {'Elapsed':>10}")
    print("-" * 66)

    import time as _time

    for h in tasks:
        elapsed = _time.time() - h.started_at
        if elapsed < 3600:
            elapsed_str = f"{elapsed:.0f}s"
        else:
            elapsed_str = f"{elapsed / 3600:.1f}h"
        print(
            f"{h.task_id:<14} {h.spec_mode:<10} {h.system_alias:<16} "
            f"{h.backend:<8} {elapsed_str:>10}"
        )

    print()
    return 0


def _cmd_engage(parsed: argparse.Namespace) -> int:
    from core.broker.engage import (
        ENGAGEMENT_SCOPES,
        EngagementPlan,
        clear_engagement,
        confirm_engagement,
        format_plan,
        format_proposal,
        load_engagement,
        propose_engagement,
        save_engagement,
    )

    action = parsed.action

    if action == "clear":
        if clear_engagement():
            print("[+] Active engagement plan cleared")
        else:
            print("[*] No active engagement plan")
        return 0

    if action == "show":
        plan = load_engagement()
        if not plan:
            print("[*] No active engagement plan")
            print("    Create one: raptor broker engage propose --scope full --target 'my target'")
            return 0
        print(f"\n{format_plan(plan)}")
        return 0

    if action == "propose":
        modes = _resolve_engage_modes(parsed)
        if not modes:
            return 1

        inv = Inventory()
        proposal = propose_engagement(inv, modes, parsed.target_desc)
        print(f"\n{format_proposal(proposal)}")

        print(f"\n[*] Review the proposal above.")
        print(f"    Confirm:   raptor broker engage confirm --scope {parsed.scope or 'full'} --target '{parsed.target_desc}'")
        print(f"    Override:  raptor broker engage confirm ... --set fuzz=linux-arm --exclude pixel-7")
        return 0

    if action == "confirm":
        modes = _resolve_engage_modes(parsed)
        if not modes:
            return 1

        inv = Inventory()
        proposal = propose_engagement(inv, modes, parsed.target_desc)

        overrides: dict[str, str] = {}
        if parsed.override_pairs:
            for pair in parsed.override_pairs:
                if "=" not in pair:
                    print(f"[!] Invalid override format '{pair}' — expected mode=alias", file=sys.stderr)
                    return 1
                mode, _, alias = pair.partition("=")
                overrides[mode] = alias

        exclude = frozenset(parsed.exclude.split(",")) if parsed.exclude else frozenset()

        plan = confirm_engagement(proposal, overrides=overrides, exclude=exclude)
        path = save_engagement(plan)

        print(f"\n{format_plan(plan)}")
        print(f"\n[+] Engagement plan confirmed and saved to {path}")
        print(f"    Tasks will now route according to this plan.")
        print(f"    Override per-task: raptor broker task fuzz /target --prefer other-system")
        print(f"    Clear:            raptor broker engage clear")
        return 0

    if action == "override":
        plan = load_engagement()
        if not plan:
            print("[!] No active engagement plan to override", file=sys.stderr)
            return 1

        if not parsed.override_pairs and not parsed.exclude:
            print("[!] Provide --set mode=alias and/or --exclude alias", file=sys.stderr)
            return 1

        inv = Inventory()
        proposal = propose_engagement(inv, plan.modes, plan.target_description)

        overrides: dict[str, str] = {}
        if parsed.override_pairs:
            for pair in parsed.override_pairs:
                if "=" not in pair:
                    print(f"[!] Invalid override '{pair}'", file=sys.stderr)
                    return 1
                mode, _, alias = pair.partition("=")
                overrides[mode] = alias

        existing_exclude = plan.excluded_aliases
        new_exclude = frozenset(parsed.exclude.split(",")) if parsed.exclude else frozenset()

        updated = confirm_engagement(
            proposal, overrides=overrides,
            exclude=existing_exclude | new_exclude,
        )
        path = save_engagement(updated)
        print(f"\n{format_plan(updated)}")
        print(f"\n[+] Engagement plan updated at {path}")
        return 0

    return 0


def _resolve_engage_modes(parsed: argparse.Namespace) -> frozenset[str]:
    from core.broker.engage import ENGAGEMENT_SCOPES

    if parsed.modes:
        return frozenset(parsed.modes.split(","))
    if parsed.scope:
        scope = ENGAGEMENT_SCOPES.get(parsed.scope)
        if not scope:
            print(f"[!] Unknown scope '{parsed.scope}'", file=sys.stderr)
            return frozenset()
        return scope
    print(
        "[!] Specify --scope or --modes\n"
        "    Scopes: full, source-audit, binary, web-assessment, mobile, reversing",
        file=sys.stderr,
    )
    return frozenset()


def _parse_source_spec(source: str) -> tuple[str, str]:
    """Parse ``alias:/remote/path`` into (alias, path)."""
    if ":" not in source:
        raise ValueError(
            f"invalid source format '{source}' — expected alias:/remote/path"
        )
    alias, _, path = source.partition(":")
    if not alias or not path:
        raise ValueError(
            f"invalid source format '{source}' — expected alias:/remote/path"
        )
    return alias, path


def _cmd_lift(parsed: argparse.Namespace) -> int:
    from core.broker.lift import LiftError, LiftSpec, lift, list_native_libs

    try:
        alias, remote_path = _parse_source_spec(parsed.source)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    inv = Inventory()
    spec = LiftSpec(
        source_alias=alias,
        remote_path=remote_path,
        unpack=not parsed.no_unpack,
    )

    print(f"[*] Lifting {remote_path} from {alias}...")
    try:
        lifted = lift(spec, inv, staging_dir=parsed.staging_dir)
    except LiftError as exc:
        print(f"[!] Lift failed: {exc}", file=sys.stderr)
        return 1

    size_str = f"{lifted.size_bytes / 1024:.1f} KB"
    if lifted.size_bytes > 1024 * 1024:
        size_str = f"{lifted.size_bytes / (1024 * 1024):.1f} MB"

    print(f"\n[+] Lifted successfully")
    print(f"    Source:  {alias}:{remote_path}")
    print(f"    Local:   {lifted.local_path}")
    print(f"    Size:    {size_str}")
    if lifted.file_type:
        print(f"    Type:    {lifted.file_type}")

    if lifted.unpacked_dir:
        natives = list_native_libs(lifted)
        if natives:
            print(f"    Unpacked: {lifted.unpacked_dir}")
            print(f"    Native libs ({len(natives)}):")
            for lib in natives[:10]:
                print(f"      - {lib}")
            if len(natives) > 10:
                print(f"      ... and {len(natives) - 10} more")

    print(f"\n    Route for analysis:")
    print(f"      raptor broker lift-and-route {parsed.source} fuzz --detach")
    print(f"      raptor broker lift-and-route {parsed.source} scan")

    return 0


def _cmd_lift_and_route(parsed: argparse.Namespace) -> int:
    from core.broker.lift import (
        LiftError,
        LiftSpec,
        choose_fuzz_target,
        lift,
    )
    from core.broker.scoring import TaskConstraints
    from core.broker.tasks import (
        TaskExecutor,
        TaskRouter,
        TaskRoutingError,
        TaskSpec,
    )

    try:
        alias, remote_path = _parse_source_spec(parsed.source)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    inv = Inventory()

    # Phase 1: Lift
    print(f"[*] Phase 1: Lifting {remote_path} from {alias}...")
    spec = LiftSpec(
        source_alias=alias,
        remote_path=remote_path,
        unpack=not parsed.no_unpack,
    )

    try:
        lifted = lift(spec, inv)
    except LiftError as exc:
        print(f"[!] Lift failed: {exc}", file=sys.stderr)
        return 1

    size_mb = lifted.size_bytes / (1024 * 1024)
    print(f"    Lifted {lifted.original_name} ({size_mb:.1f} MB)")
    if lifted.file_type:
        print(f"    Type: {lifted.file_type}")

    # Pick best target (native .so for APKs, original otherwise)
    if parsed.mode == "fuzz":
        target_path = choose_fuzz_target(lifted)
        if target_path != lifted.local_path:
            print(f"    Fuzz target: {target_path}")
    else:
        target_path = lifted.local_path

    # Phase 2: Route
    print(f"\n[*] Phase 2: Routing {parsed.mode} to best system...")

    labels = frozenset(parsed.labels.split(",")) if parsed.labels else frozenset()

    req_os = OperatingSystem(parsed.os) if parsed.os else None
    req_arch = Architecture(parsed.arch) if parsed.arch else None

    constraints = None
    if any((req_os, req_arch)):
        constraints = TaskConstraints(
            require_os=req_os,
            require_arch=req_arch,
        )

    task_spec = TaskSpec(
        mode=parsed.mode,
        target_path=target_path,
        args=tuple(parsed.extra_args),
        labels=labels,
        prefer_alias=parsed.prefer_alias,
        timeout=parsed.timeout,
        constraints=constraints,
    )

    router = TaskRouter(inv)
    try:
        assignment = router.route(task_spec)
    except TaskRoutingError as exc:
        print(f"[!] Routing failed: {exc}", file=sys.stderr)
        return 1

    s = assignment.system
    print(f"    Routed: {s.entry.alias} ({s.entry.host})")
    print(f"    Score:  {s.score:.1f}")
    print(f"    Reason: {assignment.reason}")
    print(f"    Path:   {alias} → localhost → {s.entry.alias}")

    if parsed.dry_run:
        print(f"\n    [dry-run] Would execute {parsed.mode} on {s.entry.alias}")
        return 0

    # Phase 3: Execute
    print(f"\n[*] Phase 3: Executing on {s.entry.alias}...")
    executor = TaskExecutor()

    if parsed.detach:
        handle = executor.launch(assignment)
        print(f"\n[+] Task {handle.task_id} running in {handle.backend} session")
        print(f"    Source:  {alias}:{remote_path}")
        print(f"    Target:  {s.entry.alias}")
        print(f"    Check:   raptor broker task-status {handle.task_id}")
        print(f"    Collect: raptor broker task-collect {handle.task_id}")
        return 0

    result = executor.execute(assignment)

    print(f"\n[{'+'if result.state.value == 'completed' else '!'}] {result.state.value}")
    if result.duration_secs is not None:
        print(f"    Duration: {result.duration_secs}s")
    if result.output_dir:
        print(f"    Results:  {result.output_dir}")
    if result.error:
        print(f"    Error:    {result.error}")

    return 0 if result.state.value == "completed" else 1


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
