---
description: Manage remote systems for cross-platform capability brokering
dispatch: python3 raptor.py broker
---

# /broker - RAPTOR System / Capability Broker

**`--help` / `-h`:** If the user passes only `--help` or `-h`, run `python3 raptor.py broker --help` and present its output.

You are helping the user manage a fleet of remote systems that RAPTOR can dispatch work to when the local host lacks required capabilities.

## When to Use

The broker solves the problem where the RAPTOR head is running on a system that cannot execute a particular mode. Examples:
- Running `/fuzz` from macOS (AFL++ requires Linux)
- Running analysis tools that need specific architectures
- Distributing heavy workloads across dedicated machines

## Subcommands

### Add a system
```bash
python3 raptor.py broker add <alias> <host> [--port 22] [--user root] [--transport ssh|winrm] [--key /path/to/key] [--labels gpu,high-mem]
```

### Remove a system
```bash
python3 raptor.py broker remove <alias>
```

### List all systems
```bash
python3 raptor.py broker list
```

### Check mode compatibility
```bash
python3 raptor.py broker check <mode>
```
Shows whether a mode can run locally and which remote systems could handle it.

### Probe a system
```bash
python3 raptor.py broker probe <alias>
```
Re-probes a registered system and refreshes its cached capabilities (OS, arch, tools, RAM, cores, disk).

### Provision missing tools
```bash
python3 raptor.py broker provision <alias> <mode> [--apply]
```
Shows what needs to be installed (dry-run by default). Pass `--apply` to actually install.

## Workflow

1. Register remote systems: `raptor broker add ci-linux 10.0.0.5 --user raptor --key ~/.ssh/id_ed25519`
2. Check what you can run: `raptor broker check fuzz`
3. Provision if needed: `raptor broker provision ci-linux fuzz --apply`
4. Run normally — the broker auto-routes when local capabilities are insufficient

## Transport

- **SSH** (default): Linux and macOS targets. Uses paramiko + SFTP. rsync used as fast-path when available.
- **WinRM**: Windows targets. Uses pywinrm + PowerShell. File transfer via base64-encoded chunks.

## Dependencies

- SSH transport: `pip install paramiko`
- WinRM transport: `pip install pywinrm`

## Inventory

Systems are persisted in `~/.raptor/broker/inventory.json`. Each entry stores connection details and a cached capability snapshot (refreshed on probe).
