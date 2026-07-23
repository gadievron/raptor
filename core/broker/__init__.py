"""
RAPTOR System / Capability Broker

Routes work to compatible systems when the local host lacks required
capabilities. Maintains an inventory of remote systems reachable via
SSH (Linux/macOS) or WinRM (Windows) and matches capability
requirements declared by each RAPTOR mode against what each system
provides.

Architecture
------------
- **Capabilities** — declarative model: each mode declares what it
  needs (OS, arch, tools); each system advertises what it has.
- **Inventory** — persistent registry of remote systems (JSON on
  disk, keyed by alias).
- **Transport** — abstract interface with SSH and WinRM backends.
- **Provisioner** — installs missing tools on a remote system.
- **Transfer** — ships source/binaries out, collects artifacts back.
- **Broker** — the top-level dispatcher: given a mode and its
  requirements, find or prepare a compatible system, execute there,
  and return artifacts to the head.
"""
