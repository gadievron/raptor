# Frida on macOS

Host: anything modern (Frida 17.x supports Apple Silicon natively).
Target: any macOS process you have permission to instrument.

## Host install

```bash
pipx install frida-tools
```

System Python on macOS is externally-managed under PEP 668; `pipx` is the cleanest path. Plain `pip install frida-tools` works inside a virtualenv.

## Attaching to your own processes

No SIP changes required. `task_for_pid` works for processes you own when you're the same UID.

```bash
raptor frida --target Safari --template api-trace --duration 30
```

If you don't see the process under `frida-ps`, the target's owning UID is probably different (root daemons, helper processes signed by Apple). See below.

## Attaching to system / Apple-signed processes

These are blocked by default by `task_for_pid` checks even as root, because the targets have the `com.apple.private.disable-task_for_pid` entitlement.

To attach: SIP must be partially disabled. Boot into recovery mode and:

```
csrutil disable --without debug
```

Then reboot. This permits `task_for_pid` but keeps filesystem and kext protections.

**This significantly reduces system security. Use a dedicated research VM.** RAPTOR's runner does not require SIP to be off; it only matters for the targets you can attach to.

## Spawning a binary you don't own

Frida spawn-and-attach for a binary you can execute works without SIP changes:

```bash
raptor frida --target ./my-binary --template api-trace --duration 60
```

Hardened-runtime binaries with `com.apple.security.get-task-allow=false` (most distributed App Store apps) reject the attach. Either:
- Use a debug build, or
- Re-sign the binary with `--entitlements` that include `get-task-allow=true`.

`codesign -d --entitlements - <binary>` shows the existing entitlements.

## Remote frida-server (e.g., from a macOS host to a Linux target)

Same as Linux - see `SETUP_LINUX.md`. macOS-side just needs `frida-tools` and a route to the target's port 27042.

## Apple Silicon notes

`frida 17.x` ships arm64 builds. If you see "no provisioning profile" or arch mismatches, you're likely on an old Intel `frida-server` binary. Match host and target architectures.
