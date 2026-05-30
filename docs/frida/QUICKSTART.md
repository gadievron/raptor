# Frida - Quickstart

Dynamic instrumentation via Frida, wired into RAPTOR's run-lifecycle.

## Install (host)

Frida host CLI + Python bindings:

```bash
pipx install frida-tools         # recommended (PEP 668-safe)
# or:
pip install --user frida-tools
```

Verify:

```bash
raptor doctor          # confirms `frida` binary is detected
frida --version        # client version
```

## Install (target)

Frida-server on the target is the operator's concern. Common shapes:

- **Local macOS / Linux process**: no target install needed - frida attaches via task_for_pid / ptrace.
- **Android (rooted) / iOS (jailbroken)**: drop the matching `frida-server` build under `/data/local/tmp/` or `/usr/sbin/`, run it, then connect with `--usb`. Target-side setup is device- and OS-version-specific - follow the upstream frida-server instructions for your platform.
- **Remote Linux**: copy `frida-server` to the host, start with `-l 0.0.0.0:27042` (not the default localhost-only bind), then connect from the host with `--host <ip>`.

`raptor doctor` only checks the host side. Target reachability is your job.

## Run

```bash
# List bundled templates
raptor frida --list-templates

# Attach to a local process by PID
raptor frida --target 1234 --template api-trace --duration 30

# Spawn a binary and trace its first 60 seconds of syscalls
raptor frida --target ./victim --template api-trace --duration 60

# Bypass SSL pinning on a USB-attached mobile target. Spawn by bundle id (frida resolves bundle ids for spawn); attach-by-name needs the running process's name, not the bundle id, so --spawn is the reliable form.
raptor frida --target com.example.app --template ssl-unpin --usb --spawn --duration 120

# Remote frida-server on the LAN
raptor frida --target target-binary --template api-trace --host 10.10.20.1
```

Operator-supplied scripts:

```bash
raptor frida --target Safari --script ./my-hook.js --duration 30
```

## Output

Each run drops into a lifecycle-managed directory:

```
out/projects/<project>/frida-<timestamp>/      # if a /project is active
out/frida_<timestamp>/                         # otherwise
```

Contents:

- `events.jsonl` - one JSON object per `send(...)` from the script.
- `metadata.json` - target, host info, timings, errors.
- `script.js` - copy of what executed (template or operator-supplied).
- `frida-report.md` - short human-readable summary.

## Common failure modes

| Symptom | Likely cause |
|---------|--------------|
| `frida: run failed: ptrace denied` (Linux) | `kernel.yama.ptrace_scope` ≥ 1; relax via `sysctl` or attach as the target's owning user. |
| `frida: run failed: ... task_for_pid` (macOS) | System process or hardened target; needs SIP-disabled or signed binary entitlement. |
| `Failed to enumerate processes: unable to connect to remote frida-server` | frida-server bound to localhost only - re-launch with `-l 0.0.0.0:27042` or SSH-forward 27042. |
| Empty `events.jsonl` | Script didn't hook anything that fired during the window; raise `--duration` or check `metadata.json` for an `error`. |

## Status

Alpha. Templates and runner are minimal starters - richer bundle in progress. See `docs/frida-integration-proposal.md` for the v2 design and roadmap.
