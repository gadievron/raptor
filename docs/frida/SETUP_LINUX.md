# Frida on Linux

## Host install

```bash
pipx install frida-tools       # Ubuntu 24.04+ / Debian 12+ (PEP 668)
# or, in a venv:
pip install frida-tools
```

## Ptrace permissions

The kernel `yama.ptrace_scope` sysctl gates who can `ptrace` what:

| Value | Meaning |
|-------|---------|
| 0 | Classic - any process can ptrace any other process with the same UID. |
| 1 | Default - only child / explicit-trace targets allowed (most distros). |
| 2 | Admin-only. |
| 3 | Ptrace disabled entirely. |

To attach to a sibling process you own (the common case), drop to 0 temporarily:

```bash
sudo sysctl -w kernel.yama.ptrace_scope=0
```

`raptor doctor` reports the current `ptrace_scope` in its host snapshot, and `metadata.json` from each run records it - useful for "why did attach fail" forensics.

## Spawn-and-attach

Spawning a binary you can execute doesn't need ptrace_scope=0:

```bash
raptor frida --target ./vulnerable --template api-trace --duration 60
```

## Remote frida-server (the common ARM / embedded case)

On the target (typically an embedded device or VM):

```bash
# download matching frida-server for the target's arch
./frida-server -l 0.0.0.0:27042 &
```

**The `-l 0.0.0.0:27042` is critical.** Default builds bind to `127.0.0.1` only, which is unreachable from another host. (We tripped on this during proposal drafting - host pinged but every frida port refused connection. See `docs/frida-integration-proposal.md` "Operational note from the field.")

From the RAPTOR host:

```bash
raptor frida --target some-process --host 10.10.20.1 --template api-trace
```

Treat the network channel as **unauthenticated**. Frida-server has no auth in front of it. Bind to a trusted-only network, or SSH-forward 27042 instead of exposing it.

## Hardening notes

A frida-server bound to `0.0.0.0` is effectively a remote-attach service for any host on the network. For research labs this is fine; on shared networks, prefer:

```bash
# On the target: bind to localhost only
./frida-server -l 127.0.0.1:27042 &

# On the host: SSH-forward instead of --host
ssh -L 27042:127.0.0.1:27042 target-user@10.10.20.1
raptor frida --target some-process --host 127.0.0.1 --template api-trace
```

## Common errors

| Symptom | Fix |
|---------|-----|
| `ptrace: Operation not permitted` | Lower `ptrace_scope` or spawn-and-attach instead. |
| `unable to connect to remote frida-server` | frida-server isn't running, or bound to localhost only. Check from the target with `ss -tlnp | grep 27042`. |
| `failed to enumerate processes: timeout` | Network filter / firewall between host and target. |
| frida-server killed by SELinux on Android-flavoured Linux | Run `setenforce 0` while researching, or label the binary appropriately. |
