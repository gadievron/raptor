---
name: frida
description: Dynamic instrumentation via Frida - attach to or spawn a process, load a JS hook script, capture send() events into a lifecycle-managed run directory. Supports local, USB-attached, and remote frida-server targets.
---

# Frida - dynamic instrumentation (alpha)

Hook a target at runtime to confirm LLM-flagged sinks actually execute, trace API calls, bypass SSL pinning, scan memory for secrets.

## When to use

- `/scan` or `/agentic` flagged a sink and you want to confirm it fires at runtime before treating it as exploitable.
- A binary or mobile app is doing something opaque and a few minutes of API-trace would reveal the shape.
- A pinned mobile app is blocking your MITM proxy.
- A crash you can't `rr`-record (macOS) needs a function-call trace.

## Install

```bash
pipx install frida-tools                       # host CLI + python bindings
raptor doctor                                  # confirms frida is detected
```

For remote / mobile targets, install the matching `frida-server` on the target side. See `docs/frida/SETUP_MACOS.md`, `SETUP_LINUX.md`. Note: most `frida-server` binaries bind to `127.0.0.1` by default - start with `-l 0.0.0.0:27042` or SSH-forward port 27042.

## Invocation

The slash command surfaces the libexec wrapper; run it as Bash. Lifecycle (output dir, run state) is handled by the wrapper.

```
libexec/raptor-frida --target <pid|name|bundle-id|binary>
                     (--template <name> | --script <path>)
                     [--host HOST[:PORT]] [--usb]
                     [--duration N] [--spawn] [--unsafe-attach]
```

Equivalent CLI without a Claude session: `raptor frida ...`.

## Templates

```bash
raptor frida --list-templates
```

| Name | Purpose |
|------|---------|
| `api-trace` | Hooks `open`/`read`/`write`/`connect`/`fork`/`execve` etc. Most useful default. |
| `ssl-unpin` | Bypasses iOS/macOS Security.framework, OpenSSL `SSL_get_verify_result`, and Android `X509TrustManager`. |

Operator-supplied scripts via `--script ./hook.js` - same `send(...)` capture path.

## Examples

```bash
# Trace API calls in a local PID for 30s
raptor frida --target 1234 --template api-trace --duration 30

# Spawn a binary and watch its first minute
raptor frida --target ./victim --template api-trace --duration 60

# Bypass SSL pinning on a USB-attached mobile target. Spawn by bundle id (frida resolves bundle ids for spawn); attach-by-name needs the running process's name, not the bundle id, so --spawn is the reliable form.
raptor frida --target com.example.app --template ssl-unpin --usb --spawn --duration 120

# Connect to remote frida-server
raptor frida --target target-proc --host 10.10.20.1 --template api-trace

# Operator-supplied hook
raptor frida --target Safari --script ./my-hook.js --duration 30
```

## Output layout

```
<run-dir>/
  events.jsonl       # one JSON object per send() from the script
  metadata.json      # target, host info, timings, errors
  script.js          # copy of the script that ran
  frida-report.md    # short human-readable summary
```

`<run-dir>` is resolved by `libexec/raptor-run-lifecycle`:
- Active `/project`: `out/projects/<name>/frida-<timestamp>/`
- Otherwise: `out/frida_<timestamp>/`

## Failure modes (read `metadata.json` first)

| Error fragment | Likely cause |
|---|---|
| `ptrace denied` | Linux `kernel.yama.ptrace_scope` ≥ 1. Lower it or spawn-and-attach. |
| `task_for_pid` | macOS hardened-runtime target or system process - needs SIP-disabled or signed-with-`get-task-allow`. |
| `unable to connect to remote frida-server` | Target not running, or bound to localhost only. SSH-forward 27042 or rebind. |
| `frida-python not installed` | `pipx install frida-tools`. |

## Threat model

Frida-instrumented targets are **untrusted** - that's the whole point. The runner is wrapped in `core.sandbox.run()` with the `debug` profile (ptrace allowed, `skip_pid_ns=True` for `/proc` access):

- **Spawn mode** (`--target ./binary`): `block_network=True` — the target can't reach out.
- **Attach mode** (`--target <pid|name>`): network untouched — the process is already running with whatever connectivity it needs.
- **`--unsafe-attach`**: sandbox bypassed entirely (system processes, SIP targets). Logged in `metadata.json`.

## Status

Alpha. Two templates ship; richer set in progress (collab with @Splinters-io). Integration into `/validate --runtime` and `/crash-analysis` on macOS is planned. The autonomous LLM-guided mode from the abandoned PR #57 is intentionally **not** in this slice.
