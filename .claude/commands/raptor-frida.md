---
description: Dynamic instrumentation via Frida (alpha) - attach or spawn, hook with JS templates, capture runtime events
dispatch: libexec/raptor-frida
---

# /raptor-frida - Frida Dynamic Instrumentation (alpha)

Runtime instrumentation substrate. Attach to (or spawn) a target, load a hook script (bundled template or operator-supplied), capture `send(...)` events into a lifecycle-managed run directory.

## Usage

```
/raptor-frida --target <pid|name|bundle-id|binary>
              (--template <name> | --script <path>)
              [--host HOST[:PORT]] [--usb]
              [--duration N] [--spawn] [--unsafe-attach]
```

Equivalent shell:

```
raptor frida --target ... --template ...
# or directly:
libexec/raptor-frida --target ... --template ...
```

## What This Does

1. Resolves the target (PID, process name, bundle id, or binary path).
2. Resolves the device - local, `--usb`-attached, or remote `--host`.
3. Loads the hook script (template by name or `--script` JS file).
4. For spawn-and-attach: calls `device.spawn`, attaches, loads the script, *then* resumes - so hooks are in place before `main()` runs.
5. Runs for `--duration` seconds (default 60), capturing every `send(...)` from the script into `events.jsonl`.
6. Detaches cleanly on time-up or SIGINT; writes `metadata.json` + `frida-report.md`.

## Bundled Templates

| Name | Purpose |
|------|---------|
| `api-trace` | libc/syscall surface: `open`, `read`, `write`, `connect`, `fork`, `execve`, etc. |
| `ssl-unpin` | iOS/macOS Security.framework, OpenSSL `SSL_get_verify_result`, Android `X509TrustManager`. |

List dynamically: `raptor frida --list-templates`.

## Examples

```bash
# Trace local PID for 30 seconds
/raptor-frida --target 1234 --template api-trace --duration 30

# Spawn and watch
/raptor-frida --target ./victim --template api-trace --duration 60

# Bypass mobile SSL pinning via USB (spawn by bundle id - attach-by-name needs the running process name, not the bundle id)
/raptor-frida --target com.example.app --template ssl-unpin --usb --spawn --duration 120

# Remote frida-server
/raptor-frida --target target-proc --host 10.10.20.1 --template api-trace

# Operator-supplied hook
/raptor-frida --target Safari --script ./my-hook.js --duration 30
```

## Output

Resolved by `libexec/raptor-run-lifecycle`:
- Active project: `out/projects/<name>/frida-<timestamp>/`
- Otherwise: `out/frida_<timestamp>/`

Artefacts:
- `events.jsonl` - one JSON object per `send(...)`.
- `metadata.json` - target, host info, timings, errors.
- `script.js` - the script that ran.
- `frida-report.md` - human-readable summary.

## Requirements

- **Host:** `frida` CLI on PATH and the `frida` Python module importable by raptor's Python 3 interpreter.
  - `pipx install frida-tools` puts the CLI on PATH but isolates the Python binding - `raptor frida` will report `FridaUnavailable` until the module is also installed.
  - Add the module with: `python3 -m pip install --user --break-system-packages frida`.
- **Target:** for remote / mobile targets, run the matching `frida-server`. Bind to `0.0.0.0:27042` (default builds bind to localhost only - `raptor doctor` won't tell you this, but `metadata.json` will record the connect failure).

See `docs/frida/QUICKSTART.md`, `docs/frida/SETUP_MACOS.md`, `docs/frida/SETUP_LINUX.md`.

## Failure Modes

Read `metadata.json` first. Common patterns:

| Error fragment | Cause |
|---|---|
| `ptrace denied` (Linux) | `kernel.yama.ptrace_scope` ≥ 1. Lower it, or spawn-and-attach instead. |
| `task_for_pid` (macOS) | Hardened-runtime target / system process. SIP-disabled or `get-task-allow` signing required. |
| `unable to connect to remote frida-server` | frida-server not running, or bound to localhost only. SSH-forward 27042 or rebind. |
| `frida-python not installed` | Install per "Requirements" above. |

## Status

Alpha. Two templates ship; richer set in progress (collab with @Splinters-io after his abandoned PR #57). Integration into `/validate --runtime` and `/crash-analysis` on macOS is planned - see `docs/frida-integration-proposal.md`.

The runner currently does **not** wrap frida in `core/sandbox/`; the `--unsafe-attach` flag is forward-looking and logged into `metadata.json` for when the sandbox envelope lands.

---
