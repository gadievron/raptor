---
description: Dynamic instrumentation via Frida (alpha) - attach or spawn, hook with JS templates, capture runtime events
dispatch: libexec/raptor-frida $ARGUMENTS
exclude_from_listing: true
---

# /raptor-frida - Frida Dynamic Instrumentation (alpha)

Runtime instrumentation substrate. Attach to (or spawn) a target, load a hook script (bundled template or operator-supplied), capture `send(...)` events into a lifecycle-managed run directory.

## Usage

```
/raptor-frida --target <pid|name|bundle-id|binary>
              (--template <name>[+<name>] | --script <path> | --sink-watch <file>)
              [--host HOST[:PORT]] [--usb]
              [--duration N] [--stdin FILE] [--spawn] [--unsafe-attach]
              [--follow-children]
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
| `ssl-unpin` | iOS/macOS Security.framework, OpenSSL `SSL_get_verify_result`; Android `X509TrustManager` needs the Java bridge (inactive on Frida 17 via the runner). |
| `bb-coverage` | Basic-block coverage collection. |
| `binary-flow-trace` | Flow tracing used by `/binary runtime`. |
| `seed-harvest` | Dump received input buffers; auto-distilled into a `--corpus`-ready seed dir for `/fuzz`. |
| `exec-and-load` | Command execution (argv + caller module/offset) and `dlopen` activity. |
| `sink-watch` | Argument-level sink evidence; parameterize with `--sink-watch <sinks.json|attack-paths.json>` instead of `--template`. |
| `jni-trace` | Android/ART RegisterNatives mapping: Java method → native module + offset. |
| `call-edges` | Dynamic call-graph edges (Stalker) → `frida_call_edge` reachability witness. |
| `heap-trace` | Heap lifecycle: double-free / invalid-free / freed-memory-use candidates + leak sites. |

List dynamically: `raptor frida --list-templates`. Combine templates
in one session with `--template a+b` (e.g.
`seed-harvest+exec-and-load` — this pairing also triggers the
automatic post-run I/O correlation join).

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
- Otherwise: `out/frida_<timestamp>_pid<N>_<tail>/` (uniquified)

Artefacts:
- `events.jsonl` - one JSON object per `send(...)`.
- `metadata.json` - target, host info, timings, errors.
- `script.js` - the script that ran.
- `frida-report.md` - human-readable summary.
- `seeds/` + `seeds-manifest.json` - fuzz-ready corpus (data-carrying events, e.g. seed-harvest).
- `coverage.drcov` - bb-coverage template only.
- `io-correlation.json` - ingest/later-call joins (combined-template sessions, only when matches found).

## Requirements

- **Host:** `frida` CLI on PATH and the `frida` Python module importable by raptor's Python 3 interpreter.
  - `pipx install frida-tools` puts the CLI on PATH but isolates the Python binding - `raptor frida` will report `FridaUnavailable` until the module is also installed.
  - Add the module with: `python3 -m pip install --user --break-system-packages frida`.
- **Target:** for remote / mobile targets, run the matching `frida-server`. Prefer keeping its default localhost-only bind and reaching it over an SSH port-forward (`ssh -L 27042:127.0.0.1:27042 <target>`) — frida-server is an unauthenticated code-execution service, so binding it to `0.0.0.0:27042` exposes it to every host on the network; do that only on an isolated lab segment. Either way, a connect failure is recorded in `metadata.json` (`raptor doctor` won't tell you this).

See `docs/frida.md`.

## Failure Modes

Read `metadata.json` first. Common patterns:

| Error fragment | Cause |
|---|---|
| `ptrace denied` (Linux) | `kernel.yama.ptrace_scope` ≥ 1. Lower it, or spawn-and-attach instead. |
| `task_for_pid` (macOS) | Hardened-runtime target / system process. SIP-disabled or `get-task-allow` signing required. |
| `unable to connect to remote frida-server` | frida-server not running, or bound to localhost only. SSH-forward 27042 or rebind. |
| `frida-python not installed` | Install per "Requirements" above. |

## Status

Alpha. Bundled templates: see the table above (authoritative list via `--list-templates`). Integration into `/validate` is automatic (Stage B collects runtime evidence via the validation bridge; sink/exec/load evidence is target-attributed). `/crash-analysis` integration on macOS is planned; richer template set in progress (collab with @Splinters-io after his abandoned PR #57).

The runner wraps frida in `core/sandbox/` by default (spawn-mode runs execute inside the sandbox envelope). `--unsafe-attach` opts out with a "running WITHOUT sandbox" warning — required for templates and attach modes that need `PTRACE_ATTACH` / `task_for_pid`.

---
