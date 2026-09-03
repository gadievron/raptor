# Frida Dynamic Instrumentation

RAPTOR wraps the Frida dynamic instrumentation framework into a
lifecycle-managed session runner. It resolves devices (local, USB,
remote frida-server), resolves targets (PID, process name, bundle ID, or
binary path), spawns or attaches, loads JavaScript hook scripts, captures
`send()` messages into `events.jsonl`, and writes structured metadata and
a human-readable report.

The Frida subsystem is both a standalone operator tool (`/frida`) and a
pipeline component that feeds runtime evidence into
[/binary](binary-analysis.md), [/validate](validation.md)
and [/understand](commands.md#understand).

See also: [commands](commands.md), [binary analysis](binary-analysis.md),
[sandbox](sandbox.md).

**Status:** Alpha. Templates and runner are minimal starters.

---

## Setup

### Host Install

```bash
pipx install frida-tools         # recommended (PEP 668-safe)
# or, in a virtualenv:
uv sync --locked --no-dev --group frida
```

Verify:

```bash
raptor doctor          # confirms frida binary is detected
frida --version        # client version
```

`raptor doctor` only checks the host side. Target reachability is the
operator's responsibility.

**Supported frida versions:** frida/frida-tools ≥ 16; frida 17 is
what RAPTOR tests against. Templates carry dual-path guards for the
APIs that changed across 16→17, and version gaps degrade LOUDLY —
the runner warns when frida-python is too old to drive an rpc-only
flush script (bundled templates also handle the posted
`raptor:flush` message and are immune), and templates report
inactive hook layers in their loaded `_meta` event rather than
silently no-oping.

### Linux

The kernel `yama.ptrace_scope` sysctl gates who can `ptrace` what:

| Value | Meaning |
|-------|---------|
| 0 | Classic -- any process can ptrace any other process with the same UID. |
| 1 | Default -- only child/explicit-trace targets allowed (most distros). |
| 2 | Admin-only. |
| 3 | Ptrace disabled entirely. |

To attach to a sibling process you own (the common case), drop to 0
temporarily:

```bash
sudo sysctl -w kernel.yama.ptrace_scope=0
```

Spawning a binary you can execute does not need `ptrace_scope=0`:

```bash
raptor frida --target ./vulnerable --template api-trace --duration 60
```

`metadata.json` from each run records the current `ptrace_scope` --
useful for "why did attach fail" forensics.

### macOS

No SIP changes required for processes you own. `task_for_pid` works for
same-UID processes.

**System / Apple-signed processes** are blocked by
`com.apple.private.disable-task_for_pid` even as root. To attach, SIP
must be partially disabled:

```
csrutil disable --without debug
```

This significantly reduces system security. Use a dedicated research VM.
RAPTOR's runner does not require SIP to be off; it only matters for the
targets you can attach to.

Hardened-runtime binaries with `com.apple.security.get-task-allow=false`
(most distributed App Store apps) reject attach. Either use a debug
build or re-sign with `--entitlements` that include
`get-task-allow=true`. Check existing entitlements with
`codesign -d --entitlements - <binary>`.

Frida 17.x ships arm64 builds for Apple Silicon natively.

### Remote frida-server

On the target (typically an embedded device or VM):

```bash
# download the matching frida-server for the target's arch
./frida-server -l 0.0.0.0:27042 &
```

The `-l 0.0.0.0:27042` is critical. Default builds bind to `127.0.0.1`
only, which is unreachable from another host.

From the RAPTOR host:

```bash
raptor frida --target some-process --host 10.10.20.1 --template api-trace
```

Treat the network channel as unauthenticated. Frida-server has no auth
in front of it. On shared networks, prefer SSH-forwarding:

```bash
# On the target: bind to localhost only
./frida-server -l 127.0.0.1:27042 &

# On the host: SSH-forward instead of --host
ssh -L 27042:127.0.0.1:27042 target-user@10.10.20.1
raptor frida --target some-process --host 127.0.0.1 --template api-trace
```

---

## Usage

**Slash command:**

```bash
/frida --target <target> --template <name> --duration <seconds>
```

**CLI entry point:**

```bash
raptor frida --target <target> --template <name> --duration <seconds>
```

### CLI Flags

| Flag | Purpose |
|------|---------|
| `--target <target>` | Required. PID (digits), process name, bundle ID, or path to a binary to spawn. |
| `--template <name>` | Bundled hook template name; combine several in one session with `+` (e.g. `--template seed-harvest+exec-and-load`). Mutually exclusive with `--script` / `--sink-watch`. |
| `--script <path>` | Path to an operator-supplied JS hook file. Mutually exclusive with `--template` / `--sink-watch`. |
| `--sink-watch <file>` | Watch a finding-specific sink list: a sinks JSON or a validation run's `attack-paths.json`. Mutually exclusive with `--template` / `--script`. |
| `--host <host[:port]>` | Connect to a remote frida-server. Default port 27042. Mutually exclusive with `--usb`. |
| `--usb` | Connect to the first USB-attached device. Mutually exclusive with `--host`. |
| `--duration <seconds>` | Seconds to run before detaching. Default 60. |
| `--stdin <file>` | Feed a file to the spawned target on stdin (PoC delivery; spawn mode). |
| `--spawn` | Force spawn-and-attach. Implied when `--target` is an existing file path. |
| `--unsafe-attach` | Required for templates/modes needing `PTRACE_ATTACH` or `task_for_pid`. Logged in metadata. |
| `--follow-children` | Trace fork()/exec() children too (Frida child gating); children get the same hook script, events land in the same `events.jsonl`. |
| `--list-templates` | Print bundled template names and exit. |

### Examples

```bash
# List bundled templates
raptor frida --list-templates

# Attach to a local process by PID
raptor frida --target 1234 --template api-trace --duration 30

# Spawn a binary and trace for 60 seconds
raptor frida --target ./victim --template api-trace --duration 60

# Bypass SSL pinning on a USB-attached mobile target (spawn by bundle ID)
raptor frida --target com.example.app --template ssl-unpin --usb --spawn --duration 120

# Remote frida-server on the LAN
raptor frida --target target-binary --template api-trace --host 10.10.20.1

# Operator-supplied hook script
raptor frida --target Safari --script ./my-hook.js --duration 30
```

---

## Bundled Templates

Use `--list-templates` to see the current set. Templates can be
combined into one session with `--template a+b` (duplicate or empty
names are rejected); each template's events land in the same
`events.jsonl`.

### I/O correlation

When one session captures both an ingest family and a later-call
family — `--template seed-harvest+exec-and-load`, add `+sink-watch`
for sink arguments — the CLI automatically joins the harvested input
payloads against string arguments of later events (exec argv, command
strings, sink arguments) after the run. A byte sequence the target
received from outside reappearing inside an `execve` argument is
direct, cheap evidence that external input steers command execution:
crude taint, no taint engine. Matches (8+ printable bytes; all
indexing and scanning bounded, truncations counted in the manifest)
are written to `io-correlation.json` and announced on the console.
Correlation is additive — a correlation failure never fails a
completed run.

### api-trace

Hooks common input/output APIs (`recv`, `recvfrom`, `read`, `write`,
`send`, `sendto`, etc.) and records call arguments and return values.
The general-purpose starting point for understanding what a binary does
at runtime.

```bash
raptor frida --target ./app --template api-trace --duration 30
```

### ssl-unpin

Bypasses SSL/TLS certificate pinning for common frameworks and
libraries. Useful for intercepting HTTPS traffic from mobile
applications during security assessment.

Coverage caveat: the Android `X509TrustManager` bypass needs the Java
bridge, which Frida 17 unbundled — loaded through RAPTOR's runner it
is INACTIVE on current Frida (the run says so in a `_meta` event; the
OpenSSL and Security.framework hooks are unaffected). For Android
unpinning on Frida 17, use a frida-compiled agent that bundles
frida-java-bridge.

```bash
raptor frida --target com.example.app --template ssl-unpin --usb --spawn
```

### binary-flow-trace

Records ASLR-relative callsites for input APIs (`recv`, `recvfrom`,
`read`) and high-value parser entry points (`XML_Parse`,
`xmlReadMemory`, `d2i_X509`, `jpeg_read_header`, `inflate`). When a
callsite maps back to a recovered function address, RAPTOR emits
`OBSERVED_CALLSITE` or `OBSERVED_PARSER_CALLSITE` graph edges.

This template is used by `/binary trace-parser` to fold runtime
evidence back into an existing binary investigation. It proves the
function called the API during that run; it does not claim those bytes
reached a later sink.

```bash
raptor frida --target ./app --template binary-flow-trace --duration 20
```

### bb-coverage

Basic-block coverage collection via Frida Stalker. Records which basic
blocks execute during the traced session and writes a drcov-format
`coverage.drcov` that `parse_drcov` / the coverage store consume
directly. Useful for measuring code coverage of specific inputs or
comparing coverage between test cases.

Only the target module (and libraries in its directory) is stalked —
that is all the drcov consumer reads, and it keeps Stalker overhead
survivable. Coverage is emitted on the controller's flush clock, so a
target that exits within ~0.3s of resume yields little or none: keep
it alive via stdin or arguments.

```bash
raptor frida --target ./app --template bb-coverage --duration 30
```

### seed-harvest

Dumps the input buffers the target actually received (`read`, `recv`,
`recvfrom`, `SSL_read`, `fread`, `fgets`, `getline`, ...) and distills
them into a fuzz-ready seed corpus. After the session the CLI writes
one file per unique payload into `<out>/seeds/` plus a
`seeds-manifest.json` sibling with per-function counts.

Observing a network daemon or file parser under real traffic for a
minute yields protocol-realistic seeds — usually the hardest part of
fuzzing a binary-only target.

```bash
raptor frida --target ./daemon --template seed-harvest --duration 60
raptor fuzz --binary ./daemon --corpus out/frida_<ts>/seeds
```

Captures are capped (8 KiB per buffer, 2048 events per hooked
function) and deduplicated in-process; caps are reported in the event
stream and manifest, never applied silently.

Seeds are the raw bytes the target received — decrypted TLS payloads
(`SSL_read`), file contents, anything on its sockets. Treat a
harvested corpus as potentially secret-bearing and review it before
sharing or committing it anywhere.

### exec-and-load

Records command execution (`system`, `popen`, the `exec` family,
`posix_spawn`) with the resolved argv, and dynamic-loader activity
(`dlopen`, `dlmopen`, `android_dlopen_ext`) — each event annotated
with the calling module, offset, and backtrace. Answers "did that
command-injection sink actually fire, and from where?" and enumerates
runtime-loaded libraries/plugins that static import tables miss.

```bash
raptor frida --target ./app --template exec-and-load --duration 60
```

Events are captured on function entry: `execve` does not return on
success, so exit-side hooks would miss exactly the interesting calls.

By default the session traces one process, so a plain `fork()` child
is outside it and the fork()+exec pattern emits nothing. Pass
`--follow-children` to trace children too (Frida child gating): each
fork/exec child is attached, gets the same hook script, and its
events land in the same `events.jsonl` — the child's `execv` shows up
with full argv. Without the flag, treat the *absence* of an exec
event as unknown, never as proof the sink did not fire.

### sink-watch

Records every call to a configured list of dangerous sinks with its
arguments and full callsite. Two modes:

- `--template sink-watch` watches the default sink vocabulary from the
  central function taxonomy (memory-copy, string-overflow,
  format-string, and exec sinks).
- `--sink-watch <file>` watches a finding-specific list — either a
  hand-written sinks JSON (`["memcpy", {"fn": "SSL_write", "module":
  "libssl.so.3"}]`) or a validation run's `attack-paths.json`, from
  which every step function is derived mechanically.

Per-sink resolution tries module-scoped exports, global exports, then
`DebugSymbol` — the fallback rescues project-internal sink wrappers on
targets that ship symbols. Unresolved sinks are listed in the `_meta`
event, and hot sinks are capped at 500 events each with a loud cap
marker.

```bash
# Run the PoC input while watching exactly the finding's sinks:
raptor frida --target ./srv --sink-watch out/validate_<ts>/attack-paths.json --duration 60
```

Sink events carry `category=sink` and the function name in `fn` — the
exact shape the validation bridge counts, so the observed arguments
("the tainted length reached the memcpy") flow into `/validate`'s
`runtime_evidence` annotations with no extra wiring.

Evidence is target-attributed: a call counts when the target binary
appears at the call site or anywhere on the captured backtrace.
Consequences worth knowing, in both directions. Calls with no target
frame anywhere on the stack — pre-main libc startup activity, calls
made entirely inside shipped libraries, a watched `main` invoked from
`__libc_start_main` — record events but yield no evidence; when a
collection pass yields nothing, the dropped events are reported with
their caller modules as a warning (routine startup drops on
evidence-bearing runs log at debug). Conversely, hot libc sinks
(`memcpy` and friends) WILL attribute from any I/O the target
performs — `printf` reaches libc-internal `memcpy` with the target on
the stack — so treat `function_observed` on a ubiquitous sink as
reachability corroboration, not proof that the finding's specific
call site ran; each event carries `caller_module`/`caller_offset`, and the
validation bridge resolves target-binary call sites to source
(`observed_callsites`, sandboxed `addr2line` on debug-built targets;
a binary directly under `/tmp` is masked by the sandbox and cannot
resolve) and marks `callsite_match: true` when an observed call lands
on the finding's own location — site-level proof, not just
function-level. The key is absent when nothing resolved (unknown) and
`false` only when resolved sites landed elsewhere. A caller
module whose on-disk path lives under the target binary's directory
also attributes — project-shipped libraries whose call chains never
touch the main binary (plugin callbacks, dlopen'd codecs) — without
admitting system libraries. Spawn a
binary target to get attributable evidence; attach-by-name sessions
still record sink events for the operator but yield no `/validate`
evidence. Aliased sinks that share one implementation address (glibc
`memcpy`/`memmove`) are hooked once and credited under every watched
name, and `seed-harvest`/`jni-trace` runs never feed `/validate`
evidence at all — their outputs are seeds and boundary mappings, not
call proof.

### jni-trace

Maps the Java↔native boundary on ART (Android) targets by hooking
`RegisterNatives` (every `art::JNI<...>` instantiation, CheckJNI twin
excluded): one event per registered native method with the method
name, JNI signature, and the native implementation's module + offset.
This bridges jadx-level Java analysis to native-code analysis — jadx
shows which class declares a `native` method with that name and
signature; the emitted offset says which native function backs it.

```bash
raptor frida --target com.example.app --template jni-trace --usb --spawn --duration 30
```

On a non-ART process the template loads, reports the miss in a
`_meta` event, and hooks nothing. Class names resolve only when the
Java bridge is present in the agent — Frida 17 unbundled it, and
RAPTOR loads scripts unbundled via `create_script`, so on current
Frida expect the raw `jclass` handle per registration batch (the
method/signature/module mapping is unaffected).

### call-edges

Collects the dynamic call graph via Stalker and emits one
`category=call_edge` event per unique caller→callee pair whose CALLEE
is target-owned (the main binary or a library in its directory). The
`/agentic` reachability prepass turns these into `frida_call_edge`
REACHABLE witnesses — the dynamic complement to `--binary-edges`: an
indirect call or vtable dispatch the static graph cannot resolve is
ground truth here, because the call executed.

```bash
raptor frida --target ./app --template call-edges --duration 60
```

System libraries are excluded from stalking (edges from target code
are captured; callbacks invoked from inside excluded libraries are
not), callee names resolve via DebugSymbol (symbol-bearing builds
give the best coverage), and emission is driven by the controller's
flush clock — in-agent timers are not dependable across frida
installs, so the runner drives flushes on a cadence: the first one
0.3s after resume (never immediately — that races target startup),
every 0.3s early on, then every ~2s, and a final one before
teardown. Bundled templates receive them as posted `raptor:flush`
messages (fire-and-forget, so a delivery race costs one tick instead
of wedging the run); custom scripts without that handler get their
exported `flush()` called instead.

Experimental: CAPTURE is best-effort — Stalker thread-following is
flaky on some frida builds (a run may follow nothing; check
`followed_threads` in the summary `_meta` and re-run). Teardown is
always safe: the run cannot hang or lose its metadata, and because
`frida_call_edge` only ever PROMOTES reachability, a capture-less run
costs nothing while a captured one rescues functions.

### heap-trace

Heap lifecycle evidence for memory-corruption findings on binaries
you cannot rebuild with ASAN: double frees, invalid frees,
freed-memory-use candidates at libc boundaries, and leak-candidate
allocation sites.

Per-allocation events are never sent — allocator traffic aggregates
in-agent and leaves on the controller's flush clock; only anomaly
events (budgeted, target-attributed) stream live. The flush summary
carries totals and the top outstanding allocation sites of the
target's own code, symbolised when debug info allows. Anomaly events
flow into the validation bridge as attributed runtime evidence.

```bash
raptor frida --target ./app --template heap-trace --duration 30
```

Honest limits: `uaf_candidate` sees uses only at hooked libc
boundaries (compilers inline small constant `memcpy`/`strcpy` calls,
which never reach a hook; direct pointer dereferences are invisible
without whole-process Stalker instrumentation), the freed-range
quarantine is bounded, and `invalid_free` is only emitted for
spawn-mode runs (in attach mode a pre-attach allocation freed later
is indistinguishable) and is suppressed entirely if any alloc-source
export failed to hook. The malloc/calloc/realloc/memalign families
are tracked; a custom allocator that manages its own mmap'd arenas
is invisible (its frees are counted as `unknown_frees`, never
reported as anomalies). In multi-threaded targets a realloc-move
races the tracker by construction (the allocator's internal free
happens before the hook can observe it), so cross-thread reuse can
occasionally mis-sequence — one more reason every anomaly is a
candidate for triage, not a verdict. A detected double free usually
aborts the target moments later — the abort path is held briefly so
the event drains before the process dies.

---

## Pipeline Integration

Beyond standalone use, `/binary` and `/agentic` launch Frida
observation themselves when dynamic evidence collection is warranted
(programmatic entry points `observe_target` / `observe_paired` /
`auto_observe` / `watch_sinks` in `packages/frida/`; existing fresh
evidence for a target is reused rather than re-collected), and
`/validate` Stage E auto-launches a finding-parameterized sink watch
against the matched binaries — gated on the operator's dynamic-trust
grant (`--dynamic` or the project `dynamic` marker), promote-only,
feeding the finding's `poc.payload` on stdin when one exists,
per-binary evidence scoping, deduplicated via a helper-owned launch
ledger. Frida sessions run under
the same [sandbox](sandbox.md) constraints as every other RAPTOR
subprocess, observed callsites and parser boundaries are folded back
into `/understand` context maps, and `/binary map --runtime-dir`
ingests evidence from prior runs.

---

## Patch Verification

`libexec/raptor-frida-patch-verify` turns a `/patch` candidate into a
dynamically verified one: it runs the same proof-of-concept input
against the unpatched binary and a build of the patched source, each
under a sink watch, and compares target-attributed sink evidence.

```bash
libexec/raptor-frida-patch-verify \
    --before ./build-orig/app --after ./build-patched/app \
    --sink system --poc poc.txt --location src/handler.c:42
```

Verdicts (exit codes are verdict-bearing; 2 is reserved for errors):

| Verdict | Exit | Meaning |
|---------|------|---------|
| `Closed` | 0 | Sink fired pre-patch, silent post-patch. `site`-level when the pre-patch firing resolved to `--location`, else `function`-level. |
| `Still Fires` | 1 | Sink fired in both runs. A sanitising patch can legitimately leave the call in place — confirm manually. |
| `Inconclusive` | 3 | Sink never fired pre-patch (the PoC does not demonstrate the vulnerable path), or the post-patch session produced no events at all (broken session, not a silent sink). |

The comparison is function-level on the post-patch side by design:
patches move source lines, so matching the patched run against the
original finding's line would be unsound. Give `--duration` enough
headroom for the PoC to reach the sink in the slower build — the
sink not firing within the window is indistinguishable from it never
firing. The report (`patch-verify.json`) carries both runs' evidence,
and both binaries run under frida without a sandbox — only verify
patches on binaries you built yourself.

---

## Custom Scripts

Operator-supplied scripts are loaded verbatim via `--script`. The script
runs in Frida's JavaScript runtime and should use `send()` to emit
structured messages, which RAPTOR captures in `events.jsonl`.

```javascript
// my-hook.js
Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function(args) {
        send({
            type: 'open',
            path: args[0].readUtf8String(),
            flags: args[1].toInt32()
        });
    }
});
```

```bash
raptor frida --target ./app --script ./my-hook.js --duration 30
```

A copy of the executed script (template or operator-supplied) is saved
as `script.js` in the output directory for reproducibility.

---

## Output

Each run drops into a lifecycle-managed directory:

```
out/projects/<project>/frida-<timestamp>/      # if a /project is active
out/frida_<timestamp>/                         # otherwise
```

Contents:

| File | Purpose |
|------|---------|
| `events.jsonl` | One JSON object per `send(...)` from the script. |
| `metadata.json` | Target, host info, timings, errors, ptrace_scope (Linux). |
| `script.js` | Copy of the hook that executed. |
| `frida-report.md` | Short human-readable summary. |
| `seeds/` + `seeds-manifest.json` | Fuzz-ready corpus distilled from data-carrying events (only when the script emitted `args.data_hex` payloads, e.g. seed-harvest). |
| `coverage.drcov` | drcov-format basic-block coverage (bb-coverage template only). |
| `io-correlation.json` | Ingest-payload / later-call-argument joins (written when the post-run join finds matches; needs one session capturing both families, e.g. `--template seed-harvest+exec-and-load`). |

---

## Common Failure Modes

| Symptom | Likely cause |
|---------|-------------|
| `frida: run failed: ptrace denied` (Linux) | `kernel.yama.ptrace_scope` >= 1; relax via `sysctl` or attach as the target's owning user. |
| `frida: run failed: ... task_for_pid` (macOS) | System process or hardened target; needs SIP-disabled or signed binary entitlement. |
| `Failed to enumerate processes: unable to connect to remote frida-server` | frida-server bound to localhost only -- re-launch with `-l 0.0.0.0:27042` or SSH-forward 27042. |
| `failed to enumerate processes: timeout` | Network filter/firewall between host and target. |
| Empty `events.jsonl` | Script did not hook anything that fired during the window; raise `--duration` or check `metadata.json` for an error. |
| `PermissionDeniedError: unable to access executable at ...` (wrapper spawn) | The sandbox read allowlist does not cover the target's path — the wrapper grants the `--target` file's directory automatically; if you see this, the target argument is likely not the real binary path (symlink chain outside the granted tree, or a name that shadows a file). |
| `Error sending credentials` / `ProcessNotRespondingError: unexpected early end-of-stream` (wrapper spawn) | Frida's agent-injection channel blocked by the sandbox on this host. Pre-flight the target with the raw CLI (`python3 -m packages.frida.cli ...`) to distinguish sandbox friction from a target problem. |
| frida-server killed by SELinux (Android-flavoured Linux) | Run `setenforce 0` while researching, or label the binary appropriately. |
| No provisioning profile / arch mismatch (macOS) | Old Intel frida-server binary on Apple Silicon; match host and target architectures. |
