# Sandbox

RAPTOR sandboxes every subprocess that handles untrusted content --
LLM-generated PoCs, target build scripts, CodeQL queries, Semgrep,
[fuzz](fuzzing.md) targets, [Frida](frida.md) instrumentation helpers,
and anything whose arguments or input came from a repository under
analysis. The sandbox composes Linux kernel isolation primitives
(namespaces, Landlock, seccomp-bpf) into a layered defence that
degrades gracefully on hosts missing any single layer, while failing
loudly when no isolation can engage at all.

On macOS, the same machinery routes through `sandbox-exec(1)` and
Seatbelt profiles. See [Platform support](#platform-support) for the
capability comparison.

For CLI flag reference, see [commands](commands.md).

---

## What a sandboxed run gets you

- Network blocked at the namespace level (fresh namespace with only an
  isolated loopback interface — no route out).
- Filesystem restricted to the target (read-only), the run's output
  directory (writable), a fresh per-sandbox `/tmp`, and a curated
  system-directory read allowlist. `$HOME` redirected to an empty
  per-sandbox directory, so `cat ~/.ssh/id_rsa`, `~/.aws/credentials`,
  and `~/.config/raptor/models.json` all come back empty or denied.
- Dangerous syscalls blocked: `io_uring`, `ptrace` (in `full`),
  `keyctl`, `bpf`, `userfaultfd`, `perf_event_open`, tty-injection
  ioctls, plus raw/packet/netlink sockets.
- No core dumps, memory/CPU caps, and a per-sandbox process cap that
  bounds fork bombs.
- Environment sanitised through a strict allowlist; API keys and other
  credentials never reach untrusted children.

Programmatically, `core.sandbox` exposes two trust levels:
`run_untrusted()` / `run_untrusted_networked()` for anything
attacker-derived (read restriction and fake home on by default), and
`run_trusted()` for commands whose full command line is RAPTOR-owned
(env sanitisation and rlimits only). The finer-grained `sandbox()` /
`run()` API sits underneath; its docstrings are the reference.

## Isolation layers

The sandbox composes up to six layers. Each falls back gracefully if the
kernel does not support it -- RAPTOR logs a warning once per layer per
process.

1. **User namespace** -- unprivileged root-mapping foundation.
2. **Network namespace** -- sandboxed process sees only an isolated
   loopback interface; no route out.
3. **PID namespace** -- hides host PIDs; also blocks cross-process
   `/proc/<pid>/environ` credential reads.
4. **IPC namespace** -- isolates SysV shm/sem/message queues.
5. **Mount namespace** -- per-sandbox `/tmp` and `/run`, host system
   dirs bind-mounted read-only, target and output bind-mounted at
   their original absolute paths. **Disabled on Ubuntu 24.04 by
   default** (AppArmor gates unprivileged user namespaces); see
   [Troubleshooting](#troubleshooting).
6. **Landlock + seccomp-bpf + rlimits** -- always applied when
   available, even when namespaces fall back.

On kernels that lack any particular layer, the sandbox proceeds with the
remaining ones and emits a one-time warning. Nothing silently downgrades
to "no isolation".

**Landlock is fail-closed.** If installing the Landlock ruleset fails
in the child (kernel drift, ABI mismatch), the child exits 126 rather
than continue unsandboxed; the parent sees a non-zero return code plus
a `RAPTOR: Landlock ...` line on stderr explaining which step failed.

**Untrusted runs refuse to degrade silently.** On Linux hosts without
unprivileged user namespaces, untrusted execution fails closed with a
`SandboxSetupError` naming the host fix. Setting
`RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1` is the explicit operator acceptance
of Landlock/seccomp-only containment (see
[environment.md](environment.md)); every waived run warns that same-UID
`/proc` credential reads are not blocked in that mode.

---

## Profiles

Profiles bundle layer settings into a single name for CLI use:
`--sandbox <profile>` on any RAPTOR command that honours it.

| Profile | Network | Landlock | Seccomp | Notes |
|---|---|---|---|---|
| `full` | blocked | yes | full | The default. Warns and degrades if a host layer is missing (untrusted entry points excepted — see above). |
| `strict` | blocked | yes | full | Fail-closed version of `full`. For autonomous work where weaker isolation is not acceptable. Also requires mount namespaces when target/output isolation is requested. |
| `target_run` | **open** | yes | full | For harness-spawned target binaries that need a local listener (loopback TCP, Unix domain sockets). Paired processes (server + client) can share one isolated network namespace. |
| `debug` | blocked | yes | debug (permits ptrace) | For [crash analysis](crash-analysis.md) with gdb/rr. Target and debugger run in the same sandbox. Composes with `--audit`. |
| `frida` | **open** | yes | frida (AF_UNIX allowed) | For [Frida](frida.md) helper IPC. Netlink/packet/raw sockets stay blocked. |
| `network-only` | blocked | off | none | Tools whose correctness needs unrestricted filesystem or syscalls. |
| `none` | open | off | none | Emergency escape hatch. Rlimits only. |

Use `--sandbox strict` when a run should stop rather than quietly carry
on with less isolation. On macOS, the strict profile adds
probe-validated Seatbelt denies (cross-process signals, nvram, a
curated mach-lookup allowlist) on top of `full`.

**Read-denial recovery:** `--sandbox-readable-path PATH` (repeatable;
file or directory) extends the read allowlist of every read-restricting
sandbox in the run, and `--sandbox-tool-path DIR` (repeatable) makes an
operator-installed tool directory visible inside the sandbox
(read-only — pip `--user`, pyenv, `~/.cargo/bin`, `/usr/local`
installs). The loop: run with `--audit` to see what enforcement would
deny, read `suggested_fix` in `sandbox-summary.json`, then re-run with
the named path. Both flags loosen isolation — grant the narrowest path
that fixes the denial, never `$HOME` itself. Paths are validated at
parse time; the flags are rejected alongside `--sandbox none` /
`--no-sandbox` (no allowlist to extend).

**Tool visibility:** the mount-namespace sandbox bind-mounts a fixed
set of system dirs; a tool installed anywhere else (`~/.local/bin/`,
`/opt/homebrew/bin/`) would be invisible (exit 127). The sandbox
auto-falls back to Landlock-only isolation when the command resolves
outside the bind tree, and callers can opt tool directories in
(`--sandbox-tool-path`, or `tool_paths=` programmatically — with
`python_runtime_tool_paths()` auto-discovering the running Python's
runtime roots for Python tools). If a bind set turns out insufficient,
the call automatically retries at Landlock-only and caches the result
for the rest of the process.

If a tool genuinely needs a config file from your real home, copy it
into the sandbox's fake home (`<output>/.home/`) before the run. Git is
the exception: internal git runs with global/system config disabled
unconditionally, no matter what is placed in the fake home.

---

## Egress proxy

An in-process HTTPS-CONNECT proxy lets a sandboxed tool reach a
specific set of hostnames while everything else stays blocked — used
when a tool needs one or two API endpoints (a Claude sub-agent,
a CodeQL pack download) but should not get open network.

- The child's `HTTPS_PROXY`/`http_proxy` point at a loopback port; the
  proxy rejects any `CONNECT` to a hostname not on the allowlist.
- Resolved IPs are screened — loopback, private, link-local, multicast,
  and reserved addresses are rejected even for allowlisted hostnames
  (DNS-rebinding defence).
- Enforcement is tiered, strongest available first: an empty network
  namespace where the proxy is the only reachable endpoint; a
  Landlock pin to the proxy's port plus a UDP block (closing DNS
  exfiltration) when namespaces are unavailable; environment variables
  alone as the last resort. Runs record which tier engaged.

### Upstream proxy support

If `HTTPS_PROXY` is set in the parent environment (e.g. corporate
proxy), the RAPTOR proxy forwards its `CONNECT` tunnels through that
upstream, honouring `NO_PROXY`. This is transparent to callers. The
upstream handshake has its own budget (default 10 s); slow or
authenticated corporate proxies can widen it with
`RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S` — the signal you need it is
`upstream_failed` events in `proxy-events.jsonl` on a proxy that is
otherwise working.

### Proxy events

Every CONNECT attempt is recorded and persisted to
`{output}/proxy-events.jsonl`:

```json
{
  "t": 12345.678,
  "caller": "claude-sub-agent",
  "host": "api.anthropic.com",
  "port": 443,
  "result": "allowed",
  "reason": null,
  "resolved_ip": "160.79.104.10",
  "bytes_c2u": 1234,
  "bytes_u2c": 5678,
  "duration": 0.412
}
```

Results: `allowed`, `denied_host`, `denied_resolved_ip`, `dns_failed`,
`upstream_failed`, `timed_out`, `bad_request`, `handler_error`.

---

## Audit and observe modes

### Audit mode

`--audit` (composed with any compatible profile) runs a workflow to
completion AND records what enforcement WOULD have blocked. It is the
soft-default fallback when `full` is too strict for a workload but you
want visibility into policy violations -- far better than
`--sandbox none`.

Audited layers: the egress-proxy hostname gate logs-and-allows (the
resolved-IP block stays enforcing), blocked syscalls are traced and
logged instead of denied — **except escape primitives** (ptrace family,
keyctl, bpf, userfaultfd, io_uring, tty-injection ioctls), which stay
hard-denied even under audit — and file opens / network connects that
would have been blocked are logged with the offending path or address.

| Invocation | Effect |
|---|---|
| `--sandbox full` (default) | Full enforcement |
| `--sandbox full --audit` | Full layout, would-be-blocked events logged |
| `--sandbox full --audit --audit-verbose` | Logs EVERY traced syscall (strace-style) |
| `--sandbox debug --audit` | gdb-friendly seccomp + audit signal |
| `--sandbox network-only --audit` | Only the egress-proxy gate audits |
| `--sandbox none --audit` | **Error** -- incoherent (nothing to audit against) |
| `--audit-verbose` without `--audit` | **Error** |

Audit mode adds roughly 3.5x overhead versus plain `full` (per-syscall
tracing), so use it diagnostically, not as the standing default.

**Degradation when ptrace is unavailable** (Yama scope 3, container
`--cap-drop SYS_PTRACE`): network audit still works; syscall and
filesystem audit degrade to enforcement. The degradation is loud: a
WARNING plus a `sandbox-audit-degraded.json` marker (reason +
remediation) in the audit target.

### Observe mode

Observe mode is a superset of audit that additionally traces
stat-family syscalls, producing a profile of every path the binary
read or wrote and every network target it tried. Use it to derive a
read allowlist or an egress hostname allowlist from actual behaviour:

```bash
raptor-sandbox-observe -- /usr/bin/true           # human summary
raptor-sandbox-observe --json -- ./scan-target    # machine-readable profile
```

Programmatic consumers parse the observe log into an `ObserveProfile`
(`parse_observe_log`) with `paths_read`, `paths_written`, and
`connect_targets`; the profile can also be merged into a `/understand`
context map to corroborate static analysis with runtime evidence.

### Audit budget

`--audit-budget=N` (default 10000) caps records per run. Per-category
and per-PID sub-caps stop one chatty category or spamming subprocess
from squeezing everything else out, a token bucket lets long-running
workloads at low steady-state run indefinitely, and high-volume
categories keep emitting a sampled trickle after their cap so you can
see "still happening". Budget markers appear in the JSONL alongside
data records.

### Audit output

After a `--audit` run completes, inspect the run's output directory.
Three possible states:

**1. Audit ran and recorded events** -- `sandbox-summary.json` is
present. Each entry includes `audit: true`:

```json
{
  "run_dir": "/path/to/run",
  "generated_at": "2026-04-27T15:00:00Z",
  "total_denials": 2,
  "by_type": {"network": 1, "seccomp": 1},
  "denials": [
    {"ts": "...", "cmd": "...", "returncode": 0, "type": "network",
     "host": "evil.example.com", "port": 443, "audit": true,
     "suggested_fix": "audit: outbound network to `evil.example.com` would be blocked under `--sandbox full`"}
  ]
}
```

**2. Audit ran, no enforcement events** -- no `sandbox-summary.json`
and no degraded marker. The workflow ran and nothing would have been
blocked. (This is success.)

**3. Audit was requested but did not actually run** --
`sandbox-audit-degraded.json` is present. Follow the `instructions`
field and rerun.

---

## Binary calibration

Hardcoded sandbox allowlists drift: a provider adds an endpoint, an
operator points pip at a corporate index, CodeQL pulls packs from a
GHE host. The calibration tool runs a binary once under a permissive
observed policy and caches the paths and hosts it actually touched
(keyed on the binary's hash, under `~/.cache/raptor/sandbox-profiles/`),
so allowlists can follow reality instead of hardcoded guesses:

```bash
libexec/raptor-sandbox-calibrate --bin <binary> [--json | --show | --force | --clear | --clear-all]
```

Calibration is a portability / drift-detection tool, NOT a security
feature: by the time behaviour is observed, the binary has already
executed once. The programmatic API (`calibrate_binary`,
`load_or_calibrate`, `clear_cache`) lives in `core.sandbox.calibrate`.

---

## Observability

Each sandboxed result carries a `sandbox_info` record: termination
reason (`crashed`, `signal`), sanitizer detection, enforcement events,
proxy events, and degradation stamps (`audit_engaged`,
`mount_ns_degraded`, `proxy_enforcement`, `degraded_net_deny`) that
tell you exactly which isolation tier a run actually got.

### Per-run denial summary

For commands that go through the run lifecycle (everything driven by
`/scan`, `/agentic`, `/codeql`, `/validate`, `/understand`, `/fuzz`),
every sandbox enforcement event seen during the run is aggregated into
`{run_dir}/sandbox-summary.json` at run-end. `suggested_fix` references
only the operator-facing CLI flags.

**Recovery from non-clean exits.** If a run dies before its lifecycle
hook fires:

1. **Automatic** -- the next time the same session re-runs the same
   command type, the abandoned run is marked failed and its summary is
   finalised through the standard path.

2. **Manual**:

   ```bash
   # Single run.
   libexec/raptor-sandbox-summary <run_dir>

   # All stranded runs under a project dir.
   libexec/raptor-sandbox-summary --sweep <project_dir>
   ```

### Sandbox triage and live escalation

On every terminal-state transition the lifecycle also runs a
rules-based classifier over the run's sandbox telemetry and writes
`{run_dir}/sandbox-triage.json`: a clean / notable / suspicious verdict
distinguishing escape / recon / credential-theft signatures from
ordinary "tool needed something the profile didn't allow" denial
noise. Pure and offline — no LLM call, no network, no cost.

| Signal | Severity | Meaning |
|--------|----------|---------|
| `escape_primitive_denied` | high | denial matched the escape-primitive syscall sets (ptrace, bpf, keyctl, io_uring, ...) |
| `hostile_syscall_argument` | high | denied syscall whose decoded arguments are themselves primitives (tty hijack ioctls, raw/packet sockets) |
| `telemetry_tampering` | high | a triage input failed provenance verification |
| `resolved_ip_screened` | high | a CONNECT resolved into a blocked IP range |
| `credential_path_touch` | high | denial paths matched credential signatures |
| `host_recon_pattern` | medium | distinct denied hosts over threshold (default 5) |
| `volume_anomaly` | medium | denial volume near the per-run cap |
| `seccomp_denied_unattributed` | low | non-audit run: a seccomp denial happened, syscall identity unknown |

The HIGH-severity signals also escalate LIVE to stderr the moment they
fire — escalate-only, no enforcement change, no auto-kill. Set
`RAPTOR_SANDBOX_LIVE_ESCALATION_DISABLED=1` to silence the live banners
(the post-hoc `sandbox-triage.json` is unaffected).

Because the run dir is writable by the sandboxed target while it runs,
every triage input the target could forge is stamped at write time with
an HMAC token; content failing verification is excluded and fires
`telemetry_tampering`. The token's strength depends on the run's
posture: the key lives outside the run directory, but only a mount
namespace or a `restrict_reads` read allowlist hides it from the child
— on a read-unrestricted run (the Landlock-only `full`/`target_run`
default) the target could read the key and mint valid tokens itself,
so triage records the posture and demotes token-verified telemetry to
legacy confidence on such runs (flagged in the report's caveats and
`inputs.mac_key_posture`).

Re-run triage by hand (stranded runs, scripted gates), optionally with
an LLM deeper-reasoning pass:

```bash
libexec/raptor-sandbox-triage <run_dir> [--json] [--deep]
# exit codes: 0 clean/no telemetry, 1 error, 2 usage, 3 notable, 4 suspicious
```

`--deep` sends the provenance-verified triage report to the configured
default LLM, which judges each signal as attack attempt vs tool noise.
Advisory only: the rules verdict and exit code never change.

---

## Resource limits

Every sandboxed child gets rlimit caps alongside the isolation
layers. Defaults (override per limit in
`~/.config/raptor/sandbox.json`, or per call via `limits={...}`):

| Key | Default | rlimit | Notes |
|---|---|---|---|
| `memory_mb` | `0` (off) | `RLIMIT_AS` | Deliberately off: ASAN-instrumented targets reserve ~56 TiB of shadow VA and break under ANY finite cap, and `/validate` PoCs run ASAN through the untrusted entry points. Set a value only for workloads you know are ASAN-free; use cgroup `memory.max` for a real RAM bound. |
| `max_file_mb` | `10240` | `RLIMIT_FSIZE` | Caps a single written file (10 GB accommodates debug builds and corpora). |
| `cpu_seconds` | `3600` | `RLIMIT_CPU` | Soft limit fires SIGXCPU 1s before the hard kill. |
| `nproc` | `1024` | `RLIMIT_NPROC` | Namespace paths count it against the ns-local uid (nobody = zero pre-existing processes). On the Landlock-only path (no user namespace) the same budget is applied as an absolute ceiling of current-same-uid-process-count + `nproc`, bounding fork bombs without counting the operator's unrelated work. |
| `nofile` | `4096` | `RLIMIT_NOFILE` | Bounds fd-exhaustion DoS; clamped to the inherited hard limit. `0` disables. |

Example `~/.config/raptor/sandbox.json`:

```json
{
    "memory_mb": 8192,
    "max_file_mb": 20480,
    "nofile": 8192
}
```

---

## When the sandbox cannot engage

`SandboxSetupError` is raised when sandbox isolation could not engage
for a run. It deliberately propagates past broad exception handlers
that would otherwise swallow the failure and produce a false "0
findings" result. CLI subprocesses print the actionable message and
exit with code **3**; the error carries the kernel diagnostic and the
operator's next step.

Policy: RAPTOR does NOT auto-degrade to weaker isolation when the
requested profile cannot engage. The operator resolves it explicitly
(e.g. `--sandbox network-only`).

---

## Toolchain env for builds

Environment sanitisation deliberately strips language-specific vars
like `JAVA_HOME`, `GOROOT`, `DOTNET_ROOT`, `RUSTUP_HOME`. Build
subprocesses get those auto-resolved from filesystem layout at build
time instead — and only the build subprocess sees them.

If a build tool still fails with "JDK not found" or similar: install
the toolchain into a standard location for your distro.

---

## Platform support

### Linux (full isolation)

All six layers are available: user namespace, network namespace, PID
namespace, IPC namespace, mount namespace, Landlock + seccomp-bpf +
rlimits. Each layer probes for kernel support independently at first
use.

Landlock coverage grows with kernel version: the TCP-connect allowlist
needs kernel 6.7+, truncation restriction 6.2+, device-ioctl deny
6.10+, and signal/abstract-socket scoping 6.12+. Missing pieces are
announced with a one-shot notice, never silently assumed.

### macOS (Seatbelt)

On Darwin, the sandbox routes through `sandbox-exec(1)` with an SBPL
profile. The same profiles, flags, egress proxy, audit budget, and
summary/triage output work identically. Platform limits: no PID or
mount namespaces (the read restriction is the substitute), process
caps are per-UID host-wide, syscall filtering is coarser, and host
fingerprint sanitisation is unavailable. Under `--sandbox debug`,
process-info denies are skipped so lldb/sample/dtrace can attach.

---

## Known limitations

- **Read restriction is strongest for untrusted runs.** The untrusted
  entry points default to the kernel-level read allowlist; other
  sandbox uses opt in. On Landlock-only hosts (Ubuntu 24.04 default)
  the read restriction is the load-bearing credential-exfiltration
  defence.
- **Orphan-leak potential.** If the RAPTOR parent dies with a hard
  SIGKILL, deeply nested grandchildren may survive briefly until the
  PID namespace reaps them (seconds in practice).
- **`io_uring` is hard-denied everywhere** — its file operations bypass
  syscall tracing, so it is blocked even in audit mode rather than left
  as an untraceable surface.
- **Audit mode is for operator workflows, not malware analysis** —
  code in an audited sandbox can detect tracing (TracerPid, timing).
- **Metadata operations are unrestricted in Landlock-only mode.**
  Landlock has no access right covering metadata-only syscalls, so a
  child can chmod/chown/setxattr/utimensat any same-UID file outside
  the writable allowlist (content reads/writes stay blocked). Seccomp
  cannot close this either — the target path lives behind a pointer
  argument that classic BPF cannot dereference. Mount-ns mode closes
  it (read-only binds refuse metadata writes with EROFS). Runs in
  this posture stamp `sandbox_info["landlock_metadata_ops_unrestricted"]`
  so downstream readers do not treat file modes/timestamps observed
  after such a run as trustworthy.

---

## Troubleshooting

### "Mount namespace unavailable" on Ubuntu 24.04

Ubuntu 24.04 ships with an AppArmor sysctl that blocks unprivileged
user-namespace mount operations. The sandbox still applies Landlock,
seccomp, network/PID/IPC namespaces, and rlimits -- but it cannot
provide read-only bind mounts for target/output or a fresh `/tmp`.

Both prerequisites must be met to enable mount-ns:

```bash
# 1. Allow unprivileged user namespaces (no reboot needed)
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# 2. Install newuidmap/newgidmap (setuid-root helpers)
sudo apt install uidmap
```

Without both, the sandbox falls back to Landlock-only. Landlock alone
already covers the main threat model (no writes outside the output
dir, no credential reads under the read restriction). Exception: when
the user-namespace tier is unavailable entirely, untrusted execution
refuses to fall back — set `RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1` to
explicitly accept Landlock/seccomp-only containment for untrusted code
(see [environment.md](environment.md)).

### A target binary fails with EACCES reading `/home/<user>/...`

Tools that hardcode absolute paths under `/home/<user>/` (not `$HOME`)
hit the read restriction even with the fake home. Add the specific
path with `--sandbox-readable-path`, or pre-populate the fake home and
let the tool resolve via `$HOME`.

### Shell scripts fail on `>/dev/null 2>&1`

`/dev/null` writes are permitted by a narrow Landlock rule. If you see
EACCES on `/dev/null`, check for a custom readable/writable path
override that displaced the curated `/dev` grants.

### Rust `cargo build` fails at the linker stage

Rust's `std::process::Command` uses `socketpair(AF_UNIX, ...)`
internally; the sandbox permits this explicitly. If you see EPERM on
`socketpair` itself, check for a custom seccomp override.

### CodeQL "Failed to download pack"

The egress proxy allowlist needs the full set of GHCR hosts:
`ghcr.io`, `codeload.github.com`, `objects.githubusercontent.com`,
`pkg-containers.githubusercontent.com`.

---

## Related documentation

- [Commands reference](commands.md) -- CLI flags (`--sandbox`,
  `--audit`, `--audit-verbose`, `--audit-budget`).
- [Security model](security.md) -- how the sandbox fits RAPTOR's own
  threat model.
- [Fuzzing](fuzzing.md) -- fuzz target execution under sandbox
  isolation.
- [Frida](frida.md) -- Frida instrumentation using the `frida` profile.
- [Crash analysis](crash-analysis.md) -- gdb/rr under the `debug`
  profile.

The module docstring in `core/sandbox/__init__.py` carries the current
threat-model statement -- what the sandbox does and does not protect
against.
