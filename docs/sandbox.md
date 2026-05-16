# Subprocess Sandbox

RAPTOR sandboxes any subprocess that handles untrusted content — LLM-generated
PoCs, target build scripts, CodeQL queries, semgrep, fuzz targets, anything
whose arguments or input came from a repo under analysis. This page covers
what the sandbox protects against, how to invoke it, and how to read the
diagnostics it emits.

## When to use which entry point

| Entry point | Use when | Network | Landlock | Seccomp | rlimits |
|---|---|---|---|---|---|
| `run_untrusted()` | command or its input is attacker-derived | blocked | enforced (restrict_reads) | full | yes |
| `sandbox()` + `run()` | you need fine-grained control (allowed TCP ports, egress proxy, no network ns) | configurable | configurable | configurable | yes |
| `run_trusted()` | RAPTOR chose the command AND its inputs; no untrusted content flows into it | open | off | off | yes |
| `run()` (top-level) | you know which kwargs you need; one-shot convenience over `sandbox()` | configurable | configurable | configurable | yes |

Rule of thumb: **default to `run_untrusted()`**. Downgrade to `sandbox()` only
when the tool genuinely needs something the untrusted defaults deny (e.g. a
CodeQL sub-agent that needs `api.anthropic.com` on port 443). Downgrade to
`run_trusted()` only when the full command line is RAPTOR-owned and no
attacker-derived bytes feed into it.

## Quick start

```python
from core.sandbox import run_untrusted

# Run a compiled target binary that was built from an untrusted repo.
result = run_untrusted(
    [target_binary, "--flag", input_file],
    target=repo_path,          # bind-mounted / Landlock-allowed ro
    output=work_dir,            # writable scratch area
    limits={"memory_mb": 2048, "cpu_seconds": 30},
    capture_output=True,
)
```

What this gets you:

- network blocked at the namespace level (no interfaces inside)
- filesystem restricted to `target` (read-only), `output` (writable), `/tmp`
  (fresh tmpfs), and a curated system-dir read allowlist
- `$HOME` redirected to an empty per-sandbox directory
- dangerous syscalls blocked: io_uring, kcmp, pidfd_getfd, handle_at,
  TIOCSTI/TIOCCONS, SysV IPC, ptrace (in `full`), keyctl, bpf, userfaultfd,
  perf_event_open, plus `socket()` for AF_UNIX / AF_PACKET / AF_NETLINK /
  SOCK_RAW (docker.sock escape, raw-packet sniffing)
- RLIMIT_CORE = 0 (no core-dump exfil), memory/CPU caps, and a `prlimit
  --nproc=<limit>` wrapper sitting *inside* the `unshare` chain so
  RLIMIT_NPROC counts against the namespace-local UID — bounds fork bombs
  per sandbox

## Isolation layers

The sandbox composes up to six layers. Each falls back gracefully if the kernel
doesn't support it — RAPTOR logs a warning once per layer per process.

1. **User namespace** (`unshare --user`) — unprivileged root-mapping foundation.
2. **Network namespace** (`--net`) — sandboxed process sees no interfaces.
   Active under `full`, `debug`, `network-only` profiles.
3. **PID namespace** (`--pid --fork`) — hides host PIDs; target runs as PID 1.
4. **IPC namespace** (`--ipc`) — isolates SysV shm/sem/message queues.
5. **Mount namespace** (pivot_root onto a fresh tmpfs) — per-sandbox `/tmp`
   and `/run`, host system dirs (`/usr`, `/lib`, `/etc` etc.) bind-mounted
   read-only, caller's `target` + `output` bind-mounted at their ORIGINAL
   absolute paths (no caller argv rewriting needed). Uses `newuidmap`
   (from the `uidmap` package) for the user-ns mapping and drives mount
   syscalls from Python via ctypes BEFORE Landlock install — otherwise
   Landlock (on kernel 6.15+) would block the mount topology changes.
   **Disabled on Ubuntu 24.04 by default** (AppArmor sysctl gates
   unprivileged user-ns); see [Troubleshooting](#troubleshooting).
6. **Landlock + seccomp-bpf + rlimits** — always applied when available, even
   when namespaces fall back.

On kernels that lack any particular layer, the sandbox proceeds with the
remaining ones and emits a one-time warning. Nothing silently downgrades to
"no isolation".

**Landlock is fail-closed.** If `landlock_restrict_self()` returns an error
inside `preexec_fn` (kernel drift, ABI mismatch, EINVAL on a rule), the child
calls `os._exit(126)` rather than continue unsandboxed. The parent sees a
non-zero `result.returncode` plus a `RAPTOR: Landlock …` line on the child's
stderr explaining which step failed.

### Profiles

Profiles bundle layer settings into a single name for CLI use:

| Profile | Network | Landlock | Seccomp | Notes |
|---|---|---|---|---|
| `full` | blocked | yes | full | default for `run_untrusted()` and `sandbox()` |
| `debug` | blocked | yes | full (permits ptrace) | for `/crash-analysis` with gdb/rr |
| `network-only` | blocked | off | off | tools whose correctness needs unrestricted fs |
| `none` | open | off | off | emergency escape hatch; rlimits only |

CLI: `--sandbox <profile>` on any RAPTOR command that honours it.

**Audit mode** is engaged orthogonally via `--audit` (and optionally
`--audit-verbose` for strace-style output). It composes with any profile
that has enforcement layers — i.e., `full` or `debug`. Combinations:

| Invocation | Effect |
|---|---|
| `--sandbox full` (default) | full enforcement |
| `--sandbox full --audit` | full layout, but proxy gate logs-and-allows + tracer logs would-be-blocked syscalls + filtered fs/connect tracing |
| `--sandbox full --audit --audit-verbose` | same as above but tracer logs EVERY traced syscall (strace-style diagnosis) |
| `--sandbox debug --audit` | gdb-friendly seccomp + audit signal — operators running `/crash-analysis` can also see what enforcement would have blocked |
| `--sandbox network-only --audit` | only the egress-proxy gate audits (other layers off). Coherent but most layers no-op |
| `--sandbox none --audit` | **error** — incoherent (nothing to audit against) |
| `--audit-verbose` without `--audit` | **error** — audit-verbose only controls tracer output |

### Audit mode in detail

`--audit` (composed with any compatible profile) runs a workflow to
completion AND records what enforcement WOULD have blocked. It's the
soft-default fallback for the case where `full` is too strict for
the workload but operators still want visibility into the policy
violations — far better than reaching for `--sandbox none` (which
loses all observability).

Programmatic equivalent: `sandbox(profile=..., audit=True)` or
`run(..., audit=True)`. The CLI flag composes with any profile
automatically.

Three layers, audit-mode each:

| Layer | Mechanism | Behaviour |
|---|---|---|
| Network (egress proxy) — **only when `use_egress_proxy=True`** | hostname allowlist gate emits `would_deny_host` event AND records to `sandbox-summary.json`, then permits the CONNECT | resolved-IP block (DNS-rebinding defense) stays enforcing — purely-attack pattern, no legitimate-workflow false positives. Without the proxy, the namespace network block applies normally and there's nothing to audit-log. |
| Syscalls (seccomp) | swaps deny action from `SCMP_ACT_ERRNO(EPERM)` to `SCMP_ACT_TRACE`; tracer logs each blocked syscall + resumes | the existing blocklist (ptrace, bpf, io_uring, etc.) is observed instead of EPERM'd |
| Filesystem (`open` / `openat`) | tracer derefs path arg, resolves relative paths via `/proc/<pid>/cwd` and `/proc/<pid>/fd/<dirfd>`, matches against the Landlock allowlist | filtered mode logs only paths that would have been blocked; verbose mode logs every traced open. Symlink-following diverges from real Landlock (we don't readlink in the tracer) so a small number of edge cases over-report. |
| Network (`connect` syscall) | tracer decodes sockaddr (AF_INET / AF_INET6) to `ip:port`, compares port against `allowed_tcp_ports` (typically the egress-proxy port) | filtered mode logs only would-be-blocked ports; verbose mode logs every connect attempt. Distinct from the egress-proxy row above — this catches direct `connect()` syscalls that don't go through the proxy. |

The tracer is a Python subprocess (`core.sandbox.tracer`) running on
the same host. It attaches to the target via `PTRACE_SEIZE` with
`TRACEFORK | TRACEVFORK | TRACECLONE` so multi-process workloads
(`make -j N`) audit every subprocess. `PTRACE_O_EXITKILL` ensures
that if the tracer dies, the kernel cascades `SIGKILL` to all
tracees rather than letting them `SIGSYS`-die on the next traced
syscall.

Records merge into the same `sandbox-summary.json` that
`record_denial`'s `audit=True` entries write to — operators see one
unified view across all three layers.

**Degradation when ptrace is unavailable** (Yama scope 3, container
`--cap-drop SYS_PTRACE`, restrictive container seccomp):

- Network audit still works (no ptrace dependency).
- Syscall + filesystem audit silently degrade to enforcement (the
  `SCMP_ACT_TRACE` swap is skipped because TRACE without an attached
  tracer SIGSYS-kills the target).
- A one-time WARNING surfaces the degradation with workaround
  pointers (run outside container, set `kernel.yama.ptrace_scope=1`).

**Audit-coverage gaps (acknowledged):**

- File operations performed via `io_uring` SQEs (submission queue
  entries written to shared memory after `io_uring_setup`) bypass
  the syscall layer entirely and are invisible to seccomp tracing.
  Mitigation: every `io_uring_setup` audit record carries an
  explicit `note` field warning that subsequent ring operations
  by the same process are untraceable. RAPTOR's seccomp blocklist
  already disallows `io_uring_setup` under `full`/`debug` (so the
  ring never gets created in enforcement mode); under `--audit` it
  is logged-and-allowed but operators see the gap explicitly in
  the record.
- Anti-debug detectable via `/proc/self/status`'s `TracerPid`
  field, ptrace self-test, or syscall timing. Audit mode is for
  operator workflows (gcc, make, python, claude sub-agents) — none
  of which evade observation. Hiding ptrace presence from a
  hostile tracee requires kernel-level instrumentation (out of
  scope; see "Anti-debug surface" below).

`openat2(2)` (Linux 5.6+) IS in the trace set. The flags-bit
extraction reads the first 8 bytes of the `struct open_how`
pointer via `process_vm_readv` — the same plumbing used for path
strings. If the deref fails (bad pointer), the tracer
conservatively treats the call as write-intent so the record is
NOT silently dropped from filtered mode.

**Audit-record integrity.** When `audit_run_dir=` is supplied
explicitly (e.g. by `codeql/agent.py`, `query_runner.py`), the
audit JSONL lives in a directory that is NOT in `writable_paths`,
so the traced target cannot open it for append — a hostile target
cannot inject false records. When `audit_run_dir` is omitted and
the legacy `output=` fallback is used, the JSONL DOES live inside
the target's writable surface and a hostile target could append
garbage. Mitigations regardless of mode:

- `O_NOFOLLOW` defends against symlink swaps (target can't
  redirect the JSONL to a different file).
- Records are operator-visible signal, not authoritative truth.

**Recommendation:** for sandbox calls handling untrusted content
where audit signal must survive a hostile target, pass
`audit_run_dir=` explicitly to a directory the target cannot
write to. The kwarg also avoids the Landlock writable-path
restriction that comes with `output=`.

**Performance.** Audit mode adds:

- ~200 ms of fixed setup cost per sandbox call (tracer fork + execvpe
  + PTRACE_SEIZE + sync handshake + teardown)
- ~5 ms of per-traced-syscall overhead (kernel pauses tracee on
  SCMP_ACT_TRACE → context switch to tracer → register read → path
  resolution + allowlist check → PTRACE_CONT → context switch back)

Measured on a Python startup + short script benchmark on Ubuntu 24.04
/ Python 3.13: `--audit` ≈ `--audit --audit-verbose` ≈ 3.5x `--sandbox full`
alone. The per-call setup cost dominates short workloads.

Filtered (`--audit`) and unfiltered (`--audit --audit-verbose`) run at
essentially the same speed — the filter only saves the JSONL write
cost, not the per-syscall ptrace context switch. The OPERATOR-VISIBLE
difference is record volume (filtered: a handful, verbose: thousands)
not wall-clock time.

Use audit mode for diagnosis, not routine work. Drop `--audit` for
production scans (the profile alone runs at full speed).

**Disk usage cap.** Both filtered and verbose modes are routed
through `core.sandbox.audit_budget.AuditBudget` (default global
cap 10000, mirrors `core/sandbox/summary.py`'s `MAX_DENIALS_PER_RUN`).
Per record is bounded by `MAX_CMD_LEN = 2048` bytes after
truncation — upper bound on the JSONL is ≈ 20 MB. The budget also
enforces per-category sub-caps (file-write 3000, file-read-data
2000, etc.) and per-PID caps (5000) so one chatty source can't
squeeze out the others. Operators see `category_budget_exceeded`
and `pid_budget_exceeded` markers in the JSONL when caps fire, and
an `audit_summary` record at end-of-run with totals. Override the
global cap via `--audit-budget=N` (sub-caps scale proportionally).
See the "Audit budget" section below for the full mechanism.

**Anti-debug surface (acknowledged, acceptable).** Code in an
audited sandbox can detect tracing via `/proc/self/status`'s
`TracerPid` field, ptrace self-test, or syscall timing. Audit mode
is for operator workflows (gcc, make, python, claude sub-agents) —
none of which evade observation. RAPTOR is not a malware-analysis
sandbox; if that use case ever lands, anti-anti-debug is a separate
engineering effort.

### What audit-mode output looks like

After a `--audit` run completes, inspect the run's output directory.
There are three possible states; each one writes a different file (or
no file) so you can tell them apart at a glance:

**1. Audit ran and recorded events** — `sandbox-summary.json` is
present. Each entry includes an `audit: true` field so you can filter
"would-have-been-blocked" events from real enforcement events
(both can coexist — audit-mode keeps the network proxy in
log-and-allow but hard-fails on a real Landlock denial elsewhere):

```json
{
  "run_dir": "/path/to/run",
  "generated_at": "2026-04-27T15:00:00Z",
  "total_denials": 2,
  "by_type": {"network": 1, "seccomp": 1},
  "denials": [
    {"ts": "2026-04-27T15:00:01Z",
     "cmd": "claude --model gemini-2.5-pro",
     "returncode": 0, "type": "network",
     "host": "evil.example.com", "port": 443,
     "audit": true,
     "suggested_fix": "audit: outbound network to `evil.example.com` would be blocked under `--sandbox full`"},
    {"ts": "2026-04-27T15:00:03Z",
     "cmd": "make -j4",
     "returncode": 0, "type": "seccomp", "syscall": "ptrace",
     "audit": true,
     "suggested_fix": "syscall blocked by seccomp; use `--sandbox debug` (allows ptrace) or `--sandbox network-only`/`--sandbox none` (drops seccomp)"}
  ]
}
```

**2. Audit ran, no enforcement events** — no `sandbox-summary.json`
and no degraded marker. The workflow ran and nothing it did would
have been blocked. (This is success.)

**3. Audit was requested but didn't actually run** —
`sandbox-audit-degraded.json` is present. Most often: Ubuntu 24.04
default (`apparmor_restrict_unprivileged_userns=1`) blocks the
mount-ns path, which the tracer needs to attach. Network audit (b1)
still works, but syscall + filesystem audit (b2/b3) silently degrade
to enforcement.

```json
{
  "audit_requested": true,
  "audit_engaged": false,
  "degraded": true,
  "reason": "mount-ns / spawn-path unavailable; tracer cannot attach",
  "instructions": "set kernel.apparmor_restrict_unprivileged_userns=0 (Ubuntu 24.04+) and install the uidmap package; or rerun on a host where mount-ns is available.",
  "generated_at": "2026-04-27T15:00:00Z"
}
```

If you see this marker, follow the `instructions` field and rerun.
Without the marker, an empty result genuinely means "audit ran,
nothing would be blocked" — distinguishable from "audit didn't run".

## Configuration

All kwargs accepted by `sandbox()` and `run()` (and most by `run_untrusted()`):

| Kwarg | Default | Meaning |
|---|---|---|
| `target` | `None` | Path to attacker-derived content. Read-only inside sandbox; engages Landlock. |
| `output` | `None` | Scratch area. Writable inside sandbox; engages Landlock. |
| `block_network` | `False` | Unshare network namespace — no interfaces inside. |
| `allowed_tcp_ports` | `None` | Landlock TCP-connect allowlist (ABI v4+, kernel 6.7+). Mutually exclusive with `block_network=True`. |
| `limits` | built-in defaults | Resource caps: `memory_mb`, `max_file_mb`, `cpu_seconds`. |
| `profile` | `None` | Named profile (see table above). Overrides individual layer flags. |
| `disabled` | `False` | Shortcut for `profile='none'`. |
| `map_root` | `False` | Map caller UID to root inside namespace (for tools that check `getuid()==0`). |
| `use_egress_proxy` | `False` | Route outbound HTTPS through the RAPTOR proxy with a hostname allowlist. See [Egress proxy](#egress-proxy). |
| `proxy_hosts` | `None` | Hostname allowlist for the egress proxy. Required when `use_egress_proxy=True`. |
| `restrict_reads` | `False` (`True` in `run_untrusted`) | Flip Landlock to allowlist-only reads (blocks `$HOME`, custom paths, etc.). |
| `readable_paths` | `None` | Extra paths to add to the read allowlist. Ignored when `restrict_reads=False`. |
| `fake_home` | `False` (`True` in `run_untrusted`) | Override child `HOME` + `XDG_*_HOME` to `{output}/.home/`. Requires `output`. |
| `caller_label` | `None` | Short identifier stamped onto every proxy event emitted during this sandbox's lifetime. Lets you tell apart concurrent/sequential callers in `proxy-events.jsonl`. |
| `tool_paths` | `None` | Extra dirs to bind-mount into the mount-ns sandbox so a non-system tool's binary + dependencies are visible. Speculative — if mount-ns engages with the supplied bind set but the tool fails at exec (typical Python tool with native exec deps not in any reasonable bind set), the sandbox automatically retries via Landlock-only. Worst-case: same isolation as not passing `tool_paths` at all. Per-cmd cache prevents repeated retry overhead within a process. See [Mount-ns tool visibility](#mount-ns-tool-visibility) below. |
| `audit_run_dir` | `None` | Directory where audit JSONL lands when `--audit` is engaged. **Decoupled from `output=`** — passing this does NOT add the directory to Landlock `writable_paths`, so callers like `codeql analyze` (which legitimately writes to `~/.codeql`, the database dir, etc.) can collect audit signal without taking a writable-path restriction that would break the workflow. Falls back to `output=` when not supplied (preserves pre-existing behaviour). For untrusted-target audit, prefer `audit_run_dir=` over `output=` so a hostile target can't inject false records into the JSONL (the audit dir is unreachable from the target's writable surface). |

> **`env=` passthrough.** If you pass an explicit `env=` dict to `run()`, it
> is forwarded verbatim to the child — `RaptorConfig.get_safe_env()` is NOT
> applied (we log an INFO-level note when this happens). `env=None` or omitting
> `env=` engages the safe-env path. Callers opting into custom `env=` own the
> sanitisation of what they pass.

### Mount-ns tool visibility

The mount-ns sandbox bind-mounts a fixed set of system dirs (`/usr`,
`/lib`, `/lib64`, `/etc`, `/bin`, `/sbin`) plus `target`/`output`
plus a per-sandbox `/tmp` tmpfs. **Anything else is invisible inside
the sandbox** — invoking a tool at `~/.local/bin/X`, `/opt/homebrew/bin/X`,
or `~/bin/X` would otherwise produce ENOENT (subprocess exit 127)
with empty stderr.

Two mechanisms keep workflows running regardless of the tool's
install location:

**Auto-fallback (no caller cooperation needed).** If `cmd[0]`
resolves to a path outside the mount-ns bind tree, the sandbox skips
mount-ns and runs the call at Landlock-only isolation. The workflow
proceeds; isolation matches the Ubuntu-default posture (where
mount-ns never engages anyway because the apparmor sysctl gates
unprivileged user-ns). Logged at DEBUG.

**`tool_paths=` opt-in.** Callers that know their tool's install
layout pass `tool_paths=[<bin_dir>, <lib_dir>, ...]`. Those dirs are
bind-mounted read-only into the mount-ns sandbox so the tool is
visible. **Speculative**: if the bind set turns out insufficient
(mount-ns engages but the tool fails at exec — typical of Python
tools whose native exec deps live outside any reasonable bind set),
the sandbox automatically retries via Landlock-only. First failure
per binary fires one INFO log; subsequent calls hit a per-cmd cache
and skip the doomed mount-ns attempt directly.

When to use what:

- **Standalone binary in a system dir** (`/usr/local/bin/`): no
  action needed; mount-ns engages cleanly.
- **Standalone binary outside system dirs** (e.g. `/opt/foo/bin/foo`
  with all deps in `/opt/foo/`): pass `tool_paths=["/opt/foo"]`.
  Mount-ns engages with `/opt/foo` bind-mounted.
- **Self-contained distribution** (codeql ships at
  `~/.local/share/codeql/` with java/, lib/, packs/ siblings): pass
  `tool_paths=[<codeql_install_dir>]`. Mount-ns engages.
- **Python tools** (semgrep, etc.): pass `tool_paths=` covering the
  bin dir + Python stdlib dir. Often works; sometimes the tool also
  exec's native binaries from elsewhere — speculative retry catches
  it. Worst case: same as no `tool_paths` (Landlock-only).

The cache is per-process: a fresh RAPTOR invocation re-probes (so
operators changing their install layout don't see stale cache hits).

### Read restriction (`restrict_reads` + `fake_home`)

Under `run_untrusted()`, both default to `True`. This is the primary defence
against credential exfiltration:

- `restrict_reads=True` — Landlock blocks reads outside the system-dir
  allowlist (`/usr`, `/lib`, `/lib64`, `/etc`, `/proc`, `/sys`, `target`,
  `output`, `/tmp`, and curated `/dev` files). `$HOME` is **not** on the
  allowlist.
  - `/dev` is narrowed: `/dev/null`, `/dev/tty` (writable), plus `/dev/zero`,
    `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty` (readable). Does
    not include `/dev/shm`.
  - `/proc` is wholesale allowlisted, but cross-process
    `/proc/<host_pid>/environ` reads are still blocked: `restrict_reads=True`
    also triggers a PID-namespace unshare, and the kernel's per-ns `/proc`
    access check denies reads of any host-pid `/proc/<pid>/environ` even
    though `/proc` is visible. This stops a compromised child lifting
    `ANTHROPIC_API_KEY` and other credentials out of the parent RAPTOR
    process's environment when running in Landlock-only mode (no
    `block_network=True`, no mount-ns). The PID ns also hides host PIDs
    for `kill()` / `ptrace()`.
- `fake_home=True` — child's `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`,
  `XDG_DATA_HOME`, `XDG_STATE_HOME` all point at `{output}/.home/` — an
  empty directory created fresh per sandbox. Tools see no dotfiles.

Together they ensure:

- `cat ~/.ssh/id_rsa` → ENOENT (home is empty)
- `cat /home/user/.ssh/id_rsa` → EACCES (absolute path blocked by Landlock)
- `cat ~/.aws/credentials` → ENOENT
- `cat ~/.config/raptor/models.json` → ENOENT

If a tool genuinely needs a config file, pre-populate the fake home before
calling:

```python
import shutil, os

os.makedirs(f"{out}/.home", exist_ok=True)
shutil.copy(os.path.expanduser("~/.gitconfig"), f"{out}/.home/.gitconfig")
run_untrusted(["git", "...args..."], target=repo, output=out)
```

Or extend the read allowlist:

```python
run_untrusted(
    cmd, target=repo, output=out,
    readable_paths=["/opt/jdk", "/var/cache/debconf"],
)
```

## Egress proxy

An in-process HTTPS-CONNECT proxy lets callers allow a specific set of hostnames
while still blocking everything else. Use it when the tool needs one or two
API endpoints (e.g. Claude sub-agent, CodeQL pack download) but you don't want
to open the full network.

```python
from core.sandbox import run

run(
    ["claude", "..."],
    target=repo, output=out,
    use_egress_proxy=True,
    proxy_hosts=["api.anthropic.com"],
    caller_label="claude-sub-agent",
)
```

How it works:

- A daemon thread runs an asyncio HTTP-CONNECT proxy on a loopback port.
- Child env gets `HTTPS_PROXY` and `http_proxy` set to that port; most tools
  (curl, pip, Java/CodeQL) honour these.
- Landlock restricts TCP `connect()` to the proxy's port, so the child
  cannot bypass it.
- Seccomp blocks `AF_INET`/`AF_INET6` `SOCK_DGRAM`, closing the DNS-exfil
  path.
- The proxy rejects any `CONNECT` to a hostname not on the allowlist.
- Resolved IPs are screened — loopback, private, link-local, multicast,
  reserved, and unspecified addresses are rejected even if the hostname
  was on the allowlist. (When an upstream HTTPS proxy is configured, IP
  screening is skipped because the upstream handles DNS.)

Multiple callers share one proxy singleton; their hostname allowlists are
union'd. Event observability is **per-run**, not shared: each `run()` call
(whether inside a `with sandbox()` block or via the top-level `run()`)
calls `register_sandbox(caller_label)` before spawning the subprocess,
gets a token, and the proxy fans every event generated during that
subprocess into the token's own buffer. On subprocess exit the sandbox
calls `unregister_sandbox(token)` to drain and stamp the events with
`caller_label`. Concurrent sandboxes therefore each get the full event
stream for their lifetime — one noisy caller can't mask another's events.

For a `with sandbox(...)` block with multiple `run()` calls, each
individual `result.sandbox_info["proxy_events"]` holds that specific
subprocess's slice. The **cumulative** view across every run in the
block is exposed as `run.events` — a live list appended to on each
inner `run()` call:

```python
with sandbox(use_egress_proxy=True, proxy_hosts=["api.example.com"]) as run:
    run(["curl", "https://api.example.com/a"])
    run(["curl", "https://api.example.com/b"])
    print(run.events)  # combined list covering both calls
```

### Upstream proxy support

If `HTTPS_PROXY` is set in the parent environment (e.g. corporate proxy), the
RAPTOR proxy forwards its `CONNECT` tunnels through that upstream. `NO_PROXY` /
`no_proxy` are honoured for the upstream decision. This is transparent to
callers.

## Observability

`sandbox_info` is attached to each `run()` return value and captures what
actually happened:

```python
from core.sandbox import sandbox

with sandbox(target=repo, output=out, use_egress_proxy=True,
             proxy_hosts=["api.anthropic.com"]) as run:
    result = run(cmd)
    info = result.sandbox_info

    # Keys are populated on demand — check with .get():
    print(info.get("crashed"), info.get("signal"))    # termination reason
    print(info.get("sanitizer"))                       # asan/ubsan/msan/tsan
    print(info.get("evidence"))                        # factual summary string
    print(info.get("blocked"))                         # sandbox-enforcement events
    print(info.get("proxy_events"))                    # list of connect attempts
```

### Proxy events

When `use_egress_proxy=True`, every CONNECT attempt is recorded:

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
`upstream_failed`, `timed_out`, `bad_request`, `handler_error`. `t` is
`time.monotonic()` seconds (monotonic across clock jumps, not wall time).
`caller` is added from `caller_label=` when set.

Events are also persisted to `{output}/proxy-events.jsonl` when `output` is
set — useful for post-run auditing. Each sandbox's buffer grows independently
for its lifetime (no fixed cap, no ring-buffer eviction); the buffer is
discarded when the sandbox context exits.

### Per-run denial summary

For commands that go through the lifecycle helpers (`core.run.metadata.start_run`
/ `complete_run` / `fail_run` / `cancel_run` — i.e., everything driven by
`/scan`, `/agentic`, `/codeql`, `/validate`, `/understand`, `/fuzz`, etc.), every
sandbox enforcement event seen during the run is aggregated into
`{run_dir}/sandbox-summary.json` at run-end.

Format:

```json
{
  "run_dir": "/path/to/run",
  "generated_at": "2026-04-27T15:00:00Z",
  "total_denials": 3,
  "by_type": {"network": 1, "write": 1, "seccomp": 1},
  "denials": [
    {"ts": "...", "cmd": "git clone evil.com",
     "returncode": 1, "type": "network",
     "suggested_fix": "outbound network blocked; use `--sandbox none` to allow network (or accept the block)"},
    {"ts": "...", "cmd": "tool /etc/blocked",
     "returncode": 1, "type": "write", "path": "/etc/blocked",
     "suggested_fix": "write outside allowed paths blocked to `/etc/blocked`; use `--sandbox network-only` or `--sandbox none` to drop Landlock (or move write into target dir)"},
    {"ts": "...", "cmd": "...",
     "returncode": 137, "type": "seccomp", "profile": "full",
     "suggested_fix": "syscall blocked by seccomp; use `--sandbox debug` (allows ptrace) or `--sandbox network-only`/`--sandbox none` (drops seccomp)"}
  ]
}
```

`suggested_fix` references only the operator-facing CLI flags exposed by
`add_cli_args` — `--sandbox {full,debug,network-only,none}`. Per-host or
per-path overrides exist as sandbox API kwargs (`proxy_hosts`,
`writable_paths`, `readable_paths`) but aren't exposed at the CLI level,
so suggestions don't mention them. Generated regardless of profile, so
even `--sandbox full` runs produce a summary.

**Recovery from non-clean exits.** If a run dies before its lifecycle
hook fires (hard kill, SIGKILL, OOM), the intermediate
`.sandbox-denials.jsonl` is left on disk and `sandbox-summary.json`
isn't written. Two paths recover it:

1. **Automatic** — the next time the same Claude Code session re-runs the
   same command type (the Esc-then-retry pattern), `start_run`'s
   `_cleanup_abandoned` sees the prior run still at `status=running`,
   marks it `failed`, and `fail_run` routes through the standard
   summary-finalize path. No operator action needed.

2. **Manual** — for cases the auto-recovery doesn't cover (different
   session, different command, host reboot, deliberate cleanup):

   ```bash
   # Single run.
   libexec/raptor-sandbox-summary <run_dir>

   # All stranded runs under a project dir at once.
   libexec/raptor-sandbox-summary --sweep <project_dir>
   ```

   Sweep mode iterates direct subdirectories, finalizes each one that
   still has a `.sandbox-denials.jsonl`, and skips the rest (no JSONL
   means either nothing was blocked or the summary is already written).

### Crash signals across the pid-ns boundary

`unshare --pid --fork` makes the forked child pid-1 of the new pid-ns.
Linux's pid-ns policy drops signals sent to pid-1 via `raise()` /
`kill(self, ...)` unless the process has installed a handler (see
`man 7 pid_namespaces`). If the target runs directly as pid-1, a
self-signalled crash — `abort()`, explicit `raise(SIGFPE)` — exits
`rc=0` and the sandbox sees a clean return where the target actually
crashed. Nested-ns environments (Docker-in-CI, systemd-nspawn) can
extend the filter to synchronous CPU exceptions too in some kernel
combinations.

The subprocess-path sandbox interposes `libexec/raptor-pid1-shim` so
the target runs as **pid-3** of the new pid-ns, not pid-1:

- shim (`/usr/bin/python3 -I`, pid-1) — reaps, forwards termination
  signals (`SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT`) to the target,
  mirrors exit status.
- intermediate (pid-2) — exists only to escape process-group
  leadership so the grandchild can `setsid()`.
- target (pid-3) — executes the caller's command, session leader,
  no controlling tty (so `open("/dev/tty")` returns ENXIO).

Because the shim is itself pid-1 it can't `raise()` the target's
signal on itself either, so signal death is encoded using the
standard unix `128+sig` exit-code convention. `observe._interpret_result`
decodes both `rc<0` (direct-child signal death) and `128<rc<128+NSIG`
(shim-mirrored signal death) to the same `sandbox_info["crashed"] = True`
state, so downstream consumers don't need to know which path fired.

Side-effect of the `-I` shebang on the shim interpreter: `PYTHONPATH`,
`PYTHONHOME`, and `PYTHONSTARTUP` in the child env are ignored at
interpreter startup, blocking a `sitecustomize.py` injection surface
should a caller-supplied `env=` pass those names through (the default
`get_safe_env()` strips them already — `-I` is belt-and-braces for
callers that supply their own env).

The mount-ns path (`core/sandbox/_spawn.py`) handles pid-ns setup via
its own `os.fork()` after `unshare(NEWPID)`, so the grandchild target
is pid-2 of the new ns and this shim isn't required there.
## Toolchain env for builds

The sandbox's `get_safe_env()` keeps a tight allowlist and deliberately
strips language-specific vars like `JAVA_HOME`, `GOROOT`, `DOTNET_ROOT`,
`RUSTUP_HOME` — adding them globally would broaden exposure for every
non-that-language caller. Instead, each build-system entry in
`packages/codeql/build_detector.BUILD_SYSTEMS` declares an
`env_detect` list, and `core/build/toolchain.py` auto-resolves those
vars from filesystem layout (e.g. `/usr/lib/jvm/default-java`, or
`readlink -f $(which java)`) at build time.

Scope: detected values land in the build subprocess's env ONLY —
scanners, LLM sub-agents, the proxy thread, and other sandbox calls
in the same context do not see them. See `~/design/env-handling.md`
for the full design and deferred items (user-provided build env,
target-runtime env, macOS detector paths).

If the build tool still fails with "JDK not found" or similar:
install the toolchain into a standard location, or expand the
detector fallback chain in `core/build/toolchain.py` for your distro.

## Troubleshooting

### "Mount namespace unavailable" on Ubuntu 24.04

Ubuntu 24.04 ships with an AppArmor sysctl that blocks unprivileged
user-namespace mount operations. The sandbox still applies Landlock, seccomp,
network/PID/IPC namespaces, and rlimits — but it can't provide read-only bind
mounts for `target`, `output`, or a fresh `/tmp`.

Both prerequisites must be met to enable mount-ns:

```bash
# 1. Allow unprivileged user namespaces (no reboot needed)
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# 2. Install newuidmap/newgidmap (setuid-root helpers that set up
#    the uid_map — direct /proc/self/uid_map writes fail EPERM for
#    unprivileged callers)
sudo apt install uidmap
```

The probe reports whichever prerequisite is missing. With both in
place, mount-ns engages automatically on the next sandbox() call — no
code changes, no profile flag. Without either, the sandbox silently
falls back to Landlock-only (writes restricted, reads wide by default
plus optional `restrict_reads=True`). Landlock alone already covers the
main threat model (no writes outside `output`, no reads of credentials
under `restrict_reads`); mount-ns adds per-sandbox `/tmp`, invisible
host paths outside the bind-mounts, and stronger `/dev/shm` isolation.

### A target binary fails with EACCES reading `/home/<user>/...`

Tools that hardcode absolute paths under `/home/<user>/` (not `$HOME`) will
hit the Landlock read-restriction even under `fake_home=True`. Either:

- add the specific path to `readable_paths=[...]`
- pre-populate the fake home and let the tool resolve via `$HOME`
- run under `sandbox()` with `restrict_reads=False` if the tool is trusted

### Shell scripts fail on `>/dev/null 2>&1`

`/dev/null` writes are permitted by a narrow Landlock rule. If you see EACCES
on `/dev/null`, you're likely running on a kernel without Landlock ABI v3
(TRUNCATE) — the probe will warn. Upgrade to 5.19+.

### Rust `cargo build` fails at the linker stage

`std::process::Command` in Rust uses `socketpair(AF_UNIX, ...)` for its internal
error-reporting channel. The sandbox permits this (explicit seccomp allow).
If you see EPERM on `socketpair` itself, you're on a seccomp profile that does
not include the sandbox package's built-in allowlist — check for a custom
`seccomp` override.

### CodeQL "Failed to download pack"

The egress proxy allowlist needs the full set of GHCR hosts. Use:

```python
proxy_hosts=[
    "ghcr.io",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "pkg-containers.githubusercontent.com",
]
```

## Integrity guard

The sandbox includes a runtime self-test on first use — it forks a child,
installs Landlock with `WRITE_FILE` and `READ_FILE` restrictions, and verifies
both are actually enforced. If the UAPI constants ever drift (kernel header
changes, version mismatch), this test fails loudly instead of silently granting
all access.

A static UAPI regression test
(`test_e2e_sandbox.py::TestE2ELandlockBitValues::test_access_bits_match_uapi`)
pins the bit values against `/usr/include/linux/landlock.h`.

## Module layout

```
core/sandbox/
├── __init__.py        # public API + threat-model docstring
├── context.py         # sandbox(), run(), run_trusted(), run_untrusted()
├── profiles.py        # named profile definitions
├── cli.py             # --sandbox / --no-sandbox argparse integration
├── probes.py          # per-layer availability detection
├── _spawn.py          # Linux: fork+newuidmap+pivot_root+Landlock+seccomp
├── mount_ns.py        # Linux: ctypes mount() / pivot_root() for _spawn
├── mount.py           # Linux: legacy shell-script mount builder
├── landlock.py        # Linux: Landlock ABI + rule construction
├── seccomp.py         # Linux: seccomp-bpf syscall filters
├── preexec.py         # POSIX: preexec_fn composition (rlimits)
├── proxy.py           # cross-platform: HTTPS-CONNECT egress proxy
├── observe.py         # cross-platform: sandbox_info attachment
├── state.py           # cross-platform: singletons + cached state
├── _macos_spawn.py    # macOS: sandbox-exec wrapper
├── seatbelt.py        # macOS: SBPL profile generator
└── seatbelt_audit.py  # macOS: `log stream` capture + JSONL append
```

See the module docstring in `core/sandbox/__init__.py` for the current
threat-model statement — what the sandbox does and does not protect against.

## macOS backend

On Darwin, the sandbox routes through `core.sandbox._macos_spawn`
instead of the Linux `_spawn.run_sandboxed()`. The kwarg surface is
identical — callers don't need to switch on platform — but the
underlying mechanism is `sandbox-exec(1)` + the kernel `Sandbox.kext`
applying an SBPL (Sandbox Profile Language) profile.

### What works the same

- `sandbox()`, `run()`, `run_trusted()`, `run_untrusted()` — same
  context-manager + helper surface.
- `block_network=True`, `allowed_tcp_ports=`, `use_egress_proxy=`,
  `proxy_hosts=` — translated to SBPL `(deny network*)` / `(allow
  network-outbound (remote tcp ...))` / loopback proxy port allow.
- `target=`, `output=`, `writable_paths=` — translated to SBPL
  `(deny file-write* (require-not (subpath ...)))`. Paths are
  realpath-canonicalised because SBPL's `(subpath ...)` matches the
  canonical resolved path (macOS has pervasive symlinks like `/var
  → /private/var`).
- `restrict_reads=True`, `readable_paths=` — translated to SBPL
  `(deny file-read* (require-not ...))` with the same system-dirs
  allowlist (`/usr`, `/System`, `/Library/Frameworks`, `/private/etc`,
  `/dev`).
- `fake_home=True` — env-side; sets `HOME` and `XDG_*_HOME` to the
  per-sandbox `{output}/.home/`. Same env-mutation as Linux.
- `audit=True` / `--audit` CLI flag — replaces the file-write deny
  with `(allow file-write* (with report))`. The kernel emits a
  Sandbox.kext log entry for each write; `seatbelt_audit.LogStreamer`
  reads `log stream` ndjson output, parses with the spike-validated
  regex, and appends records to `<run>/.sandbox-denials.jsonl`
  matching the Linux ptrace-tracer schema. `summarize_and_write`
  works unchanged.
- `limits=` — POSIX setrlimit via the same preexec_fn pattern.
- Sandbox-summary aggregation (`summarize_and_write`,
  `record_audit_degraded`, `proxy-events.jsonl`) — identical
  cross-platform.

### What's different (platform limits)

| Linux feature                | macOS status   | Why / mitigation                                               |
| ---------------------------- | -------------- | -------------------------------------------------------------- |
| PID namespace                | ⚠ absent       | No unprivileged equivalent on macOS. Host PIDs visible.        |
| Mount namespace + pivot_root | ⚠ absent       | `restrict_reads=True` is the substitute (read-deny via SBPL).  |
| `RLIMIT_NPROC` per-namespace | weaker         | macOS rlimit is per-UID host-wide. Lower the limit on Darwin.  |
| `seccomp_profile=full`       | partial        | Mapped to `(deny process-info* (target others))` — coarse.     |
| `audit_verbose` (per-syscall)| partial        | SBPL `(allow X (with report))` for an extended category set    |
|                              |                | (file-read*, mach-lookup, process-exec*, process-fork, signal, |
|                              |                | iokit-open, sysctl-read, process-info*). Coarser than seccomp's|
|                              |                | per-syscall trace and no argv, but operationally similar.      |
| `--audit-budget=N`           | full           | Same `audit_budget.AuditBudget` module on both backends —      |
|                              |                | token-bucket + per-category + per-PID + 1-in-N sampling.       |
| `map_root` (UID re-mapping)  | ⚠ absent       | macOS sandbox-exec keeps caller UID.                           |
| `--sandbox debug` (lldb)     | full           | Same intent as Linux: full enforcement EXCEPT keep debugger    |
|                              |                | introspection unrestricted. macOS skips the process-info-*     |
|                              |                | denies under debug so lldb / sample / dtrace can attach.       |

### macOS-specific operator notes

- **First-run cost**: `check_seatbelt_available()` invokes
  `sandbox-exec` with a minimal `(allow default)` profile against
  `/usr/bin/true` once per process to verify the kernel sandbox is
  functional. ~50ms.
- **No `(deny default)`**: pure deny-default profiles SIGABRT modern
  macOS binaries before dyld can load libSystem (spike-validated).
  We always use `(allow default)` + targeted denies.
- **Default exception list**: `/private/tmp` is always added to the
  write-allowlist exception so standard `tempfile.mkstemp()` works.
  This matches Linux's default `/tmp` writable.
- **Audit log latency**: kernel → log subsystem → `log stream`
  pipeline has ~tens-of-ms latency for steady-state and ~1.5s for a
  cold first event. `LogStreamer.stop(drain_timeout=1.5)` accounts
  for this; very short workloads may drop the last record.

### Audit budget (cross-platform)

Both backends route audit-record decisions through one shared module
(`core.sandbox.audit_budget.AuditBudget`). The budget composes four
mechanisms:

1. **Global cap** — `--audit-budget=N` (default 10000). Hard ceiling
   on records per run.
2. **Per-category sub-cap** — file-read-metadata (500), file-write
   (3000), mach-lookup (1000), etc. Stops one chatty category from
   squeezing important low-volume categories out of the global pool.
3. **Per-PID sub-cap** — default 5000. One spamming subprocess can't
   dominate the JSONL.
4. **Token-bucket refill** — burst capacity = cap, sustained rate =
   refill rate. Long-running workloads at low steady-state never trip.
5. **1-in-N post-cap sampling** — high-volume categories
   (file-read-metadata, file-read-data, process-info, iokit-open,
   sysctl-read) keep emitting a trickle even after their bucket
   empties so operators see "still happening".

Markers and a final summary record appear in the JSONL alongside
data records — operators see `category_budget_exceeded`,
`pid_budget_exceeded`, `category_budget_exceeded_sampling`, and
`audit_summary` types in the same file.

CLI:

```bash
raptor scan target/  --sandbox full --audit                    # default 10000
raptor scan target/  --sandbox full --audit --audit-budget 100 # quick diag
raptor scan target/  --sandbox full --audit --audit-verbose --audit-budget 50000  # long run
```

The defaults in `core.sandbox.audit_budget.DEFAULT_*` are tuned as
starting heuristics for typical `/scan` and `/agentic` workloads.
After first deployment, measure real workload distributions and
re-tune if entire categories disappear into the dropped bucket
(too tight) or the JSONL still bloats (too lax).

### Backend selection

`core/sandbox/context.py` dispatches at the spawn-eligibility check:

```
if sys.platform == "darwin":
    use_seatbelt = use_sandbox and check_seatbelt_available()
else:
    use_mount = use_sandbox and ... and check_mount_available()
```

`spawn_eligible` triggers either backend; the post-run aggregation
(proxy events, `_check_blocked` engagement booleans, sandbox-summary
JSONL) is platform-independent.

### Spike scripts

Phase 0 design spikes are in `scripts/macos_sandbox_spike{1,2,3,4}.py`
— each validates one assumption used by `seatbelt.py` /
`seatbelt_audit.py`. Re-run them on a new macOS major version to
confirm the SBPL idioms haven't drifted.
