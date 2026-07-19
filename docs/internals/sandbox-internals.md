# Sandbox Internals

Contributor-facing reference for the subprocess sandbox: the isolation-layer
composition, the pid-1 shim, the ptrace audit tracer, the token-bucket audit
budget, host-fingerprint spoofing, and the file-by-file module map. For the
operator surface — entry points, profiles, kwargs, troubleshooting — read
[`../sandbox.md`](../sandbox.md) first. The canonical threat-model statement
lives in the module docstring of `core/sandbox/__init__.py`.

> Module inventory verified against `core/sandbox/` in the working tree as of
> 2026-07-18. Regenerate (`ls core/sandbox/`) if files are added, removed, or
> renamed — treat this as a snapshot, not a contract.

---

## Isolation layers

The Linux sandbox composes up to six layers. Each falls back gracefully if the
kernel doesn't support it — RAPTOR logs a warning once per layer per process.
Nothing silently downgrades to "no isolation".

1. **User namespace** (`unshare --user`) — unprivileged root-mapping
   foundation. Uses `newuidmap`/`newgidmap` (the `uidmap` package) for the
   uid/gid map because direct `/proc/self/uid_map` writes fail EPERM for
   unprivileged callers.
2. **Network namespace** (`--net`) — the sandboxed process sees no interfaces.
   Active under `full`, `strict`, `debug`, `network-only`.
3. **PID namespace** (`--pid --fork`) — hides host PIDs; also triggered by
   `restrict_reads=True` so cross-process `/proc/<host_pid>/environ` reads are
   denied.
4. **IPC namespace** (`--ipc`) — isolates SysV shm/sem/message queues.
5. **Mount namespace** (`pivot_root` onto a fresh tmpfs) — per-sandbox `/tmp`
   and `/run`, host system dirs (`/usr`, `/lib`, `/etc`, …) bind-mounted
   read-only, caller's `target`/`output` bind-mounted at their ORIGINAL
   absolute paths (no argv rewriting). Mount syscalls are driven from Python
   via ctypes (`mount_ns.py`) BEFORE Landlock install — otherwise Landlock (on
   kernel 6.15+) would block the mount topology changes. **Disabled on Ubuntu
   24.04 by default** (AppArmor sysctl gates unprivileged user-ns).
6. **Landlock + seccomp-bpf + rlimits** — always applied when available, even
   when namespaces fall back.

**Landlock is fail-closed.** If `landlock_restrict_self()` errors inside
`preexec_fn` (kernel drift, ABI mismatch, EINVAL on a rule), the child calls
`os._exit(126)` rather than continue unsandboxed. The parent sees a non-zero
`returncode` plus a `RAPTOR: Landlock …` stderr line naming the failed step.

Two Linux spawn paths exist:

- **Mount-ns path** (`_spawn.py`) — the load-bearing path when mount-ns is
  available: `fork` + `newuidmap` + `pivot_root` + Landlock + seccomp. Handles
  pid-ns setup via its own `os.fork()` after `unshare(NEWPID)`, so the
  grandchild target is pid-2 of the new ns.
- **Landlock-only path** (`_landlock_audit.py`) — the fallback when mount-ns is
  unavailable (Ubuntu-default). Applies Landlock in the child via `preexec_fn`
  with no namespace pivot; carries the audit/observe tracer support.

## The pid-1 shim

`unshare --pid --fork` makes the forked child pid-1 of the new pid-ns. Linux's
pid-ns policy drops signals sent to pid-1 via `raise()` / `kill(self, …)`
unless a handler is installed (`man 7 pid_namespaces`). If the target ran
directly as pid-1, a self-signalled crash — `abort()`, `raise(SIGFPE)` — would
exit `rc=0` and the sandbox would see a clean return where the target actually
crashed.

The subprocess-path sandbox interposes `libexec/raptor-pid1-shim` so the target
runs as **pid-3**, not pid-1:

- **shim** (`/usr/bin/python3 -I`, pid-1) — reaps, forwards termination signals
  (`SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT`) to the target, mirrors exit status.
- **intermediate** (pid-2) — exists only to escape process-group leadership so
  the grandchild can `setsid()`.
- **target** (pid-3) — executes the caller's command, session leader, no
  controlling tty (so `open("/dev/tty")` returns ENXIO — defeats the passive
  keystroke-sniffer surface).

Because the shim is pid-1 it can't `raise()` the target's signal on itself
either, so signal death is encoded using the unix `128+sig` convention.
`observe._interpret_result` decodes both `rc<0` (direct-child signal death) and
`128<rc<128+NSIG` (shim-mirrored signal death) to the same
`sandbox_info["crashed"] = True` state, so downstream consumers don't need to
know which path fired.

Side-effect of the `-I` shebang: `PYTHONPATH`, `PYTHONHOME`, and
`PYTHONSTARTUP` in the child env are ignored at interpreter startup, blocking a
`sitecustomize.py` injection surface should a caller-supplied `env=` pass those
through (`get_safe_env()` strips them already — `-I` is belt-and-braces).

The mount-ns path (`_spawn.py`) does its own pid-ns setup and does not need the
shim.

## Audit-mode tracer (ptrace)

`--audit` runs a workflow to completion while recording what enforcement WOULD
have blocked. The tracer (`tracer.py`) is a Python subprocess on the same host.
It attaches to the target via `PTRACE_SEIZE` with `TRACEFORK | TRACEVFORK |
TRACECLONE` so multi-process workloads (`make -j N`) audit every subprocess.
`PTRACE_O_EXITKILL` cascades `SIGKILL` to all tracees if the tracer dies, rather
than letting them `SIGSYS`-die on the next traced syscall. Availability is
gated by `ptrace_probe.py` ("can this process ptrace its own children?").

Three layers, audit-mode each:

| Layer | Mechanism | Behaviour |
|---|---|---|
| Network (egress proxy) — only when `use_egress_proxy=True` | hostname-allowlist gate emits `would_deny_host` + records to `sandbox-summary.json`, then permits the CONNECT | resolved-IP block (DNS-rebinding defence) stays enforcing. Without the proxy, the namespace network block applies normally and there's nothing to audit-log. |
| Syscalls (seccomp) | swaps deny action from `SCMP_ACT_ERRNO(EPERM)` to `SCMP_ACT_TRACE`; tracer logs each blocked syscall + resumes | the blocklist (ptrace, bpf, io_uring, …) is observed instead of EPERM'd |
| Filesystem (`open`/`openat`/`openat2`) | tracer derefs the path arg, resolves relative paths via `/proc/<pid>/cwd` and `/proc/<pid>/fd/<dirfd>`, matches against the Landlock allowlist | filtered mode logs only would-be-blocked paths; verbose mode logs every traced open |
| Network (`connect` syscall) | tracer decodes sockaddr (AF_INET/AF_INET6) to `ip:port`, compares port against `allowed_tcp_ports` | catches direct `connect()` syscalls that don't go through the proxy |

`openat2(2)` (Linux 5.6+) is in the trace set; the flags bit is read from the
first 8 bytes of the `struct open_how` pointer via `process_vm_readv`. If the
deref fails, the tracer conservatively treats the call as write-intent so the
record is not silently dropped.

**Degradation when ptrace is unavailable** (Yama scope 3, container `--cap-drop
SYS_PTRACE`, restrictive container seccomp): network audit still works (no
ptrace dependency); syscall + filesystem audit silently degrade to enforcement
(the `SCMP_ACT_TRACE` swap is skipped because TRACE without an attached tracer
SIGSYS-kills the target). A one-time WARNING surfaces the degradation with
workaround pointers, and `sandbox-audit-degraded.json` is written.

**Coverage gaps (acknowledged):**

- File ops via `io_uring` SQEs bypass the syscall layer entirely — invisible to
  seccomp tracing. Every `io_uring_setup` audit record carries a `note` field
  warning subsequent ring operations are untraceable. The seccomp blocklist
  disallows `io_uring_setup` under `full`/`debug`, so the ring never gets
  created in enforcement mode; under `--audit` it's logged-and-allowed but the
  gap is explicit in the record.
- **Anti-debug**: code in an audited sandbox can detect tracing via
  `/proc/self/status`'s `TracerPid`, a ptrace self-test, or syscall timing.
  Audit mode targets operator workflows (gcc, make, python, claude sub-agents),
  none of which evade observation. RAPTOR is not a malware-analysis sandbox;
  anti-anti-debug is a separate effort if that use case ever lands.

**Audit-record integrity.** When `audit_run_dir=` is supplied explicitly, the
JSONL lives in a directory NOT in `writable_paths`, so a hostile target cannot
open it for append. When omitted and the legacy `output=` fallback is used, the
JSONL lives inside the target's writable surface and a hostile target could
append garbage. Mitigations regardless of mode: `O_NOFOLLOW` defends against
symlink swaps; records are operator-visible signal, not authoritative truth.
For untrusted-target audit, always pass `audit_run_dir=`.

**Performance.** Audit adds ~200 ms fixed setup per sandbox call (tracer fork +
execvpe + `PTRACE_SEIZE` + sync handshake + teardown) and ~5 ms per-traced-
syscall (kernel pauses tracee on `SCMP_ACT_TRACE` → context switch to tracer →
register read → path resolution + allowlist check → `PTRACE_CONT` → switch
back). Filtered (`--audit`) and verbose (`--audit --audit-verbose`) run at
essentially the same wall-clock — the filter only saves the JSONL write, not
the per-syscall context switch; the operator-visible difference is record
volume (a handful vs thousands). Measured ≈ 3.5x `--sandbox full` on a Python
startup benchmark (Ubuntu 24.04 / Python 3.13).

Observe mode (`sandbox(observe=True)`, `raptor-sandbox-observe`) is
"audit + audit_verbose + separate JSONL + stat-family trace extension" with a
128-bit per-run nonce threaded into the audit-config tempfile so a target binary
can't spoof records. Extraction lives in `observe_profile.py`; merge into a
`/understand` context map in `observe_context_merge.py`.

## Audit budget (token bucket)

Both backends route audit-record decisions through one shared module
(`audit_budget.AuditBudget`). Five mechanisms compose:

1. **Global cap** — `--audit-budget=N` (default 10000). Hard ceiling per run.
   Upper clamp 10M (≈2GB JSONL) — anything past that fails loud as a likely
   operator typo.
2. **Per-category sub-cap** — file-read-metadata (500), file-write (3000),
   mach-lookup (1000), etc. Stops one chatty category squeezing out low-volume
   categories.
3. **Per-PID sub-cap** — default 5000. One spamming subprocess can't dominate
   the JSONL.
4. **Token-bucket refill** — burst capacity = cap, sustained rate = refill
   rate. Long-running low-steady-state workloads never trip.
5. **1-in-N post-cap sampling** — high-volume categories keep emitting a trickle
   after their bucket empties so operators see "still happening".

Markers and a final summary record appear inline in the JSONL:
`category_budget_exceeded`, `pid_budget_exceeded`,
`category_budget_exceeded_sampling`, `audit_summary`. Per-record size is bounded
by `MAX_CMD_LEN = 2048` after truncation. The `DEFAULT_*` values are tuned as
starting heuristics for typical `/scan`/`/agentic` workloads — re-tune after
measuring real workload distributions.

## Integrity guard

The sandbox runs a self-test on first use: it forks a child, installs Landlock
with `WRITE_FILE` and `READ_FILE` restrictions, and verifies both are actually
enforced. If the UAPI constants ever drift (kernel-header changes, version
mismatch), this fails loudly instead of silently granting all access. A static
UAPI regression test
(`test_e2e_sandbox.py::TestE2ELandlockBitValues::test_access_bits_match_uapi`)
pins the bit values against `/usr/include/linux/landlock.h`.

## Host-fingerprint sanitisation

Opt-in via `sandbox(..., sanitise_host_fingerprint=True)` (`fingerprint.py`).
When engaged, the mount-ns child bind-mounts canonical files over the host's
identity surfaces and the spawn machinery sets a canonical UTS namespace +
`sched_setaffinity` mask. Persona: "boring Debian 12 cloud VM on QEMU/KVM with
Intel Xeon" — picked for hide-intent (most common Linux workload; sentinel-
looking values like a "sandbox" hostname or all-zero machine-id are avoided).

Spoofed: `/proc/cpuinfo` (N blocks, host flags preserved), `/proc/version`,
`/proc/cmdline`, `/proc/stat`, `/etc/os-release`, `/etc/machine-id`,
`/etc/hostname`, DMI `sys_vendor`/`product_name`, CPU online/possible masks,
`uname()` nodename/domainname, `sched_getaffinity`.

**Preserved** (capability surface, not identity): the `/proc/cpuinfo` `flags`
line (SMEP/SMAP detection, SIMD dispatch, ASAN shadow-mem), `uname()`
sysname/release/machine (kernel version + arch for exploit_feasibility and
shellcode dispatch), the mitigation sysctls
(`randomize_va_space`, `kptr_restrict`, `yama/ptrace_scope`, `mmap_min_addr`),
and `/proc/self/*` (maps, exe, status, auxv — ASAN, GDB, pwntools depend on
real values). `cpu_count=` sets the presented CPU count; `require_sanitisation`
raises instead of warning if the host can't provide the overlay.

## Toolchain env for builds

`get_safe_env()` keeps a tight allowlist and deliberately strips language-
specific vars (`JAVA_HOME`, `GOROOT`, `DOTNET_ROOT`, `RUSTUP_HOME`) — adding
them globally would broaden exposure for every non-that-language caller.
Instead, each build-system entry in
`packages/codeql/build_detector.BUILD_SYSTEMS` declares an `env_detect` list,
and `core/build/toolchain.py` auto-resolves those vars from filesystem layout
(e.g. `/usr/lib/jvm/default-java`, `readlink -f $(which java)`) at build time.
Detected values land in the build subprocess's env ONLY — scanners, LLM
sub-agents, the proxy thread, and other sandbox calls in the same context never
see them.

## Mount-ns tool visibility

The mount-ns sandbox bind-mounts a fixed set of system dirs (`/usr`, `/lib`,
`/lib64`, `/etc`, `/bin`, `/sbin`) plus `target`/`output` plus a per-sandbox
`/tmp` tmpfs. Anything else is invisible — invoking a tool at `~/.local/bin/X`
or `/opt/homebrew/bin/X` would otherwise ENOENT (exit 127) with empty stderr.
Two mechanisms keep workflows running:

- **Auto-fallback** (no caller cooperation) — if `cmd[0]` resolves outside the
  bind tree, the sandbox skips mount-ns and runs at Landlock-only isolation
  (the Ubuntu-default posture anyway). Logged at DEBUG.
- **`tool_paths=` opt-in** — callers that know their tool's layout pass
  `tool_paths=[<bin_dir>, <lib_dir>, …]`; those dirs are bind-mounted read-only.
  Speculative: if the bind set is insufficient (mount-ns engages but the tool
  fails at exec — typical of Python tools with native exec deps outside the
  bind set), the sandbox automatically retries via Landlock-only. First failure
  per binary fires one INFO log; subsequent calls hit a per-cmd cache and skip
  the doomed mount-ns attempt. Worst case: same isolation as no `tool_paths`.

**When to use what:**

- **Standalone binary in a system dir** (`/usr/local/bin/`) — nothing needed;
  mount-ns engages cleanly.
- **Standalone binary outside system dirs** (`/opt/foo/bin/foo`, deps in
  `/opt/foo/`) — pass `tool_paths=["/opt/foo"]`.
- **Self-contained distribution** (CodeQL at `~/.local/share/codeql/` with
  `java/`, `lib/`, `packs/` siblings) — pass `tool_paths=[<install_dir>]`.
- **Python tools** (semgrep, etc.) — pass `tool_paths=` covering the bin dir +
  Python stdlib dir; if the tool also exec's native binaries elsewhere the
  speculative retry catches it (worst case: Landlock-only).

The cache is per-process, so operators changing their install layout don't see
stale hits. `python_paths.py` discovers Python runtime paths for the `tool_paths`
allowlist when a sandbox call spawns an interpreter.

## Module layout

```
core/sandbox/
├── __init__.py               # public API + threat-model docstring
├── context.py                # sandbox(), run(), run_trusted(), run_untrusted(), run_untrusted_networked()
├── profiles.py               # the 7 named profiles + _SANDBOX_KWARGS frozenset
├── cli.py                    # --sandbox / --no-sandbox / --audit / --audit-verbose / --audit-budget argparse
├── state.py                  # shared mutable module state (CLI-forced profile, audit flags, singletons)
├── probes.py                 # per-layer availability detection
├── ptrace_probe.py           # "can this process ptrace its own children?" (audit b2/b3 gate)
├── errors.py                 # sandbox error types (dependency-free)
├── exit_codes.py             # documented fail-closed child exit codes
│
│  # Linux spawn + isolation
├── _spawn.py                 # mount-ns spawn: fork + newuidmap + pivot_root + Landlock + seccomp
├── _landlock_audit.py        # Landlock-only spawn variant (fallback) with audit/observe tracer
├── mount_ns.py               # ctypes mount()/pivot_root() run inside the forked child
├── mount.py                  # legacy shell-script mount builder
├── landlock.py               # Landlock ABI + rule construction
├── seccomp.py                # seccomp-bpf syscall filters
├── preexec.py                # POSIX preexec_fn composition (rlimits)
├── netns_coordinator.py      # paired-process isolation in a shared netns (target_run listeners)
│
│  # Egress proxy
├── proxy.py                  # HTTPS-CONNECT egress proxy (hostname allowlist + IP screening)
├── _proxy_bridge.py          # TCP↔Unix-socket relay inside the child's empty netns
│
│  # Audit / observe
├── tracer.py                 # ptrace tracer subprocess for --audit
├── audit_budget.py           # token-bucket + per-category + per-PID record budget (cross-platform)
├── summary.py                # sandbox-summary.json aggregation + suggested_fix
├── observe.py                # post-run result interpretation + enforcement detection
├── observe_profile.py        # observe-mode profile extraction from tracer JSONL
├── observe_context_merge.py  # merge an ObserveProfile into /understand context-map.json
├── observe_cli.py            # raptor-sandbox-observe entry point
│
│  # Misc
├── fingerprint.py            # host-fingerprint sanitisation overlay
├── calibrate.py              # generic sandbox-binary calibration (what a tool touches)
├── calibrate_cli.py          # calibration CLI
├── python_paths.py           # discover Python runtime paths for tool_paths allowlists
├── _fork_safe_warn.py        # fork-safe degraded-mode warning helper (logging is fork-unsafe)
│
│  # macOS
├── _macos_spawn.py           # sandbox-exec wrapper
├── seatbelt.py               # SBPL profile generator
├── seatbelt_audit.py         # `log stream` capture + JSONL append (LogStreamer)
│
├── helpers/                  # coordinator launcher (C source, AppArmor/SELinux policy, Makefile)
└── tests/                    # sandbox test suite (incl. E2E + UAPI regression)
```

## macOS backend internals

On Darwin, `context.py` dispatches to `_macos_spawn.run_sandboxed()` at the
spawn-eligibility check instead of the Linux `_spawn.run_sandboxed()`:

```python
if sys.platform == "darwin":
    use_seatbelt = use_sandbox and check_seatbelt_available()
else:
    use_mount = use_sandbox and ... and check_mount_available()
```

`spawn_eligible` triggers either backend; the post-run aggregation (proxy
events, `_check_blocked` engagement booleans, sandbox-summary JSONL) is
platform-independent. The mechanism is `sandbox-exec(1)` + the kernel
`Sandbox.kext` applying an SBPL profile generated by `seatbelt.py`; audit mode
uses `(allow file-write* (with report))` and `seatbelt_audit.LogStreamer` reads
`log stream` ndjson, parses with a spike-validated regex, and appends records
matching the Linux tracer schema. The kwarg surface and audit-budget module are
shared with Linux (see the operator page's macOS tables for the per-feature
parity/limits matrix).

Phase-0 design spikes live in `scripts/macos_sandbox_spike{1,2,3,4}.py` — each
validates one assumption used by `seatbelt.py`/`seatbelt_audit.py`. Re-run them
on a new macOS major version to confirm the SBPL idioms haven't drifted.
