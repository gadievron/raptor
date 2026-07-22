# Sandbox

RAPTOR sandboxes every subprocess that handles untrusted content --
LLM-generated PoCs, target build scripts, CodeQL queries, Semgrep,
[fuzz](fuzzing.md) targets, [Frida](frida.md) instrumentation helpers,
and anything whose arguments or input came from a repository under
analysis. The sandbox composes Linux kernel isolation primitives
(namespaces, Landlock, seccomp-bpf) into a layered defence that
degrades gracefully on hosts missing any single layer, while failing
loudly when no isolation can engage at all.

On macOS, the same API routes through `sandbox-exec(1)` and Seatbelt
profiles. See [Platform support](#platform-support) for the capability
comparison.

For how the sandbox fits into the broader RAPTOR pipeline, see the
[architecture overview](architecture.md). For CLI flag reference, see
[commands](commands.md).

---

## Quick start

```python
from core.sandbox import run_untrusted

# Run a compiled target binary built from an untrusted repo.
result = run_untrusted(
    [target_binary, "--flag", input_file],
    target=repo_path,          # bind-mounted / Landlock-allowed ro
    output=work_dir,            # writable scratch area
    limits={"memory_mb": 2048, "cpu_seconds": 30},
    capture_output=True,
)
```

What this gets you:

- Network blocked at the namespace level (no interfaces inside).
- Filesystem restricted to `target` (read-only), `output` (writable),
  `/tmp` (fresh tmpfs), and a curated system-directory read allowlist.
- `$HOME` redirected to an empty per-sandbox directory.
- Dangerous syscalls blocked: `io_uring`, `kcmp`, `pidfd_getfd`,
  `handle_at`, `TIOCSTI`/`TIOCCONS`, SysV IPC, `ptrace` (in `full`),
  `keyctl`, `bpf`, `userfaultfd`, `perf_event_open`, plus `socket()`
  for `AF_UNIX` / `AF_PACKET` / `AF_NETLINK` / `SOCK_RAW` (docker.sock
  escape, raw-packet sniffing).
- `RLIMIT_CORE = 0` (no core-dump exfiltration), memory/CPU caps, and
  a `prlimit --nproc=<limit>` wrapper inside the `unshare` chain so
  `RLIMIT_NPROC` counts against the namespace-local UID -- bounds fork
  bombs per sandbox.

---

## Entry points

| Entry point | Use when | Network | Landlock | Seccomp | Read restriction |
|---|---|---|---|---|---|
| `run_untrusted()` | Command or its input is attacker-derived | blocked (namespace) | enforced | full | `restrict_reads=True` by default |
| `run_untrusted_networked()` | Attacker-derived input but needs hostname-allowlisted HTTPS egress | egress proxy only | enforced | full | `restrict_reads=True` by default |
| `sandbox()` + `run()` | Fine-grained control (allowed TCP ports, egress proxy, custom paths) | configurable | configurable | configurable | `restrict_reads=False` by default |
| `run_trusted()` | RAPTOR chose the command AND its inputs; no untrusted content | open | off | off | off |
| `run()` (top-level) | One-shot convenience over `sandbox()` -- you know which kwargs you need | configurable | configurable | configurable | `restrict_reads=False` by default |

Rule of thumb: **default to `run_untrusted()`**. Downgrade to `sandbox()`
only when the tool genuinely needs something the untrusted defaults deny
(e.g. a CodeQL sub-agent that needs `api.anthropic.com` on port 443).
Downgrade to `run_trusted()` only when the full command line is
RAPTOR-owned and no attacker-derived bytes feed into it. Use
`run_untrusted_networked()` when an LLM-driven sub-agent or tool must
reach a known upstream API but is otherwise treated as adversarial.

### `run_untrusted()`

```python
def run_untrusted(
    cmd: List[str], *,
    target: str = None,
    output: str = None,
    limits: dict = None,
    restrict_reads: bool = True,
    readable_paths: list = None,
    writable_paths: list = None,
    fake_home: bool = True,
    **kwargs,
) -> subprocess.CompletedProcess
```

Always engages `profile='full'`: network blocked by namespace, Landlock
filesystem restriction (via `target`/`output`), resource rlimits. At
least one of `target` or `output` must be truthy so Landlock actually
engages. `block_network` and `allowed_tcp_ports` are deliberately not
accepted -- this function forces namespace-level network block. Callers
wanting a network allowlist must use `sandbox()` directly.

Defaults `stdin` to `subprocess.DEVNULL` and `start_new_session=True`
to prevent the sandboxed process from reading the operator's TTY.

Passes `strict_env=True` internally to strip dangerous environment
variables from any caller-supplied `env=` dict.

### `run_untrusted_networked()`

```python
def run_untrusted_networked(
    cmd: List[str], *,
    target: str = None,
    output: str = None,
    proxy_hosts: list,          # required -- egress allowlist
    limits: dict = None,
    restrict_reads: bool = True,
    readable_paths: list = None,
    writable_paths: list = None,
    fake_home: bool = False,
    **kwargs,
) -> subprocess.CompletedProcess
```

Variant of `run_untrusted()` that allows hostname-allowlisted HTTPS
egress instead of full network block. Enforces:

- `restrict_reads=True` -- kernel-level read allowlist; `$HOME` is denied.
- `use_egress_proxy=True` + `proxy_hosts=[...]` -- egress proxy with
  hostname allowlist.
- `allowed_tcp_ports=[443]` -- only HTTPS to the proxy.
- `block_network=False` -- the proxy must be reachable from inside
  the sandbox.
- `strict_env=True` -- strips dangerous env vars.

`proxy_hosts` is mandatory. Callers wanting unrestricted network should
use `sandbox()` directly.

### `run_trusted()`

```python
def run_trusted(cmd: List[str], **kwargs) -> subprocess.CompletedProcess
```

Applies `get_safe_env()` and resource rlimits but skips
namespace/Landlock isolation. Rejects any sandbox-level kwargs (raises
`TypeError`) to catch accidental misuse. Always runs with
`profile='none'`.

### `sandbox()` context manager

```python
@contextmanager
def sandbox(
    block_network=_UNSET, target=None, output=None,
    map_root=False, limits=None, allowed_tcp_ports=None,
    profile=None, disabled=False,
    use_egress_proxy=False, proxy_hosts=None,
    restrict_reads=False, readable_paths=None,
    caller_label=None, fake_home=False, tool_paths=None,
    audit=False, audit_verbose=False, audit_run_dir=None,
    observe=False, writable_paths=None,
    exclude_tmp_baseline=False,
    sanitise_host_fingerprint=False, cpu_count=None,
    require_sanitisation=False, etc_overlay=None,
)
```

Context manager yielding a `run()` callable. Each `run()` call inside
the context runs the target command with the isolation configured on the
context. Multiple `run()` calls share the same proxy instance and
cumulative event buffer.

```python
with sandbox(use_egress_proxy=True,
             proxy_hosts=["api.example.com"]) as run:
    run(["curl", "https://api.example.com/a"])
    run(["curl", "https://api.example.com/b"])
    print(run.events)  # combined list covering both calls
```

### `run()` (top-level convenience)

```python
def run(cmd: List[str], block_network=True, target=None, output=None,
        ..., **kwargs) -> subprocess.CompletedProcess
```

Creates a one-shot `sandbox()` context, forwards all kwargs, runs the
command, returns the result. Accepts the same kwargs as `sandbox()`.

---

## Isolation layers

The sandbox composes up to six layers. Each falls back gracefully if the
kernel does not support it -- RAPTOR logs a warning once per layer per
process.

1. **User namespace** (`unshare --user`) -- unprivileged root-mapping
   foundation.
2. **Network namespace** (`--net`) -- sandboxed process sees no
   interfaces. Active under `full`, `strict`, `debug`, `target_run`
   (when paired with the [netns coordinator](#netns-coordinator)),
   `network-only` profiles.
3. **PID namespace** (`--pid --fork`) -- hides host PIDs; target runs as
   PID 1 (or PID 3 behind the [pid1 shim](#crash-signal-handling)).
4. **IPC namespace** (`--ipc`) -- isolates SysV shm/sem/message queues.
5. **Mount namespace** (pivot_root onto a fresh tmpfs) -- per-sandbox
   `/tmp` and `/run`, host system dirs (`/usr`, `/lib`, `/etc` etc.)
   bind-mounted read-only, caller's `target` + `output` bind-mounted at
   their original absolute paths (no caller argv rewriting needed). Uses
   `newuidmap` (from the `uidmap` package) for the user-ns mapping and
   drives mount syscalls from Python via ctypes BEFORE Landlock install
   -- otherwise Landlock (on kernel 6.15+) would block the mount
   topology changes. **Disabled on Ubuntu 24.04 by default** (AppArmor
   sysctl gates unprivileged user-ns); see
   [Troubleshooting](#troubleshooting).
6. **Landlock + seccomp-bpf + rlimits** -- always applied when
   available, even when namespaces fall back.

On kernels that lack any particular layer, the sandbox proceeds with the
remaining ones and emits a one-time warning. Nothing silently downgrades
to "no isolation".

**Landlock is fail-closed.** If `landlock_restrict_self()` returns an
error inside `preexec_fn` (kernel drift, ABI mismatch, EINVAL on a
rule), the child calls `os._exit(126)` rather than continue unsandboxed.
The parent sees a non-zero `result.returncode` plus a `RAPTOR: Landlock
...` line on the child's stderr explaining which step failed.

---

## Profiles

Profiles bundle layer settings into a single name for CLI use.
All seven are defined in `core/sandbox/profiles.py` as immutable
`MappingProxyType` dicts.

| Profile | Network | Landlock | Seccomp | Notes |
|---|---|---|---|---|
| `full` | blocked | yes | full | Default for `run_untrusted()` and `sandbox()`. Warns and degrades if a host layer is missing. |
| `strict` | blocked | yes | full | Fail-closed version of `full`. For autonomous work where weaker isolation is not acceptable. Also requires mount namespaces when target/output isolation is requested. |
| `target_run` | **open** | yes | full | For harness-spawned target binaries that need a local listener (loopback TCP, Unix domain sockets). Same Landlock + seccomp as `full` but `block_network=False` so the listener is reachable. Pair with the [netns coordinator](#netns-coordinator) for loopback-only isolation. |
| `debug` | blocked | yes | debug (permits ptrace) | For [crash analysis](crash-analysis.md) with gdb/rr. Target and debugger run in the same sandbox. Composes with `--audit`. |
| `frida` | **open** | yes | frida (AF_UNIX allowed) | For [Frida](frida.md) helper IPC. `AF_UNIX` sockets are allowed for Frida's internal IPC with the target process. `AF_NETLINK`/`AF_PACKET`/`SOCK_RAW` stay blocked. |
| `network-only` | blocked | off | off | Tools whose correctness needs unrestricted filesystem or syscalls. |
| `none` | open | off | off | Emergency escape hatch. Rlimits only. |

CLI: `--sandbox <profile>` on any RAPTOR command that honours it.

Use `--sandbox strict` when a run should stop rather than quietly carry
on with less isolation. On Linux, strict mode also requires mount
namespaces when target/output isolation is requested. On macOS, the
Seatbelt backend is the strict isolation layer.

---

## Configuration

All kwargs accepted by `sandbox()` and `run()` (and most by
`run_untrusted()` unless noted):

| Kwarg | Default | Meaning |
|---|---|---|
| `target` | `None` | Path to attacker-derived content. Read-only inside sandbox; engages Landlock. |
| `output` | `None` | Scratch area. Writable inside sandbox; engages Landlock. |
| `block_network` | `False` | Unshare network namespace -- no interfaces inside. |
| `allowed_tcp_ports` | `None` | Landlock TCP-connect allowlist (ABI v4+, kernel 6.7+). Mutually exclusive with `block_network=True`. |
| `limits` | built-in defaults | Resource caps: `memory_mb`, `max_file_mb`, `cpu_seconds`. |
| `profile` | `None` | Named profile (see table above). Overrides individual layer flags. |
| `disabled` | `False` | Shortcut for `profile='none'`. |
| `map_root` | `False` | Map caller UID to root inside namespace (for tools that check `getuid()==0`). |
| `use_egress_proxy` | `False` | Route outbound HTTPS through the RAPTOR proxy with a hostname allowlist. See [Egress proxy](#egress-proxy). |
| `proxy_hosts` | `None` | Hostname allowlist for the egress proxy. Required when `use_egress_proxy=True`. |
| `restrict_reads` | `False` (`True` in `run_untrusted` / `run_untrusted_networked`) | Flip Landlock to allowlist-only reads (blocks `$HOME`, custom paths, etc.). |
| `readable_paths` | `None` | Extra paths to add to the read allowlist. Ignored when `restrict_reads=False`. |
| `writable_paths` | `None` | Extra paths to add to the Landlock write allowlist beyond `output`. |
| `fake_home` | `False` (`True` in `run_untrusted`) | Override child `HOME` + `XDG_*_HOME` to `{output}/.home/`. Requires `output`. |
| `caller_label` | `None` | Short identifier stamped onto every proxy event during this sandbox's lifetime. |
| `tool_paths` | `None` | Extra dirs to bind-mount into mount-ns so non-system tools are visible. See [Mount-ns tool visibility](#mount-ns-tool-visibility). |
| `audit` | `False` | Engage audit mode: log what enforcement would have blocked. See [Audit and observe modes](#audit-and-observe-modes). |
| `audit_verbose` | `False` | Strace-style output: log every traced syscall, not just blocked ones. |
| `audit_run_dir` | `None` | Directory for audit JSONL, decoupled from `output`. Prevents hostile targets from injecting false records. |
| `observe` | `False` | Superset of audit. Adds stat-family syscall tracing with per-run nonce for spoof-resistant JSONL. See [Audit and observe modes](#audit-and-observe-modes). |
| `exclude_tmp_baseline` | `False` | Exclude `/tmp` baseline paths from observe profiles (reduce noise). |
| `sanitise_host_fingerprint` | `False` | Engage host fingerprint sanitisation. See [Host fingerprint sanitisation](#host-fingerprint-sanitisation). |
| `cpu_count` | `None` | Number of CPUs to present to the sandboxed child (via affinity masking and `/proc/cpuinfo` overlay). Use `HOST_CPU_COUNT` sentinel to preserve the host's real count. |
| `require_sanitisation` | `False` | Fail-closed if fingerprint sanitisation cannot engage (e.g. no mount-ns). |
| `etc_overlay` | `None` | Dict mapping in-sandbox `/etc` paths to host source files for bind-mount overlay. Context-level (set once, reused across `run()` calls). |
| `strict_env` | `False` | Strip `DANGEROUS_ENV_VARS` from any caller-supplied `env=` dict. Automatically `True` in `run_untrusted()` / `run_untrusted_networked()`. |
| `env_caller_filtered` | `False` | Caller assertion that the `env=` dict was already filtered. Suppresses the operational-hygiene warning without stripping vars. |
| `skip_pid_ns` | `False` | Skip PID namespace isolation. Internal use by the netns coordinator. |
| `skip_mount_ns` | `False` | Skip mount namespace isolation. Internal use. |
| `inherit_netns` | `False` | Inherit the parent's network namespace instead of creating a new one. Used by the netns coordinator for shared-netns pairing. |

> **`env=` passthrough.** If you pass an explicit `env=` dict to `run()`,
> it is forwarded verbatim to the child -- `RaptorConfig.get_safe_env()`
> is NOT applied (a WARNING-level log is emitted). `env=None` or omitting
> `env=` engages the safe-env path. Callers opting into custom `env=`
> own the sanitisation of what they pass.

### Mount-ns tool visibility

The mount-ns sandbox bind-mounts a fixed set of system dirs (`/usr`,
`/lib`, `/lib64`, `/etc`, `/bin`, `/sbin`) plus `target`/`output`
plus a per-sandbox `/tmp` tmpfs. **Anything else is invisible inside
the sandbox** -- invoking a tool at `~/.local/bin/X`, `/opt/homebrew/bin/X`,
or `~/bin/X` would produce ENOENT (subprocess exit 127).

Two mechanisms keep workflows running:

**Auto-fallback (no caller cooperation needed).** If `cmd[0]` resolves
to a path outside the mount-ns bind tree, the sandbox skips mount-ns
and runs the call at Landlock-only isolation. The workflow proceeds;
isolation matches the Ubuntu-default posture (where mount-ns never
engages anyway). Logged at DEBUG.

**`tool_paths=` opt-in.** Callers that know their tool's install layout
pass `tool_paths=[<bin_dir>, <lib_dir>, ...]`. Those dirs are
bind-mounted read-only into the mount-ns sandbox. **Speculative**: if
the bind set turns out insufficient (tool fails at exec), the sandbox
automatically retries via Landlock-only. First failure per binary fires
one INFO log; subsequent calls hit a per-cmd cache and skip the doomed
mount-ns attempt directly.

When to use what:

- **Standalone binary in a system dir** (`/usr/local/bin/`): no action
  needed; mount-ns engages cleanly.
- **Standalone binary outside system dirs** (e.g. `/opt/foo/bin/foo`
  with all deps in `/opt/foo/`): pass `tool_paths=["/opt/foo"]`.
- **Self-contained distribution** (CodeQL ships at
  `~/.local/share/codeql/` with java/, lib/, packs/ siblings): pass
  `tool_paths=[<codeql_install_dir>]`.
- **Python tools** (Semgrep, etc.): pass `tool_paths=` covering the
  bin dir + Python stdlib dir. `python_runtime_tool_paths()` from
  `core.sandbox.python_paths` auto-discovers the running interpreter's
  runtime roots.

The cache is per-process: a fresh RAPTOR invocation re-probes.

---

## Read restriction (`restrict_reads` + `fake_home`)

Under `run_untrusted()`, both default to `True`. This is the primary
defence against credential exfiltration:

- `restrict_reads=True` -- Landlock blocks reads outside the
  system-directory allowlist (`/usr`, `/lib`, `/lib64`, `/etc`,
  `/proc`, `/sys`, `target`, `output`, `/tmp`, and curated `/dev`
  files). `$HOME` is **not** on the allowlist.
  - `/dev` is narrowed: `/dev/null`, `/dev/tty` (writable), plus
    `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`
    (readable). Does not include `/dev/shm`.
  - `/proc` is wholesale allowlisted, but cross-process
    `/proc/<host_pid>/environ` reads are still blocked:
    `restrict_reads=True` also triggers a PID-namespace unshare, and
    the kernel's per-ns `/proc` access check denies reads of any
    host-pid `/proc/<pid>/environ` even though `/proc` is visible.
    This stops a compromised child lifting `ANTHROPIC_API_KEY` out of
    the parent's environment.
- `fake_home=True` -- child's `HOME`, `XDG_CONFIG_HOME`,
  `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME` all point at
  `{output}/.home/` -- an empty directory created fresh per sandbox.
  Tools see no dotfiles.

Together they ensure:

- `cat ~/.ssh/id_rsa` -> ENOENT (home is empty)
- `cat /home/user/.ssh/id_rsa` -> EACCES (absolute path blocked by Landlock)
- `cat ~/.aws/credentials` -> ENOENT
- `cat ~/.config/raptor/models.json` -> ENOENT

If a tool genuinely needs a config file, pre-populate the fake home
before calling:

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

---

## Egress proxy

An in-process HTTPS-CONNECT proxy lets callers allow a specific set of
hostnames while still blocking everything else. Use it when the tool
needs one or two API endpoints (e.g. Claude sub-agent, CodeQL pack
download) but you do not want to open the full network.

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
- Child env gets `HTTPS_PROXY` and `http_proxy` set to that port; most
  tools (curl, pip, Java/CodeQL) honour these.
- Landlock restricts TCP `connect()` to the proxy's port, so the child
  cannot bypass it.
- Seccomp blocks `AF_INET`/`AF_INET6` `SOCK_DGRAM`, closing the
  DNS-exfiltration path.
- The proxy rejects any `CONNECT` to a hostname not on the allowlist.
- Resolved IPs are screened -- loopback, private, link-local, multicast,
  reserved, and unspecified addresses are rejected even if the hostname
  was on the allowlist. (When an upstream HTTPS proxy is configured, IP
  screening is skipped because the upstream handles DNS.)

Multiple callers share one proxy singleton; their hostname allowlists
are union'd. Event observability is **per-run**, not shared: each
`run()` call registers with the proxy, gets a token, and the proxy fans
every event generated during that subprocess into the token's own
buffer. Concurrent sandboxes each get the full event stream for their
lifetime.

### Netns proxy enforcement fallback

On kernels with Landlock ABI < 4 (pre-6.7), the Landlock TCP-connect
allowlist is unavailable. The sandbox falls back to a TCP-to-Unix-socket
relay (`core/sandbox/_proxy_bridge.py`): a small forwarder process runs
inside the sandboxed child's empty network namespace, listening on
`127.0.0.1:<port>` (TCP) and relaying connections to the egress proxy's
Unix socket in the parent namespace (visible via bind-mount). This
ensures the child can only reach the proxy regardless of Landlock ABI
version. The forwarder uses only fork-safe, async-signal-safe
primitives (no Python logging, no threading, no C-extension init).

### Upstream proxy support

If `HTTPS_PROXY` is set in the parent environment (e.g. corporate
proxy), the RAPTOR proxy forwards its `CONNECT` tunnels through that
upstream. `NO_PROXY` / `no_proxy` are honoured for the upstream
decision. This is transparent to callers.

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
`time.monotonic()` seconds (monotonic across clock jumps, not wall
time). `caller` is added from `caller_label=` when set.

Events are also persisted to `{output}/proxy-events.jsonl` when
`output` is set. Each sandbox's buffer grows independently for its
lifetime (no fixed cap, no ring-buffer eviction); the buffer is
discarded when the sandbox context exits.

For a `with sandbox(...)` block with multiple `run()` calls, each
individual `result.sandbox_info["proxy_events"]` holds that specific
subprocess's slice. The **cumulative** view across every run in the
block is exposed as `run.events`.

---

## Host fingerprint sanitisation

Opt-in via `sandbox(..., sanitise_host_fingerprint=True)`. When engaged,
the mount-ns child bind-mounts canonical files over the host's identity
surfaces and the spawn machinery sets a canonical UTS namespace +
`sched_setaffinity` mask. The result presents a "boring Debian 12 cloud
VM on QEMU/KVM" persona -- the most common Linux workload profile,
chosen to avoid tipping off analysis-aware targets.

Implemented in `core/sandbox/fingerprint.py` (~580 lines).

### What is sanitised

| Surface | Overlay value |
|---|---|
| `/proc/cpuinfo` | N CPU blocks (configurable via `cpu_count`); host `flags` line preserved |
| `/proc/version` | `Linux version <host-release>` (real kernel version kept) |
| `/proc/cmdline` | `BOOT_IMAGE=/boot/vmlinuz root=/dev/vda1 ro quiet` |
| `/proc/stat` | Aggregate + N per-cpu lines |
| `/etc/os-release` | Debian 12 (bookworm) stub |
| `/etc/machine-id` | Deterministic pseudo-random per RAPTOR install (SHA-256 of install path) |
| `/etc/hostname` | `localhost` |
| `/sys/class/dmi/id/sys_vendor` | `QEMU` |
| `/sys/class/dmi/id/product_name` | `Standard PC (i440FX + PIIX, 1996)` |
| `/sys/devices/system/cpu/online` | `0..N-1` |
| `/sys/devices/system/cpu/possible` | `0..N-1` |
| `uname()` nodename | `localhost` |
| `uname()` domainname | `localdomain` |
| `sched_getaffinity` | bits `0..N-1` |

### What is preserved (capability surface, not identity)

- `/proc/cpuinfo` `flags` line (SMEP/SMAP detection in
  `packages/exploit_feasibility`, SIMD dispatch, ASAN shadow-mem).
- `uname()` sysname (always "Linux"), release (kernel version for
  exploit feasibility's `uname -r`), machine (arch -- shellcode payload
  dispatch needs it).
- `/proc/sys/kernel/{randomize_va_space, kptr_restrict,
  yama/ptrace_scope}`, `/proc/sys/vm/mmap_min_addr` (mitigation reads).
- `/proc/self/*` (maps, exe, status, auxv -- ASAN, GDB, pwntools
  `context.aslr` depend on real values).

### Residuals (documented, not addressed)

- **CPUID instruction bypass**: direct `cpuid` execution reads the real
  CPU; fixing this requires ptrace syscall rewriting + userspace
  emulation (out of scope).
- **AT_HWCAP auxiliary vector**: kernel-supplied at exec; not file-based.
- **Vendor preservation via flags-line**: Intel vs AMD distinguishable
  via flag-set differences. Trade-off for SIMD compatibility.

### Configuration

- `cpu_count=N`: present N CPUs to the child (default: 4). Use
  `HOST_CPU_COUNT` sentinel (value `-1`) to preserve the host's actual
  CPU count -- useful for `codeql database create` and other parallel
  builds where pinning to 4 CPUs on a 32-core host causes build
  timeouts.
- `require_sanitisation=True`: fail-closed if sanitisation cannot engage
  (e.g. no mount-ns available).
- `etc_overlay={"/etc/foo": "/path/to/overlay"}`: additional `/etc` bind
  mounts applied during mount-ns initialisation.

**Platform support:** Linux only. macOS lacks unprivileged bind-mount
and UTS-namespace primitives. `fingerprint.is_supported()` returns
`False` on non-Linux; callers soft-degrade with a one-shot WARNING.

---

## Audit and observe modes

### Audit mode

`--audit` (composed with any compatible profile) runs a workflow to
completion AND records what enforcement WOULD have blocked. It is the
soft-default fallback when `full` is too strict for a workload but
operators want visibility into policy violations -- far better than
`--sandbox none`.

Programmatic equivalent: `sandbox(profile=..., audit=True)` or
`run(..., audit=True)`. The CLI flag composes with any profile
automatically.

Three layers, audit-mode each:

| Layer | Mechanism | Behaviour |
|---|---|---|
| Network (egress proxy) -- **only when `use_egress_proxy=True`** | Hostname allowlist gate emits `would_deny_host` event, then permits the CONNECT | Resolved-IP block (DNS-rebinding defence) stays enforcing. |
| Syscalls (seccomp) | Swaps deny action from `SCMP_ACT_ERRNO(EPERM)` to `SCMP_ACT_TRACE`; tracer logs each blocked syscall + resumes | The existing blocklist is observed instead of EPERM'd. |
| Filesystem (`open`/`openat`) | Tracer dereferences path arg, resolves via `/proc/<pid>/cwd` and `/proc/<pid>/fd/<dirfd>`, matches against Landlock allowlist | Filtered mode logs only paths that would have been blocked; verbose mode logs every traced open. |
| Network (`connect` syscall) | Tracer decodes sockaddr to `ip:port`, compares against `allowed_tcp_ports` | Filtered mode logs only would-be-blocked ports; verbose mode logs every connect. |

| Invocation | Effect |
|---|---|
| `--sandbox full` (default) | Full enforcement |
| `--sandbox full --audit` | Full layout, proxy gate logs-and-allows + tracer logs would-be-blocked syscalls |
| `--sandbox full --audit --audit-verbose` | Same as above but tracer logs EVERY traced syscall (strace-style) |
| `--sandbox debug --audit` | gdb-friendly seccomp + audit signal |
| `--sandbox network-only --audit` | Only the egress-proxy gate audits (other layers no-op) |
| `--sandbox none --audit` | **Error** -- incoherent (nothing to audit against) |
| `--audit-verbose` without `--audit` | **Error** -- verbose only controls tracer output |

The tracer is a Python subprocess (`core.sandbox.tracer`) that attaches
via `PTRACE_SEIZE` with `TRACEFORK | TRACEVFORK | TRACECLONE` so
multi-process workloads audit every subprocess.
`PTRACE_O_EXITKILL` ensures that if the tracer dies, the kernel
cascades `SIGKILL` to all tracees.

`openat2(2)` (Linux 5.6+) IS in the trace set. The flags-bit extraction
reads the first 8 bytes of the `struct open_how` pointer via
`process_vm_readv`.

**Audit-record integrity.** When `audit_run_dir=` is supplied
explicitly, the audit JSONL lives in a directory NOT in
`writable_paths`, so the traced target cannot inject false records.
When `audit_run_dir` is omitted and `output=` is used as fallback,
the JSONL lives inside the target's writable surface. Mitigations:
`O_NOFOLLOW` defends against symlink swaps; records are
operator-visible signal, not authoritative truth.

**Performance.** Audit mode adds ~200 ms fixed setup cost per sandbox
call and ~5 ms per traced syscall. Measured on Ubuntu 24.04 / Python
3.13: `--audit` is roughly 3.5x `--sandbox full` alone. Filtered and
verbose run at the same speed -- the filter only saves the JSONL write
cost.

**Degradation when ptrace is unavailable** (Yama scope 3, container
`--cap-drop SYS_PTRACE`): network audit still works; syscall +
filesystem audit silently degrade to enforcement. A one-time WARNING
surfaces the degradation.

### Observe mode

`sandbox(..., observe=True)` is a superset of audit mode. In addition
to the standard audit layers, observe mode adds stat-family syscall
tracing (`stat`, `fstat`, `lstat`, `statx`, `newfstatat`) which are
excluded from normal audit to reduce noise. Each observe run carries a
per-run nonce written into the JSONL records, providing spoof-resistant
integrity -- a hostile target that manages to append to the JSONL cannot
produce records with the correct nonce.

Observe JSONL is written to `<run_dir>/.sandbox-observe.jsonl`
(distinct from the audit JSONL). The resulting records can be parsed
into an `ObserveProfile` dataclass via `parse_observe_log()`:

```python
from core.sandbox import parse_observe_log, ObserveProfile

profile: ObserveProfile = parse_observe_log(Path(run_dir))
print(profile.paths_read)        # set of paths the binary read
print(profile.paths_written)     # set of paths written
print(profile.connect_targets)   # set of (host, port) tuples
```

Use cases:

- Derive a Landlock `readable_paths` set from "every path the binary
  actually touched" (auto-calibration).
- Derive an egress-proxy hostname allowlist from observed connections.
- Surface "binary X probes 47 candidate config locations during startup"
  for [/understand](code-understanding.md) or audit work.

CLI: `raptor-sandbox-observe -- /usr/bin/true` (human summary) or
`raptor-sandbox-observe --json -- ./scan-target` (machine-readable
`ObserveProfile`).

The observe profile can be merged into a `/understand` context-map.json
via `core.sandbox.observe_context_merge` to corroborate static analysis
with runtime evidence.

### Landlock-only audit spawn path

On Ubuntu 24.04+ where mount-ns is blocked by AppArmor,
`_landlock_audit.py` provides a focused spawn function that does NOT
touch namespaces but forks a tracer subprocess in parallel with the
target child, mirroring the sync-pipe handshake from `_spawn.py`.
This restores audit/observe signal that would otherwise silently degrade
on Landlock-only hosts.

### Audit budget (cross-platform)

Both backends route audit-record decisions through one shared module
(`core.sandbox.audit_budget.AuditBudget`). The budget composes four
mechanisms:

1. **Global cap** -- `--audit-budget=N` (default 10000). Hard ceiling
   on records per run.
2. **Per-category sub-cap** -- file-read-metadata (500), file-write
   (3000), mach-lookup (1000), etc. Stops one chatty category from
   squeezing important low-volume categories out of the global pool.
3. **Per-PID sub-cap** -- default 5000. One spamming subprocess cannot
   dominate the JSONL.
4. **Token-bucket refill** -- burst capacity = cap, sustained rate =
   refill rate. Long-running workloads at low steady-state never trip.
5. **1-in-N post-cap sampling** -- high-volume categories keep emitting
   a trickle even after their bucket empties so operators see "still
   happening".

Markers appear in the JSONL alongside data records:
`category_budget_exceeded`, `pid_budget_exceeded`,
`category_budget_exceeded_sampling`, and `audit_summary`.

```bash
raptor scan target/  --sandbox full --audit                     # default 10000
raptor scan target/  --sandbox full --audit --audit-budget 100  # quick diag
raptor scan target/  --sandbox full --audit --audit-verbose --audit-budget 50000
```

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

`core/sandbox/calibrate.py` (~500 lines) provides auto-calibration of
sandbox allowlists by empirically observing what a binary touches during
a controlled probe run. The calibration result is keyed on
`(sha256(binary), env_signature)` and cached on disk under
`~/.cache/raptor/sandbox-profiles/` (mode 0700/0600).

### API

```python
from core.sandbox.calibrate import calibrate_binary, load_or_calibrate, clear_cache

# Always-fresh measurement.
profile = calibrate_binary("/usr/bin/claude", ["--version"], env_keys=("HOME",))

# Cache-first variant (default path for cc_dispatch consumers).
profile = load_or_calibrate("/usr/bin/claude", ["--version"])

# Force recalibration.
profile = load_or_calibrate("/usr/bin/claude", ["--version"], force=True)

# Clear cache.
clear_cache()                          # all entries
clear_cache(bin_path="/usr/bin/claude") # one entry
```

### Why generalise

Hardcoded sandbox allowlists drift silently across binary versions and
operator setups:

- Anthropic adds a new endpoint -- the hardcoded `api.anthropic.com`
  allowlist breaks.
- An operator points pip at a corporate index -- `pypi.org` is never
  touched; `pypi.corp.example` is.
- CodeQL on a GHE host pulls packs from `ghe.corp.example` instead of
  `github.com`.

Auto-calibration resolves the actual reach empirically and surfaces a
profile the operator or downstream allowlist code can consume.

### Threat model

Calibration is a portability / drift-detection tool, NOT a security
feature. The probe runs the binary once with a permissive policy -- by
the time we observe its behaviour, the binary has already executed.
Defence against malicious binary updates lives upstream (signed
installers, package-hash verification). The cache itself is mode-0600
with SHA-256 self-integrity check.

CLI: `raptor sandbox calibrate -- <binary> [args...]` (via
`core/sandbox/calibrate_cli.py`).

---

## Netns coordinator

`core/sandbox/netns_coordinator.py` (~550 lines) provides paired-process
isolation for sibling sandboxed processes sharing a single isolated
network namespace. This is the substrate for the `target_run` profile:
when a harness needs to spawn a target binary that listens on loopback
TCP and a test client that connects to it, both run inside the same
isolated netns so they can communicate while remaining isolated from the
host network.

### Architecture

The naive approach -- two `sandbox.run` calls each `setns()`-ing into a
shared netns fd -- fails for two reasons:

1. `setns(fd, CLONE_NEWNET)` requires `CAP_SYS_ADMIN` in the user-ns
   that owns the netns. An unprivileged sandbox child does not have
   that capability.
2. Namespace file descriptors inside the sandbox are permission tokens
   -- adversarial code could `setns()` them to re-enter the shared
   user-ns and gain capabilities.

The coordinator avoids both by forking both children from itself, so
they inherit the user-ns and net-ns by the kernel's normal
fork-inheritance mechanism. No `setns` call, no namespace fd inside the
sandbox.

### Namespace setup paths

Two paths for namespace creation:

**A. Direct unshare.** Works on hosts where the operator has disabled
the LSM restriction (`kernel.apparmor_restrict_unprivileged_userns=0`
on Ubuntu, or equivalent). Tried first.

**B. Privileged launcher binary** at
`core/sandbox/helpers/raptor-coord-launcher`. The launcher creates the
namespaces in a brief privileged window, drops every capability, and
execs the coordinator script with `RAPTOR_COORD_FROM_LAUNCHER=1` set.
The coordinator then proceeds as if it had done the unshare itself.
AppArmor and SELinux policy files are provided alongside the launcher
source.

If both paths fail, the coordinator writes a structured error to stdout
and exits non-zero. The caller surfaces the message to the operator.

### Protocol

The coordinator reads a JSON request from stdin describing both
commands, sets up the shared namespaces, forks both children (each
inheriting the shared namespaces), waits for both, writes a JSON
response to stdout, and exits.

---

## Crash signal handling

`unshare --pid --fork` makes the forked child pid-1 of the new pid-ns.
Linux's pid-ns policy drops signals sent to pid-1 via `raise()` /
`kill(self, ...)` unless the process has installed a handler. If the
target runs directly as pid-1, a self-signalled crash -- `abort()`,
explicit `raise(SIGFPE)` -- exits `rc=0` and the sandbox sees a clean
return where the target actually crashed.

The subprocess-path sandbox interposes `libexec/raptor-pid1-shim` so the
target runs as **pid-3** of the new pid-ns, not pid-1:

- **shim** (pid-1) -- reaps children, forwards termination signals
  (`SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT`) to the target, mirrors exit
  status.
- **intermediate** (pid-2) -- exists only to escape process-group
  leadership so the grandchild can `setsid()`.
- **target** (pid-3) -- executes the caller's command, session leader,
  no controlling tty (so `open("/dev/tty")` returns ENXIO).

Signal death is encoded using the standard Unix `128+sig` exit-code
convention. `observe._interpret_result` decodes both `rc<0` (direct
child signal death) and `128<rc<128+NSIG` (shim-mirrored signal death)
to the same `sandbox_info["crashed"] = True` state.

Side-effect of the `-I` shebang on the shim interpreter:
`PYTHONPATH`, `PYTHONHOME`, and `PYTHONSTARTUP` in the child env are
ignored at interpreter startup, blocking a `sitecustomize.py` injection
surface.

The mount-ns path (`core/sandbox/_spawn.py`) handles pid-ns setup via
its own `os.fork()` after `unshare(NEWPID)`, so the grandchild target
is pid-2 of the new ns and this shim is not required there.

---

## Observability

`sandbox_info` is attached to each `run()` return value:

```python
from core.sandbox import sandbox

with sandbox(target=repo, output=out, use_egress_proxy=True,
             proxy_hosts=["api.anthropic.com"]) as run:
    result = run(cmd)
    info = result.sandbox_info

    print(info.get("crashed"), info.get("signal"))    # termination reason
    print(info.get("sanitizer"))                       # asan/ubsan/msan/tsan
    print(info.get("evidence"))                        # factual summary string
    print(info.get("blocked"))                         # sandbox-enforcement events
    print(info.get("proxy_events"))                    # list of connect attempts
```

### Per-run denial summary

For commands that go through the lifecycle helpers (i.e., everything
driven by [/scan, /agentic, /codeql, /validate, /understand,
/fuzz](commands.md)), every sandbox enforcement event seen during the
run is aggregated into `{run_dir}/sandbox-summary.json` at run-end.

`suggested_fix` references only the operator-facing CLI flags --
`--sandbox {full,debug,network-only,none}`.

**Recovery from non-clean exits.** If a run dies before its lifecycle
hook fires:

1. **Automatic** -- the next time the same session re-runs the same
   command type, `start_run`'s `_cleanup_abandoned` sees the prior run
   still at `status=running`, marks it `failed`, and `fail_run` routes
   through the standard summary-finalise path.

2. **Manual**:

   ```bash
   # Single run.
   libexec/raptor-sandbox-summary <run_dir>

   # All stranded runs under a project dir.
   libexec/raptor-sandbox-summary --sweep <project_dir>
   ```

---

## `SandboxSetupError`

`SandboxSetupError` (defined in `core/sandbox/errors.py`) is raised when
sandbox isolation could not **engage** for a run. It subclasses
`BaseException` (not `Exception`) deliberately -- like
`KeyboardInterrupt` and `SystemExit` -- so it propagates past broad
`except Exception` handlers that would otherwise silently swallow the
failure and produce a "0 findings" result.

The error carries two fields:
- `reason`: the kernel/wrapper diagnostic.
- `instructions`: actionable next step for the operator.

When a RAPTOR CLI subprocess (scanner, CodeQL agent) catches this
error, it prints the actionable message and exits with code 3
(`SANDBOX_ENGAGE_EXIT_CODE`). The parent detects exit code 3 and
re-raises `SandboxSetupError` to preserve the fail-loud invariant
across process boundaries.

Policy: RAPTOR does NOT auto-degrade to weaker isolation when the
requested profile cannot engage. The operator resolves it explicitly
(e.g. `--sandbox network-only`).

---

## Toolchain env for builds

The sandbox's `get_safe_env()` keeps a tight allowlist and deliberately
strips language-specific vars like `JAVA_HOME`, `GOROOT`, `DOTNET_ROOT`,
`RUSTUP_HOME`. Instead, each build-system entry in
`packages/codeql/build_detector.BUILD_SYSTEMS` declares an `env_detect`
list, and `core/build/toolchain.py` auto-resolves those vars from
filesystem layout at build time.

Scope: detected values land in the build subprocess's env ONLY --
scanners, LLM sub-agents, the proxy thread, and other sandbox calls in
the same context do not see them.

If the build tool still fails with "JDK not found" or similar: install
the toolchain into a standard location, or expand the detector fallback
chain in `core/build/toolchain.py` for your distro.

---

## Platform support

### Linux (full isolation)

All six layers are available: user namespace, network namespace, PID
namespace, IPC namespace, mount namespace (with pivot_root), Landlock +
seccomp-bpf + rlimits. Each layer probes for kernel support
independently at first use and caches the result per-process.

### macOS (Seatbelt)

On Darwin, the sandbox routes through `core.sandbox._macos_spawn`
using `sandbox-exec(1)` and the kernel `Sandbox.kext` with an SBPL
(Sandbox Profile Language) profile.

**What works the same:**

- `sandbox()`, `run()`, `run_trusted()`, `run_untrusted()` -- same API.
- `block_network`, `allowed_tcp_ports`, `use_egress_proxy`, `proxy_hosts`
  -- translated to SBPL network rules.
- `target`, `output`, `writable_paths` -- translated to SBPL
  file-write deny rules with subpath exceptions.
- `restrict_reads`, `readable_paths` -- translated to SBPL file-read
  deny rules.
- `fake_home` -- env-side; same env mutation as Linux.
- `audit` -- replaces file-write deny with `(allow file-write*
  (with report))`; `seatbelt_audit.LogStreamer` reads `log stream`
  ndjson output.
- `limits` -- POSIX `setrlimit` via the same `preexec_fn` pattern.
- Sandbox-summary aggregation, proxy events -- identical cross-platform.
- `--audit-budget=N` -- same `AuditBudget` module on both backends.

**What is different (platform limits):**

| Linux feature | macOS status | Mitigation |
|---|---|---|
| PID namespace | absent | No unprivileged equivalent. Host PIDs visible. |
| Mount namespace + pivot_root | absent | `restrict_reads=True` is the substitute (SBPL deny). |
| `RLIMIT_NPROC` per-namespace | weaker | macOS rlimit is per-UID host-wide. |
| `seccomp_profile=full` | partial | Mapped to `(deny process-info* (target others))` -- coarse. |
| `audit_verbose` (per-syscall) | partial | SBPL `(allow X (with report))` for an extended category set. |
| `map_root` (UID re-mapping) | absent | macOS sandbox-exec keeps caller UID. |
| Host fingerprint sanitisation | absent | macOS identity reads are syscall/IOKit-based, not file-based. |
| `--sandbox debug` (lldb) | full | Same intent as Linux: full enforcement except debugger introspection. macOS skips process-info denies under debug so lldb/sample/dtrace can attach. |

**macOS-specific operator notes:**

- **First-run cost**: `check_seatbelt_available()` invokes
  `sandbox-exec` with a minimal `(allow default)` profile once per
  process to verify the kernel sandbox is functional. ~50 ms.
- **No `(deny default)`**: pure deny-default profiles SIGABRT modern
  macOS binaries before dyld can load libSystem. Always uses
  `(allow default)` + targeted denies.
- **Default exception list**: `/private/tmp` is always added to the
  write-allowlist exception so standard `tempfile.mkstemp()` works.
- **Audit log latency**: kernel-to-log-subsystem pipeline has ~tens-ms
  latency for steady-state and ~1.5 s for a cold first event.

### Backend selection

`core/sandbox/context.py` dispatches at the spawn-eligibility check:

```
if sys.platform == "darwin":
    use_seatbelt = use_sandbox and check_seatbelt_available()
else:
    use_mount = use_sandbox and ... and check_mount_available()
```

Post-run aggregation (proxy events, engagement booleans,
sandbox-summary JSONL) is platform-independent.

---

## Known limitations

### Read restriction is opt-in for `sandbox()` and `run()`

`restrict_reads=False` is the default for `sandbox()` and `run()`.
Only `run_untrusted()` and `run_untrusted_networked()` default to
`restrict_reads=True`. Callers using `sandbox()` directly must
explicitly set `restrict_reads=True` to protect against credential
exfiltration -- particularly important on Landlock-only hosts (Ubuntu
24.04 default) where the mount-ns filesystem hiding is unavailable.

### macOS exec-status pipe gap

macOS uses `sandbox-exec`, which does not provide an exec-status pipe
mechanism. The parent cannot distinguish "the child failed to exec"
from "the child exec'd and exited non-zero with empty output" at the
same fidelity as the Linux `_spawn` path.

### Orphan-leak potential

The sandbox uses a pid1-shim, death-pipe, and `--kill-child=SIGKILL`
to cascade cleanup. However, `prctl(PR_SET_PDEATHSIG)` is not fully
wired in all spawn paths. If the RAPTOR parent dies unexpectedly (hard
`SIGKILL`), the death-pipe mechanism cleans up the immediate child, but
deeply nested grandchildren may survive briefly until the pid-ns reaps
them. In practice, the pid-ns hierarchy ensures cleanup within seconds.

### Landlock ABI requirements

- **ABI v4 (kernel 6.7+)** required for `allowed_tcp_ports` (TCP
  connect allowlist). Earlier kernels emit a WARNING and the parameter
  is silently ignored -- use the [egress proxy](#egress-proxy) instead.
- **ABI v3 (kernel 5.19+)** required for `TRUNCATE` support. Without
  it, writes to `/dev/null` via truncation may hit EACCES.

### Audit coverage gaps

- **`io_uring`**: file operations via submission queue entries bypass
  the syscall layer and are invisible to seccomp tracing. RAPTOR's
  seccomp blocklist already disallows `io_uring_setup` under
  `full`/`debug`; under `--audit` it is logged-and-allowed with an
  explicit gap note.
- **Anti-debug detection**: code in an audited sandbox can detect
  tracing via `/proc/self/status` `TracerPid`, ptrace self-test, or
  syscall timing. Audit mode is for operator workflows (gcc, make,
  python), not malware analysis.

### Symlink divergence in audit tracer

The audit tracer's filesystem path resolution does not `readlink` in the
tracer -- a small number of edge cases over-report compared to real
Landlock enforcement.

---

## Integrity guard

The sandbox includes a runtime self-test on first use: it forks a child,
installs Landlock with `WRITE_FILE` and `READ_FILE` restrictions, and
verifies both are actually enforced. If the UAPI constants ever drift,
this test fails loudly instead of silently granting all access.

A static UAPI regression test
(`test_e2e_sandbox.py::TestE2ELandlockBitValues::test_access_bits_match_uapi`)
pins the bit values against `/usr/include/linux/landlock.h`.

---

## Troubleshooting

### "Mount namespace unavailable" on Ubuntu 24.04

Ubuntu 24.04 ships with an AppArmor sysctl that blocks unprivileged
user-namespace mount operations. The sandbox still applies Landlock,
seccomp, network/PID/IPC namespaces, and rlimits -- but it cannot
provide read-only bind mounts for `target`, `output`, or a fresh `/tmp`.

Both prerequisites must be met to enable mount-ns:

```bash
# 1. Allow unprivileged user namespaces (no reboot needed)
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# 2. Install newuidmap/newgidmap (setuid-root helpers)
sudo apt install uidmap
```

Without both, the sandbox falls back to Landlock-only. Landlock alone
already covers the main threat model (no writes outside `output`, no
reads of credentials under `restrict_reads`); mount-ns adds per-sandbox
`/tmp`, invisible host paths outside the bind-mounts, and stronger
`/dev/shm` isolation.

### A target binary fails with EACCES reading `/home/<user>/...`

Tools that hardcode absolute paths under `/home/<user>/` (not `$HOME`)
hit the Landlock read-restriction even under `fake_home=True`. Either:

- Add the specific path to `readable_paths=[...]`.
- Pre-populate the fake home and let the tool resolve via `$HOME`.
- Run under `sandbox()` with `restrict_reads=False` if the tool is
  trusted.

### Shell scripts fail on `>/dev/null 2>&1`

`/dev/null` writes are permitted by a narrow Landlock rule. If you see
EACCES on `/dev/null`, you are likely running on a kernel without
Landlock ABI v3 (TRUNCATE). Upgrade to 5.19+.

### Rust `cargo build` fails at the linker stage

`std::process::Command` in Rust uses `socketpair(AF_UNIX, ...)` for its
internal error-reporting channel. The sandbox permits this (explicit
seccomp allow). If you see EPERM on `socketpair` itself, check for a
custom `seccomp` override.

### CodeQL "Failed to download pack"

The egress proxy allowlist needs the full set of GHCR hosts:

```python
proxy_hosts=[
    "ghcr.io",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "pkg-containers.githubusercontent.com",
]
```

---

## Module layout

```
core/sandbox/
+-- __init__.py                # public API + threat-model docstring
+-- context.py                 # sandbox(), run(), run_trusted(), run_untrusted(),
|                              #   run_untrusted_networked()
+-- profiles.py                # named profile definitions (7 profiles)
+-- cli.py                     # --sandbox / --no-sandbox argparse integration
+-- probes.py                  # per-layer availability detection
+-- errors.py                  # SandboxSetupError (BaseException subclass)
+-- exit_codes.py              # documented exit codes for fail-closed sites
+-- _spawn.py                  # Linux: fork + newuidmap + pivot_root + Landlock + seccomp
+-- _landlock_audit.py         # Linux: Landlock-only audit spawn for Ubuntu 24.04
+-- _macos_spawn.py            # macOS: sandbox-exec wrapper
+-- _proxy_bridge.py           # TCP-to-Unix-socket relay for netns proxy enforcement
+-- _fork_safe_warn.py         # fork-safe degraded-mode warning helper
+-- mount_ns.py                # Linux: ctypes mount() / pivot_root() for _spawn
+-- mount.py                   # Linux: legacy shell-script mount builder
+-- landlock.py                # Linux: Landlock ABI + rule construction
+-- seccomp.py                 # Linux: seccomp-bpf syscall filters
+-- preexec.py                 # POSIX: preexec_fn composition (rlimits)
+-- proxy.py                   # cross-platform: HTTPS-CONNECT egress proxy
+-- observe.py                 # cross-platform: sandbox_info attachment + result
|                              #   interpretation
+-- observe_cli.py             # CLI: raptor-sandbox-observe
+-- observe_profile.py         # observe-mode profile extraction from tracer JSONL
+-- observe_context_merge.py   # merge ObserveProfile into /understand context-map
+-- state.py                   # cross-platform: singletons + cached state
+-- summary.py                 # per-run denial recording + sandbox-summary.json
+-- tracer.py                  # Linux: ptrace-based syscall tracer for audit/observe
+-- audit_budget.py            # cross-platform: token-bucket rate limiter for audit
+-- calibrate.py               # binary calibration: auto-derive sandbox allowlists
+-- calibrate_cli.py           # CLI: raptor sandbox calibrate
+-- fingerprint.py             # host-fingerprint sanitisation overlays
+-- netns_coordinator.py       # paired-process isolation in shared netns
+-- ptrace_probe.py            # detect ptrace availability
+-- python_paths.py            # discover Python runtime paths for tool_paths
+-- seatbelt.py                # macOS: SBPL profile generator
+-- seatbelt_audit.py          # macOS: log stream capture + JSONL append
+-- helpers/                   # privileged helper binaries
|   +-- raptor-coord-launcher.c          # netns coordinator launcher (C, setuid)
|   +-- raptor-coord-launcher.apparmor   # AppArmor policy
|   +-- raptor-coord-launcher.selinux.te # SELinux policy
|   +-- Makefile                         # build instructions
+-- tests/                     # unit and integration tests
```

See the module docstring in `core/sandbox/__init__.py` for the current
threat-model statement -- what the sandbox does and does not protect
against.

---

## Spike scripts

Phase 0 design spikes are in `scripts/macos_sandbox_spike{1,2,3,4}.py`
-- each validates one assumption used by `seatbelt.py` /
`seatbelt_audit.py`. Re-run them on a new macOS major version to confirm
the SBPL idioms have not drifted.

---

## Related documentation

- [Architecture overview](architecture.md) -- how the sandbox fits into
  the broader RAPTOR pipeline.
- [Commands reference](commands.md) -- CLI flags (`--sandbox`,
  `--audit`, `--audit-verbose`, `--audit-budget`).
- [Binary analysis](binary-analysis.md) -- how binary oracle
  reachability uses sandboxed subprocess execution.
- [Fuzzing](fuzzing.md) -- fuzz target execution under sandbox
  isolation.
- [Frida](frida.md) -- Frida instrumentation using the `frida` profile.
- [Crash analysis](crash-analysis.md) -- gdb/rr under the `debug`
  profile.
