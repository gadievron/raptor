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

> **`env=` passthrough.** If you pass an explicit `env=` dict to `run()`, it
> is forwarded verbatim to the child — `RaptorConfig.get_safe_env()` is NOT
> applied (we log an INFO-level note when this happens). `env=None` or omitting
> `env=` engages the safe-env path. Callers opting into custom `env=` own the
> sanitisation of what they pass.

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
├── __init__.py     # public API + threat-model docstring
├── context.py      # sandbox(), run(), run_trusted(), run_untrusted()
├── profiles.py     # named profile definitions
├── cli.py          # --sandbox / --no-sandbox argparse integration
├── probes.py       # per-layer availability detection
├── _spawn.py       # fork+newuidmap+pivot_root+Landlock+seccomp spawn path
├── mount_ns.py     # ctypes mount() / pivot_root() for the _spawn path
├── mount.py        # legacy shell-script mount builder (kept for tests)
├── landlock.py     # Landlock ABI + rule construction + self-test
├── seccomp.py      # seccomp-bpf syscall filters
├── preexec.py      # preexec_fn composition (PR_SET_NO_NEW_PRIVS etc.)
├── proxy.py        # HTTPS-CONNECT egress proxy
├── observe.py      # sandbox_info attachment, SIGSYS decoding
└── state.py        # singletons and per-process cached state
```

See the module docstring in `core/sandbox/__init__.py` for the current
threat-model statement — what the sandbox does and does not protect against.
