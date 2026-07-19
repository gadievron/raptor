# Subprocess Sandbox

RAPTOR sandboxes any subprocess that handles untrusted content — LLM-generated
PoCs, target build scripts, CodeQL queries, semgrep, fuzz targets, anything
whose arguments or input came from a repo under analysis.

For the mechanics behind these guarantees — the ptrace tracer, the pid-1 shim,
the token-bucket audit budget, host-fingerprint spoofing, and the full module
map — see [`internals/sandbox-internals.md`](internals/sandbox-internals.md).

## When to use which entry point

| Entry point | Use when | Network | Reads restricted |
|---|---|---|---|
| `run_untrusted()` | command or its input is attacker-derived | blocked (namespace) | yes (`restrict_reads` + `fake_home` default on) |
| `run_untrusted_networked()` | attacker-derived, but must reach one known API (e.g. `api.anthropic.com`) | egress-proxy allowlist only | yes (`restrict_reads` on; `fake_home` off) |
| `sandbox()` + `run()` | you need fine-grained control (allowed TCP ports, egress proxy, writable paths, no network ns) | configurable | configurable |
| `run_trusted()` | RAPTOR chose the command AND its inputs; no untrusted content flows in | open | no |
| `run()` (top-level) | you know which kwargs you need; one-shot convenience over `sandbox()` | configurable | configurable |

Rule of thumb: **default to `run_untrusted()`**. Reach for
`run_untrusted_networked()` only when the tool genuinely needs a known upstream
API and pass the exact hostnames. Downgrade to `sandbox()` when you need
something the untrusted defaults deny that neither helper covers. Downgrade to
`run_trusted()` only when the full command line is RAPTOR-owned and no
attacker-derived bytes feed into it.

## Quick start

```python
from core.sandbox import run_untrusted

# Run a compiled target binary that was built from an untrusted repo.
result = run_untrusted(
    [target_binary, "--flag", input_file],
    target=repo_path,          # read-only inside the sandbox
    output=work_dir,           # writable scratch area
    limits={"memory_mb": 2048, "cpu_seconds": 30},
    capture_output=True,
)
```

What this gets you:

- network blocked at the namespace level (no interfaces inside)
- filesystem restricted to `target` (read-only), `output` (writable), `/tmp`
  (fresh tmpfs), and a curated system-dir read allowlist
- `$HOME` redirected to an empty per-sandbox directory — no dotfiles, no
  credentials
- dangerous syscalls blocked: io_uring, kcmp, pidfd_getfd, ptrace, keyctl,
  bpf, userfaultfd, perf_event_open, `open_by_handle_at` / `name_to_handle_at`
  (open a file by opaque handle, bypassing path checks), the `ioctl` tty cmds
  TIOCSTI / TIOCCONS (inject input into / redirect the controlling tty), and
  `socket()` for AF_UNIX / AF_PACKET / AF_NETLINK / SOCK_RAW (docker.sock escape,
  raw-packet sniffing)
- `RLIMIT_CORE = 0` (no core-dump exfil), memory/CPU caps, and per-namespace
  `RLIMIT_NPROC` bounding fork bombs

At least one of `target` or `output` must be truthy so Landlock actually
engages — `run_untrusted()` rejects empty strings.

## Profiles

Profiles are the only supported way to downgrade isolation. They bundle layer
settings under one name. **There are seven** (`core/sandbox/profiles.py`):

| Profile | Network | Landlock | Seccomp | Use for |
|---|---|---|---|---|
| `full` | blocked | yes | full | default for `run_untrusted()` and `sandbox()`; warns and degrades if a host layer is missing |
| `strict` | blocked | yes | full | fail-closed `full`: stops rather than degrade. On Linux, target/output isolation also requires mount namespaces |
| `target_run` | **not blocked** (loopback listener reachable) | yes | full | spawning a harness-authored target binary that must expose a local listener (loopback TCP / UDS) |
| `debug` | blocked | yes | full (permits ptrace) | `/crash-analysis` with gdb/rr |
| `frida` | **not blocked** | yes | full + ptrace + AF_UNIX (frida-helper IPC); AF_NETLINK/AF_PACKET/SOCK_RAW stay blocked | Frida dynamic instrumentation |
| `network-only` | blocked | off | off | tools whose correctness needs unrestricted fs/syscalls within a build |
| `none` | open | off | off | emergency escape hatch; rlimits only |

CLI: `--sandbox <profile>` on any RAPTOR command that honours it. **All seven
profile names are valid choices** (the flag validates against the full profile
set). `--no-sandbox` is an alias for `--sandbox none`.

Use `--sandbox strict` when a run should stop rather than quietly carry on with
less isolation. On macOS, the Seatbelt backend is the strict isolation layer.

## Is it safe to scan an untrusted repo?

Short answer: **yes for read-only scanning (`/scan`), with caveats for agentic
modes** — because in RAPTOR the repo being analysed is also the adversary. A
crafted repo can carry prompt-injection payloads in comments, a hostile
`.claude/settings.json`, module-shadowing files, or exfiltration markup in
strings. What protects you:

- **Trust pre-flight** — `.claude/settings.json`, `.claude/settings.local.json`,
  and `.mcp.json` are scanned before any dispatch; hooks, credential helpers,
  dangerous env vars (`LD_PRELOAD`, `PYTHONPATH`, `RAPTOR_*`/`SAGE_*` prefixes),
  stdio MCP servers, and symlinks are blocked.
- **Module-shadowing defence** — trust checks run under `python3 -I` (isolated
  mode strips `PYTHONPATH`/`PYTHONHOME`, no cwd on `sys.path`); env
  sanitisation strips the Python-path vars from every subprocess.
- **Prompt-injection handling** — a per-call nonce envelope defeats structural
  tag-escapes; autofetch markup (`![]()`, `<img>`, `data:` URIs) is stripped
  from input before it reaches the model.
- **The sandbox itself (this page)** — child processes get network block,
  Landlock/SBPL write-deny, seccomp, and `restrict_reads` credential isolation,
  so even a successful injection can't write outside `output` or read your
  `~/.ssh` / `~/.aws` / API keys.
- **Confused-deputy gate** — `/validate` and `/understand` agentic passes are
  blocked entirely in non-interactive (CI) mode by the Rule of Two gate; in
  interactive mode every `Write`/`Bash` action surfaces a permission prompt.

Honest gaps (know these before running agentic modes on a repo you don't
trust):

- **Natural-language prompt injection** in comments/strings is signalled by a
  regex corpus but **not blocked** — plain English persuasion needs no tag to
  escape. Review agentic verdicts before acting on them.
- **LLM-generated exfil markup** is stripped on *input*, not output. If an
  injection makes the model emit a beacon URL in a report, view that report in
  a renderer that won't auto-fetch.
- **Backdoored patches** — a prompt-injected patch you copy-paste out of RAPTOR
  is not executed inside the sandbox; read patches before applying them.
- **API-budget DoS** — a dense repo can burn tokens; rlimits don't cap that.

Operator guidance: keep the sandbox **on** (never `--no-sandbox`) when scanning
an untrusted repo. `/scan` (static analysis, no `Write`/`Bash`) is low-risk.
`/agentic` and `/validate` grant the agent `Write`+`Bash` — run those
interactively so the permission prompts are your human-in-the-loop, and review
outputs before trusting them. Full threat model:
[`internals/security/adversarial-repo-threat-model.md`](internals/security/adversarial-repo-threat-model.md).

### Strict sandbox mode for autonomous runs

For unattended `/agentic` work — no operator watching permission prompts —
prefer `--sandbox strict` over the default `full`. `full` warns and quietly
degrades if the host can't provide an isolation layer; `strict` fails closed
instead (see the [Profiles](#profiles) table above), because a hostile repo
silently continuing under weaker isolation than you asked for is worse than
the run stopping:

```bash
raptor agentic /path/to/code --sandbox strict
```

This matters most for project threat-modelled runs (`--threat-model`) on
repos you haven't reviewed yet, where the whole point is letting the agent
work autonomously.

## Configuration

Kwargs accepted by `sandbox()` and `run()` (and most by the `run_untrusted*`
helpers). See the source docstrings in `core/sandbox/context.py` for the full
detail.

| Kwarg | Default | Meaning |
|---|---|---|
| `target` | `None` | Path to attacker-derived content. Read-only inside sandbox; engages Landlock. |
| `output` | `None` | Scratch area. Writable inside sandbox; engages Landlock. |
| `block_network` | `False` (`True` in `run_untrusted`) | Unshare the network namespace — no interfaces inside. |
| `allowed_tcp_ports` | `None` | Landlock TCP-connect allowlist (ABI v4+, kernel 6.7+). Mutually exclusive with `block_network=True`. |
| `limits` | built-in defaults | Resource caps: `memory_mb`, `max_file_mb`, `cpu_seconds`. |
| `profile` | `None` | Named profile (see [Profiles](#profiles)). Overrides individual layer flags. |
| `disabled` | `False` | Shortcut for `profile='none'`. |
| `map_root` | `False` | Map caller UID to root inside the namespace (for tools that check `getuid()==0`). |
| `use_egress_proxy` | `False` | Route outbound HTTPS through the RAPTOR proxy with a hostname allowlist. |
| `proxy_hosts` | `None` | Hostname allowlist for the egress proxy. Required when `use_egress_proxy=True`. |
| `restrict_reads` | `False` (`True` in `run_untrusted*`) | Flip Landlock to allowlist-only reads (blocks `$HOME`, custom paths). |
| `readable_paths` | `None` | Extra paths to add to the read allowlist. Ignored when `restrict_reads=False`. |
| `writable_paths` | `None` | Extra writable dirs (beyond `output` and `/tmp`) added to the Landlock write allowlist. |
| `fake_home` | `False` (`True` in `run_untrusted`) | Override child `HOME` + `XDG_*_HOME` to `{output}/.home/`. Requires `output`. |
| `exclude_tmp_baseline` | `False` | Drop the default writable `/tmp` from the write allowlist (only when you've provided your own scratch dir). |
| `etc_overlay` | `None` | Dict mapping in-sandbox `/etc/<path>` → host source file to bind-mount over it inside the mount-ns sandbox. |
| `caller_label` | `None` | Short identifier stamped onto every proxy event so concurrent callers are distinguishable in `proxy-events.jsonl`. |
| `tool_paths` | `None` | Extra dirs to bind-mount so a non-system tool's binary + deps are visible in mount-ns mode. Speculative: falls back to Landlock-only if the bind set is insufficient. See [internals](internals/sandbox-internals.md#mount-ns-tool-visibility). |
| `audit_run_dir` | `None` | Directory where audit JSONL lands. Decoupled from `output=` — does **not** add the dir to the Landlock write allowlist, so a hostile target can't inject false records. |
| `sanitise_host_fingerprint` | `False` | Spoof host identity surfaces (`/proc/cpuinfo`, `/etc/machine-id`, DMI, hostname, uname) toward a generic Debian/QEMU persona. Capability surface (CPU flags, kernel version, arch) is preserved. See [internals](internals/sandbox-internals.md#host-fingerprint-sanitisation). |
| `cpu_count` | `None` | With `sanitise_host_fingerprint=True`, the CPU count the persona presents. |
| `require_sanitisation` | `False` | Raise instead of warn if fingerprint sanitisation was requested but the host can't provide it. |
| `skip_pid_ns` | `False` | Advanced: keep the child in the parent's PID namespace instead of unsharing a fresh one. Used by the net-ns coordinator; not needed for normal calls. |

> **`env=` passthrough.** If you pass an explicit `env=` dict to `run()`, it is
> forwarded verbatim — `RaptorConfig.get_safe_env()` is NOT applied (logged at
> WARNING). `env=None` or omitting `env=` engages the safe-env path. Callers
> opting into custom `env=` own sanitising what they pass.

### Read restriction (`restrict_reads` + `fake_home`)

Under `run_untrusted()` both default to `True`. This is the primary defence
against credential exfiltration:

- `restrict_reads=True` — Landlock blocks reads outside the system-dir
  allowlist (`/usr`, `/lib`, `/lib64`, `/etc`, `/proc`, `/sys`, `target`,
  `output`, `/tmp`, and curated `/dev` files). `$HOME` is **not** on the
  allowlist. It also triggers a PID-namespace unshare, so cross-process
  `/proc/<host_pid>/environ` reads are denied — a compromised child can't lift
  `ANTHROPIC_API_KEY` out of the parent process's environment.
- `fake_home=True` — child's `HOME` and every `XDG_*_HOME` point at
  `{output}/.home/`, an empty directory created fresh per sandbox. Tools see no
  dotfiles.

Together:

- `cat ~/.ssh/id_rsa` → ENOENT (home is empty)
- `cat /home/user/.ssh/id_rsa` → EACCES (absolute path blocked by Landlock)
- `cat ~/.aws/credentials` → ENOENT

If a tool genuinely needs a config file, pre-populate the fake home before
calling, or extend the read allowlist:

```python
run_untrusted(
    cmd, target=repo, output=out,
    readable_paths=["/opt/jdk", "/var/cache/debconf"],
)
```

## Egress proxy

An in-process HTTPS-CONNECT proxy lets callers allow a specific set of
hostnames while blocking everything else. Use it when the tool needs one or two
API endpoints (Claude sub-agent, CodeQL pack download) but you don't want to
open the full network.

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

- A daemon thread runs a loopback HTTP-CONNECT proxy; the child env gets
  `HTTPS_PROXY`/`http_proxy` pointing at it (curl, pip, Java/CodeQL honour
  these).
- Landlock pins TCP `connect()` to the proxy's port; seccomp blocks
  `AF_INET`/`AF_INET6` `SOCK_DGRAM`, closing DNS-exfil.
- The proxy rejects any `CONNECT` to a host not on the allowlist, and screens
  resolved IPs (loopback/private/link-local/reserved rejected even if the
  hostname was allowlisted — DNS-rebinding defence). IP screening is skipped
  when an upstream HTTPS proxy is configured (the upstream resolves DNS).
- If `HTTPS_PROXY` is set in the parent env (corporate proxy), the RAPTOR proxy
  forwards its tunnels through that upstream; `NO_PROXY`/`no_proxy` honoured.
- The proxy is a process-wide **singleton**: concurrent callers share it and
  their hostname allowlists are **union'd** (no per-caller host isolation) — if
  sandbox A allows `api.anthropic.com` and sandbox B allows `ghcr.io`, both can
  reach both. Event observability, however, stays per-run.

**GHCR allowlist for CodeQL.** CodeQL pack downloads need the full GHCR host
set:

```python
proxy_hosts=[
    "ghcr.io",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "pkg-containers.githubusercontent.com",
]
```

## Audit mode (`--audit`)

`--audit` runs a workflow to completion **and** records what enforcement WOULD
have blocked, instead of blocking it. It's the soft-default alternative to
`--sandbox none` when `full` is too strict for a workload but you still want
visibility into the policy violations. Programmatic equivalent:
`sandbox(profile=..., audit=True)` / `run(..., audit=True)`.

`--audit-verbose` (requires `--audit`) flips the tracer from filtered
(would-be-blocked only) to strace-style (every traced syscall). `--audit-budget
N` overrides the record cap (default 10000).

| Invocation | Effect |
|---|---|
| `--sandbox full` (default) | full enforcement |
| `--sandbox full --audit` | full layout, but proxy gate logs-and-allows + tracer logs would-be-blocked syscalls + filtered fs/connect tracing |
| `--sandbox full --audit --audit-verbose` | as above but tracer logs EVERY traced syscall |
| `--sandbox debug --audit` | gdb-friendly seccomp + audit signal |
| `--sandbox network-only --audit` | only the egress-proxy gate audits (other layers off) |
| `--sandbox none --audit` | **error** — incoherent (nothing to audit against) |
| `--audit-verbose` without `--audit` | **error** — audit-verbose only controls tracer output |

Audit adds ~3.5x wall-clock over `--sandbox full` (per-call tracer setup
dominates short workloads). **Use it for diagnosis, not routine scans** — drop
`--audit` for production runs.

### Reading audit output

After a `--audit` run, inspect the run's output directory. Three states, each
distinguishable at a glance:

1. **Audit ran and recorded events** — `sandbox-summary.json` is present. Each
   entry carries `"audit": true` so you can filter would-have-been-blocked
   events from real enforcement:

   ```json
   {
     "total_denials": 2,
     "by_type": {"network": 1, "seccomp": 1},
     "denials": [
       {"cmd": "claude --model gemini-2.5-pro", "type": "network",
        "host": "evil.example.com", "port": 443, "audit": true,
        "suggested_fix": "audit: outbound network to `evil.example.com` would be blocked under `--sandbox full`"}
     ]
   }
   ```

2. **Audit ran, nothing would have been blocked** — no `sandbox-summary.json`
   and no degraded marker. This is success.

3. **Audit was requested but couldn't run** — `sandbox-audit-degraded.json` is
   present. Most often the Ubuntu 24.04 default
   (`apparmor_restrict_unprivileged_userns=1`) blocks the mount-ns/spawn path
   the tracer needs to attach. Network audit still works; syscall + filesystem
   audit silently degrade to enforcement. Follow the `instructions` field
   (set the sysctl to 0, install `uidmap`) and rerun.

## Recovering `sandbox-summary.json`

Commands driven through the run lifecycle (`/scan`, `/agentic`, `/codeql`,
`/validate`, `/understand`, `/fuzz`) aggregate every sandbox enforcement event
into `{run_dir}/sandbox-summary.json` at run-end, with a `suggested_fix` per
denial that references only operator-facing CLI flags (`--sandbox
{full,debug,network-only,none}`). It is written **only when at least one
enforcement denial was recorded** — a clean run (nothing blocked) produces no
summary file.

If a run dies before its lifecycle hook fires (hard kill, SIGKILL, OOM), the
intermediate `.sandbox-denials.jsonl` is left on disk and no summary is
written. Two recovery paths:

1. **Automatic** — the next time the same session re-runs the same command type
   (the Esc-then-retry pattern), `start_run` sees the prior run still at
   `status=running`, marks it failed, and finalizes the summary. No action
   needed.

2. **Manual** — for cases auto-recovery doesn't cover (different session,
   different command, host reboot):

   ```bash
   # Single run.
   libexec/raptor-sandbox-summary <run_dir>

   # All stranded runs under a project dir at once.
   libexec/raptor-sandbox-summary --sweep <project_dir>
   ```

## Observability

`sandbox_info` is attached to each `run()` return value:

```python
from core.sandbox import sandbox

with sandbox(target=repo, output=out, use_egress_proxy=True,
             proxy_hosts=["api.anthropic.com"]) as run:
    info = run(cmd).sandbox_info
    print(info.get("crashed"), info.get("signal"))   # termination reason
    print(info.get("sanitizer"))                      # asan/ubsan/msan/tsan
    print(info.get("blocked"))                        # enforcement events
    print(info.get("proxy_events"))                   # connect attempts
```

When `use_egress_proxy=True`, every CONNECT attempt is recorded (result is one
of `allowed`, `denied_host`, `denied_resolved_ip`, `dns_failed`,
`upstream_failed`, `timed_out`, `bad_request`, `handler_error`) and persisted
to `{output}/proxy-events.jsonl` when `output` is set. Each record:

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

`t` is `time.monotonic()` seconds (monotonic across clock jumps, **not** wall
time); `caller` comes from `caller_label=` when set.

For a `with sandbox(...)` block with multiple `run()` calls, each
`result.sandbox_info["proxy_events"]` holds that subprocess's own slice; the
**cumulative** list across every run in the block is exposed as `run.events`:

```python
with sandbox(use_egress_proxy=True, proxy_hosts=["api.example.com"]) as run:
    run(["curl", "https://api.example.com/a"])
    run(["curl", "https://api.example.com/b"])
    print(run.events)  # combined list covering both calls
```

## Troubleshooting

### "Mount namespace unavailable" on Ubuntu 24.04

Ubuntu 24.04 ships an AppArmor sysctl that blocks unprivileged user-namespace
mount operations. The sandbox still applies Landlock, seccomp, network/PID/IPC
namespaces, and rlimits — but it can't provide read-only bind mounts for
`target`/`output` or a fresh `/tmp`. Two prerequisites enable mount-ns:

```bash
# 1. Allow unprivileged user namespaces (no reboot needed)
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# 2. Install newuidmap/newgidmap (setuid-root helpers that write uid_map —
#    direct /proc/self/uid_map writes fail EPERM for unprivileged callers)
sudo apt install uidmap
```

With both in place, mount-ns engages automatically on the next `sandbox()` call
— no code changes, no profile flag. Without either, the sandbox silently falls
back to Landlock-only (writes restricted, reads wide unless
`restrict_reads=True`). Landlock alone already covers the main threat model;
mount-ns adds per-sandbox `/tmp`, invisible host paths outside the bind-mounts,
and stronger `/dev/shm` isolation.

### A target binary fails with EACCES reading `/home/<user>/...`

Tools that hardcode absolute paths under `/home/<user>/` (not `$HOME`) hit the
Landlock read-restriction even under `fake_home=True`. Either:

- add the specific path to `readable_paths=[...]`
- pre-populate the fake home and let the tool resolve via `$HOME`
- run under `sandbox()` with `restrict_reads=False` if the tool is trusted

### Shell scripts fail on `>/dev/null 2>&1`

`/dev/null` writes are permitted by a narrow Landlock rule. If you see EACCES on
`/dev/null`, you're likely on a kernel without Landlock ABI v3 (TRUNCATE) — the
probe warns. Upgrade to 6.2+.

### Rust `cargo build` fails at the linker stage

`std::process::Command` uses `socketpair(AF_UNIX, ...)` for its internal
error-reporting channel; the sandbox permits this. If you see EPERM on
`socketpair`, you're on a seccomp profile without the sandbox package's built-in
allowlist — check for a custom `seccomp` override.

### CodeQL "Failed to download pack"

The egress proxy allowlist needs the full GHCR host set — see the
[Egress proxy](#egress-proxy) section.

### Build tool reports "JDK not found" / missing toolchain

`get_safe_env()` strips language-specific vars like `JAVA_HOME`, `GOROOT`,
`RUSTUP_HOME`; RAPTOR auto-resolves them per build from filesystem layout
instead. If resolution fails, install the toolchain into a standard location or
extend the detector in `core/build/toolchain.py`. Mechanics:
[internals](internals/sandbox-internals.md#toolchain-env-for-builds).

## macOS backend

On Darwin the sandbox routes through `core.sandbox._macos_spawn` (using
`sandbox-exec(1)` + the kernel `Sandbox.kext` applying an SBPL profile) instead
of the Linux spawn path. **The kwarg surface is identical** — callers don't
switch on platform.

### What works the same

- `sandbox()`, `run()`, `run_trusted()`, `run_untrusted()` — same surface.
- `block_network`, `allowed_tcp_ports`, `use_egress_proxy`, `proxy_hosts` —
  translated to SBPL `(deny network*)` / `(allow network-outbound ...)` /
  loopback proxy allow.
- `target`, `output`, `writable_paths` — translated to SBPL `(deny file-write*
  (require-not (subpath ...)))`, realpath-canonicalised (macOS symlinks like
  `/var → /private/var`).
- `restrict_reads`, `readable_paths` — SBPL `(deny file-read* ...)` with the
  same system-dirs allowlist (`/usr`, `/System`, `/Library/Frameworks`,
  `/private/etc`, `/dev`).
- `fake_home` — env-side; same `HOME`/`XDG_*_HOME` redirection as Linux.
- `audit=True` / `--audit` — replaces the file-write deny with `(allow
  file-write* (with report))`; `seatbelt_audit.LogStreamer` reads `log stream`
  and appends records matching the Linux tracer schema.
- `limits=` — POSIX `setrlimit`. Sandbox-summary aggregation and
  `proxy-events.jsonl` are identical cross-platform.

### What's different (platform limits)

| Linux feature | macOS status | Why / mitigation |
|---|---|---|
| PID namespace | absent | No unprivileged equivalent. Host PIDs visible. |
| Mount namespace + pivot_root | absent | `restrict_reads=True` is the substitute (read-deny via SBPL). |
| `RLIMIT_NPROC` per-namespace | weaker | macOS rlimit is per-UID host-wide. Lower the limit on Darwin. |
| `seccomp_profile=full` | partial | Mapped to `(deny process-info* (target others))` — coarse. |
| `audit_verbose` (per-syscall) | partial | SBPL `(allow X (with report))` for an extended category set; coarser than seccomp, no argv. |
| `--audit-budget=N` | full | Same `audit_budget.AuditBudget` module on both backends. |
| `map_root` (UID re-mapping) | absent | macOS sandbox-exec keeps caller UID. |
| `--sandbox debug` (lldb) | full | Skips the process-info denies so lldb/sample/dtrace can attach. |

### macOS operator notes

- **First-run cost**: `sandbox-exec` is invoked once per process against
  `/usr/bin/true` to verify the kernel sandbox is functional (~50ms).
- **No `(deny default)`**: pure deny-default profiles SIGABRT modern macOS
  binaries before dyld loads libSystem. RAPTOR always uses `(allow default)` +
  targeted denies.
- **`/private/tmp`** is always added to the write-allowlist exception so
  `tempfile.mkstemp()` works (matches Linux's `/tmp` writable).
- **Audit log latency**: the kernel → `log stream` pipeline has ~tens-of-ms
  steady-state latency (~1.5s cold); very short workloads may drop the last
  record.

## Internals

The threat-model statement (what the sandbox does and does not protect against)
lives in the module docstring of `core/sandbox/__init__.py`. The deep mechanics
— isolation-layer composition, the pid-1 shim, the ptrace audit tracer, the
token-bucket audit budget, host-fingerprint spoofing, and the full module map —
are in [`internals/sandbox-internals.md`](internals/sandbox-internals.md).
