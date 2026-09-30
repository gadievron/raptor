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
  ioctls, raw/packet/netlink sockets, plus namespace creation on the
  fork-backend lane (`unshare` / `clone` with any `CLONE_NEW*` flag /
  `setns`; `clone3` returns ENOSYS) so a target cannot build a nested
  namespace to confuse the supervisor. The plain subprocess lane
  installs the same namespace-creation deny rules via its preexec —
  its payload never legitimately unshares. (The former unshare-CLI
  lane was the one lane that could not take them, because its own
  bootstrap had to `unshare` under the filter; it was deleted in
  favour of the fork backend.)
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
   loopback interface; no route out. The coordinator-internal
   `inherit_netns=` escape (paired-isolation runs that must stay in a
   shared isolated netns) is never silent: dropping a requested
   network block is stamped per run (`netns_inherited`), warned once
   per process, and refused for untrusted-contract calls.
3. **PID namespace** -- combined with a fresh in-namespace `/proc`
   mount, hides host PIDs and blocks cross-process
   `/proc/<pid>/environ` credential reads. The fresh mount is
   mandatory for untrusted runs: if it fails, the run aborts rather
   than exposing the host-pid process table (override with
   `RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1`). The spawn chain additionally
   zeroes credential values out of its own environment image, so
   even a host-procfs-visible degrade has nothing to read.
4. **IPC namespace** -- isolates SysV shm/sem/message queues.
5. **Mount namespace** -- per-sandbox `/tmp` and `/run`, host system
   dirs bind-mounted read-only, target and output bind-mounted at
   their original absolute paths. When a caller-supplied `/etc`
   overlay targets entries the host does not have, `/etc` becomes a
   private tmpfs populated by a budgeted copy of the host's (64 MiB /
   8192 entries, breadth-first so `passwd`, `hosts`, and TLS trust
   roots copy first; `/etc/skel` and non-regular entries are never
   copied). **Disabled on Ubuntu 24.04 by
   default** (AppArmor gates unprivileged user namespaces); see
   [Troubleshooting](#troubleshooting).
   If namespace creation succeeds but the bind tree cannot be built,
   trusted tool runs can keep the network, PID, IPC, fresh-proc, Landlock,
   seccomp, and rlimit layers through the mountless backend. Untrusted runs
   require the existing `RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1` opt-in.
6. **Landlock + seccomp-bpf + rlimits** -- always applied when
   available, even when namespaces fall back.

On kernels that lack any particular layer, the sandbox proceeds with the
remaining ones and emits a one-time warning. Nothing silently downgrades
to "no isolation".

**Landlock is fail-closed.** If installing the Landlock ruleset fails
in the child (kernel drift, ABI mismatch), the run never continues
unsandboxed. On the mount-ns spawn lane the failure reports through
the setup-status pipe and the parent raises a typed
`SandboxSetupError` (`setup_category` `"L"`) naming the failing step —
attributable, and unspoofable by a target that happens to exit 126.
On the preexec lane, where raising is not fork-safe, the child exits
126; the parent sees the non-zero return code plus a
`sandbox: Landlock ...` line on stderr explaining which step failed.

**Untrusted runs refuse to degrade silently.** On Linux hosts without
unprivileged user namespaces, untrusted execution fails closed with a
`SandboxSetupError` naming the host fix. Setting
`RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1` is the explicit operator acceptance
of Landlock/seccomp-only containment (see
[environment.md](environment.md)); every waived run warns that same-UID
`/proc` credential reads are not blocked in that mode.

---

## Containment floor

The sandbox enforces untrusted-execution requirements through a single
two-sided contract instead of per-lane checks. Execution lanes form a
total order of **containment tiers** per platform:

| Tier | Lane | Delivers |
|---|---|---|
| `mount-ns` | fork spawn backend | pivot_root bind tree, full namespace set, fresh procfs, Landlock, seccomp |
| `mountless-ns` | fork spawn backend, no bind tree | full namespace set, fresh procfs, Landlock, seccomp; host paths visible by name |
| `ns-only` | fork spawn backend, Landlock-absent mode | full namespace set, fresh procfs, seccomp; no Landlock filesystem/TCP policy (kernels without Landlock, floor-consented only) |
| `landlock` | plain subprocess | Landlock, seccomp, rlimits; host namespaces |
| `none` | plain subprocess | rlimits only |
| `seatbelt` | macOS `sandbox-exec` | SBPL write/read scoping, network denial, process-info denial (macOS's top tier; never compared to Linux tiers) |

Each call resolves a **floor** once at entry: untrusted work
(`run_untrusted*` and every caller passing the `require_fresh_procfs`
contract) floors at `mount-ns` on Linux and `seatbelt` on macOS by
default; the consent chain below can move it; trusted calls have no
floor (`none`) and keep their existing enforceability refusals; the
operator's explicit `--sandbox none` / `--no-sandbox` /
`disabled=True` remains globally authoritative (floor `none`) — and
the CLI spelling of that disable is itself consent-gated (see
[Disabling the sandbox](#disabling-the-sandbox)).
Nothing consents untrusted work to a bare run implicitly.

### Consent surfaces

The untrusted floor is resolved from one precedence chain (highest
wins):

```
--sandbox-floor <tier>  >  /project set sandbox-floor <tier>
                        >  RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1
                        >  WSL host-consent marker  >  default (refuse)
```

* **`--sandbox-floor {mount-ns,mountless-ns,ns-only,landlock,none}`**
  — per-run consent, parsed only from entry-point argparse (same
  prompt-injection posture as `--sandbox`). It works in **both
  directions**: `--sandbox-floor landlock` accepts
  Landlock/seccomp-only containment for this run's untrusted work on
  a host without user namespaces; `--sandbox-floor mount-ns` pins the
  full contract, overriding a project setting or the env waiver. Each
  value consents **exactly its named tier and nothing lower** — a
  lane below the consented floor still refuses. `ns-only` is the
  consent for Landlock-less kernels (namespaces, fresh procfs and
  seccomp still enforced). The value `none` is **not** a consentable
  untrusted floor: it parses, but untrusted-class work under it
  refuses loudly, naming the authoritative `--sandbox none` /
  `--no-sandbox` surface — untrusted work never runs bare by consent.
  Nested RAPTOR workers inherit the flag on their command lines (the
  `/agentic` sandbox passthrough); no environment variable expresses
  it, so target code can neither observe nor influence the consent.
* **`/project set sandbox-floor <tier>`** — the standing project
  surface (registry-validated; `none` is refused at `set` time).
  Consumed once at run start like the trust markers, with the same
  one-target rule (the consent applies only when the run's target is
  the project's target) and a banner line whenever it affects a run.
  Dispatched workers re-read it through their run-pin bootstrap.
* **`RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1`** — the legacy env var, kept
  indefinitely with a **frozen meaning**: untrusted floor :=
  `landlock` on Linux (it never reaches `none` there; on macOS it
  keeps its documented rlimits-only acceptance). All new consent
  semantics ship only on the explicit surfaces.
* **WSL host-consent marker** — a standing, host-scoped consent to
  exactly the `ns-only` tier for the one situation where that tier
  is the deliverable maximum: a WSL kernel without Landlock. Granted
  only through the TTY-gated `bin/raptor wsl-consent grant` ceremony
  and conditional at read time (inert off WSL, inert the moment the
  kernel gains Landlock, inert across a kernel-flavour change or on
  another machine, fail-closed on a corrupt record). Lowest
  precedence: it only ever replaces the default refusal — a floor
  any other surface chose, higher or lower, is never moved by it.
  Full semantics in [wsl.md](wsl.md).

When surfaces disagree, the explicit surface wins and a banner names
both sides and both values (e.g. a paranoid `--sandbox-floor
mount-ns` over a CI-wide env waiver refuses the degraded lanes and
says why). Floor refusals always carry the exact re-run remedies —
the flag spelling, the project spelling, and the env var — with the
honesty rule preserved: when an explicit surface pinned the floor,
the refusal says the env var will NOT relax it. In an unattended
session the refusal stands (fail closed); an interactive session may
offer the remedies as a structured choice, but never selects a floor
on the operator's behalf. The degraded-**network** acceptance is a
separate axis and stays env-var-only — a tier floor never consents
the network posture. The **seccomp-absence** acceptance is also
env-var-only in the lowering direction (no `--sandbox-floor` tier
waives a missing libseccomp — every tier's contract includes the
filter), and it is WITHDRAWN whenever an explicit surface pins a
floor: an operator who typed `--sandbox-floor mount-ns` gets the
full contract, filter included, even on a host where CI exported the
env waiver. Two reach notes: the project consumption is wired at the
run entry points and dispatch helpers that execute untrusted/target
code (`/agentic`, `/codeql`, `/fuzz`, their scanner and CodeQL-agent
workers, the `/audit` CLI, and the `/validate` helper); and the
construction-time Landlock-enforceability acceptance follows the
same chain for ALL calls (the env var's existing host-wide reach) —
an explicitly raised floor therefore also refuses that acceptance
for trusted policy-bearing calls on Landlock-less kernels.

Enforcement is two-sided: an entry-time check refuses
statically-knowable shapes up front with the full remedy text, and a
hard runtime assertion inside the **checked dispatch chokepoint** —
the only construct in the sandbox module that hands a command to an
executor — compares the lane's declared tier against the floor
immediately before invoking it. A demotion that would cross the floor
converts into a typed `SandboxFloorError` (a `SandboxSetupError`
subtype carrying `floor`/`achievable`/`setup_category`) chained to the
original backend failure. A future demotion lane routed through the
chokepoint therefore fails closed if it sits below the floor. Two
backstops guard the chokepoint itself: an AST executor gate in the
contract tests forbids in-module spawning outside it (bare
`subprocess.run`/`Popen`/`os.exec*` calls, module aliasing, and
direct spawn-callable imports all refuse), and a runtime dominance
stamp makes run()'s epilogue reject any result that did not pass
through the chokepoint — catching an executor added in another
module at its first use. In-process code that deliberately subverts
the module is outside the threat model — it is already the
orchestrator.

Every result stamps the posture: `sandbox_info["containment_tier"]`
(the tier the call actually ran at — per-call posture reductions such
as `skip_pid_ns`, which keeps the host procfs on both spawn lanes, cap
the stamp accordingly), `containment_floor`, and `floor_source`
(`default` / `flag` / `project` / `env` / `operator-disable`);
tracked runs merge the
weakest tier per run directory into `sandbox-summary.json`'s posture
record. When a consent surface lowers the floor, a one-line banner
names the surface, and every consented call that lands on a
reduced lane (`ns-only` or below) warns individually — naming the
host process table when the lane leaves it visible, or the missing
Landlock policy layer on the `ns-only` tier (which keeps a fresh
pid-ns procfs); the mountless fallback keeps its existing
once-per-process notice.

**What a floor refusal looks like at the verification seams.** The
attacker-payload executors — `/audit`'s dark-witness execution,
exploit execution (`--execute-exploits`), and the mitigation-profile
witness replay — map a floor refusal to a structured **unverifiable
environment** outcome instead of a hypothesis verdict: the finding's
record keeps its existing error-shaped vocabulary (a dark-verify
`verdict: "error"`, an execution outcome of `unknown`) and carries a
detail payload with `status: "unverifiable_environment"`, the required
`floor`, the `achievable` tier, and the operator `remedies`. The
semantics are record-then-raise: the refusal is host-deterministic, so
the first one records that verdict on the finding it was verifying,
prints one summary line (`1 execution(s) refused: environment cannot
meet the containment floor (mount-ns required, landlock achievable) —
remedies: ...`), and re-raises the typed error so the run fails loudly
rather than continuing to mint identical refusals. An unverifiable
environment is neither a confirmation nor a refutation — fix the host
(or consent to a lower floor) and re-run.

The refusal is also recorded at run level: whenever a floor refusal
fires for a call that has a run/audit directory, the sandbox appends
a `floor_refusal` record to the run's evidence stream, and
`sandbox-summary.json` then carries `total_floor_refusals`, the
structured `floor_refusals` records, and a `floor_refusal_line`
rendered in the same wording as the per-finding summary line — so a
run whose payload executions were refused is distinguishable from a
run that simply recorded nothing, even after the fact.

### Disabling the sandbox

`--no-sandbox` / `--sandbox none` is a **request** for tier `none`,
honoured only when the invocation carries a consent of matching
authority. Anything that can compose a command line reaches these
flags — including an LLM session assembling a `python3 raptor.py ...`
invocation from injected text — so the flag alone is not evidence an
operator chose a bare run. The ONLY consent source is the **minted
nonce**: `RAPTOR_NO_SANDBOX_NONCE` carries a nonce minted by
`core/sandbox/scripts/mint-no-sandbox-nonce`, backed by a fresh
(600 s), mode-0600, uid-owned consent file under the invoking user's
home. The env var alone grants nothing (it is plain composable data);
the file alone grants nothing (it stores only the nonce's digest).
Minting is a deliberate, attributable act. A live nonce is multi-use
within its window by design — one exported consent covers the spine
children that re-validate it independently — bounded by the TTL and
the uid-owned mode-0600 file checks. The refusal message points at
this section rather than quoting the runnable mint path: a refusal
that hands the refused composer a copy-pasteable mint command would
be a bypass recipe.

The operator lane is one mint per window:

```sh
RAPTOR_NO_SANDBOX_NONCE=$(core/sandbox/scripts/mint-no-sandbox-nonce) \
    python3 raptor.py scan --repo <path> --no-sandbox
```

There is deliberately **no interactive-terminal consent arm** — and
this is a behaviour change: a `--no-sandbox` command typed at a real
terminal (including an interactive session's `!`-passthrough lane)
now refuses unless a nonce was minted first. Terminal presence on the
process fds carries no authority because it is manufacturable: a
pseudo-terminal wrapper (`script -qec …`, Python `pty.spawn`) hands
any composed child real TTYs on stdin/stderr with no operator
present, and the signals that might distinguish a laundered pty from
an operator's terminal (session leadership, ctty coherence, pty age,
master-holder ancestry) are each either manufacturable by the same
composer or invalid on real terminal topologies (terminal
multiplexers and sshd hold the pty master from an ancestor position
exactly like a wrapper does). Requiring the mint converts the
cheapest bypass from an innocuous-looking wrapper into an explicit,
self-describing, artifact-leaving action.

Without a consent the run **refuses** — a single-line argparse error
(exit 2) naming the flag, the reason, and both escape hatches: the
mint route (by documentation anchor), and `--audit` for debugging
enforcement without going bare. The disable is never silently
re-enabled or downgraded; refusal preserves the operator's ability to
decide.

There is deliberately **no standing consent**: no project setting can
disable the sandbox (`/project set sandbox-floor` refuses `none`),
trust markers grant nothing here, and the nonce var is never part of
the safe-env allowlist — target-bound environments strip it, so
scanned code can neither observe nor replay a live consent. The strip
holds even on the keep-trust dispatch lane that keeps RAPTOR's own
markers: trust markers and disable-consent are different authorities,
and a dispatched child never inherits a live nonce.

What the gate honestly claims is **guardrail plus attribution**, not
a security boundary against same-uid code execution: a same-uid
unsandboxed composer can run the mint script itself. That is accepted
— with the programmatic `sandbox(disabled=True)` keyword deliberately
ungated, no userspace consent design stops same-uid arbitrary code
execution; the mint path is kept off the runtime and `libexec`
dispatch surfaces, is self-describing in any audit trail, and leaves
a durable consent artifact. And when a patient composer does present
a minted nonce it obtained that way, the stamp says `nonce`, which is
true (a mint happened and is on disk) — attribution stays honest even
in the abuse case.

An accepted disable is attributable after the fact:
`sandbox_info["disable_consent"]` on every run result names the
consent source (`nonce`), and the acceptance is
logged at WARNING with the same label. RAPTOR's own pipeline parents
that forward the flag to workers (the `/agentic` sandbox passthrough)
extend their already-accepted consent across the spawn boundary
automatically — consent extension is possible only from a process
that already holds one, never creatable from nothing.

The attribution persists past the process too: a run executed with an
accepted disable writes `sandbox-summary.json` even with zero denials
(nothing was enforced, so there is nothing else to write), carrying
`cli_sandbox_disabled: true` plus `disable_consent`, both bound into
the summary's integrity token — stripping or rewriting either field
reads as tampering on the verifying triage path. Operator CLIs
surface the record as a run-context line: `raptor-verified-outcomes`
prefixes its human summary with the disable and its consent source
(the `--json` output shape is unchanged — the annotation is
human-render only), and the scorecard `tool-evidence` join notes when
the validation run it is grading against executed unsandboxed.

The programmatic `sandbox(disabled=True)` keyword is unchanged: it is
not reachable from argv, and in-process code is already the
orchestrator.

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
`/opt/homebrew/bin/`) would be invisible (exit 127). The sandbox retries
through its namespace backend without the bind tree when a bind mount or
in-tree exec fails. This keeps the PID, user, IPC, and network namespaces,
fresh procfs, Landlock, seccomp, limits, and proxy bridge active. The result
reports `backend=landlock-pidns` and `mount_ns_active=false`; tracked runs also
write `posture.mountless_backend=true` in `sandbox-summary.json`. Callers can opt
tool directories in
(`--sandbox-tool-path`, or `tool_paths=` programmatically — with
`python_runtime_tool_paths()` auto-discovering the running Python's
runtime roots for Python tools). If the reduced namespace backend cannot
mount fresh procfs or apply Landlock, seccomp, or namespaces, the call fails
closed before the target executes. The fallback preserves the caller's read
policy. Host paths remain visible by name, including an `ENOENT` versus
`EACCES` filesystem-existence oracle. Landlock cannot block metadata changes
such as `chmod` outside the write allowlist. For read-restricted calls, every
mountless lane replaces the construction-time `/tmp` and `/dev/shm` write
grants with a private mode-`0700` scratch directory and points `TMPDIR`,
`TEMP`, and `TMP` at it. Explicit non-shared writable paths remain available.
Calls with
`restrict_reads=False` retain their historical writable baseline, which means
host `/tmp` and `/dev/shm` are writable when the bind tree is absent.
Untrusted runs therefore
require `RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1`. On Landlock ABI below 3,
where `truncate()` outside the write allowlist is not controlled, the
mountless backend is not achievable for untrusted or read-restricted
work at all: an unwaived untrusted run is refused at its containment
floor, and a waived (or trusted read-restricted) run continues down the
demotion ladder to a lane its floor admits — a lane whose weaker,
documented contract the consent covers — instead of retrying a
mountless lane whose write policy the kernel cannot enforce.

Declaring a directory via `tool_paths` is also how `$HOME`-resident
toolchains stay runnable: the sandboxed child's environment scrub
drops every home-rooted `PATH` entry, EXCEPT entries that equal or sit
under a declared `tool_paths` dir (matched by both the literal and the
symlink-resolved spelling). Declare `~/.cargo/bin` and a rustup
toolchain resolves by name inside the sandbox; leave it undeclared and
the entry is scrubbed, so the exec fails with ENOENT (exit 127).

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

### Request-line parser jail

The proxy never interprets a client's raw request-line bytes in its
own process. Those bytes come straight from sandboxed (potentially
compromised) code, so parsing them — the decode, the method split, the
host/port extraction — is delegated to a dedicated, long-lived worker
process that does nothing else. The proxy sends each raw line to the
worker and consumes only a small structured verdict, re-validating
every field (type, length, charset, range) before using it; a worker
that deviates from the protocol in any way is killed and respawned,
and the request that hit the deviation is refused.

The worker confines itself at startup, in layers:

- Every inherited file descriptor is closed except the single socket
  to the proxy; stdio is bound to `/dev/null`.
- Resource limits: a CPU budget that kills a runaway parse, an
  address-space cap, a file-descriptor cap, zero file writes, and
  zero forks.
- Landlock (when the kernel supports it): read-only access to its own
  code trees, no writes anywhere, no network.
- Requests carry unpredictable random ids, and the proxy checks for
  unsolicited buffered bytes before each send — a worker that
  pre-queues a forged verdict or volunteers data is killed rather
  than believed.

There is no inline-parse fallback. If no confined worker can be
spawned, the proxy refuses to start; if the worker becomes
unavailable mid-run, affected requests are answered `503` and
recorded as `parser_unavailable` events — the bytes are never parsed
in-process instead.

On kernels without Landlock the worker steps down to the remaining
layers (resource limits, descriptor hygiene, process isolation) and
says so loudly: a one-time warning at startup and a
`parser_jail_degraded` event in every registration's audit stream.
If Landlock is available but its policy fails to install, the worker
does not serve at all — that is a fault, not a degradation.

Method accounting is unaffected: the `requests_connect` /
`requests_non_connect` counters keep their historical meaning, fed by
a classification the worker returns with each verdict.

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
`upstream_failed`, `timed_out`, `bad_request`, `handler_error`, plus
`would_deny_host` in [audit mode](#audit-mode).

---

## LLM dispatcher response-scan jail

The credential-isolation dispatcher books spend-capped ("scoped")
token usage from the response bytes it relays — bytes sent by a
remote LLM backend and embedding model-authored text. Interpreting
them (SSE line splitting, JSON parsing, the truncation-recovery
scans) is delegated to a dedicated, long-lived worker process, the
same pattern as the [request-line parser
jail](#request-line-parser-jail): the dispatcher — the process
holding every provider API key — sends the bounded head/tail windows
it retained and consumes only a small structured usage verdict,
re-validating every field before the spend ledger sees it. A worker
that deviates from the protocol is killed and respawned; values an
honest worker could legitimately relay from a hostile upstream are
sanitised (model strings) or clamped (token counts) rather than
trusted. The worker self-confines exactly like the parser-jail
worker: descriptor hygiene, resource limits (CPU, address space,
zero writes, zero forks), and Landlock (read-only code trees, no
network) when the kernel supports it. Because scans recur for every
relayed response, the worker is also proactively recycled between
scans so its lifetime CPU budget never interrupts an honest run.

Unlike the parser jail, this jail degrades by HOST CAPABILITY —
never by input — through three tiers, announcing a step-down with
exactly one warning per process:

1. **Full jail** (`jail_landlock`) — process isolation, descriptor
   hygiene, sanitised environment, resource limits, Landlock.
2. **Jail without Landlock** (`jail_no_landlock`) — the kernel lacks
   Landlock: everything above minus the Landlock policy.
3. **In-process scan** (`in_process`) — the worker cannot run at all
   on this host (spawning keeps failing on a Landlock-incapable
   kernel): the scan runs in the dispatcher process via the same
   pure scan core, the pre-jail behaviour.

Every `child_token.spend` audit row records the serving tier in
`usage_scan_tier`.

On a kernel where Landlock IS available, an unspawnable or
unconfinable worker is a fault, not a degradation — the dispatcher
fails closed: scoped-token requests are refused `503` before any
upstream byte is spent, recorded as `usage_scan.unavailable` events
(relaying a spend-capped token's response unbooked would silently
disable the cap). Worker-token relays carry no scanner and are
unaffected, and the next scoped request retries the spawn under
backoff. The in-process tier is never used on a Landlock-capable
kernel, and never because a particular response crashed the worker:
a mid-scan worker death books that response as `scan_failed` — a $0
booking made loud with a warning and a `scan_failed` flag on the
spend row, mirroring the `unscanned_response` contract — and the
next scan is served by a fresh worker. The poison bytes are never
handed to an in-process parser.

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
keyctl, bpf, userfaultfd, io_uring, tty-injection ioctls, and — on the
lane that blocks it — namespace creation), which stay hard-denied even
under audit — and file opens / network connects that
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

`degraded_net_deny` means one specific thing: the per-call Landlock
TCP-connect deny-all engaged because no namespace backend could
deliver the requested network block. On seccomp-enabled profiles
(`full`, `strict`, `debug`), this fallback also engages a seccomp
filter blocking IPv4/IPv6 UDP socket creation, including DNS to the
host's recursive resolver. The same requirement applies after a
runtime namespace failure and during audit execution; audit does not
relax the UDP deny. If the profile expects seccomp but libseccomp is
unavailable, construction refuses with `SandboxSetupError` — the
Landlock-only fallback cannot close the UDP egress path without it.

Seccomp-less profiles (`network-only`) do not trigger this refusal:
they accepted reduced isolation at profile selection, so the fallback
engages Landlock TCP deny without the UDP block. The operator chose
that trade-off explicitly.

`degraded_net_deny=False` remains the explicit per-call acceptance of
open network on the fallback.

**Degraded-host escape hatches.** When the refusal fires (no
namespaces AND no working seccomp), the operator has several options:

- Fix the environment: enable user namespaces (`sysctl
  kernel.unprivileged_userns_clone=1`), or install/fix libseccomp.
- `degraded_net_deny=False` per-call: explicitly accept that UDP
  egress is open on this fallback.
- `profile="network-only"`: accept the weaker posture (Landlock TCP
  deny, UDP open) without a per-call opt-out.
- Docker hosts: run with `--privileged` (enables namespaces) or
  ensure libseccomp is installed in the image.

Trusted tool execution (`run_trusted()`, profile `none`) is never
affected — those profiles do not request network blocking.

Its ABSENCE on a proxied run
that resolved to the tier-2 `landlock_tcp` lane is a named contract,
not an oversight — on that lane the proxy port allowlist is the live
network policy and no deny-all engages, so read
`proxy_enforcement` (`"landlock_tcp"` there) for the delivered
network posture rather than inferring anything from the missing
deny stamp.

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
| `max_file_mb` | `~10240` (+ per-install jitter) | `RLIMIT_FSIZE` | Caps a single written file (10 GB accommodates debug builds and corpora). |
| `cpu_seconds` | `~3600` (+ jitter) | `RLIMIT_CPU` | Soft limit fires SIGXCPU 1s before the hard kill. |
| `nproc` | `~1024` (+ jitter) | `RLIMIT_NPROC` | Namespace paths count it against the ns-local uid (nobody = zero pre-existing processes). On the Landlock-only path (no user namespace) the same budget is applied as an absolute ceiling of current-same-uid-process-count + `nproc`, bounding fork bombs without counting the operator's unrelated work. The macOS seatbelt lane applies the same relative ceiling (count via `ps`; macOS `RLIMIT_NPROC` counts the user's processes host-wide), bounded by the kernel's silent `kern.maxprocperuid` clamp — macOS stores at most that value whatever is requested, so the lane requests the honoured number. |
| `nofile` | `~4096` (+ jitter) | `RLIMIT_NOFILE` | Bounds fd-exhaustion DoS; clamped to the inherited hard limit. `0` disables. |

Defaults carry a small deterministic per-install surplus (stable
within an install, different across installs) so the exact tuple is
not a published fingerprint; explicit operator overrides are used
verbatim.

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

### OS-capability degradation map

Sandbox behaviours — and the test families that exercise them — key on
truthful runtime probes, not on binary presence alone. When a
capability is genuinely absent the affected behaviour degrades by
design and the corresponding tests skip with the missing capability
named (never error); everywhere the capability exists they run
unchanged.

| OS capability | Sandbox behaviour it gates | Tests |
|---|---|---|
| Unprivileged user namespaces, incl. the staged second pid-ns unshare | namespace backend selection (network/PID/IPC isolation) | `requires_userns` families |
| `unshare(CLONE_NEWNS)` + `mount(2)` in an owned userns, plus `newuidmap`/`newgidmap` | mount-ns tier: bind tree, fresh `/tmp`, read-only root | `requires_mount` families |
| Landlock (ABI v4+ for the degraded TCP-connect deny) | filesystem confinement; network deny fallback | `requires_landlock` families |
| subuid/subgid-range id-maps — impossible inside an unprivileged NESTED user namespace (rootless container, namespaced test runner): the range is unmapped in the writer's namespace, so the kernel refuses the write regardless of `/etc/subuid` or the setuid helpers | rootfs (image) mode's range map; setup fails closed, and the error names the nested-userns cause when detected | rootfs E2E family probes the exact `newuidmap` invocation up front and skips with the reason |
| A FOREIGN (root-owned) init user namespace — absent when pid 1 is the runner's own init inside a nested userns | none (refusal-test posture only) | foreign-namespace refusal tests (pytest and the C harness pid-1 case) skip when pid 1's userns is self-owned |
| A promptly-reaping init for re-parented orphans — a pid-namespace init that never `wait()`s keeps killed orphans visible as zombies | none (process-teardown observability only) | kill/reap tests read `/proc/<pid>/stat` state, so dead-but-unreaped counts as killed (hermetic — no skip) |

---

## Supervised process trees (not a sandbox)

RAPTOR sometimes needs a long-running helper -- an analysis server, a
JVM, a tool daemon -- that must reliably disappear when it is stopped
or when the RAPTOR process that owns it dies, taking every descendant
it spawned with it. `core.sandbox.supervised.spawn_supervised()` is
that primitive: a teardown domain, **not a security boundary**.

A supervised tree gets **no confinement of any kind** -- no Landlock,
no seccomp, no filesystem or network policy. The helper runs with the
caller's full ambient authority. Anything untrusted belongs under the
sandbox profiles above, never under supervision alone.

Two tiers, selected automatically:

- **pidns** -- the tree runs in its own PID namespace with a minimal
  init process. Stopping the tree, or the owner's death (in `kill`
  mode), collapses the namespace: the kernel itself guarantees no
  descendant survives, including double-forked daemons. Optionally a
  private network namespace (loopback only) can be added. Namespace
  setup writes the deny-setgroups sequence and identity uid/gid maps
  (`_ns_setup`), so the tree's effective uid is always mapped in its
  user namespace: workloads inside may themselves create nested
  namespaces where host policy allows -- an unmapped euid would make
  a nested `unshare(CLONE_NEWUSER)` fail with EPERM.
- **group** -- on hosts where unprivileged user namespaces are
  restricted, the same call degrades -- loudly (a logged warning
  names the refusal and the weaker teardown scope), never a crash --
  to a plain process group with parent-death kill: the exact posture
  RAPTOR tool spawns already had, so nothing gets worse. This tier's
  honest gap: a descendant that leaves the process group (setsid, a
  double-forked daemon) is invisible to group-scoped teardown and
  survives it. Callers that need the namespace guarantee pass
  `pid_ns="require"`, which refuses instead of degrading.

  The group tier's kill verification reads `/proc`, so it defends the
  evidence it reads: each scan holds one private fd on
  `/proc/self/mounts` (checked to really be procfs where `fstatfs` is
  available), which latches the kernel's mount-event signal for the
  whole scan window. Any mount-table change during the scan --
  including an overmount attached and detached entirely between the
  scan's own reads -- marks the scan occluded instead of trusted;
  occluded scans are retried on a fresh fd a bounded number of times,
  then refuse loudly. This NARROWS the `/proc`-masking channel, it
  does not close it: a hidepid-class superblock flip made from a
  sibling mount namespace does not fire the mount-event signal (a
  persisting flip is still declared by the scan's ordinary reads, and
  the channel is bounded to cross-uid group members), and fully forged
  `/proc` content served through an undetected mask remains out of
  scope for a `/proc`-based proof. On kernels without the mounts poll
  hook the signal simply never fires and behaviour is unchanged from
  the pre-latch posture. A co-resident able to churn mounts (for
  example via a setuid FUSE helper) can delay or force loud refusal of
  verification, never a silent false verify -- and kills themselves
  are never suppressed by occlusion.

Every spawn states its fate explicitly: `on_parent_death="kill"` ties
the tree's lifetime to the owning process; `"survive"` lets it outlive
the owner (for shared servers that later runs reattach to). Teardown
is verified, never assumed -- on the pidns tier a stop call returns
only once the kernel has proven the tree empty; on the group tier the
proof is scoped to the process group (see the gap above). On either
tier, a stop that cannot prove its claim reports an error and leaves
the handle retryable.

Because supervision is not a sandbox, it appears in none of the
profile or containment-floor tables above, and no consent surface
applies to it.

---

## Toolchain env for builds

Environment sanitisation deliberately strips language-specific vars
like `JAVA_HOME`, `GOROOT`, `DOTNET_ROOT`, `RUSTUP_HOME`. Build
subprocesses get those auto-resolved from filesystem layout at build
time instead — and only the build subprocess sees them.

If a build tool still fails with "JDK not found" or similar: install
the toolchain into a standard location for your distro.

---

## Host-fingerprint sanitisation

Opt-in (`sandbox(..., sanitise_host_fingerprint=True)`): the mount-ns
child bind-mounts canonical files over the host's identity surfaces
(`/proc/cpuinfo`, `/proc/version`, `/etc/os-release`,
`/etc/machine-id`, `/etc/hostname`, DMI vendor/product, UTS
nodename/domainname, CPU affinity) so a hostile target that
fingerprints its environment sees a boring Debian 12 cloud VM on
QEMU/KVM instead of analysis infrastructure. The `/etc/passwd` and
`/etc/group` tables are replaced with neutral stubs, so the operator's
username never reaches the target. Capability surfaces stay real (CPU
flags, kernel release, arch, mitigation sysctls) so exploit
feasibility analysis keeps working. The persona defaults to claiming
4 CPUs; pass `cpu_count=HOST_CPU_COUNT` to expose the real count for
parallelism-hungry targets.

The persona only exists on the full mount-ns lane. On a demoted
(Landlock-only) lane it cannot apply: by default the run proceeds with
a one-shot WARNING; with `require_sanitisation=True` it refuses
instead of degrading silently. Linux only — on macOS
`is_supported()` is False and callers soft-degrade with a warning.
Known residuals (direct `cpuid` execution, `AT_HWCAP`) are documented
in `core/sandbox/fingerprint.py`.

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

## Host and network perimeter

RAPTOR's sandbox isolates individual subprocesses — it cannot secure
the host it runs on. The sandbox is one layer of defence in depth;
the layers below it are the operator's responsibility.

### Dedicated execution environment

Run RAPTOR inside a dedicated VM or container whose compromise does
not grant lateral movement to production systems, developer
workstations, or credential stores. Treat the analysis host as
disposable infrastructure.

### UID hygiene

The UID running the Claude Code session (and therefore RAPTOR) should
be an unprivileged, purpose-specific account:

- Not in `sudoers`, `wheel`, `docker`, `lxd`, `disk`, `adm`, or any
  group that grants privilege escalation or raw device access.
- No `NOPASSWD` sudo rules. No polkit authorisations.
- No access to host credentials (`~/.ssh`, `~/.aws`,
  `~/.config/gcloud`, `~/.kube`). The sandbox blocks reads from
  inside sandboxed children; the UID having no access in the first
  place closes the gap for unsandboxed processes in the same session.
- Home directory should contain only the analysis workspace — nothing
  else of value.

### Mandatory access control

Confine the session UID with SELinux or AppArmor:

- **SELinux:** a dedicated type (e.g. `raptor_t`) with a policy that
  denies network connect except to the egress proxy port, denies
  write to anything outside the workspace and `/tmp`, and denies
  transitions to privileged domains.
- **AppArmor:** a profile that achieves the same — deny network,
  restrict filesystem writes, deny capability acquisition and
  mount/ptrace.

MAC enforcement is orthogonal to RAPTOR's own Landlock/seccomp
filters and stacks with them. It catches anything that escapes the
process-level sandbox or runs outside it.

### Network egress controls

RAPTOR's egress proxy and seccomp UDP block operate inside the host.
A compromised process that escapes the sandbox can bypass both.
Network policy must be enforced at a layer the host cannot subvert:

- **Upstream HTTP proxy (recommended).** Set `HTTPS_PROXY` to a
  corporate or infrastructure proxy with a default-deny allowlist.
  RAPTOR's egress proxy honours `HTTPS_PROXY` and tunnels through it
  transparently. The upstream proxy becomes the network-level
  chokepoint — only explicitly allowed destinations are reachable,
  regardless of what happens on the analysis host.
- **Host firewall.** Apply iptables/nftables rules or a security
  group that drops all egress except to the upstream proxy (and SSH
  for operator access). Deny DNS directly from the host — force it
  through the proxy's resolver.
- **Network-layer enforcement.** The firewall or proxy should run on
  a device or system outside the analysis host itself. Rules applied
  only inside the host are bypassable by anything running as the
  same UID or as root.

### Kernel hardening

- Keep the kernel patched.
- Enable unprivileged user namespaces where possible — RAPTOR's
  strongest isolation tier (mount-ns + PID-ns + network-ns) requires
  them.
- Disable or restrict `bpf()`, `userfaultfd`, `io_uring` at the
  sysctl level. The sandbox's seccomp filter blocks these per-child,
  but a host-wide restriction covers processes outside the sandbox.

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

If user, network, PID, and IPC namespaces are available but bind mounts
fail, the sandbox retains those namespaces and uses Landlock read/write
rules in place of the bind tree for trusted tool runs. Host paths remain
visible by name and metadata-only operations are outside Landlock's control.
Untrusted execution refuses both this tier and the namespace-less fallback.
Consent to the reduced containment only explicitly: `--sandbox-floor
landlock` (this run), `/project set sandbox-floor landlock` (standing
for the project), or `RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1` (host-wide;
see [environment.md](environment.md)).

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

## Namespace supervision outside the sandbox

The sandbox is not RAPTOR's only namespace user. The Joern analysis
server boots inside its own private network namespace (its TCP port
and per-boot credential are reachable only through a unix socket the
forwarder owns), and on hosts that allow it the same single unshare
call also creates a pid namespace: the forwarder then supervises the
whole server tree, so one verified kill of one process tears down the
JVM and every helper with kernel-guaranteed delivery instead of
process-group enumeration.

This is process-tree containment for one of RAPTOR's own trusted
services, not the security sandbox this document describes — no
Landlock, seccomp, or filesystem confinement applies to the Joern
server through it.

Capability degradation is automatic and visible, never fatal: the
kernel is probed before the tier engages (the verdict is cached for
the process's lifetime and re-probed only after a runtime refusal);
a pid-namespace refusal (common under
the same AppArmor userns gating covered in
[Troubleshooting](#troubleshooting)) degrades that server to
process-group supervision; and every boot logs one posture line
(`Joern server supervision tier: pidns` or `group`) naming the tier
actually achieved — plus the refusal reason when a runtime refusal
forced the degrade.

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
