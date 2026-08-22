# Environment Variable Reference

**Related documentation:**
[Configuration](configuration.md) |
[LLM Providers](llm.md) |
[Sandbox](sandbox.md) |
[SAGE](sage.md) |
[Security](security.md)

Canonical registry of every environment variable RAPTOR reads or
writes. When a change introduces a new variable, add its row here in
the same change — subsystem docs carry the explanatory prose; this
file is the index. A daily CI check
(`.github/scripts/check_env_docs.py`) extracts the variable inventory
from the tree and fails on undocumented operator-facing variables and
on documented variables that no longer exist in code.

Conventions used below:

- **Precedence** is per-run flag > environment variable > config file
  \> built-in default, unless a row says otherwise. The known
  exceptions are called out explicitly (worker caps, model selection).
- **Fail direction** for toggles: *fail-closed* means the unset/invalid
  state is the restrictive one; *fail-open* means it is the permissive
  one.
- **Boolean toggles** parsed through the shared parser
  (`core.config.env_flag`) accept `1`/`true`/`yes`/`on` and
  `0`/`false`/`no`/`off` (case-insensitive, whitespace-trimmed);
  unset/empty means the row's default and any other spelling warns and
  uses the default. Rows below say "shared toggle spellings" for these.
  Toggles not yet on the parser state their accepted spellings per row.


## Core runtime

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_OUT_DIR` | `out/` under the repo | Output-directory root override. Validated fail-closed by `RaptorConfig.get_out_dir()`: refuses paths under `/etc /usr /bin /sbin /boot /dev /proc /sys` (checked on both the literal and symlink-resolved path, component-boundary matched) and refuses paths whose parent does not exist (typo guard). Propagates to children via the safe-env allowlist so `raptor-run-lifecycle` resolves the same directory. |
| `RAPTOR_CONFIG` | `~/.config/raptor/models.json` | Path to the models config consumed by `core.llm` (`{"models": [...]}` or a bare list; `//` comments allowed). This variable belongs to `core.llm` alone: `packages/exploit_feasibility` historically read the same name for its *analysis-settings* JSON but cut over to `RAPTOR_EF_CONFIG`. Both readers keep schema guards for stale environments: `core.llm` logs an error (once per path) and loads zero models when the file is AnalysisConfig-shaped; `exploit_feasibility`'s `from_file` raises `ValueError` when the file is models-config-shaped. Both messages name the right variable. |
| `RAPTOR_TARGET_KIND` | auto-detect | Target-classification override: `library`, `hybrid`, or `application` (consumed by `core.inventory.library_detection`; any other value falls through to auto-detection — fail-open to auto). Prefer `/project set target-kind` or the per-run flag; programmatic setting > env > auto. Allowlisted so child inventory rebuilds honour it. |
| `RAPTOR_SESSION_PID` | set by `bin/raptor` | The launcher session's PID — one half of the session identity credential that lets deep children (skill dispatches, nested `claude -p` subagents, PID-namespace-blind helpers) resolve this session's project binding in `~/.local/share/raptor/sessions.d/`. Validated on every read: digits, the paired token must match the 0700 registry entry (constant-time compare), and the entry's identity stamp (starttime + boot_id + pidns) must match the live process — a recycled or guessed PID resolves nothing. Never set it by hand; stripped from every target-bound sandbox env (`TARGET_ENV_STRIP_SET`). |
| `RAPTOR_SESSION_TOKEN` | set by `bin/raptor` | The launcher-minted random token paired with `RAPTOR_SESSION_PID` — makes the env credential unforgeable against env injection (an attacker able to write the 0700 registry already owns every project file, so the pair grants nothing new). Same strip rule: target code never sees it. |
| `RAPTOR_LOG_FILE_LEVEL` | `INFO` | Level of the per-process JSONL audit-log file handler (`core.logging`). Any `logging` level name, case-insensitive; unknown names fall back to `INFO` rather than erroring during bootstrap. `DEBUG` opts into the full firehose. |
| `RAPTOR_TMP_REAP_MAX_AGE_H` | `24` (hours) | Age floor for the best-effort sweep of orphaned RAPTOR temp artifacts in `$TMPDIR` (`core.run.tmp_reaper`; known RAPTOR prefixes, a few anchored third-party tool names RAPTOR's own tool runs strand — e.g. `semmleTempDir*`, `scala-repl-pp*` — and the neutral de-branded scratch names (`.scr-*`, `.fp-*`) anchored to their exact random suffix; same-euid, live-process-safe). `0`/negative disables; non-numeric falls back to 24 h (sweep still runs); values below 0.5 h clamp to 30 min with a warning (a shorter floor could reap a live sandbox's scratch between its keepalive refreshes). |
| `RAPTOR_WORK_DIR` | unset (falls back to `$TMPDIR`, then `/tmp`) | Base directory for RAPTOR's own work tree `<base>/raptor-<uid>/session-<pid>-<rand>/`. Consumed in two places with the same precedence: the `bin/raptor` launcher uses it as the per-session `TMPDIR` base, and `core.run.workdir.exec_workdir()` uses it when a process runs *outside* a launcher session so RAPTOR-executed temp artifacts (dark-verify witnesses, dynamic-sweep harnesses, PoC compile stubs, toolchain probes) still consolidate under the one family instead of scattering across the temp root. Gives operators a single stable prefix for endpoint-security (EDR) exclusions — see "Running under endpoint security / EDR" in docs/troubleshooting.md. The dir must be on a filesystem the current user owns a 0700 `raptor-<uid>/` dir on; symlinked or foreign-owned family dirs are refused (falls back to the plain temp dir, i.e. prior behaviour). No effect on sandbox policy or on where TARGET code runs. |
| `RAPTOR_RUN_REAP_MAX_AGE_D` | `30` (days) | Age floor for reaping run directories whose status is `failed`/`cancelled` only — completed runs are never age-reaped. `0`/negative disables; non-numeric falls back to 30 d. |
| `RAPTOR_LOG_REAP_MAX_AGE_D` | unset = disabled | **Opt-in** sweep of old JSONL audit logs. Unlike the two sweeps above, this one defaults OFF and a non-numeric value leaves it off — deleting audit data is an operator decision. |
| `RAPTOR_REACH_VERDICT_LOG` | `$RAPTOR_DIR/out/reach_verdict_log.json` | Path override for the privacy-bounded reachability-verdict telemetry sidecar (`core.analysis.reach_verdict_log`; only language/verdict counts). |
| `RAPTOR_REACH_VERDICT_LOG_DISABLED` | unset | Any non-empty value disables reach-verdict telemetry recording (checked per call). The test suite sets it globally in `conftest.py`. Telemetry failures never affect analysis. |
| `RAPTOR_BINARY_CACHE_DIR` | `<repo>/.cache/binary` | Location of the build-ID binary cache (`core.audit.build_id_cache`). Explicit `cache_dir` argument > env > default. Set to share the cache across hosts/tools. |
| `RAPTOR_HITL_TTY_MAX_AGE_S` | `86400` (24 h) | Recency threshold for the human-attended probe (`core.security.rule_of_two`): the controlling TTY must show read activity (atime) within this many seconds for the session to count as human-attended. `<= 0` disables the recency check (pure TTY-presence, the pre-fix behaviour); non-numeric falls back to the default with a warning. |
| `RAPTOR_SELFTEST_MODEL` | unset | Default for `raptor-self-test --model` (budget-capped LLM cases). Flag > env > RAPTOR's own model resolution. |
| `RAPTOR_REGISTRY_ALLOW` | unset | Comma-separated registry authorities (URL-ish forms accepted; Docker Hub aliases collapse to `docker.io`) added to the manifest-probe allowlist in `core.container.registry`. By default `docker manifest inspect` probes only the candidate cascade's six public registries; refs carrying any other authority (including agent-influenced `product` strings that smuggle one) classify `denied` without network contact. Explicit ports are part of the authority: `localhost:5000` allowlists exactly that endpoint, and a port-bearing ref (`quay.io:8080/...`) never inherits the bare host's allowlisting. The `CVE_ENV_DENY_REGISTRY` denylist still applies on the cve-env cascade. |
| `RAPTOR_NONINTERACTIVE` | unset | Explicit non-interactive override for the AskUserQuestion interactivity gate (`core.ux.interactivity`, consulted via `libexec/raptor-may-ask`). Any truthy value forces the `non-interactive` verdict, so sessions apply the documented default behaviour instead of presenting structured operator prompts. Stamped `=1` into every `claude` CLI child RAPTOR spawns (`core.llm.cc_adapter.cc_subprocess_env`) — dispatched sub-agents are unattended by definition. Falsy spellings (`0`, `false`, `no`, `off`) are ignored; without the override the gate falls through to `rule_of_two.is_ci()`, the std-fd TTY predicate, and the rule-of-two human-attendance probe, failing closed. |
| `RAPTOR_CI` | auto-detected | CI-posture marker for the rule-of-two interactivity gate (`core.security.rule_of_two`). Normally parent-stamped: `get_safe_env()` writes `RAPTOR_CI=1` into every sanitised child env whenever the parent judged itself in CI, so the gate keeps working in children whose scrubbed env lost the vendor markers (`CI`, `GITHUB_ACTIONS`, ...). It is also the first — authoritative — entry in the recognised-marker list, so an operator may set `RAPTOR_CI=1` to force CI posture on any host. The whole marker set is unioned into `SAFE_ENV_ALLOWLIST`, so the verdict survives further spawns. |
| `RAPTOR_NO_LAUNCHER_HARDENING` | unset | Any non-empty value skips the `bin/raptor` exec-boundary hardening block entirely: the soft core-dump cap, the umask floor (current \| `022`), the PATH scrub (empty / relative / world-writable entries), the world-writable-ancestor warning on the resolved `claude`, and the per-session TMPDIR (creation and stale-sibling sweep). Single opt-out for environments that legitimately violate one of the checks. Fail-closed: unset means hardening runs. |
| `RAPTOR_ALLOW_UNSAFE_PATH` | unset | Any non-empty value makes the launcher PATH scrub KEEP entries it would otherwise drop (empty, relative, world-writable dirs), each with a stderr warning naming the entry and reason. Escape hatch for hosts where a required tool lives under a loose directory. Only consulted while the hardening block runs (no effect under `RAPTOR_NO_LAUNCHER_HARDENING`). |

### `RAPTOR_ALLOW_UNSANDBOXED_TOOLS`

The sandbox waiver, and the only variable that weakens an isolation
guarantee. Policy point: `core.run.sandbox_policy`; honoured by the
Joern and hypothesis-validation tool runners at their
sandbox-import seams.

When `core.sandbox` cannot be imported, tool runners **fail closed**:
they raise `SandboxUnavailableError` naming the remedy, and the tool
does not run. Setting `RAPTOR_ALLOW_UNSANDBOXED_TOOLS=1` (exactly the
string `1`; anything else stays closed) waives that: the runner falls
back to a bare `subprocess.run` with **no isolation**, emits a loud
warning, and records an `unsandboxed_tool_fallback` security event in
the audit trail. Intended only for dev hosts where the sandbox's
platform prerequisites are genuinely absent *and* the input is
trusted. Never set it when scanning untrusted repositories.

### `RAPTOR_ALLOW_DEGRADED_UNTRUSTED`

The other isolation waiver, scoped to the untrusted entry points.
Policy point: `core.sandbox.context._require_userns_or_optin`,
checked by `run_untrusted()` and `run_untrusted_networked()` on
Linux (macOS is exempt — the seatbelt tier provides the contract
there).

The untrusted-execution contract's credential-exfil defence is the
PID/user namespace: without it the child runs as the caller's uid in
the **host** namespaces, where `/proc/<pid>/environ` of same-UID
processes is readable. On hosts that cannot create unprivileged user
namespaces the entry points **fail closed** with a
`SandboxSetupError` naming the host fix. Setting
`RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1` (`1`/`true`/`yes`/`on`,
case-insensitive) is the explicit operator acceptance of
Landlock/seccomp-only containment on that host; every waived run
emits a loud warning that same-UID `/proc` credential reads are not
blocked in this mode. The waived posture also leaves the HOST
process table readable, including the command lines of any running
RAPTOR orchestrator — a framework-attribution channel no
anti-fingerprint masking can close while the host `/proc` is
visible.

The same override also waives the **fresh-procfs requirement** on
namespace-capable hosts: untrusted runs mount a pid-namespace-local
`/proc` inside the sandbox (hiding the host process table and the
spawn chain's own environ images). The requirement binds everywhere
the contract would otherwise silently degrade: a failed fresh-proc
mount aborts instead of warning, a mount-ns setup failure refuses
the Landlock-only retry, hosts whose mount-namespace backend cannot
engage at all (`newuidmap` missing) refuse untrusted runs up front,
and so do the pre-flight demotions (a tool resolving outside the
mount-ns bind tree — pass `tool_paths=` — a speculative-failure
cache hit, `skip_mount_ns=`, and `pass_fds=`) — each with a
`SandboxSetupError` naming this override. Witness bytes passed via
`input=` do NOT degrade the lane: they convert to a private unlinked
stdin spool and ride the fork backend. `--sandbox none` remains
authoritative: an explicitly disabled sandbox is the operator's
global escape hatch, not a silent degrade. When the override waives
a refusal that lands the run on a host-procfs-visible lane — the
no-backend refusal, or a per-call `pass_fds=` demotion — every
affected untrusted run logs a WARNING. With the override set, those
runs proceed with the old warn-only degrade. Two bounds on the
waiver: on a kernel with no Landlock at all, "Landlock/seccomp-only
containment" does not exist, so a demoted call that declared a
filesystem/TCP policy (`target=`/`output=`/`allowed_tcp_ports=`/
`restrict_reads=`) still refuses; and the override DOES extend to
the `block_network` refusal on hosts missing both the namespace
backend and Landlock ABI v4+ — accepting it there means accepting
UNRESTRICTED network for those runs, and the warning says so (the
narrower per-run escapes are a profile without the network block,
e.g. `--sandbox target_run`, or `degraded_net_deny=False`).

Distinct from `RAPTOR_ALLOW_UNSANDBOXED_TOOLS`, which waives a
*missing sandbox module* at the tool-runner import seam — this one
waives a missing *namespace tier* inside an otherwise-working
sandbox. Neither implies the other.

### `RAPTOR_MATRIX_RESULTS` and `RAPTOR_MATRIX_APT_MIRROR`

Knobs for the sandbox feature-matrix harness
(`core/sandbox/scripts/feature-matrix/run-matrix.sh`, weekly CI wrapper
`.github/workflows/sandbox-matrix.yml`). `RAPTOR_MATRIX_RESULTS` sets
the base directory for run results (default:
`${RUNNER_TEMP:-/tmp}/raptor-sandbox-matrix` — deliberately outside
the repository; results are never committed).
`RAPTOR_MATRIX_APT_MIRROR`, when set, replaces the apt sources inside
the lane image builds — for build environments where the default
Ubuntu archives are unreachable. Both are read from the calling
environment only; nothing in the harness hardcodes hosts.

### Housekeeping asymmetry

The three reaper knobs deliberately disagree on invalid input: the
tmp and run sweeps fall back to their defaults (sweeping is safe),
while the log sweep disables itself (audit data biases toward not
deleting).


## LLM model selection and transport

These knobs are covered in full in [LLM Providers](llm.md)
— Claude Code transport, Bedrock opt-in/authentication/region, and
cost management. `models.json` entries beat every env knob for model
selection.

### Claude Code transport (`RAPTOR_CC_*`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_CC_MODEL` | unset | Pin the model for the claudecode transport (passed verbatim to `claude -p --model`). Unset: cached probe identity, then the session default. |
| `RAPTOR_CC_PIN_MODEL` | `1` | Exactly `0` disables probe-based model pinning (children then inherit the CLI session default). Other spellings still pin. |
| `RAPTOR_CC_FALLBACK_MODEL` | unset | Emitted as `claude -p --fallback-model` — CLI-native retry when the primary model is overloaded. |
| `RAPTOR_CC_EFFORT` | unset | Emitted as `claude -p --effort`; valid `low\|medium\|high\|xhigh\|max`. Invalid values warn and are ignored (CLI default applies). |
| `RAPTOR_CC_BUDGET_USD` | `5.00` | Per-**call** abort ceiling (`--max-budget-usd`) for the claudecode provider — not the run budget (that is `--max-cost`). Non-numeric warns and uses the default. |
| `RAPTOR_CC_MAX_WORKERS` | `4` | Claudecode subprocess concurrency cap, clamped 1–32. **Precedence inversion:** `tuning.json max_llm_workers` beats this env var. |
| `RAPTOR_CC_PROBE_CACHE` | `~/.raptor/cache/cc-probe.json` | cc-probe cache path override. Read **once at import** — set before launch; changes after `core.llm` imports are ignored. |
| `RAPTOR_CC_PROBE_WARM` | `1` | Exactly `0` skips the run-start probe warm (one tiny `claude -p` call). Auto-skipped under pytest and on non-claudecode providers. |
| `RAPTOR_CC_CALIBRATE_NETWORK_PROBE` | off | Exactly `1` opts the sandbox-calibration probe into a real (token-billing) network call so calibrated `proxy_hosts` populate; requires an auth signal (`ANTHROPIC_API_KEY` or a `CLAUDE_CODE_USE_*` flag), else silently falls back to `claude --version`. |
| `RAPTOR_CC_TRANSPORT_DISABLED` | unset | Anything but `0`/empty refuses every **billed** `claude` spawn (dispatch and the live pre-flight probe) at the exec chokepoint with a named `RuntimeError` — no CLI process, no spend. Detection, model selection and mock-driven transport code are unaffected. The pytest root conftest sets it for every test session unless `RAPTOR_TEST_LIVE_LLM=1`: live-LLM invocation from tests is explicit opt-in, never a side effect of running a tier. |
| `RAPTOR_CC_STREAM_STDOUT_CAP` | `67108864` (64 MiB) | Retention ceiling (bytes) for a streamed `claude` child's stdout: the drain loop keeps reading past the cap (no pipe deadlock) but retains only the head plus a rolling tail, so a hostile or looping endpoint cannot balloon parent memory; the authoritative stream-json `result` event arrives last and rides the retained tail. Positive integer; zero/negative/non-numeric falls back silently. |
| `RAPTOR_CC_STREAM_STDERR_CAP` | `8388608` (8 MiB) | Same head-plus-tail retention ceiling for the streamed child's stderr. |
| `RAPTOR_CC_CREDENTIAL_MODE` | `env` | Credential posture for CC skill-pass children (`/understand` prepass, `/validate` postpass). `env` = current behaviour (backend credential overlay + AWS minting). `proxy` = child env carries ZERO provider credentials; the child authenticates to the local LLM dispatcher with a scoped minted token, sent by the CLI as `ANTHROPIC_AUTH_TOKEN` against the gateway route the CLI's backend mode reads — `ANTHROPIC_BASE_URL` on API installs; `ANTHROPIC_BEDROCK_MANTLE_BASE_URL`/`ANTHROPIC_BEDROCK_BASE_URL` with `CLAUDE_CODE_SKIP_MANTLE_AUTH`/`CLAUDE_CODE_SKIP_BEDROCK_AUTH` on Bedrock installs. The mint's model allowlist comes from the install's pins (`ANTHROPIC_MODEL`, `ANTHROPIC_SMALL_FAST_MODEL`, `ANTHROPIC_DEFAULT_HAIKU_MODEL`/`ANTHROPIC_DEFAULT_SONNET_MODEL`/`ANTHROPIC_DEFAULT_OPUS_MODEL`, `RAPTOR_CC_MODEL`, `RAPTOR_CC_FALLBACK_MODEL`) (budget = the pass budget, TTL sized to the pass timeout, model allowlist from the install's model pins) and the dispatcher fronts the provider. Requires the dispatcher route + the netns sandbox tier; setup failure fails the pass loudly (never a silent fallback to env credentials). Invalid values warn and use `env`. |

### Bedrock (`RAPTOR_BEDROCK_*`)

Setting `RAPTOR_BEDROCK_MODEL`, `RAPTOR_BEDROCK_PROFILE`, or
`AWS_BEARER_TOKEN_BEDROCK` is the explicit Bedrock opt-in — ambient
AWS credentials alone never select Bedrock.

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_BEDROCK_MODEL` | unset | Bedrock opt-in + model pin (SigV4 path). models.json entries override; mantle surface normalises ids, runtime ids pass verbatim. |
| `RAPTOR_BEDROCK_PROFILE` | unset | AWS named profile for SigV4 signing; also an opt-in signal. Per-model `aws_profile` > this > ambient `AWS_PROFILE`. |
| `RAPTOR_BEDROCK_REGION` | unset | Region pin. Per-model entry > this > ambient `AWS_REGION`/`AWS_DEFAULT_REGION`; never a silent default. |
| `RAPTOR_BEDROCK_API` | `mantle` | HTTP surface: `mantle` (SSE streaming) or `runtime` (legacy InvokeModel). Case-insensitive; unrecognised values quietly fall back to `mantle`. Per-model `bedrock_api` always wins. |
| `RAPTOR_BEDROCK_MAX_WORKERS` | `8` | Bedrock concurrency cap, clamped 1–32; quota is per-account-per-region. Same inversion: `tuning.json max_llm_workers` wins. |
| `RAPTOR_BEDROCK_PREFLIGHT_CACHE` | `~/.raptor/cache/bedrock-preflight.json` | Entitlement-preflight cache path (successes cached 24 h, failures never; the preflight is advisory and never blocks startup). Read at import — set before launch. |

### LLM response cache and scorecard

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_LLM_CACHE` | on | LLM response cache kill-switch: `off`/`none`/`0`/`false`/`no` disables the cache entirely (no reads, no writes). Use when re-measuring model behaviour — cached completions replay verbatim. The corpus runner's `--no-llm-cache` sets this for the whole run. |
| `RAPTOR_LLM_CACHE_TTL_S` | `86400` (24 h) | TTL of the on-disk LLM response cache (guards against same-name model drift). `none`/`off`/`0`/non-positive disables expiry entirely; garbled values fall back to 24 h. |
| `RAPTOR_SCORECARD_PATH` | `out/llm_scorecard.json` | Per-model reliability scorecard location (feeds `/scorecard` and cross-model merge weights). Set by tests/sandboxed runs for isolation. |
| `RAPTOR_SCORECARD_TEST_FLUSH` | unset | Test-harness escape hatch. Under pytest the process-exit scorecard flush is suppressed (per-test isolation is torn down before atexit; flushing would corrupt real reliability data with mock usage). Any non-empty value opts the atexit flush back in — for tests exercising that path against an isolated `RAPTOR_SCORECARD_PATH`. No effect outside pytest. |

### Credential-isolation dispatcher knobs

Numeric knobs on the dispatcher server
(`core/llm/dispatcher/server.py`), plus one boolean opt-out
(`RAPTOR_LLM_TOKEN_RENEW`). The numeric knobs resolve env > default —
only the token pair (`RAPTOR_LLM_DISPATCHER_TOKEN_TTL_S` /
`_TOKEN_BUDGET`) additionally accepts a caller argument, which wins
over both. Non-numeric or below-minimum values fall back to the
default with a debug log — a typo never breaks dispatcher startup.
The minimum is 1 unless a row says otherwise.

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S` | `600` | Read/write/pool timeout in seconds on the dispatcher→provider forwarding leg, re-read per request. The connect timeout stays fixed at 10 s: a provider that cannot finish the TCP/TLS handshake in 10 s is down, and a long connect timeout only delays failover. |
| `RAPTOR_LLM_DISPATCHER_TOKEN_TTL_S` | `28800` (8 h) | Lifetime of a worker's one-shot auth token; bump for kernel-scale runs that outlive the default. The in-process self-serve route (`core/llm/dispatcher/lifecycle.py`) sizes its own token to 7 days when this is unset — an explicit value pins both. Workers renew a still-valid token in place before expiry (see `RAPTOR_LLM_TOKEN_RENEW`), so for a live worker the TTL bounds time-since-last-renewal, not total run length. |
| `RAPTOR_LLM_TOKEN_RENEW` | enabled | Worker-side proactive token renewal on the dispatcher socket (`POST /_token/renew` shortly before the token's TTL window closes). Set `0` / `false` / `no` to opt out — the worker then keeps the original fixed TTL and runs longer than it will 401 at expiry. |
| `RAPTOR_LLM_DISPATCHER_TOKEN_BUDGET` | `10000` | Requests allowed per worker token; bump alongside the TTL for runs whose workers legitimately make more calls. |
| `RAPTOR_LLM_DISPATCHER_MAX_BODY_BYTES` | `33554432` (32 MiB) | Request-body ceiling on the provider plane. Content-Length is peer-typed input even on the token-authenticated planes, so oversized or negative declared lengths are refused instead of allocated. Clears the largest legitimate Messages payloads (multi-image requests); the child-admin plane keeps its own fixed 1 MiB cap. |
| `RAPTOR_LLM_DISPATCHER_RELAY_MAX_BYTES` | `268435456` (256 MiB) | Cumulative byte cap on one upstream response relay — bounds what a fire-hosing (mis)behaving upstream can stream through the process. Exceeding it aborts the request mid-stream: partial usage is booked and a `request.error` audit row records the limit class. |
| `RAPTOR_LLM_DISPATCHER_RELAY_DEADLINE_S` | `3600` | Total wall deadline on one upstream response relay — bounds how long a drip-feeding upstream can hold a handler thread and connection slot. Same mid-stream abort path as the byte cap. |
| `RAPTOR_LLM_DISPATCHER_CHILD_RESERVE_USD` | `0.25` | Fallback per-request budget reservation for scoped child tokens when the model is *unpriced* (no USD ceiling derivable from pricing); priced requests reserve their derived worst-case cost instead. Float, minimum `0.01`. |

Not to be confused with the dispatcher *route pair*
(`RAPTOR_LLM_SOCKET` / `RAPTOR_LLM_TOKEN_FD`) — that is per-child
internal plumbing, never operator-set (see below).

### `OLLAMA_HOST`

Ollama base URL, default `http://localhost:11434`. Re-read from the
environment on every access (`RaptorConfig.OLLAMA_HOST` descriptor),
so late changes are honoured. Consumers normalise (strip whitespace
and trailing `/`, prefix `http://` when schemeless — `host:port` is
valid). Logs substitute `[REMOTE-OLLAMA]` for non-loopback hosts; the
loopback check parses the URL properly so `localhost.attacker.example`
does not count as local.


## LLM HTTP transport

See "HTTP Transport Tuning" in [LLM Providers](llm.md) for the
full version. Pooled
`httpx` transports for the in-process SDK clients
(`core.llm.http_pool`); all numeric knobs must be strictly positive —
absent, unparseable, or non-positive values warn and fall back.

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_HTTP_KEEPALIVE_S` | `60` | Idle keepalive expiry (seconds) for pooled SDK transports (httpx default is 5 s — shorter than RAPTOR's inter-call think time). |
| `RAPTOR_HTTP_MAX_KEEPALIVE` | `20` | Idle connections kept in each SDK transport pool. |
| `RAPTOR_HTTP_MAX_CONNECTIONS` | `100` | Total concurrent connections per SDK transport. |
| `RAPTOR_HTTP2` | off | `1`/`true`/`yes`/`on` opts pooled transports into HTTP/2; additionally requires the `h2` package (opted-in-but-missing warns once and stays on HTTP/1.1). Off by default: TCP head-of-line blocking and middlebox risk are real. |
| `RAPTOR_LLM_STREAM_TRANSPORT` | off | `1`/`true`/`yes`/`on` carries non-streaming Anthropic calls over the SDK streaming transport (identical response object). Defeats corporate-proxy idle timers during long silent generations. |
| `RAPTOR_STUDY_MAX_OUTPUT_TOKENS` | `16384` | Output-token cap passed per call on `/understand --study` Phase 2 batch (and threat-frame derivation) structured generations, keeping responses inside upstream non-streaming request limits. Lower it if a provider truncates structured study output; raising it increases exposure to long-request aborts on non-streaming surfaces. |
| `RAPTOR_LLM_WORKER_KEYLESS` | off | `1`/`true`/`yes`/`on` spawns analysis workers WITHOUT provider keys in env (safe baseline + routing names only) — workers rely on the credential-isolation dispatcher alone for provider auth. Opt-in because the env-direct key fallback is the resilience path when the dispatcher route is unusable and for providers the dispatcher doesn't route; flip it once the install's providers are all dispatcher-routed. |


## Egress proxy

See "Egress proxy" and "Upstream proxy support" in
[Sandbox](sandbox.md) for the full version.

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S` | `10` | Budget (seconds) for connecting to and CONNECT-negotiating with the operator's upstream proxy. Widens only the handshake leg — the per-IO read budget is untouched (widening that would slow dead-target detection). Invalid/non-positive falls back. |
| `RAPTOR_PROXY_AUDIT_ENFORCE` | off (log-only) | In proxy **audit mode**, gate 1 (hostname allowlist) normally logs `would_deny_host` and allows. `1`/`true`/`yes`/`on` switches audit mode to log-AND-deny (403). Gate 2 (resolved-IP private/loopback block, the DNS-rebinding defence) is always enforcing; normal mode always denies regardless of this flag. |
| `RAPTOR_NAT64_PREFIXES` | unset (RFC 6052 well-known prefix only) | Comma-separated IPv6 `/96` networks treated as NAT64 prefixes by the proxy's resolved-IP gate. The well-known `64:ff9b::/96` is always decoded; deployments translating through a **network-specific prefix** (RFC 6052 §2.2) must declare its `/96` form here so an attacker DNS answer of `<NSP>::169.254.169.254` has its embedded IPv4 re-checked against the private/metadata blocklist instead of passing as a global IPv6. Exactly `/96` is accepted — RFC 6052's wider prefixes embed the IPv4 at a different position, and a low-32 decode of them would check the wrong address; malformed or non-`/96` entries warn and are ignored. |


## Analysis pipeline

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_SANITIZER_CUT` | off | Legacy env interface for the sanitizer vertex-cut gate; truthy `1`/`true`/`on`/`yes`. **Prefer the `--sanitizer-cut off\|on\|strict\|shadow` flag** on `/agentic`, `/validate`, `/codeql`; the flag always wins. The pipeline also re-exports the resolved value to its own workers (internal transport). |
| `RAPTOR_SANITIZER_CUT_NO_LEXICAL` | off | Disables the lexical fallback (strict mode). Footgun-guarded: set without `RAPTOR_SANITIZER_CUT` it warns on stderr and is ignored — suppression never silently turns off. |
| `RAPTOR_SANITIZER_CUT_PARITY_LOG` | off | Parity-telemetry log path; boolean-style values resolve to the default filename `sanitizer_cut_parity.jsonl` rather than creating a file named `1`. |
| `RAPTOR_SANITIZER_CUT_AUDIT_DIR` | unset | Run directory where the value-bound gate writes its `suppressions.jsonl` audit records. Set by the pipeline for its own workers (internal transport, like the resolved `RAPTOR_SANITIZER_CUT` re-export); ignored when the gate is off. |
| `RAPTOR_NO_PERLASM` | unset | Any non-empty value (including `0`) disables the perlasm generated-asm inventory enrichment pass (`core.inventory.perlasm`); the `PERLASM_INVENTORY` config gate disables it too. Enrichment is best-effort — failures never break the inventory build. |
| `RAPTOR_PERLASM_CACHE_DIR` | `<repo>/.cache/perlasm` | Generated-asm cache root for the perlasm pass (build-ID-cache resolution precedent: env > default). Set to share or relocate the cache. |
| `RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD` | `25` | Minimum unique applicable Semgrep rule count below which the thin-coverage hint fires (`packages/static-analysis`). `0` disables the hint; non-integer/negative warns and uses 25. |
| `RAPTOR_PATCH_GATE_SCOPE_SLACK` | `40` | Hunk slack (lines around the finding span) the patch gate tolerates (`packages/llm_analysis.patch_gate`). Per-call argument > env > default; malformed/negative values warn and use 40. |
| `RAPTOR_CORPUS_HISTORY` | `~/.local/share/raptor/corpus-history.jsonl` | Path of the append-only corpus run-history store (`core.audit.corpus.history`). Each corpus run appends a run header plus per-label verdict records after results.json is finalized; a write failure warns and never fails the run. Run headers record the run's profile (`cold`/`deployed`); `compare` warns across differing profiles. Reporting-only: the read side is the `python3 -m core.audit.corpus.history` CLI (`runs`/`compare`/`trend`/`stability`/`import`) plus one post-run operator report — nothing reads it to alter behavior. Tests must point this at a temporary path. |

One more knob rides in prose rather than a row because no static
in-repo read exists for the inventory to key on: the build script
`core/build/build_detector.py` *synthesises* for CodeQL database
creation reads `RAPTOR_COMPILE_TIMEOUT_S` at DB-build time (the read
lives inside the generated script's source text). Default `120`
seconds, capping each single-file compile the build prober runs, so a
pathological input
(fork-bomb template instantiation, deliberately slow untrusted
source) cannot hang a CodeQL DB build — a hung compile is killed and
counted as a failure and the pass continues. Non-numeric falls back
to 120. Raise it only for unusually slow toolchains.


## Feature packages

| Variable | Default | Purpose |
|----------|---------|---------|
| `CODEQL_CLI` | `codeql` on `PATH` | Path to the CodeQL CLI binary. Env (validated: must be an executable regular file) > `PATH` lookup; an invalid explicit value warns and falls back to `PATH`; neither resolving raises `RuntimeError` (fail-closed). |
| `CODEQL_QUERIES` | official packs | Path to a local CodeQL queries checkout; pack references are rewritten to absolute suite paths (offline/pinned query sets). Unresolvable suites log an error and fall back to the pack reference. |
| `CVE_DIFF_DISABLE_RULES` | rules on | Truthy disables the cve-diff agent's mechanical no-evidence surrender rule (benchmarking/ablation). Shared toggle spellings; unrecognised values warn and leave the rules on. |
| `CVE_DIFF_SURRENDER_COST_FLOOR_USD` | `0.80` | Minimum spend before the surrender rule may fire. Read at module import; malformed falls back silently. |
| `CVE_DIFF_MIN_CLASSES_FOR_SURRENDER` | `5` | Distinct source classes that must be tried before surrender. Read at module import; malformed falls back silently. |
| `NVD_API_KEY` | unset | NVD API key (raises quota from 5 to 50 req/30 s). Must be a UUID — non-UUID values are silently dropped to avoid 401 retry storms. Unset is fine (public quota + backoff). |
| `DT_API_KEY` | unset | Dependency-Track API key for `raptor-sca dt-push`. `--api-key` flag > env; neither → exit 2 with a clear message. |
| `GHIDRA_INSTALL_DIR` | auto-detected | Ghidra installation root for the pyghidra session backend (`packages/ghidra/session.py`). When unset, derived from `analyzeHeadless` on `PATH` (the wrapper lives in `$GHIDRA_INSTALL_DIR/support/`) and exported for pyghidra; neither present raises with a clear message. The subprocess headless backend uses `PATH` lookup only and ignores this variable. |
| `RAPTOR_GHIDRA_IN_PROCESS` | off | Truthy (`1/true/yes/on`) makes Ghidra operations prefer the in-process pyghidra JVM over the sandboxed `analyzeHeadless` subprocess (`packages/ghidra/detect.py::prefer_in_process`). The in-process JVM parses attacker-controlled project databases with full process privileges — set only for projects you trust. Without the flag, pyghidra engages only when `analyzeHeadless` is absent (with a posture warning). |
| `RAPTOR_SCA_AGENT` | in-tree agent | Path override for the sandboxed SCA agent entry point (legacy external checkouts). Must exist, be readable, and carry the SCA marker import — a bad override disables the subprocess launch rather than silently falling back. |
| `RAPTOR_SCA_STRESS_EPHEMERAL` | off | Any non-empty value (including `0`) makes SCA stress calibration clone into a throwaway temp dir instead of the persistent cache. Diagnostic only. |
| `RAPTOR_SCA_REGISTRY_PORTS` | unset | Comma-separated extra ports tolerated on repo-derived registry host strings (`packages/sca/__init__.py`), e.g. `5000,8081` for self-hosted registries like `reg.corp:5000`. Ports outside 1-65535 (or non-numeric) warn and are ignored. The port is always stripped before the hostname enters the proxy allowlist — this only widens which `host:port` spellings are considered well-formed; `80`/`443` are always accepted. |
| `RAPTOR_SCA_MAVEN_REGISTRY` | upstream | Maven mirror URL for SCA resolution (`packages/sca/private_registry.py`). Must be http(s) — other schemes warn and are ignored. PyPI and npm mirrors reuse the upstream tool conventions instead: `PIP_INDEX_URL` and `NPM_CONFIG_REGISTRY`. |
| `RAPTOR_SCA_PYPI_AUTH` | unset | `Authorization` header value sent to the PyPI mirror. Only honoured when the matching mirror URL var (`PIP_INDEX_URL`) is set — auth without a mirror is ignored. |
| `RAPTOR_SCA_NPM_AUTH` | unset | Same, for the npm mirror (`NPM_CONFIG_REGISTRY`). |
| `RAPTOR_SCA_MAVEN_AUTH` | unset | Same, for the Maven mirror (`RAPTOR_SCA_MAVEN_REGISTRY`). |
| `STUDIO_DATA_DIR` | `~/.raptor-studio` | raptor-studio's own state: job-queue SQLite DB, job logs, and project-extras sidecars (`packages/studio/config.py`). |
| `STUDIO_PROJECTS_DIR` | unset | Studio-side project-registry *view* override for demo/test registries (`packages/studio/config.py`). Studio otherwise reads raptor's canonical `core/project` registry; this never redirects raptor itself — jobs launched from an overridden view still use raptor's real locations. |
| `STUDIO_ALLOW_REMOTE` | unset | Channel set by `raptor_studio.py --allow-remote`: `1` disables the studio app's loopback Host-header validation (`packages/studio/security.py`). The launcher owns it; setting it by hand bypasses the bind-address gate and its warning. |
| `STUDIO_AUTH_TOKEN` | unset | Shared secret every studio client must present when set (`Authorization: Bearer`, the `studio_auth` cookie, or a one-time `?token=` exchange). Provisioned randomly by `raptor_studio.py --allow-remote`; pre-set it to keep a stable token across restarts. |
| `RAPTOR_SAGE_AFL_PRIOR` | `1` | Falsy disables mechanical AFL flag injection from high-confidence SAGE cross-run priors. Shared toggle spellings (`off` now works); unrecognised values warn and leave it enabled. |
| `RAPTOR_SANDBOX_LIVE_ESCALATION_DISABLED` | unset | Truthy (`1/true/yes/on`) silences the live stderr escalation banners for HIGH-severity sandbox telemetry (escape-primitive syscalls, credential-path touches, blocked-resolved-IP CONNECTs). Alerting only — enforcement and the run-end `sandbox-triage.json` classification are unaffected. See [Sandbox](sandbox.md) triage section. |
| `RAPTOR_SANDBOX_PHASE_TRACE` | unset | Host-visible file path for sandbox spawn-phase tracing (`core/sandbox/mount_ns.py`). When set, the sandbox child appends one marker line per mount-namespace setup phase (append-only, symlink-refusing, never raises); after a wedged spawn times out, the file's last line names the phase that never completed. Markers stop at `pivot_root` by design — a trace ending at the pivot marker means the wedge is post-pivot. Diagnostic only; leave unset in normal operation. |
| `RAPTOR_SAGE_FP_SUPPRESS` | `1` | Falsy disables SAGE cross-run false-positive suppression entirely (every finding re-tests). The force gate for consumers without a `--force` flag of their own — /agentic's analysis loop suppresses pre-LLM through this hook. |
| `RAPTOR_SAGE_CVE_PRIOR` | `1` | Falsy disables mechanical reuse of SAGE-remembered verified CVE fix pointers in /cve-diff discovery. MAC-gated: rows without a verifying token are ignored regardless. |
| `RAPTOR_EF_CONFIG` | unset | Path to `packages/exploit_feasibility`'s analysis-settings JSON (chain: explicit arg > `RAPTOR_EF_CONFIG` > `./.raptor.json` > `~/.config/raptor/config.json`). Not to be confused with `RAPTOR_CONFIG` (core.llm models config) — this reader historically shared that name; each side's schema guard names the right variable on mismatch. See "Exploit-feasibility analysis settings" below for the rest of the `RAPTOR_EF_*` family. |

### cve-env (`CVE_ENV_*`)

`packages/cve_env` (the LLM-agentic CVE → Docker environment builder,
`bin/cve-env` / `libexec/raptor-cve-env`) reads its own `CVE_ENV_`
family. Precedence is env var > `cve-env.toml` config file > code
default; malformed values warn (or fall back silently where a row says
so) and never abort a run.

| Variable | Default | Purpose |
|----------|---------|---------|
| `CVE_ENV_CONFIG_FILE` | unset | Path to the optional `cve-env.toml` config file (the middle tier of the precedence chain). Unset, missing, or unreadable → no file, silently; env vars and code defaults still apply. Loaded once at module import — changing it later in the same process has no effect. |
| `CVE_ENV_REPO_ROOT` | marker walk | Pins the project root for pip-installed layouts where no `pyproject.toml`/`.git` marker is reachable above the installed package (site-packages). Unset: walk up from the package looking for a marker, then the legacy `parents[2]` fallback. |
| `CVE_ENV_ALLOW_DEVICES` | off | Exactly `1` keeps `devices:` bindings when a compose file is rewritten for local launch (equivalent to the tool's `allow_devices` parameter); any other value strips them. Fail-closed: device passthrough is opt-in. |
| `CVE_ENV_DENY_REGISTRY` | unset | Comma-separated registry denylist filtering the `image_resolve` candidate cascade (URL-ish forms accepted; `docker.io` also drops bare-name and `library/*` refs). Empty/unset = no-op. For experimental benches testing behaviour when the high-success registries are unavailable. |
| `CVE_ENV_IMAGE_RESOLVE_BUDGET_S` | `600` | Per-call wall budget (seconds, float) for one `image_resolve` candidate cascade; `0` disables. Malformed/negative falls back silently. Resolved at call time, so per-run overrides take effect. |
| `CVE_ENV_DOCKER_RUN_TIMEOUT_S` | `600` | Wall bound (seconds, float) for `docker run --pull always`. Accepted range 10–3600; malformed or out-of-range values fall back silently to 600. |
| `CVE_ENV_RECOVERY_GAP_TURNS` | `20` | Recovery audit telemetry: max turn gap between a build-path tool failure and a same-tool success for the success to count as a `recovery` audit row. Positive integer; malformed warns and uses the default. |
| `CVE_ENV_RECOVERY_ELIGIBLE_STAGES` | `ACQUIRE,RESOLVE,LAUNCH,VERIFY` | Comma-separated stage set (upcased) where recovery emission is enabled. DIAGNOSTIC and RESEARCH are excluded by default — retries there are routine, not load-bearing signals. |
| `CVE_ENV_EXTRA_PROMPT_PREFIX` | unset | Bench-harness experimental hook: text prepended at the very top of the composed system prompt. Capped at 2000 characters; values containing control characters are rejected (dropped entirely). |

More knobs are read through helper functions whose env-var key is an
opaque parameter (same scanner limitation as the `RAPTOR_EF_*` family
above), so they are listed as prose:

- `CVE_ENV_MODEL` (default `claude-opus-4-7`): model override, read
  once at import. The A/B bench harness also sets it per run.
- Stage budgets: `CVE_ENV_BUDGET_<STAGE>` (USD, float; `<STAGE>` one of
  `RESEARCH`/`RESOLVE`/`ACQUIRE`/`LAUNCH`/`VERIFY`/`DIAGNOSTIC`/
  `TERMINAL`/`OTHER`) overrides the per-stage soft budget used for
  over-budget telemetry; `0` or negative = unbounded; malformed falls
  back to the code default. Telemetry only — no termination rides on it.
- Adaptive cost extension: `CVE_ENV_COST_EXTENSION_PCT` (default
  `0.10`) and `CVE_ENV_MAX_COST_EXTENSIONS` (default `1`, `0` disables)
  control the soft-cost-cap extension; malformed warns and uses the
  default.
- Registry cooldowns (seconds, int): `CVE_ENV_RATE_LIMIT_COOLDOWN_S`
  and `CVE_ENV_TRANSPORT_COOLDOWN_S` (both default `30`) gate how long
  `image_resolve` avoids a registry after rate-limit / transport
  failures.
- `source_build` extraction bounds: `CVE_ENV_MAX_TARBALL_BYTES`
  (512 MiB), `CVE_ENV_MAX_JSON_BYTES` (64 MiB),
  `CVE_ENV_MAX_EXTRACT_BYTES` (2 GiB), `CVE_ENV_MAX_EXTRACT_MEMBERS`
  (500 000).
- Post-build housekeeping toggles (shared toggle spellings, default
  off; each has a CLI flag override): `CVE_ENV_AUTO_CLEANUP_CONTAINERS`
  (`docker rm -f` this run's labeled containers),
  `CVE_ENV_AUTO_PRUNE_IMAGES` (dangling-image prune),
  `CVE_ENV_AUTO_STOP_COLIMA` (`colima stop` when no other build holds
  the lockfile).

Internal transport, not knobs: `CVE_ENV_OUTPUT_ROOT` (artifact output
root; `bin/cve-env` / `libexec/raptor-cve-env` wire it to raptor's
`out/` tree before the package loads) and `CVE_ENV_AGENT_BACKEND` (set
per run by the A/B bench harness). The compose launcher similarly sets
`DOCKER_DEFAULT_PLATFORM` in the child environment it builds for
`docker compose` (platform pinning survives the env allowlist).

### OCI registry credentials

`core.oci.auth` resolves pull credentials per registry: an anonymous
bearer token is tried first (free, correct for public images); when
the registry demands credentials, the env pair
`RAPTOR_OCI_<HOST>_USER` / `RAPTOR_OCI_<HOST>_PASSWORD` wins over
`~/.docker/config.json` inline `auths`. The host is uppercased with
`.` and `-` replaced by `_`: `ghcr.io` → `RAPTOR_OCI_GHCR_IO_USER`,
`registry-1.docker.io` → `RAPTOR_OCI_REGISTRY_1_DOCKER_IO_USER`. Both
halves of the pair must be set or it is skipped. `credsStore` /
`credHelpers` in the Docker config are deliberately ignored (honouring
them means shelling out to a helper binary); credential-helper users
use the env pair instead. See `DOCKER_CONFIG` in the external-standard
table for relocating the Docker config itself.

### Exploit-feasibility analysis settings

`packages/exploit_feasibility` reads its own `RAPTOR_EF_`-prefixed
family in `AnalysisConfig.from_env()` — env values override
config-file settings; invalid numeric values are silently ignored,
booleans use the shared toggle spellings (`1/true/yes/on` vs
`0/false/no/off`, case-insensitive; anything else warns and keeps
the default). The family previously used bare `RAPTOR_` names
(`RAPTOR_TIMEOUT_FAST`, `RAPTOR_CACHE_DIR`, ...), which read as
framework-wide knobs despite being package-local — those names are
no longer consulted. The reads go through a name→attribute mapping
table, which the inventory scanner cannot yet resolve, so the family
is listed as prose:

- Tool paths (empty = use `PATH`): `RAPTOR_EF_CHECKSEC_PATH`,
  `RAPTOR_EF_ROPGADGET_PATH`, `RAPTOR_EF_ONE_GADGET_PATH`.
- Timeout tiers in seconds: `RAPTOR_EF_TIMEOUT_FAST`,
  `RAPTOR_EF_TIMEOUT_NORMAL`, `RAPTOR_EF_TIMEOUT_MEDIUM`,
  `RAPTOR_EF_TIMEOUT_SLOW`, `RAPTOR_EF_TIMEOUT_VERY_SLOW`,
  `RAPTOR_EF_TIMEOUT_MAX`.
- Caching: `RAPTOR_EF_ENABLE_CACHING` (default on),
  `RAPTOR_EF_CACHE_DIR` (empty = temp dir; unrelated to
  `RAPTOR_BINARY_CACHE_DIR` / `RAPTOR_PERLASM_CACHE_DIR`),
  `RAPTOR_EF_ROP_CACHE_SIZE` (default 32).
- Analysis: `RAPTOR_EF_MAX_GADGETS` (default 10000),
  `RAPTOR_EF_VERIFY_FORMAT_N` (default on — empirical `%n` check),
  `RAPTOR_EF_VERBOSE` (package output verbosity; **not** a framework
  log level — that is `RAPTOR_LOG_FILE_LEVEL` above).

Config-file path: `RAPTOR_EF_CONFIG` (chain: explicit arg >
`RAPTOR_EF_CONFIG` > `./.raptor.json` > `~/.config/raptor/config.json`).

The numeric/boolean knobs above pass through `get_safe_env()` into
sandboxed subprocesses; the exec-path-class variables
(`RAPTOR_EF_*_PATH`, `RAPTOR_EF_CONFIG`, `RAPTOR_EF_CACHE_DIR`) are
deliberately scrubbed and only apply in the direct session environment.
Historically this package read `RAPTOR_CONFIG` for the same purpose —
that name now belongs exclusively to `core.llm`'s models config (see
Core runtime); pointing `RAPTOR_CONFIG` at analysis settings is a
stale configuration and each reader's schema guard says so.


## SAGE

Prose and the container-side variables: [SAGE](sage.md),
"Configuration". Operator-settable:

| Variable | Default | Purpose |
|----------|---------|---------|
| `SAGE_URL` | `http://localhost:8090` | SAGE node base URL. |
| `SAGE_TIMEOUT` | `30.0` | API request timeout in seconds (float); non-float or non-positive warns and uses the default. |
| `SAGE_OLLAMA_URL` | `http://localhost:11435` | Ollama URL for the direct-embed path (CPU hosts bypassing the Go-side embed timeout). Read once at module import. |
| `SAGE_EMBED_MODEL` | auto-detected by setup | Embedding model override — set **before running `raptor-sage-setup`** (GPU hosts auto-select `nomic-embed-text`, CPU `snowflake-arctic-embed:m`); changing it later without re-running setup desyncs client and container. |
| `SAGE_FORCE_CPU` | unset | Pipeline hooks are disabled on CPU-only Ollama by default (fail-closed for latency); truthy forces them on. Shared toggle spellings — `0`/`false`/`no`/`off` no longer force; unrecognised values warn and leave them disabled. |
| `SAGE_PROPOSE_DELAY_MS` | `0` | Safety-valve delay between SAGE proposes, capped at 300 000 ms; invalid values silently mean 0. Rarely needed. |
| `SAGE_RECALL_WORKERS` | auto (4 GPU / 2 CPU) | Recall concurrency, clamped 1–8; malformed falls back to auto. |

`SAGE_ENABLED`, `SAGE_IDENTITY_PATH`, `SAGE_PROJECT`, `SAGE_PROVIDER`,
and `SAGE_EMBED_DIM` are written by `raptor-sage-setup` (into
`.claude/settings.local.json`, `.mcp.json`, and the compose
environment) — see the internal-plumbing section below.


## Provider credentials (`LLM_API_KEY_VARS`)

Declared in `core/config/__init__.py`. Deliberately **not** in the
subprocess allowlist: untrusted-code subprocesses (CodeQL builds, fuzz
harnesses) never see credentials. `RaptorConfig.get_llm_env()` layers
them onto the sanitised base env only for RAPTOR's own LLM-calling
children; under the credential-isolation dispatcher, workers hold no
keys at all (secrets are injected per request over the dispatcher
socket), and `AWS_BEARER_TOKEN_BEDROCK` is popped out of the parent's
`os.environ` into the in-memory store at dispatcher start.

| Variable | Serves |
|----------|--------|
| `ANTHROPIC_API_KEY` | Anthropic direct API |
| `OPENAI_API_KEY` | OpenAI |
| `GEMINI_API_KEY` | Google Gemini |
| `GOOGLE_API_KEY` | Gemini (alternate name) |
| `MISTRAL_API_KEY` | Mistral |
| `GROQ_API_KEY` | Groq |
| `TOGETHER_API_KEY` | Together |
| `OPENROUTER_API_KEY` | OpenRouter |
| `ORCAROUTER_API_KEY` | OrcaRouter |
| `FIREWORKS_API_KEY` | Fireworks |
| `DEEPINFRA_API_KEY` | DeepInfra |
| `PERPLEXITY_API_KEY` | Perplexity |
| `REPLICATE_API_TOKEN` | Replicate (note the `_TOKEN` suffix) |
| `COHERE_API_KEY` | Cohere |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | Bedrock SigV4 static keys |
| `AWS_BEARER_TOKEN_BEDROCK` | Bedrock bearer auth — also an explicit Bedrock opt-in signal |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI / Foundry — an endpoint URL, not a secret; carried here so Foundry children can resolve their endpoint (also feeds the proxy-allowlist host derivation) |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCP service-account JSON *path* (Vertex as LLM gateway; also required by `/oss-forensics` BigQuery) |


## Transport routing family (`LLM_ROUTING_ENV_VARS`)

Selection flags and *names*, never secrets. Declared in
`core/config/__init__.py` alongside two prefix families
(`RAPTOR_BEDROCK_*`, `RAPTOR_CC_*`). Like the credentials, the family
is not allowlisted for ordinary subprocesses — untrusted code has no
business knowing the operator's LLM topology.

Members: `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_MANTLE`,
`CLAUDE_CODE_USE_VERTEX`, `CLAUDE_CODE_USE_FOUNDRY`,
`ANTHROPIC_MODEL`, `ANTHROPIC_SMALL_FAST_MODEL`, `ANTHROPIC_BASE_URL`,
`AWS_PROFILE`, `AWS_REGION`, `AWS_DEFAULT_REGION`,
`AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`.

**Spawn behavior** — how the family travels to children:

- `RaptorConfig.llm_routing_env()` collects the members (plus
  `RAPTOR_BEDROCK_*`/`RAPTOR_CC_*`) present and non-empty in the real
  environment.
- `RaptorConfig.get_llm_env()` = safe env (proxy preserved) + API keys
  + routing family — used when spawning RAPTOR's own LLM-calling
  scripts. Without the family, a spawned child loses the operator's
  backend selection (a Bedrock parent's child would silently flip to
  the direct API, where a Bedrock-shaped model id is a guaranteed
  HTTP 400).
- `spawn_worker()` (`core.llm.dispatcher.spawn`) defaults to safe env
  + routing family and **no API keys** — the dispatcher injects
  secrets per request. It also sets the per-child
  `RAPTOR_LLM_SOCKET`/`RAPTOR_LLM_TOKEN_FD` route pair (see internal
  plumbing).
- `cc_subprocess_env()` (`core.llm.cc_adapter`) is the seam for
  `claude` CLI children: safe env + all `CLAUDE_CODE_`/`ANTHROPIC_`/
  `RAPTOR_BEDROCK_`/`RAPTOR_CC_`-prefixed vars + the operator's proxy
  snapshot; `AWS_*` is forwarded **only when** `CLAUDE_CODE_USE_BEDROCK`
  is set, so cloud credentials never flow to CLI children on
  non-Bedrock installs.
- `RaptorConfig.strip_llm_env_vars()` removes keys, the routing
  family, and the dispatcher route pair from RAPTOR's own non-LLM
  helper children that must otherwise mirror the full environment
  (SMT/Z3 probe children).

`RAPTOR_LLM_*` is deliberately **excluded** from the forwarded prefix
families: the dispatcher route pair is per-child state that only
`spawn_worker()` may set — an inherited socket path without its token
fd is a broken route.


## External-standard variables

Variables defined by other ecosystems that RAPTOR consumes or forwards
with specific behavior.

### Proxy family (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY`)

Both cases of all four are the declared `PROXY_ENV_VARS` family.
RAPTOR-specific behavior:

- **Stripped by default** from every sanitised subprocess env
  (`get_safe_env()`): CodeQL builds, fuzz harnesses, gdb and friends
  do not inherit an interactive-use proxy.
- **Preserved + normalised on opt-in** (`preserve_proxy=True`, used
  for children that legitimately need egress): URL-shaped values pass
  through `normalise_proxy_url()` (trailing-slash removal — strict
  parsers like the JVM's HttpHost break otherwise); `NO_PROXY` is a
  host list and passes verbatim.
- **The in-process egress chokepoint** (`core.llm.egress`) snapshots
  the operator's proxy values (`HTTP_PROXY`/`http_proxy`,
  `HTTPS_PROXY`/`https_proxy`, `ALL_PROXY`/`all_proxy`,
  `NO_PROXY`/`no_proxy`), then rewrites `HTTPS_PROXY`/`https_proxy`
  in-process to point at the loopback CONNECT proxy;
  the chokepoint chains upstream through the *original* operator
  proxy. Spawned `claude` CLI children receive the operator snapshot
  (`operator_proxy_env()`), never RAPTOR's loopback pointer.
- **`NO_PROXY` loopback augmentation**: RAPTOR unions the operator's
  `NO_PROXY` with `localhost, 127.0.0.1, ::1, 0.0.0.0,
  169.254.169.254` so loopback sidecars (Ollama, SAGE, Joern) and
  EC2 IMDS credential fetches never loop through the proxy, even on
  mandatory-proxy hosts whose `NO_PROXY` lacks those entries.
- **`core.http` client**: lowercase proxy vars win over uppercase
  (curl/requests precedence), `all_proxy` is the per-scheme fallback,
  `no_proxy` is suffix-matched with port stripping — and `no_proxy`
  can never override RAPTOR's pinned egress hosts (`no_proxy=*` is
  not a bypass).

See [dependencies.md](dependencies.md) "Proxied hosts" for setup and
the JVM-installer caveat.

### Other

| Variable | RAPTOR-specific behavior |
|----------|--------------------------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Required for `/oss-forensics` BigQuery; also a Vertex credential path in the LLM key table. Its absence is reported in the startup banner. |
| `GITHUB_TOKEN` | Used by cve-diff/forensics tooling to raise GitHub API limits; forwarded to the relevant children only. |
| `CLAUDE_ENV_FILE` | Claude Code harness contract (set in `.claude/settings.json` to `.claude/raptor.env`): the SessionStart hook writes `RAPTOR_DIR` and a `PATH` extension into that file so every session Bash call inherits them. Not operator-set. |
| `CLAUDE_CODE_SUBAGENT_MODEL` | `bin/raptor` bridges it from `ANTHROPIC_MODEL` when unset (Bedrock roles entitled for only one model would otherwise 403 on subagents). An explicit operator export is never overridden. |
| `CLAUDE_SUBAGENT_BG_SHELL_MAX_MS` | Claude Code harness knob: per-SUBAGENT background-shell kill cap in ms (harness default 3,600,000). Read by `core.run.supervisor` so `/audit` can self-bound its wall budget to conclude gracefully inside the cap (cap − 300s, default 3300s; `--no-supervisor-bound` opts out). Non-numeric/non-positive values fall back to the default. See "Running long audits" in [audit.md](audit.md). |
| `AI_AGENT`, `CLAUDE_CODE_CHILD_SESSION` | Claude Code harness stamps on subagent shells; read (never set) by `core.run.supervisor.is_subagent_shell` — an `AI_AGENT` value ending `_agent` or a set `CLAUDE_CODE_CHILD_SESSION` marks a subagent background shell (main-thread shells are uncapped and never self-bounded). |
| `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_MANTLE`, `CLAUDE_CODE_USE_VERTEX`, `CLAUDE_CODE_USE_FOUNDRY` | Claude Code backend selection; members of the routing family above. Also gate `AWS_*` forwarding to CLI children, pick Bedrock hosts for the proxy allowlist, and count as auth signals for the calibration probe. Foundry set without an endpoint URL results in proxy-denied Foundry traffic with a clear log. |
| `AWS_EC2_METADATA_DISABLED` | Standard AWS SDK switch that disables EC2 IMDS lookups. RAPTOR never sets it; `raptor doctor` (`core.startup.aws_imds`) cross-checks it against the effective AWS credential chain and warns when a truthy value would break an IMDS-dependent chain (`credential_source = Ec2InstanceMetadata`, or no other credential source so SDKs fall through to IMDS). On proxied hosts whose chain does not depend on IMDS, doctor suggests it as *optional* probe-noise hygiene — never set it on instance-role hosts. |
| `AWS_ENDPOINT_URL_BEDROCK` | Honoured when deriving Bedrock hosts for the egress proxy allowlist (custom/VPC endpoints). |
| `VERTEX_LOCATION`, `CLOUD_ML_REGION` | Read when deriving Vertex hosts for the egress proxy allowlist. |
| `XDG_DATA_HOME` | Allowlisted through to children; RAPTOR stores its per-purpose HMAC keys under `$XDG_DATA_HOME/raptor/` (default `~/.local/share/raptor/`): the SAGE row key `rowmac.key`, the sandbox-telemetry key `telemetry-mac.key`, and the scorecard-sidecar key `scorecard-mac.key`. Per-purpose by design — deleting one key resets only its own subsystem's provenance. |
| `XDG_CACHE_HOME` and other `XDG_*` | Allowlisted through; `fake_home` sandbox runs override `HOME` and the `XDG_*_HOME` set to a fresh directory. Sandbox calibration profiles live under `~/.cache/raptor/`. |
| `OLLAMA_HOST` | See the LLM section above (re-read per access, remote hosts redacted in logs). |
| `PYTEST_CURRENT_TEST` | Detection only: suppresses the probe warm and attributes live-API leaks to test contexts. Never set manually. |
| `ASAN_OPTIONS`, `UBSAN_OPTIONS`, `AFL_INPUT_FILE` | Written by RAPTOR into fuzzing/crash-verification child envs (sanitizer contracts); operator values are not consumed. |
| `AFL_PATH` | Read when probing for AFL++ binary-only tracers (`afl-qemu-trace`, `afl-frida-trace.so`); also set in the campaign child env (setdefault) to the resolved tracer's directory so `afl-fuzz -Q`/`-O` finds a tracer that is not adjacent to the afl-fuzz binary. |
| `CONDA_DEFAULT_ENV`, `VIRTUAL_ENV` | Read only to phrase install hints for missing tools. |
| `SEMGREP_ENABLE_VERSION_CHECK`, `SEMGREP_SEND_METRICS` | Semgrep's own phone-home switches. Force-set to off by RAPTOR in every sanitised child env so every semgrep invocation shape stays offline — the argv flags only cover subcommands that accept them; operator values do not reach those children. The test conftest only *defaults* them off, so an ambient value survives in the test session's own process. |
| `RUNNER_TEMP` | GitHub Actions runner scratch directory; the sandbox feature-matrix harness defaults its results base under it (see `RAPTOR_MATRIX_RESULTS` in Core runtime). |
| `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL` | Pinned by RAPTOR in child envs for internal git operations (deterministic identity); operator values are not consumed. |
| `GOPATH`, `GOCACHE`, `TMPDIR` | Redirected by RAPTOR into per-run scratch space when spawning build/tool children (Go builds in cvefix/dark-verify, the run-scoped `TMPDIR` in `core.run.scratch`) so untrusted builds cannot write into the operator's real caches. |
| `CARGO_HOME` | Honoured (with the standard `~/.cargo` default) when locating the Rust toolchain for corpus builds; also on the dangerous-env scan list for target-repo settings. |
| `DOCKER_CONFIG` | Honoured when locating registry credentials for OCI auth (`core.oci.auth`), standard `~/.docker` default. |


## Test-suite and CI knobs

Read only by the test infrastructure (root `conftest.py`, per-suite
gates) — no production code path consults them — but they change what
a pytest run does, so anyone debugging CI needs them. The workflow
files under `.github/workflows/` are the reference for what each CI
tier sets.

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_TEST_LIVE_LLM` | unset | Exactly `1` lets a pytest session make live (billed) LLM calls. Otherwise the root `conftest.py` force-sets `RAPTOR_CC_TRANSPORT_DISABLED=1` for the whole session — subprocesses inherit it — so live-LLM invocation from tests is explicit opt-in, never a side effect of running a tier. |
| `RAPTOR_MAX_TEST_SECONDS` | unset = guard off | Per-test wallclock budget (seconds) for the slow-test guard: a test whose SETUP or CALL phase exceeds it is flagged and the session fails at the end naming the offenders (tests still run to completion — the signal is "this test got slow", not "killed mid-run"). Overruns of *half* the budget get a warn listing only. The default-tier CI matrix sets it; nightly (legitimately slow `slow`/`integration` tests) and local runs leave it unset. |
| `RAPTOR_MAX_SESSION_SECONDS` | unset = guard off | Per-tier aggregate wallclock tripwire, companion to the per-test guard: catches suite-wide drift no single test explains. Flags at session end, never kills; workflows set it to the tier's measured baseline plus headroom. |
| `RAPTOR_RANDOMISE_TESTS` | unset | Randomises collected test order so order-dependent failures surface early (no plugin needed). Scope-grouped shuffle: module order, then class-bucket order per module, then items per bucket — bounds expensive module/class fixtures to one setup per session. A numeric value is the seed; any other value hashes to one. Deterministic per seed, and the seed prints in the terminal header for reproduction. |
| `RAPTOR_REQUIRE_AUDIT_TESTS` | unset | Exactly `1` converts the audit-suite prerequisite skips into one loud failure naming each missing prereq (`core/sandbox/tests/test_audit_skip_budget.py`). For CI jobs asserting "audit tests must run on this host"; unset, the audit tests keep skipping silently when prereqs are absent. |
| `RAPTOR_SKIP_PROXY_TESTS` | unset | Exactly `1` skips the sandbox proxy/lane test modules — for hosts whose network posture breaks loopback-proxy tests. |
| `RAPTOR_BEDROCK_E2E_MODEL` | `claude-haiku-4-5` | Model pin for the credential-gated live Bedrock e2e suites (`core/llm/tests/test_bedrock_e2e.py`, `test_bedrock_live_features.py`; both auto-skip without Bedrock credentials in env). Bare RAPTOR names gain the `anthropic.` provider segment; IDs already carrying one pass verbatim. |
| `RAPTOR_BEDROCK_E2E_RUNTIME_MODEL` | derived | Full model ID override for the live suite's runtime-API leg, which needs a Cross-Region Inference Profile ID; unset, the regional prefix (`us.`/`eu.`/`apac.`/`au.`) is derived from `AWS_REGION`. |
| `RAPTOR_BEDROCK_E2E_APIS` | `mantle,runtime` | Which Bedrock HTTP surfaces the live feature suite exercises: `mantle`, `runtime`, or both. |

Two more are session-internal handoffs the controller conftest mints
and publishes for its own descendants — never set them manually:
`RAPTOR_GIT_AMBIENT_ENV` (JSON snapshot of the operator git env
displaced by the git-hermeticity pin, so nested pytest sessions
restore the true ambient values instead of re-capturing the pinned
ones) and `RAPTOR_EGRESS_LEAK_DIR` (marker directory through which
xdist workers report LLM-egress state leaks to their controller).
`PYTEST_XDIST_WORKER` is pytest-xdist's own contract and is read for
detection only.

Fixture sentinels (`RAPTOR_TEST_*` and similar names that exist only
as test data, with no behavioural contract to document) are tracked in
the machine inventory but deliberately not documented; run
`python3 .github/scripts/check_env_docs.py --list test-only` for the
current list.


## Internal plumbing — do not set

Set by RAPTOR (launcher, sandbox, dispatcher, setup scripts) for its
own children. Documented so child environments are explicable;
setting them manually either does nothing or weakens a boundary.

| Variable | Set by | Purpose |
|----------|--------|---------|
| `RAPTOR_DIR` | `bin/raptor` (exported after symlink resolution) | Installation root; RAPTOR's own children derive libexec/tool paths. `get_safe_env()` **re-pins** it to the current tree so a multi-checkout operator's ambient value cannot cross-import trees. The only value ever added to `sys.path`. Stripped from EVERY sandboxed target env by default (member of `TARGET_ENV_STRIP_SET`; the pid1-shim's mirror tuple follows, and `--strip-raptor-dir` survives as an argv-compat no-op) — the checkout path is a pure "inside RAPTOR" tell; only keep-trust dispatch children retain it. |
| `RAPTOR_CALLER_DIR` | `bin/raptor` | Operator's `$PWD` at launch; default-target resolution for commands run without a path. Refuses control bytes. |
| `_RAPTOR_TRUSTED` | `bin/raptor`, sandbox shims | Trust marker: `libexec/` scripts exit 2 unless it or `CLAUDECODE` is present. Stripped from target-bound envs BY DEFAULT at the sandbox env chokepoint (`TARGET_ENV_STRIP_SET` — trust markers + the session credential; the keep-trust skill dispatch is the only exception) so target-spawned processes cannot invoke libexec as trusted callers. Power users may set `_RAPTOR_TRUSTED=1` to drive libexec scripts directly — with the understanding that it bypasses the dispatch guard. |
| `CLAUDECODE` | Claude Code | Same trust-marker role, set by the harness for its child processes; allowlisted, stripped from untrusted targets. |
| `_RAPTOR_KEEP_TRUST_MARKERS` | `run_untrusted_networked(keep_trust_markers=True)` | One-hop control flag telling the pid1 shim to keep the markers for RAPTOR's own skill dispatches; popped before the child exec. |
| `_RAPTOR_ENV_RESTORE` | `core/sandbox/_env_quarantine` (launcher-bound envs only) | JSON payload of quarantined loader variables (`LD_*`/`DYLD_*`/`GCONV_PATH`/`GLIBC_TUNABLES`) so they never load code into the trusted launcher chain; the pid1/seatbelt shims pop it and re-apply the pairs at target exec. RAPTOR-minted: a caller-supplied copy is dropped, never merged, and never reaches a child. |
| `_RAPTOR_STATUS_FD` | sandbox spawn | fd where the seatbelt shim writes one readiness byte after the profile applies — absence fails loud ("sandbox did not engage"). |
| `_RAPTOR_DEATH_FD` | sandbox spawn | Read end of a liveness pipe; orchestrator death (even SIGKILL) closes it and the shim kills the sandbox process group — no leaked namespaces. |
| `RAPTOR_LLM_SOCKET`, `RAPTOR_LLM_TOKEN_FD` | `spawn_worker()` / dispatcher lifecycle | Credential-isolation dispatcher route: UDS path + fd carrying a one-shot worker auth token (fd passed via `pass_fds`). Never set manually — a socket path without its freshly allocated token fd is a broken route; presence of the socket var is itself a "dispatcher exists" signal. |
| `RAPTOR_LLM_QUIET` | `raptor-llm-ask` | Suppresses the run-end scorecard summary line for pipeable output (any non-empty value). |
| `RAPTOR_COORD_FROM_LAUNCHER` | privileged coord launcher | Marks "namespace setup already done" on the re-exec path of the netns coordinator. |
| `RAPTOR_COORD_REEXEC_GUARD` | netns coordinator | Breaks infinite re-exec loops; re-entry with the guard but without the launcher marker exits 2 with a structured error. |
| `RAPTOR_TRAJECTORY_DIR` | `raptor-cve-diff`, `raptor-understand` shims | Enables trajectory persistence into the run's output dir; the shims deliberately override any pre-set value. Unset → no-op; write failures warn only. |
| `RAPTOR_BO_OUT` | binary-oracle streaming helper | Temp-file path where a sandboxed tool's large stdout is redirected (bounded by the sandbox file-size rlimit). |
| `RAPTOR_SAGE_BOOT_CAPTURE` | `raptor-sage-setup` (capture pipeline only) | Sanctioned guard bypass in `libexec/raptor-sage-mcp`: `=1` makes the wrapper exec the SAGE server directly, skipping `raptor-sage-mcp-guard`, so the setup probe that CREATES the boot-payload stamp doesn't record the guard's own no-stamp warning text (which would make every real session mismatch forever). Agent sessions can never take this branch — Claude Code spawns the wrapper with its own environment. Setting it manually runs SAGE unguarded. |
| `OUTPUT_DIR`, `R2_TARGET_DIR` | callers of the sandboxed wrappers | Env contract of `libexec/raptor-run-sandboxed` (writable dir, required, fail-closed validation) and `libexec/raptor-r2-sandboxed` (scratch dir + read-only binary parent, set by `packages/binary_analysis/radare2_understand`). |
| `TARGET` | `packages/llm_analysis/exploit_verify` | Path of the binary under attack, exported to compiled/generated PoC scripts — PoCs must reference `$TARGET`, not hard-coded paths. |
| `SAGE_ENABLED` | `raptor-sage-setup` | Written as `true` into `.claude/settings.local.json` so sessions enable SAGE; default `false`, truthy `true`/`1`/`yes` (fail-closed). Removed by teardown. |
| `SAGE_IDENTITY_PATH`, `SAGE_PROJECT`, `SAGE_PROVIDER` | `raptor-sage-setup` → `.mcp.json` | Agent identity/namespace for the SAGE MCP wrapper (container-internal defaults). |
| `SAGE_EMBED_DIM` | `raptor-sage-setup` | Compose-time embedding dimension (default 768); no Python reads it at runtime — pairs with `SAGE_EMBED_MODEL` before setup. |

Child-env transport with no table row of its own: `_JAVA_OPTIONS`
(the Joern server child env pins `-Djava.io.tmpdir` to a run-scoped
scratch dir — unlike a launcher argv flag it reaches every JVM the
launcher shell nests; also on the dangerous-env scan list), and the
sandbox feature-matrix harness's driver→lane plumbing (`SXV_LANE`,
`SXV_TIER`, `SXV_REQHASH_MATCH`, `SXV_UNMASK`, `SXV_SG_REEXEC`,
`MATRIX_PY`, plus `run-matrix.sh`'s own script-to-container
transport: `LANE`, `LANES`, `LANE_ARR`, `LANE_OPTS`, `LANE_TIMEOUT`,
`TIER`, `TIERV`, `IMG`, `IMAGES`, `IMAGE_SEL`, `DUR`, `REF`, `REPO`,
`RESULTS_BASE`, `SKIP_BUILD`, `PY_VERSION`). The harness's operator
knobs are `RAPTOR_MATRIX_RESULTS` / `RAPTOR_MATRIX_APT_MIRROR` in
the Core runtime section.

Namespace look-alikes that are **not** environment variables: grep
also surfaces `RAPTOR_GD_*` / `RAPTOR_FLOW_*` (Joern guard-dominance
and flow-verification stdout sentinels, `core/audit/joern_verify.py`),
`RAPTOR_BATCH_*` (pip-resolver batch-output markers,
`packages/sca/resolvers/pip.py`), `RAPTOR_STUDY_PROBE` (compile-probe
static-assert marker, `core/audit/compile_probe.py`) and the
`RAPTOR_HELPERS_TEST` / `RAPTOR_GIDMAP_MAX_TRIPLES` C compile-time
macros (`core/sandbox/helpers/`). These are output-stream sentinel
strings or preprocessor symbols; none is read from a process
environment, so none belongs in the tables above.


## Policy tables

Declared in `core/config/__init__.py`; the code is the source of
truth for membership — these tables are enforced at every subprocess
seam and scanned for drift.

- **`SAFE_ENV_ALLOWLIST` + `SAFE_ENV_PREFIXES`** — the primary,
  default-deny subprocess filter (`get_safe_env()`): only ~30 named
  variables (`PATH`, `HOME`, `USER`, `LOGNAME`, `PWD`, locale/terminal — `LANG`,
  `TERM` —, the `XDG_*` set, `DEBIAN_FRONTEND`, `PYTHONUNBUFFERED`,
  trust markers, `RAPTOR_OUT_DIR`/`RAPTOR_DIR`/`RAPTOR_TARGET_KIND`)
  plus the `LC_*` prefix survive. Unknown variables never flow to
  children.
- **`DANGEROUS_ENV_VARS`** — belt-and-braces blocklist overlaying the
  allowlist and the authoritative reference for scanning untrusted
  repo content: shell-eval vectors (`BASH_ENV`, `PAGER`, `EDITOR`,
  `VISUAL`, `IFS`, ...),
  loader redirection (`LD_PRELOAD`, `DYLD_*`), glibc data-module
  hijacks (`GCONV_PATH`, `LOCPATH`, ...), Python injection
  (`PYTHONPATH`, `PYTHONUSERBASE`, ...), tool auto-load vectors.
- **`PROXY_ENV_VARS`** — both cases of the proxy family; stripped by
  default, preserved + normalised on opt-in (see above).
- **`GIT_ENV_VARS`** — git-config isolation applied to *every*
  sanitised subprocess env: `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=true`,
  `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`,
  `GIT_CONFIG_NOSYSTEM=1` — operator gitconfig (gpg signing,
  credential helpers, fsmonitor) never influences internal git.
- **`LLM_API_KEY_VARS`**, **`LLM_ROUTING_ENV_VARS`** +
  **`LLM_ROUTING_ENV_PREFIXES`** — documented in their sections above.

Test-infrastructure knobs and fixture sentinels are covered in
"Test-suite and CI knobs" above.
