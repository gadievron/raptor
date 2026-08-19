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
  > built-in default, unless a row says otherwise. The known
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
| `RAPTOR_LOG_FILE_LEVEL` | `INFO` | Level of the per-process JSONL audit-log file handler (`core.logging`). Any `logging` level name, case-insensitive; unknown names fall back to `INFO` rather than erroring during bootstrap. `DEBUG` opts into the full firehose. |
| `RAPTOR_TMP_REAP_MAX_AGE_H` | `24` (hours) | Age floor for the best-effort sweep of orphaned RAPTOR temp artifacts in `$TMPDIR` (`core.run.tmp_reaper`; known `raptor-*` prefixes only, same-euid, live-process-safe). `0`/negative disables; non-numeric falls back to 24 h (sweep still runs). |
| `RAPTOR_RUN_REAP_MAX_AGE_D` | `30` (days) | Age floor for reaping run directories whose status is `failed`/`cancelled` only — completed runs are never age-reaped. `0`/negative disables; non-numeric falls back to 30 d. |
| `RAPTOR_LOG_REAP_MAX_AGE_D` | unset = disabled | **Opt-in** sweep of old JSONL audit logs. Unlike the two sweeps above, this one defaults OFF and a non-numeric value leaves it off — deleting audit data is an operator decision. |
| `RAPTOR_REACH_VERDICT_LOG` | `$RAPTOR_DIR/out/reach_verdict_log.json` | Path override for the privacy-bounded reachability-verdict telemetry sidecar (`core.analysis.reach_verdict_log`; only language/verdict counts). |
| `RAPTOR_REACH_VERDICT_LOG_DISABLED` | unset | Any non-empty value disables reach-verdict telemetry recording (checked per call). The test suite sets it globally in `conftest.py`. Telemetry failures never affect analysis. |
| `RAPTOR_BINARY_CACHE_DIR` | `<repo>/.cache/binary` | Location of the build-ID binary cache (`core.audit.build_id_cache`). Explicit `cache_dir` argument > env > default. Set to share the cache across hosts/tools. |
| `RAPTOR_SELFTEST_MODEL` | unset | Default for `raptor-self-test --model` (budget-capped LLM cases). Flag > env > RAPTOR's own model resolution. |
| `RAPTOR_CI` | auto-detected | CI-posture marker for the rule-of-two interactivity gate (`core.security.rule_of_two`). Normally parent-stamped: `get_safe_env()` writes `RAPTOR_CI=1` into every sanitised child env whenever the parent judged itself in CI, so the gate keeps working in children whose scrubbed env lost the vendor markers (`CI`, `GITHUB_ACTIONS`, ...). It is also the first — authoritative — entry in the recognised-marker list, so an operator may set `RAPTOR_CI=1` to force CI posture on any host. The whole marker set is unioned into `SAFE_ENV_ALLOWLIST`, so the verdict survives further spawns. |

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
blocked in this mode.

Distinct from `RAPTOR_ALLOW_UNSANDBOXED_TOOLS`, which waives a
*missing sandbox module* at the tool-runner import seam — this one
waives a missing *namespace tier* inside an otherwise-working
sandbox. Neither implies the other.

### Housekeeping asymmetry

The three reaper knobs deliberately disagree on invalid input: the
tmp and run sweeps fall back to their defaults (sweeping is safe),
while the log sweep disables itself (audit data biases toward not
deleting).


## LLM model selection and transport

These knobs are covered in narrative form in [LLM Providers](llm.md)
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
| `RAPTOR_LLM_CACHE_TTL_S` | `86400` (24 h) | TTL of the on-disk LLM response cache (guards against same-name model drift). `none`/`off`/`0`/non-positive disables expiry entirely; garbled values fall back to 24 h. |
| `RAPTOR_SCORECARD_PATH` | `out/llm_scorecard.json` | Per-model reliability scorecard location (feeds `/scorecard` and cross-model merge weights). Set by tests/sandboxed runs for isolation. |
| `RAPTOR_SCORECARD_TEST_FLUSH` | unset | Test-harness escape hatch. Under pytest the process-exit scorecard flush is suppressed (per-test isolation is torn down before atexit; flushing would corrupt real reliability data with mock usage). Any non-empty value opts the atexit flush back in — for tests exercising that path against an isolated `RAPTOR_SCORECARD_PATH`. No effect outside pytest. |

### Credential-isolation dispatcher knobs

Three integer knobs on the dispatcher server
(`core/llm/dispatcher/server.py`). All resolve caller argument > env
> default; non-numeric or below-minimum (1) values fall back to the
default with a debug log — a typo never breaks dispatcher startup.
They are read by helper, not by `os.environ.get` at the call site, so
the machine inventory currently sees only the first one (its test
monkeypatches it); listed here as prose until the extractor learns
that seam:

- `RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S` (default `600`) —
  read/write/pool timeout in seconds on the dispatcher→provider
  forwarding leg, re-read per request. The connect timeout stays
  fixed at 10 s: a provider that cannot finish the TCP/TLS handshake
  in 10 s is down, and a long connect timeout only delays failover.
- `RAPTOR_LLM_DISPATCHER_TOKEN_TTL_S` (default `28800` = 8 h) —
  lifetime of a worker's one-shot auth token; bump for kernel-scale
  runs that outlive the default.
- `RAPTOR_LLM_DISPATCHER_TOKEN_BUDGET` (default `10000`) — requests
  allowed per worker token.

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
narrative version. Pooled
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
| `RAPTOR_LLM_WORKER_KEYLESS` | off | `1`/`true`/`yes`/`on` spawns analysis workers WITHOUT provider keys in env (safe baseline + routing names only) — workers rely on the credential-isolation dispatcher alone for provider auth. Opt-in because the env-direct key fallback is the resilience path when the dispatcher route is unusable and for providers the dispatcher doesn't route; flip it once the install's providers are all dispatcher-routed. |


## Egress proxy

See "Egress proxy" and "Upstream proxy support" in
[Sandbox](sandbox.md) for the narrative version.

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S` | `10` | Budget (seconds) for connecting to and CONNECT-negotiating with the operator's upstream proxy. Widens only the handshake leg — the per-IO read budget is untouched (widening that would slow dead-target detection). Invalid/non-positive falls back. |
| `RAPTOR_PROXY_AUDIT_ENFORCE` | off (log-only) | In proxy **audit mode**, gate 1 (hostname allowlist) normally logs `would_deny_host` and allows. `1`/`true`/`yes`/`on` switches audit mode to log-AND-deny (403). Gate 2 (resolved-IP private/loopback block, the DNS-rebinding defence) is always enforcing; normal mode always denies regardless of this flag. |


## Analysis pipeline

| Variable | Default | Purpose |
|----------|---------|---------|
| `RAPTOR_SANITIZER_CUT` | off | Legacy env interface for the sanitizer vertex-cut gate; truthy `1`/`true`/`on`/`yes`. **Prefer the `--sanitizer-cut off\|on\|strict\|shadow` flag** on `/agentic`, `/validate`, `/codeql`; the flag always wins. The pipeline also re-exports the resolved value to its own workers (internal transport). |
| `RAPTOR_SANITIZER_CUT_NO_LEXICAL` | off | Disables the lexical fallback (strict mode). Footgun-guarded: set without `RAPTOR_SANITIZER_CUT` it warns on stderr and is ignored — suppression never silently turns off. |
| `RAPTOR_SANITIZER_CUT_PARITY_LOG` | off | Parity-telemetry log path; boolean-style values resolve to the default filename `sanitizer_cut_parity.jsonl` rather than creating a file named `1`. |
| `RAPTOR_NO_PERLASM` | unset | Any non-empty value (including `0`) disables the perlasm generated-asm inventory enrichment pass (`core.inventory.perlasm`); the `PERLASM_INVENTORY` config gate disables it too. Enrichment is best-effort — failures never break the inventory build. |
| `RAPTOR_PERLASM_CACHE_DIR` | `<repo>/.cache/perlasm` | Generated-asm cache root for the perlasm pass (build-ID-cache resolution precedent: env > default). Set to share or relocate the cache. |
| `RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD` | `25` | Minimum unique applicable Semgrep rule count below which the thin-coverage hint fires (`packages/static-analysis`). `0` disables the hint; non-integer/negative warns and uses 25. |
| `RAPTOR_PATCH_GATE_SCOPE_SLACK` | `40` | Hunk slack (lines around the finding span) the patch gate tolerates (`packages/llm_analysis.patch_gate`). Per-call argument > env > default; malformed/negative values warn and use 40. |
| `RAPTOR_CORPUS_HISTORY` | `~/.local/share/raptor/corpus-history.jsonl` | Path of the append-only corpus run-history store (`core.audit.corpus.history`). Each corpus run appends a run header plus per-label verdict records after results.json is finalized; a write failure warns and never fails the run. Reporting-only: the store is read exclusively by the `python3 -m core.audit.corpus.history` CLI (`runs`/`compare`/`trend`/`stability`/`import`) — nothing in the audit/corpus pipeline reads it to alter behavior. Tests must point this at a temporary path. |

One more knob lives in `core/build/build_detector.py` (a directory the
inventory scanner currently skips, so prose rather than a row):
`RAPTOR_COMPILE_TIMEOUT_S` (default `120` seconds) caps each
single-file compile the build prober runs, so a pathological input
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
| `RAPTOR_SCA_AGENT` | in-tree agent | Path override for the sandboxed SCA agent entry point (legacy external checkouts). Must exist, be readable, and carry the SCA marker import — a bad override disables the subprocess launch rather than silently falling back. |
| `RAPTOR_SCA_STRESS_EPHEMERAL` | off | Any non-empty value (including `0`) makes SCA stress calibration clone into a throwaway temp dir instead of the persistent cache. Diagnostic only. |
| `RAPTOR_SCA_REGISTRY_PORTS` | unset | Comma-separated extra ports tolerated on repo-derived registry host strings (`packages/sca/__init__.py`), e.g. `5000,8081` for self-hosted registries like `reg.corp:5000`. Ports outside 1-65535 (or non-numeric) warn and are ignored. The port is always stripped before the hostname enters the proxy allowlist — this only widens which `host:port` spellings are considered well-formed; `80`/`443` are always accepted. |
| `RAPTOR_SCA_MAVEN_REGISTRY` | upstream | Maven mirror URL for SCA resolution (`packages/sca/private_registry.py`). Must be http(s) — other schemes warn and are ignored. PyPI and npm mirrors reuse the upstream tool conventions instead: `PIP_INDEX_URL` and `NPM_CONFIG_REGISTRY`. |
| `RAPTOR_SCA_PYPI_AUTH` | unset | `Authorization` header value sent to the PyPI mirror. Only honoured when the matching mirror URL var (`PIP_INDEX_URL`) is set — auth without a mirror is ignored. |
| `RAPTOR_SCA_NPM_AUTH` | unset | Same, for the npm mirror (`NPM_CONFIG_REGISTRY`). |
| `RAPTOR_SCA_MAVEN_AUTH` | unset | Same, for the Maven mirror (`RAPTOR_SCA_MAVEN_REGISTRY`). |
| `RAPTOR_SAGE_AFL_PRIOR` | `1` | Falsy disables mechanical AFL flag injection from high-confidence SAGE cross-run priors. Shared toggle spellings (`off` now works); unrecognised values warn and leave it enabled. |
| `RAPTOR_SANDBOX_LIVE_ESCALATION_DISABLED` | unset | Truthy (`1/true/yes/on`) silences the live stderr escalation banners for HIGH-severity sandbox telemetry (escape-primitive syscalls, credential-path touches, blocked-resolved-IP CONNECTs). Alerting only — enforcement and the run-end `sandbox-triage.json` classification are unaffected. See [Sandbox](sandbox.md) triage section. |
| `RAPTOR_EF_CONFIG` | unset | Path to `packages/exploit_feasibility`'s analysis-settings JSON (chain: explicit arg > `RAPTOR_EF_CONFIG` > `./.raptor.json` > `~/.config/raptor/config.json`). Not to be confused with `RAPTOR_CONFIG` (core.llm models config) — this reader historically shared that name; each side's schema guard names the right variable on mismatch. See "Exploit-feasibility analysis settings" below for the rest of the `RAPTOR_EF_*` family. |

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
| `SAGE_EMBED_MODEL` | auto-detected by setup | Embedding model override — set **before running `raptor-sage-setup`** (GPU hosts auto-select `snowflake-arctic-embed:m`, CPU `nomic-embed-text`); changing it later without re-running setup desyncs client and container. |
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
| `CLAUDE_SUBAGENT_BG_SHELL_MAX_MS` | Claude Code harness knob: per-SUBAGENT background-shell kill cap in ms (harness default 3,600,000). Read by `core.run.supervisor` so `/audit` can self-bound its wall budget to conclude gracefully inside the cap (cap − 300s, default 3300s; `--no-supervisor-bound` opts out). Non-numeric/non-positive values fall back to the default. See [long-runs.md](long-runs.md). |
| `AI_AGENT`, `CLAUDE_CODE_CHILD_SESSION` | Claude Code harness stamps on subagent shells; read (never set) by `core.run.supervisor.is_subagent_shell` — an `AI_AGENT` value ending `_agent` or a set `CLAUDE_CODE_CHILD_SESSION` marks a subagent background shell (main-thread shells are uncapped and never self-bounded). |
| `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_MANTLE`, `CLAUDE_CODE_USE_VERTEX`, `CLAUDE_CODE_USE_FOUNDRY` | Claude Code backend selection; members of the routing family above. Also gate `AWS_*` forwarding to CLI children, pick Bedrock hosts for the proxy allowlist, and count as auth signals for the calibration probe. Foundry set without an endpoint URL results in proxy-denied Foundry traffic with a clear log. |
| `AWS_ENDPOINT_URL_BEDROCK` | Honoured when deriving Bedrock hosts for the egress proxy allowlist (custom/VPC endpoints). |
| `VERTEX_LOCATION`, `CLOUD_ML_REGION` | Read when deriving Vertex hosts for the egress proxy allowlist. |
| `XDG_DATA_HOME` | Allowlisted through to children; RAPTOR stores the SAGE row-HMAC key at `$XDG_DATA_HOME/raptor/rowmac.key` (default `~/.local/share/raptor/rowmac.key`). |
| `XDG_CACHE_HOME` and other `XDG_*` | Allowlisted through; `fake_home` sandbox runs override `HOME` and the `XDG_*_HOME` set to a fresh directory. Sandbox calibration profiles live under `~/.cache/raptor/`. |
| `OLLAMA_HOST` | See the LLM section above (re-read per access, remote hosts redacted in logs). |
| `PYTEST_CURRENT_TEST` | Detection only: suppresses the probe warm and attributes live-API leaks to test contexts. Never set manually. |
| `ASAN_OPTIONS`, `UBSAN_OPTIONS`, `AFL_INPUT_FILE` | Written by RAPTOR into fuzzing/crash-verification child envs (sanitizer contracts); operator values are not consumed. |
| `CONDA_DEFAULT_ENV`, `VIRTUAL_ENV` | Read only to phrase install hints for missing tools. |
| `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL` | Pinned by RAPTOR in child envs for internal git operations (deterministic identity); operator values are not consumed. |
| `GOPATH`, `GOCACHE`, `TMPDIR` | Redirected by RAPTOR into per-run scratch space when spawning build/tool children (Go builds in cvefix/dark-verify, the run-scoped `TMPDIR` in `core.run.scratch`) so untrusted builds cannot write into the operator's real caches. |
| `CARGO_HOME` | Honoured (with the standard `~/.cargo` default) when locating the Rust toolchain for corpus builds; also on the dangerous-env scan list for target-repo settings. |
| `DOCKER_CONFIG` | Honoured when locating registry credentials for OCI auth (`core.oci.auth`), standard `~/.docker` default. |


## Internal plumbing — do not set

Set by RAPTOR (launcher, sandbox, dispatcher, setup scripts) for its
own children. Documented so child environments are explicable;
setting them manually either does nothing or weakens a boundary.

| Variable | Set by | Purpose |
|----------|--------|---------|
| `RAPTOR_DIR` | `bin/raptor` (exported after symlink resolution) | Installation root; children derive libexec/tool paths. `get_safe_env()` **re-pins** it to the current tree so a multi-checkout operator's ambient value cannot cross-import trees. The only value ever added to `sys.path`. |
| `RAPTOR_CALLER_DIR` | `bin/raptor` | Operator's `$PWD` at launch; default-target resolution for commands run without a path. Refuses control bytes. |
| `_RAPTOR_TRUSTED` | `bin/raptor`, sandbox shims | Trust marker: `libexec/` scripts exit 2 unless it or `CLAUDECODE` is present. Stripped from target-bound envs (`strip_trust_markers`) so target-spawned processes cannot invoke libexec as trusted callers. Power users may set `_RAPTOR_TRUSTED=1` to drive libexec scripts directly — with the understanding that it bypasses the dispatch guard. |
| `CLAUDECODE` | Claude Code | Same trust-marker role, set by the harness for its child processes; allowlisted, stripped from untrusted targets. |
| `_RAPTOR_KEEP_TRUST_MARKERS` | `run_untrusted_networked(keep_trust_markers=True)` | One-hop control flag telling the pid1 shim to keep the markers for RAPTOR's own skill dispatches; popped before the child exec. |
| `_RAPTOR_STATUS_FD` | sandbox spawn | fd where the seatbelt shim writes one readiness byte after the profile applies — absence fails loud ("sandbox did not engage"). |
| `_RAPTOR_DEATH_FD` | sandbox spawn | Read end of a liveness pipe; orchestrator death (even SIGKILL) closes it and the shim kills the sandbox process group — no leaked namespaces. |
| `RAPTOR_LLM_SOCKET`, `RAPTOR_LLM_TOKEN_FD` | `spawn_worker()` / dispatcher lifecycle | Credential-isolation dispatcher route: UDS path + fd carrying a one-shot worker auth token (fd passed via `pass_fds`). Never set manually — a socket path without its freshly allocated token fd is a broken route; presence of the socket var is itself a "dispatcher exists" signal. |
| `RAPTOR_LLM_QUIET` | `raptor-llm-ask` | Suppresses the run-end scorecard summary line for pipeable output (any non-empty value). |
| `RAPTOR_COORD_FROM_LAUNCHER` | privileged coord launcher | Marks "namespace setup already done" on the re-exec path of the netns coordinator. |
| `RAPTOR_COORD_REEXEC_GUARD` | netns coordinator | Breaks infinite re-exec loops; re-entry with the guard but without the launcher marker exits 2 with a structured error. |
| `RAPTOR_TRAJECTORY_DIR` | `raptor-cve-diff`, `raptor-understand` shims | Enables trajectory persistence into the run's output dir; the shims deliberately override any pre-set value. Unset → no-op; write failures warn only. |
| `RAPTOR_BO_OUT` | binary-oracle streaming helper | Temp-file path where a sandboxed tool's large stdout is redirected (bounded by the sandbox file-size rlimit). |
| `OUTPUT_DIR`, `R2_TARGET_DIR` | callers of the sandboxed wrappers | Env contract of `libexec/raptor-run-sandboxed` (writable dir, required, fail-closed validation) and `libexec/raptor-r2-sandboxed` (scratch dir + read-only binary parent, set by `packages/binary_analysis/radare2_understand`). |
| `TARGET` | `packages/llm_analysis/exploit_verify` | Path of the binary under attack, exported to compiled/generated PoC scripts — PoCs must reference `$TARGET`, not hard-coded paths. |
| `SAGE_ENABLED` | `raptor-sage-setup` | Written as `true` into `.claude/settings.local.json` so sessions enable SAGE; default `false`, truthy `true`/`1`/`yes` (fail-closed). Removed by teardown. |
| `SAGE_IDENTITY_PATH`, `SAGE_PROJECT`, `SAGE_PROVIDER` | `raptor-sage-setup` → `.mcp.json` | Agent identity/namespace for the SAGE MCP wrapper (container-internal defaults). |
| `SAGE_EMBED_DIM` | `raptor-sage-setup` | Compose-time embedding dimension (default 768); no Python reads it at runtime — pairs with `SAGE_EMBED_MODEL` before setup. |

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
  variables (`PATH`, `HOME`, `USER`, `PWD`, locale/terminal — `LANG`,
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

Test-only variables (used exclusively by the test suite, e.g.
`RAPTOR_SELFTEST_*` fixtures, `RAPTOR_TEST_*` sentinels) are tracked
in the machine inventory but deliberately not documented here; run
`python3 .github/scripts/check_env_docs.py --list test-only` for the
current list.
