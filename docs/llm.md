# LLM Providers

RAPTOR uses large language models for vulnerability analysis, exploit generation, dataflow
validation, and autonomous decision-making. This guide covers provider configuration,
model selection, multi-model workflows, and cost management.

## Supported Providers

Seven providers are supported. RAPTOR probes for configured providers in this order
and uses the first one found:

| Provider | Auth | SDK | Default Model |
|----------|------|-----|---------------|
| Anthropic | `ANTHROPIC_API_KEY` | `anthropic` | `claude-opus-4-6` |
| OpenAI | `OPENAI_API_KEY` | `openai` | `gpt-5.4` |
| Gemini | `GEMINI_API_KEY` | `google-genai` | `gemini-2.5-pro` |
| Mistral | `MISTRAL_API_KEY` | `openai` | `mistral-large-latest` |
| AWS Bedrock | `AWS_BEARER_TOKEN_BEDROCK` or SigV4 chain | `anthropic` + dispatcher | (per config) |
| Ollama | None (local) | `openai` | auto-detected |
| Claude Code | None (`claude` CLI on PATH) | None | (session model) |

See [dependencies](dependencies.md) for SDK installation.

### Claude Code transport

When no other provider is configured but the `claude` CLI is on PATH,
RAPTOR dispatches LLM calls through `claude -p` subprocesses. By
default children are pinned via `--model` to the backend-resolved
model identity (see [Model pinning](#model-pinning)); only when the
probe cache is cold or `RAPTOR_CC_PIN_MODEL=0` is set do children
inherit the CLI session's own default (settings.json,
`ANTHROPIC_MODEL`, or the backend's mapping). Because the pinned id
comes from the backend's own result envelope, this works unchanged on
Bedrock/Vertex-backed installs.

Before committing to this transport, `raptor-resolve-mode` runs a
pre-flight probe — one cheap `claude -p` call that confirms the CLI
can actually complete a request and reads the backend-resolved model
from the result envelope. The result is cached for 24 h in
`~/.raptor/cache/cc-probe.json`, keyed on the backend-selection
environment (provider/model/credential/proxy variables and the CLI
binary), so a configuration change forces a fresh probe. On probe
failure RAPTOR falls back to in-session mode rather than dispatching
into a transport whose calls would hang.

Each dispatch carries a per-call abort ceiling (`--max-budget-usd`,
default 5.00 USD). When a call exceeds it, the CLI exits 1 with
`error_max_budget_usd` in its final stream-json event and the call
fails — on pricier backends the biggest call classes (audit Mode 2
checker synthesis) can hit this. Set `RAPTOR_CC_BUDGET_USD` to raise
or lower the ceiling; total run spend is still governed by the
orchestrator-level `--max-cost`.

Timeouts are per call class: the provider default is 600 s, callers
override `timeout_s` per call (checker synthesis uses 1800 s), and
`timeout_s <= 0` means no timeout. Timed-out calls are retried once
by the client (`timeout_retry_cap`, default 1); each call's
disposition lands in `llm-telemetry.jsonl` with its `call_class`.

#### Model pinning

The transport pins children to the backend-resolved model identity
from the pre-flight probe cache, passing it as `--model` explicitly.
This makes the transport deterministic (a mid-run `settings.json`
edit can no longer switch models silently), gives the scorecard and
cost tracking a real model name, and lets worker derivation resolve
actual capacity limits — the old `session-default` sentinel resolved
to 0 RPM and serialised every review loop to one worker. Pinning is
backend-safe because the id comes from the backend's own result
envelope. Resolution order: `RAPTOR_CC_MODEL` (explicit operator
pin) → cached probe result → sentinel (probe cache cold, `--model`
omitted). `RAPTOR_CC_PIN_MODEL=0` disables probe pinning.

#### Concurrency

`derive_max_workers` clamps to a subprocess-aware ceiling (default 4,
`RAPTOR_CC_MAX_WORKERS` to change) when the primary model is served
by this transport: each worker is a full CLI process, and N parallel
first calls with an identical prompt prefix race the server-side
prompt cache — each pays the full cache write instead of one writing
and N−1 reading. `tuning.json`'s `max_llm_workers` still beats both.

#### Prompt caching

Server-side prompt caching works ACROSS separate `claude -p`
children: measured on a Bedrock-backed install, the second call with
an identical prefix read all ~19k boot-prompt tokens from cache
(~13x cheaper; a same-system-prompt call with a different user
prompt measured ~4x cheaper). Dispatches pass
`--exclude-dynamic-system-prompt-sections` so the CLI's default
system prompt is byte-stable across working directories and
machines, maximising those hits. Practical implication: batches of
similar calls (audit review loops) should share one system prompt
verbatim and run temporally clustered (the cache TTL is minutes).

#### Operator knobs (env)

| Variable | Effect |
|---|---|
| `RAPTOR_CC_MODEL` | Pin children to this model (`--model`) |
| `RAPTOR_CC_PIN_MODEL=0` | Disable probe-based model pinning |
| `RAPTOR_CC_BUDGET_USD` | Per-call abort ceiling (default 5.00) |
| `RAPTOR_CC_MAX_WORKERS` | Subprocess concurrency cap (default 4) |
| `RAPTOR_CC_EFFORT` | `--effort` for children (low/medium/high/xhigh/max) |
| `RAPTOR_CC_FALLBACK_MODEL` | `--fallback-model`: CLI-native retry on overload |
| `RAPTOR_CC_PROBE_WARM=0` | Skip the run-start probe warm |

#### Security posture

Pure-LLM children run with all internal tools disabled
(`--allowed-tools ""`), zero MCP servers (`--strict-mcp-config` with
an empty config), no session persistence, a sanitised environment
(safe-env baseline + backend auth families only), and a private
mode-0700 neutral working directory — which also means no project
CLAUDE.md, settings, or hooks are loaded. User-level settings still
load (some installs carry backend selection there); restricting
`--setting-sources` further is deliberately NOT done for that reason.

## Quick Start

```bash
# Option 1: Anthropic (recommended)
export ANTHROPIC_API_KEY=sk-ant-api03-...

# Option 2: OpenAI
export OPENAI_API_KEY=sk-...

# Option 3: Ollama (free, local, offline)
# Install Ollama, then:
ollama pull mistral

# Option 4: Gemini
export GEMINI_API_KEY=...

# Verify
python3 raptor.py doctor
```

## AWS Bedrock

Bedrock provides two API surfaces, selectable globally or per-model.

### Mantle (Default)

Endpoint: `bedrock-mantle.<region>.api.aws`. Native Anthropic Messages API with bare
model IDs (e.g. `anthropic.claude-haiku-4-5`). Full feature support: SSE streaming,
tool use, prompt caching, vision, extended thinking.

### Runtime (Legacy)

Endpoint: `bedrock-runtime.<region>.amazonaws.com`. Required for models not yet on
Mantle, cross-region inference profile IDs (`us./eu./au./apac./global.` prefixes), and
compliance-pinned ARN-versioned IDs. Non-streaming only.

### Opt-In

Bedrock is never selected implicitly. Ambient AWS credentials
(`AWS_PROFILE`, a credentials file, an instance role) do not flip
RAPTOR onto the API route — one of these explicit signals does:

- a `models.json` entry resolving to `provider: bedrock` (the primary
  path — see Minimal Configuration below);
- `RAPTOR_BEDROCK_MODEL=<id>` or `RAPTOR_BEDROCK_PROFILE=<name>` for
  env-driven one-shot runs;
- `AWS_BEARER_TOKEN_BEDROCK` (bearer auth is its own statement of
  intent).

Once opted in, ambient credentials *gate* the route (an entry without
any resolvable credential stays unusable) but never *select* it.

### Authentication

| Mode | Environment / config | Notes |
|------|----------------------|-------|
| Bearer token | `AWS_BEARER_TOKEN_BEDROCK`, `AWS_REGION` | No SDK dependency. JWT-shaped tokens get expiry countdown warnings; an expired token falls back to SigV4 when the chain resolves (one warning), else 401s with rotation guidance. |
| SigV4 — profile / role | `AWS_PROFILE` or `RAPTOR_BEDROCK_PROFILE` (or per-entry `aws_profile`) | Recommended on AWS compute: no secret at rest, auto-refreshing (SSO / assume-role / IMDS), least-privilege scoping. Needs `botocore` in the parent. |
| SigV4 — static keys | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | Standing secret; prefer a profile. Needs `botocore` (installing `boto3` also works — it includes `botocore`). |

`RAPTOR_BEDROCK_PROFILE` outranks the ambient `AWS_PROFILE`, and a
per-entry `aws_profile` pin outranks both — an entry-pinned profile
also **forces SigV4 for that entry** even when a bearer token is
present (the pin chooses which identity signs; a bearer has no
identity choice). All credential resolution and signing happen in the
dispatcher parent; workers never hold AWS credentials.

### Minimal Configuration

On a box where Claude Code itself runs against Bedrock, the working
CC session is live proof of a valid surface/model/entitlement
combination — so the minimal entry:

```json
{"models": [{"provider": "bedrock"}]}
```

backfills the surface from `CLAUDE_CODE_USE_MANTLE` and the model
from the cc-probe cache (backend-resolved; authoritative) falling
back to `ANTHROPIC_MODEL`. Backfill is same-surface only (bare vs
prefixed id shapes differ per surface) and never happens when CC is
on the direct Anthropic API — its model id is the wrong shape for
Bedrock. Explicit entry fields always win; a fully-specified entry
ignores CC entirely.

A role-less Bedrock entry is the declared default for all API work
(the standard first-entry convention). Give it `"role": "fallback"`
(or any auxiliary role) to keep primary selection unchanged.

### Region

One region value drives both the endpoint hostname and the SigV4
signing scope (they must agree). Resolution, most specific first:

1. `region` field on the entry
2. `RAPTOR_BEDROCK_REGION`
3. entry-pinned `aws_profile`'s own configured region (the pin serves
   the entry; the env serves the box)
4. ambient `AWS_REGION` / `AWS_DEFAULT_REGION`
5. the credential chain's region
6. fail with a no-region diagnostic — never a silent default

Two entries may pin different regions in one run (per-request
signing). Since Bedrock quotas are per-account-per-region, pinning
RAPTOR's entry to a different region than an interactive Claude Code
session is the clean way to stop them competing for headroom.

### Model IDs Per Surface

Mantle accepts **only bare** `<provider>.<model>` ids; RAPTOR
normalizes losslessly at config time (peels a regional prefix,
prepends the provider segment for bare catalog names). Runtime ids
pass verbatim — prefixed inference profiles, versioned ids and ARNs
are all legal there — with a loud warning when a geographic prefix
contradicts the configured region.

### Operational Guards

- **Worker cap:** Bedrock quota is shared account-wide (most visibly
  with a live Claude Code session on the same account), so analysis
  parallelism is clamped to 8 workers by default;
  `RAPTOR_BEDROCK_MAX_WORKERS` overrides, `tuning.json`'s
  `max_llm_workers` beats both.
- **Entitlement preflight:** at dispatcher startup, one 1-token probe
  per configured (model, surface, region, profile) combination turns
  an un-entitled model into an actionable warning up front instead of
  an AccessDenied mid-run. Successes cache for 24h; failures re-probe
  next run; network problems never warn or block.
- **Streaming:** Mantle streams natively; the runtime surface is
  non-streaming (InvokeModel) — selecting it logs the capability
  limit at construction time.
- **Multi-model panels:** two entries that peel to the same
  underlying model (e.g. a Bedrock id and its direct-API name) log a
  same-weights warning — their agreement is transport consistency,
  not independent consensus.

### Standalone CLIs

The Bedrock provider is dispatcher-only. Pipeline runs get the
dispatcher from the launcher; standalone CLIs whose LLM call happens
in the invoking process (`raptor-llm-ask`) self-serve an in-process
dispatcher automatically. `raptor-llm-ask` also defaults to the
configured model when `--model` is omitted — with the minimal entry
above, `/ask <prompt>` just works.

### Switching API Surface

```bash
# Globally per run
export RAPTOR_BEDROCK_API=mantle    # default
export RAPTOR_BEDROCK_API=runtime

# Per model in models.json (always wins over env var)
{"provider": "bedrock", "model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0", "bedrock_api": "runtime"}
```

A geo-prefixed model id (`us.anthropic.*` etc.) infers `provider: bedrock` but
still defaults to Mantle — select Runtime explicitly via `bedrock_api` or
`RAPTOR_BEDROCK_API`. Mantle handles regional routing at the hostname layer.

## Model Configuration

### models.json

Location: `~/.config/raptor/models.json` (override with `RAPTOR_CONFIG`). Supports
`//` line comments.

```json
{
  "models": [
    {
      "provider": "anthropic",
      "model": "claude-opus-4-6",
      "role": "analysis",
      "max_context": 1000000,
      "max_output": 128000,
      "timeout": 120
    },
    {
      "provider": "anthropic",
      "model": "claude-haiku-4-5",
      "role": "fallback"
    },
    {
      "provider": "bedrock",
      "model": "anthropic.claude-haiku-4-5",
      "bedrock_api": "mantle"
    }
  ]
}
```

Entry fields:

| Field | Required | Description |
|-------|----------|-------------|
| `provider` | No | Inferred from model name if unambiguous (`claude-*` = anthropic, `gpt-*` = openai, `us.anthropic.*` / `anthropic.*` = bedrock) |
| `model` | Mostly | Model identifier. Anthropic aliases auto-resolve to dated snapshots. Optional for `bedrock` (backfilled — see Minimal Configuration) and `claudecode` (session default). |
| `api_key` | No | Falls back to provider env var. Not needed for Bedrock SigV4 (the dispatcher signs) or claudecode (the CLI authenticates itself). |
| `role` | No | `analysis`, `code`, `consensus`, `fallback`, `judge`, `aggregate` |
| `max_context` | No | Context window size (tokens) |
| `max_output` | No | Maximum output tokens |
| `timeout` | No | Request timeout (seconds) |
| `bedrock_api` | No | `mantle` or `runtime` (Bedrock only) |
| `aws_profile` | No | Signing profile name for this entry (Bedrock only; non-secret). Forces SigV4 for the entry and outranks env profiles. |
| `region` | No | Endpoint + signing region for this entry (Bedrock only). See the Region ladder. |

A `{"provider": "claudecode", "role": "fallback"}` entry declares the
Claude Code CLI transport as an explicit safety net behind an API
primary — resolvable whenever the `claude` binary is installed.

### Model Selection Logic

1. `--model <name>` on CLI pins a specific model (bypasses auto-selection).
2. Operator `models.json` entries are scored by tier (Opus > GPT-5.4-pro > o3 > Sonnet > Gemini Pro).
   A Bedrock entry without an auxiliary role gets its own step here —
   the tier table can't score Bedrock ids, so the entry itself is the
   declared default for API work.
3. Provider auto-detect: first configured provider in the default order wins.
4. Shorthand resolution: bare tokens like `haiku`, `opus`, `sonnet` match against
   configured model names. Ambiguous matches raise an error.

### Fast-Tier Models

Certain task types (`verdict_binary`, `classify`) automatically use cheaper models:

| Provider | Fast-Tier Model |
|----------|----------------|
| Anthropic | `claude-haiku-4-5` |
| OpenAI | `gpt-4o-mini` |
| Gemini | `gemini-2.5-flash-lite` |
| Mistral | `mistral-small-latest` |

## Multi-Model Workflows

The [/agentic](commands.md#agentic), [/codeql](commands.md#codeql), and
[/analyze](commands.md#analyze) commands support multi-model configurations
via repeatable flags:

| Flag | Role | Description |
|------|------|-------------|
| `--model MODEL` | Analysis | Repeatable. Each model independently analyses every finding in parallel. Results are then correlated. |
| `--consensus MODEL` | Blind second opinion | Receives the same finding independently, never sees the primary's output. Measures agreement. |
| `--judge MODEL` | Non-blind review | Sees the primary's analysis and the finding, then renders a verdict. Runs after primary analysis. |
| `--aggregate MODEL` | Final synthesis | Receives merged results from all models plus correlation data. Produces a single consolidated output. Only one allowed. |

Constraints: consensus/judge/aggregate require at least one analysis model. The same
model cannot serve as both analysis and consensus.

Example:
```bash
/agentic ~/target \
  --model claude-opus-4-6 \
  --model gpt-5.4 \
  --consensus claude-haiku-4-5 \
  --judge claude-opus-4-6
```

## Scorecard

The model scorecard (`out/llm_scorecard.json`) tracks per-model reliability across
decision classes (e.g. `codeql:py/sql-injection`). See [/scorecard](commands.md#scorecard)
for the operator CLI.

### How It Works

- **Wilson confidence bound**: calculates upper-bound miss rate from correct/incorrect
  counts. Models below threshold are "trusted" for that decision class.
- **Short-circuit**: when a cheap-tier model has a trusted scorecard cell, the full
  analysis call to the flagship model is skipped. Cost savings reported at run end.
- **Shadow rate** (default 5%): trusted cells randomly run full analysis to detect
  model drift.
- **Freshness weighting**: optional age-weighted observations so recent data dominates.
- **Schema validity**: every `generate_structured` call records pass/fail under a
  `_structured` decision class.

### Producers

Beyond per-call recording, four producers run at analysis time:

| Producer | What it measures |
|----------|-----------------|
| Cross-run stability | Same finding across runs -- flags models whose verdict flips |
| Cross-family check | Agreement between models from different providers on the same finding |
| Self-consistency | Same model, same finding, different prompt framings -- catches prompt-sensitive models |
| Dataflow validation | Alignment between the model's verdict and the mechanical dataflow evidence |

Controlled by `LLMConfig.scorecard_enabled` (default `True`).

## Cost Management

### Budget Cap

`LLMConfig.max_cost_per_scan` sets a USD budget cap (default $10.00). Enforced via
atomic pre-debit reservation before each provider call. Concurrent dispatchers cannot
race past the cap. Override with `--max-cost-usd` on the CLI.

**Note:** there is no `RAPTOR_MAX_COST` environment variable — no code reads it.
The budget cap is set exclusively via `--max-cost-usd` (CLI) or `max_cost_per_scan`
(config).

### Token Pricing

Per-1K-token input/output rates are maintained in `core/llm/model_data.py` for every
known model, verified against provider pricing pages. Includes:

- Bedrock cross-region surcharge (10%, applied to geo-prefixed models with a
  confirmed `global.` cross-region SKU; other geo prefixes stay at 1.0x)
- Anthropic cache pricing (1.25x input for 5-minute cache writes, 2.0x for
  1-hour cache writes, 0.1x for cache reads)
- Thinking/reasoning tokens billed at output rate across all providers

Unknown models log a warning and record $0 cost (budget caps silently defeated).

### Viewing Costs

Costs are reported at the end of each run. The scorecard also tracks cumulative
per-model cost and token usage.

## Rate Limiting

RAPTOR adapts dispatch concurrency to each provider's rate limits.  The
throttle (`core/llm/throttle.py`) tracks per-model request and token
rates, backs off on 429 responses, and resumes at the observed
sustainable rate.  The concurrency controller (`core/llm/concurrency.py`)
derives `max_parallel` from the model's known RPM (requests per minute),
so a provider with a 60 RPM cap does not get 16 concurrent requests.

No operator configuration is needed — the defaults adapt automatically.
If a provider is consistently throttled, RAPTOR logs the effective rate
at run end.


## Credential Isolation

The LLM dispatcher (`core/llm/dispatcher/`) holds API keys in the parent process only.
Worker processes communicate via Unix domain socket (`RAPTOR_LLM_SOCKET`). The parent's
`CredentialStore` reads and removes sensitive environment variables so sandboxed workers
never see them.

This is automatic when running via `bin/raptor`. Direct `python3 raptor.py` invocations
hold keys in-process.

## Ollama (Offline / Airgapped)

Ollama auto-detection probes `$OLLAMA_HOST/api/tags` (2-second timeout). If no
`OLLAMA_HOST` is set, it defaults to `http://localhost:11434`.

Preferred auto-selection order: mistral > qwen > codellama > llama > gemma >
deepseek-coder > deepseek.

Models that reject tool/function calling are auto-detected at runtime and silently
fall back to JSON-in-prompt synthesis.

### Quality Tradeoffs

| Capability | Frontier Models | Ollama (Local) |
|-----------|-----------------|----------------|
| Vulnerability analysis | Excellent | Good |
| Exploitability triage | Excellent | Good |
| Exploit code generation | Compilable, working C | Often broken — invalid assembly, non-existent libc calls |
| Dataflow validation | Accurate | Prone to hallucination |
| Cost | ~$0.01/finding | Free |

Use Ollama for offline triage and analysis. Use a frontier model for exploit generation
and high-confidence validation.

## Gemini

Full native support via the `google-genai` SDK (`GeminiProvider`). Features include
native schema-constrained JSON output and accurate thinking-token tracking. Falls back
to OpenAI-compatible mode when only the `openai` SDK is installed (loses thinking-token
granularity).

Security-analysis prompts routinely discuss exploits, so every native-SDK call
disables the dangerous-content safety filter (`HARM_CATEGORY_DANGEROUS_CONTENT:
BLOCK_NONE`); if a response is still blocked, the block reason is surfaced in the
error. Truncated native structured responses (output cut mid-JSON) are detected
and raised rather than returned as silently-corrupt data.

## HTTP Transport Tuning

The in-process SDK transports (anthropic, openai, google-genai — all
httpx-based) use a shared pooled-client factory (`core/llm/http_pool.py`)
whose idle keepalive outlives the think-time gap between LLM calls.
httpx's default pool expires idle connections after 5 seconds, so
without this nearly every call re-establishes its connection — cheap on
a direct network, but behind the egress chokepoint chained to a
corporate proxy each re-establishment pays TCP + CONNECT negotiation
per hop plus the TLS handshake. Defaults: 60 s keepalive, 20 pooled
idle connections, 100 total. Tune with `RAPTOR_HTTP_KEEPALIVE_S`,
`RAPTOR_HTTP_MAX_KEEPALIVE`, `RAPTOR_HTTP_MAX_CONNECTIONS`.

`RAPTOR_HTTP2=1` opts the pooled transports into HTTP/2 (requires
`pip install h2`; warns once and stays on HTTP/1.1 when missing).
All concurrent calls then multiplex over a single connection — one
CONNECT chain and one TLS handshake total, which is the biggest
wall-clock win for high-concurrency runs behind chained proxies.
Off by default: TCP head-of-line blocking stalls every multiplexed
stream on one lost packet, and some middleboxes misbehave on
long-lived multiplexed tunnels — enable per-deployment and verify.

`RAPTOR_LLM_STREAM_TRANSPORT=1` carries non-streaming Anthropic calls
over the SDK's streaming transport (`messages.stream` +
`get_final_message()` — the identical response object, so parsing is
unchanged). Use it behind corporate proxies that idle-kill tunnels
carrying no bytes: a thinking model is silent for minutes on a
non-streamed call, while SSE keeps bytes flowing for the whole
generation. TCP keepalive does not cover this case (probes are not
tunnel payload). Off by default so proxied hosts don't silently
exercise different code paths than direct hosts; the task-budget
beta endpoint always stays on plain `create`.

### Choosing the knobs

The defaults are chosen so the pure-win changes need no opt-in and
the two transports with real failure modes need a deliberate one:

- **Keepalive (default 60 s)** must outlive the think-time gap
  between calls but stay inside middlebox idle-kill horizons (squid's
  default `read_timeout` is 15 minutes; NAT tables usually 5+). The
  default sits well inside both bounds — tune only if your proxy's
  idle timer is unusually tight.
- **HTTP/2** is a per-deployment, evidence-based opt-in. A clean
  sequential smoke test is *not* sufficient evidence — the risk cases
  are multiplexed concurrency under packet loss (TCP head-of-line
  blocking stalls every stream at once) and middleboxes that
  misbehave on long-lived multiplexed tunnels. Soak it on a real
  concurrent run (e.g. `/agentic`) before pinning it in the launcher
  environment. Do not enable it behind a TLS-intercepting
  (`ssl_bump`-style) proxy — ALPN then terminates at the proxy.
- **Stream transport** only pays off when the upstream proxy's
  idle timer on relayed bytes is *shorter* than your longest model
  silence. Check the proxy config first (`read_timeout` on squid);
  with the common defaults it buys nothing and just moves you onto
  the less-travelled code path.
- **`RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S`** stays at 10 s so a
  dead proxy fails fast. Widen it only on evidence: `upstream_failed`
  events with handshake reasons in `proxy-events.jsonl`.

### Verifying the transport behaviour

- **Connection reuse:** count tunnels per call. Every CONNECT through
  the egress chokepoint is one record in the run's
  `proxy-events.jsonl`; a healthy pooled transport opens one tunnel
  per provider host per run (plus one STS tunnel on SigV4 routes),
  not one per call.
- **TCP keepalive:** `ss -tno` during a run shows
  `timer:(keepalive,…)` on the established legs toward the upstream
  proxy.
- **Negotiated protocol:** with `RAPTOR_HTTP2=1`, httpx keeps proxied
  connections under the client's proxy *mounts* (not the default
  transport pool); their `info()` strings report `HTTP/2` once a
  request has flowed.
- **Benchmarking pitfalls:** vary prompts with a per-run nonce or the
  LLM response cache serves repeats in ~1 ms and fakes a win; and
  give thinking-tier models an adequate `max_tokens` — a tiny budget
  is consumed by the thinking block and returns zero text with
  `stop_reason=max_tokens`.

## Environment Variables Summary

The LLM-relevant subset. The complete, drift-checked registry —
including the Bedrock knob family, the routing family's spawn
behavior, and credential-isolation details — is
[Environment Variables](environment.md).

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `MISTRAL_API_KEY` | Mistral API key |
| `AWS_BEARER_TOKEN_BEDROCK` | Bedrock bearer token auth |
| `AWS_ACCESS_KEY_ID` | Bedrock SigV4 auth |
| `AWS_SECRET_ACCESS_KEY` | Bedrock SigV4 auth |
| `AWS_REGION` | Bedrock region selection |
| `RAPTOR_BEDROCK_API` | `mantle` (default) or `runtime` |
| `RAPTOR_LLM_SOCKET` | Credential isolation dispatcher socket |
| `RAPTOR_CONFIG` | Override path to `models.json` |
| `OLLAMA_HOST` | Ollama server URL |
| `RAPTOR_CC_MODEL` / `RAPTOR_CC_PIN_MODEL` | Claude Code transport model pinning (see above) |
| `RAPTOR_CC_BUDGET_USD` | Claude Code per-call abort ceiling (default 5.00) |
| `RAPTOR_CC_MAX_WORKERS` | Claude Code subprocess concurrency cap (default 4) |
| `RAPTOR_CC_EFFORT` / `RAPTOR_CC_FALLBACK_MODEL` | Claude Code child effort / fallback model |
| `RAPTOR_CC_PROBE_WARM` | `0` skips the run-start probe warm |
| `RAPTOR_LLM_CACHE_TTL_S` | LLM response cache TTL override (default 24 h) |
| `RAPTOR_HTTP_KEEPALIVE_S` | SDK transport idle keepalive expiry (default 60) |
| `RAPTOR_HTTP_MAX_KEEPALIVE` | SDK transport pooled idle connections (default 20) |
| `RAPTOR_HTTP_MAX_CONNECTIONS` | SDK transport total connections (default 100) |
| `RAPTOR_HTTP2` | `1` opts SDK transports into HTTP/2 (needs `h2`) |
| `RAPTOR_LLM_STREAM_TRANSPORT` | `1` carries Anthropic calls over the streaming transport |
