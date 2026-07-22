# LLM & Configuration

RAPTOR picks an LLM provider from env vars or `~/.config/raptor/models.json`; this page documents every variable and config field.
Every variable below is confirmed against the code (`core/llm/`, `core/config/`).

For *installing* RAPTOR and its API-key basics, see
[`install.md`](install.md) — this page does not repeat install steps.

---

## Two ways to configure a provider

1. **Environment variables** — zero-config autodetect. Export a provider's API
   key and RAPTOR uses it. Good for a single-provider setup.
2. **`~/.config/raptor/models.json`** — explicit, multi-model, role-aware.
   Overrides autodetect. Use this for multi-model correlation, per-model
   settings, or Bedrock surface selection.

A models.json entry always wins over env-var autodetect for the same provider.

---

## Environment-variable autodetect

With no config file, RAPTOR picks the first available provider in this order:

| Order | Provider | Key env var | SDK / requirement |
|-------|----------|-------------|-------------------|
| 1 | Anthropic (Claude) | `ANTHROPIC_API_KEY` | native `anthropic` SDK |
| 2 | OpenAI | `OPENAI_API_KEY` | `openai` SDK (`pip install openai`) |
| 3 | Google Gemini | `GEMINI_API_KEY` | `openai` SDK (OpenAI-compatible endpoint) |
| 4 | Mistral | `MISTRAL_API_KEY` | `openai` SDK (OpenAI-compatible endpoint) |
| 5 | AWS Bedrock | `AWS_BEARER_TOKEN_BEDROCK` (or AWS creds) | see [Bedrock](#aws-bedrock) |
| 6 | Ollama (local/remote) | `OLLAMA_HOST` | reachable Ollama server |
| 7 | Claude Code | none | `claude` CLI on `PATH` (last-resort subprocess) |

Notes:

- **`MISTRAL_API_KEY`** is the correct Mistral variable.

  > Note: there is no generic "provider key" variable — Mistral reads
  > `MISTRAL_API_KEY` specifically.
- **OpenAI / Gemini / Mistral all route through the OpenAI SDK.** If a key is
  present but the `openai` package is not installed, that provider is skipped
  and autodetect falls through to the next candidate.
- **`OLLAMA_HOST`** points RAPTOR at an Ollama server; it defaults to
  `http://localhost:11434`. Set it to your server's URL (include the scheme —
  `http://host:11434`, not `host:11434`). This is the only supported way to
  reference a remote Ollama endpoint.
- Default model per provider: Anthropic `claude-opus-4-6`, OpenAI `gpt-5.4`,
  Gemini `gemini-2.5-pro`, Mistral `mistral-large-latest`. Fast/cheap-tier
  siblings (used automatically for classification-style tasks) are
  `claude-haiku-4-5`, `gpt-4o-mini`, `gemini-2.5-flash-lite`,
  `mistral-small-latest`.

---

## `~/.config/raptor/models.json`

Path resolution:

1. `RAPTOR_CONFIG` env var (if set — points at any JSON file), else
2. `~/.config/raptor/models.json`

### Shape

Two accepted top-level shapes — a bare array, or an object with a `models` key.
`//` line comments are allowed (stripped before parsing).

```jsonc
// ~/.config/raptor/models.json — bare array form
[
  { "provider": "anthropic", "model": "claude-opus-4-6", "role": "analysis" },
  { "provider": "openai",    "model": "gpt-5.4",         "role": "consensus" },
  { "provider": "mistral",   "model": "mistral-large-latest", "role": "fallback" }
]
```

```jsonc
// object form is equivalent
{ "models": [ { "provider": "anthropic", "model": "claude-opus-4-6" } ] }
```

### Per-entry fields

| Field | Required | Meaning |
|-------|----------|---------|
| `provider` | usually | `anthropic` \| `openai` \| `gemini` \| `mistral` \| `bedrock` \| `ollama` \| `claudecode`. May be omitted when `model` is a Bedrock-shaped id (e.g. `us.anthropic.claude-opus-4-7`) — the provider is derived. |
| `model` | yes* | Model id. If omitted with a `provider`, the provider's default model is used. |
| `api_key` | no | Inline key. If absent, resolved from the provider's env var. Prefer env vars — inline keys are persisted in plaintext. |
| `role` | no | See [roles](#model-roles). |
| `max_context` | no | Override context-window token cap. |
| `max_output` | no | Override output token cap. |
| `timeout` | no | Per-call timeout in seconds (default 120). |
| `bedrock_api` | no | Bedrock only: `mantle` (default) or `runtime`. Per-model override of `RAPTOR_BEDROCK_API`. |

API-key resolution per entry: inline `api_key` → provider env var
(`PROVIDER_ENV_KEYS`) → for Bedrock entries, `AWS_BEARER_TOKEN_BEDROCK`.

---

## Model roles

Roles let multiple configured models play different parts in a run
(multi-model analysis, consensus review, synthesis). Valid roles:

| Role | Purpose |
|------|---------|
| `analysis` | Primary vulnerability analysis. Multiple allowed (multi-model mode). |
| `code` | Exploit/patch code generation. At most **one**. |
| `consensus` | Independent second-opinion review of analysis output. |
| `judge` | Adjudicates disagreements. |
| `aggregate` | Synthesises multiple models' output. At most **one**. |
| `fallback` | Used when higher-priority models fail. |

Defaults and validation:

- **No roles set** → the first model is `analysis` + `code`; the rest become
  `fallback`.
- `consensus`, `judge`, `aggregate`, and `code` each require at least one
  `analysis` model.
- You cannot configure *only* `fallback` models — at least one `analysis` model
  is required.
- The same model cannot be both `analysis` and `consensus` (use `consensus`).
- Invalid role names or the constraint violations above raise a `ConfigError` at
  startup.

The CLI-facing surface (`/agentic --model`, `--consensus`, `--judge`,
`--aggregate`) maps onto these roles.

---

## AWS Bedrock

Bedrock routes Claude (and other) models through AWS. It autodetects when
`AWS_BEARER_TOKEN_BEDROCK` is set, or is selected explicitly via a
`"provider": "bedrock"` entry (or a Bedrock-shaped model id) in models.json.

### Auth modes

Both are validated against real Bedrock; **bearer takes precedence over SigV4**
when both are present (matching the AWS SDKs).

- **Bearer token** (recommended; no AWS SDK required):
  ```bash
  export AWS_BEARER_TOKEN_BEDROCK=<token>
  export AWS_REGION=eu-west-1            # picks the regional Bedrock host
  ```
- **SigV4** (uses your AWS credential chain — env / profile / SSO / IMDS — for
  static or rotating credentials):
  ```bash
  export AWS_ACCESS_KEY_ID=...
  export AWS_SECRET_ACCESS_KEY=...
  export AWS_SESSION_TOKEN=...           # if using temporary credentials
  export AWS_REGION=eu-west-1            # or AWS_DEFAULT_REGION
  pip install boto3                      # botocore/SigV4 signing, parent-only
  ```
  SigV4 signing lives only in the parent process; workers keep using the plain
  Anthropic SDK. `botocore` (pulled in by `boto3`) is required **only** for
  SigV4 mode.

### Surfaces: Mantle vs Runtime

Two Bedrock surfaces, selectable per run or per model:

| | **Mantle** (default) | **Runtime** (legacy InvokeModel) |
|---|---|---|
| Host | `bedrock-mantle.<region>.api.aws` | `bedrock-runtime.<region>.amazonaws.com` |
| API | Native Anthropic Messages API | InvokeModel |
| Model IDs | Bare (`anthropic.claude-haiku-4-5`) | Cross-region inference profiles (`us.` / `eu.` / `apac.` / `global.`) and ARN-versioned pins (`anthropic.claude-haiku-4-5-20251001-v1:0`) |
| Streaming | Yes (SSE) | No (non-streaming only) |
| Features | Tool use, prompt caching, vision, extended thinking, computer use | Compatibility for models/ids not yet on Mantle |

Use **Runtime** when you need a cross-region inference-profile id or a
compliance-pinned ARN-versioned id; otherwise stay on **Mantle** (streaming +
full feature support). Cross-region routing on Mantle happens at the hostname
layer, so its model IDs stay bare.

### Selecting the surface

```bash
# Globally, per run:
export RAPTOR_BEDROCK_API=mantle     # default
export RAPTOR_BEDROCK_API=runtime
```

```jsonc
// Per model in models.json — always wins over the env var:
{ "provider": "bedrock",
  "model":    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
  "bedrock_api": "runtime" }
```

Unrecognised `RAPTOR_BEDROCK_API` / `bedrock_api` values fall back to `mantle`.

---

## Ollama: reliability caveat

Local Ollama models are fine for **analysis and triage** but are **unreliable
for exploit/patch code generation** — they frequently emit non-compilable C,
invalid shellcode/pointer arithmetic, calls to non-existent libc functions, and
malformed assembly. For production exploit generation use Anthropic Claude or
OpenAI. RAPTOR emits a provider-specific warning when Ollama is the active model
for code generation.

---

## Cost cap

RAPTOR caps LLM spend two ways:

- **Per-run pre-flight gate:** pass `--max-cost-usd <USD>` to a run
  (`libexec/raptor-run-lifecycle start --max-cost-usd <cap>`, and equivalents on
  `/scan`, `/agentic`, etc.). The run hard-fails before doing LLM work if the
  estimate exceeds the cap. Some commands also accept `--max-cost`.
- **Default budget:** `LLMConfig.max_cost_per_scan` defaults to **$10 USD** per
  scan when no explicit cap is given.

> **`RAPTOR_MAX_COST` has no effect.** No code reads it — use `--max-cost-usd`/`--max-cost`.

---

## Offline behaviour

RAPTOR does **not** ship a populated offline Semgrep registry cache.

What actually ships and how it behaves:

- **Local custom rules run fully offline.** ~40 rule files ship under
  `engine/semgrep/rules/` (`auth/`, `crypto/`, `deserialisation/`,
  `filesystem/`, `flows/`, `go/`, `injection/`, `java/`, `javascript/`,
  `logging/`, `python/`, `secrets/`, `sinks/`, `web/`, `xml/`). No
  network needed for these.
- **`engine/semgrep/rules/registry-cache/` ships empty** — it contains only a
  `.gitkeep`. It is a slot for cached registry packs, not a shipped cache.
- **Registry packs are fetched from semgrep.dev at scan time** and therefore
  need network access. The baseline packs are `p/security-audit`,
  `p/owasp-top-ten`, and `p/secrets`; policy-group packs (e.g.
  `p/command-injection`, `p/jwt`, `p/xss`) are also fetched on demand. If a
  matching file were present in `registry-cache/` it would be used instead —
  but none ship, so these always require network unless you populate the cache
  yourself.

Net effect: RAPTOR's local Semgrep rules and CodeQL work offline; registry
Semgrep packs and all cloud LLM providers require network. Fully air-gapped runs
should rely on the local rule dirs (+ CodeQL) and a local Ollama model.

---

## Quick reference: environment variables

| Variable | Read by | Purpose |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | `core/llm/config.py`, `PROVIDER_ENV_KEYS` | Anthropic key |
| `OPENAI_API_KEY` | `core/llm/config.py`, `PROVIDER_ENV_KEYS` | OpenAI key |
| `GEMINI_API_KEY` | `core/llm/config.py`, `PROVIDER_ENV_KEYS` | Gemini key |
| `MISTRAL_API_KEY` | `core/llm/config.py`, `PROVIDER_ENV_KEYS` | Mistral key |
| `GOOGLE_API_KEY` | `core/config` `LLM_API_KEY_VARS` | Alternate Gemini/Vertex key |
| `OLLAMA_HOST` | `core/config/__init__.py` (`RaptorConfig.OLLAMA_HOST`) | Ollama server URL (default `http://localhost:11434`) |
| `RAPTOR_CONFIG` | `core/llm/detection.py` | Override models.json path |
| `AWS_BEARER_TOKEN_BEDROCK` | `core/llm/config.py`, `dispatcher/auth.py` | Bedrock bearer token |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | `dispatcher/auth.py` | Bedrock regional host |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | `dispatcher/auth.py` (SigV4 chain) | Bedrock SigV4 credentials |
| `RAPTOR_BEDROCK_API` | `core/llm/config.py` | Bedrock surface: `mantle` \| `runtime` |

Cost caps use the `--max-cost-usd` / `--max-cost` **flags**, not an env var (see
[Cost cap](#cost-cap)).
