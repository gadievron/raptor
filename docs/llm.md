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
Mantle, cross-region inference profile IDs (`us./eu./apac./global.` prefixes), and
compliance-pinned ARN-versioned IDs. Non-streaming only.

### Authentication

Two auth modes:

| Mode | Environment Variables | Notes |
|------|----------------------|-------|
| Bearer token | `AWS_BEARER_TOKEN_BEDROCK`, `AWS_REGION` | Recommended; no SDK dependency |
| SigV4 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | Uses AWS credential chain (env/profile/SSO/IMDS); requires `boto3` |

### Switching API Surface

```bash
# Globally per run
export RAPTOR_BEDROCK_API=mantle    # default
export RAPTOR_BEDROCK_API=runtime

# Per model in models.json (always wins over env var)
{"provider": "bedrock", "model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0", "bedrock_api": "runtime"}
```

Cross-region inference (`us./eu./apac./global.` prefixes) routes through Runtime
automatically. Mantle handles regional routing at the hostname layer.

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
| `provider` | No | Inferred from model name if unambiguous (`claude-*` = anthropic, `gpt-*` = openai, `us.anthropic.*` = bedrock) |
| `model` | Yes | Model identifier. Anthropic aliases auto-resolve to dated snapshots. |
| `api_key` | No | Falls back to provider env var |
| `role` | No | `analysis`, `code`, `consensus`, `fallback`, `judge`, `aggregate` |
| `max_context` | No | Context window size (tokens) |
| `max_output` | No | Maximum output tokens |
| `timeout` | No | Request timeout (seconds) |
| `bedrock_api` | No | `mantle` or `runtime` (Bedrock only) |

### Model Selection Logic

1. `--model <name>` on CLI pins a specific model (bypasses auto-selection).
2. Operator `models.json` entries are scored by tier (Opus > GPT-5.4-pro > o3 > Sonnet > Gemini Pro).
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

- Bedrock regional surcharges (10% for geo-prefixed `us./eu./au./apac.` models)
- Anthropic cache pricing (1.25x input for cache writes, 0.1x for cache reads)
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

## Environment Variables Summary

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
