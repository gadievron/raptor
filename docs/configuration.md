# Configuration

[Documentation index](README.md)

Use `models.json` to choose LLM providers and models, `tuning.json` to set
resource limits, and environment variables for runtime overrides. Start with
the relevant section below; each setting has its own precedence rules.

**Related documentation:**
[LLM Providers](llm.md) |
[Sandbox](sandbox.md) |
[Dependencies](dependencies.md)


## LLM and model configuration

See [LLM Providers](llm.md) — covers `models.json` format and location,
provider API keys, model selection, budget cap (`--max-cost-usd`), and
cost tracking.


## tuning.json — resource tuning

**Path:** `tuning.json` in the RAPTOR repo root.

Hardware-aware resource limits. Values of `"auto"` are resolved at runtime
based on system hardware.

| Field | Default | Description |
|-------|---------|-------------|
| `codeql_enabled` | `true` | Master toggle for CodeQL |
| `codeql_ram_mb` | `"auto"` | RAM for CodeQL; auto = 25% system RAM, clamped 2048–16384 |
| `codeql_threads` | `"auto"` | CPUs for CodeQL; auto = all available |
| `codeql_max_disk_cache_mb` | `0` | CodeQL internal build-cache limit (`--max-disk-cache`); 0 leaves its default. Does not cap all retained database directories |
| `joern_enabled` | `true` | Master toggle for Joern CPG |
| `joern_heap_mb` | `"auto"` | JVM heap for Joern; auto = 25% system RAM, min 1024 MiB, subject to `joern_heap_ceiling_mb`. Derived values in the compressed-oops dead zone clamp to 31 GiB. Explicit heap values are not ceiling-capped. |
| `joern_heap_ceiling_mb` | `"auto"` | Ceiling on the derived heap; auto = min(25% system RAM, 65536 MiB), with a 1024 MiB floor |
| `joern_cpg_timeout_s` | `"auto"` | CPG generation timeout; auto = derived from in-scope source size at build time |
| `joern_import_timeout_s` | `"auto"` | Timeout for importing a built CPG into the Joern server; auto = derived from the serialized CPG size at import time |
| `joern_query_timeout_s` | `300` | Per-query timeout (the pre-sweep window additionally scales this by CPG size) |
| `max_llm_workers` | `"auto"` | Parallel LLM calls; an explicit number overrides RPM/posture/Claude Code auto ceilings, but remains clamped to 1–32 and to `RAPTOR_LOCAL_MAX_WORKERS` for a local primary (default 2) |
| `llm_account_posture` | `"shared"` | Who else spends the LLM account: `shared` keeps the fair-share auto ceilings; `solo` asserts the account belongs to this host's runs and raises the account-contention (Bedrock) ceiling. Profiles own it: `max` writes `solo`, `balanced`/`default` write `shared`. Unrecognised values warn and read as `shared` |
| `throttle_cooldown_s` | `30` | Cooldown after an LLM rate-limit response |
| `default_max_cost_usd` | `"auto"` | Standing USD ceiling applied when a run configures **no** LLM cost cap anywhere; a CLI/programmatic cap always wins. `"auto"` (or any non-positive/non-numeric value) = no default — uncapped runs print a warning banner instead |
| `max_semgrep_workers` | `"auto"` | Parallel Semgrep packs; auto = half CPUs. Each pack's `--jobs` is divided so concurrent packs share the host instead of each claiming every core |
| `max_codeql_workers` | `"auto"` | Parallel CodeQL DB builds/analyses; auto = half CPUs, capped at 8 and RAM-limited. Per-invocation `-j` is divided between concurrent builds when `codeql_threads` is auto; an explicit numeric `codeql_threads` is never second-guessed |
| `max_fuzz_parallel` | `"auto"` | AFL++ parallel instances ceiling; auto = half CPUs |
| `max_inventory_workers` | `"auto"` | Tree-sitter extractor pool; auto = half CPUs, cap 8 |
| `max_json_memo_mb` | `128` | In-process JSON cache budget |
| `sca_cache_max_mb` | `2048` | Disposable SCA disk-cache budget in MiB, including stress checkouts; 0 disables automatic cleanup |
| `sca_stress_cache_max_mb` | `512` | Idle stress-checkout sub-budget in MiB; 0 removes all idle checkouts during maintenance |

Inspect resolved values with `/tune`. `/tune max`, `/tune balanced`, and
`/tune default` rewrite resource settings; `max` also selects the `solo`
LLM account posture. Unknown keys warn and are ignored.

SCA disk budgets are soft: periodic maintenance runs between online scans,
while active scans can temporarily exceed them. See [SCA cache cleanup](sca.md#cache-cleanup).


## Environment variables

The canonical, drift-checked registry of every environment variable —
operator knobs, provider credentials, the LLM routing family, proxy
behavior, and the internal plumbing RAPTOR sets for its own children —
is [Environment Variables](environment.md).


## Sandbox calibration cache

**Path:** `~/.cache/raptor/sandbox-profiles/`

Auto-calibration profiles for external binaries (CodeQL, pip, etc.). Cache
key is `sha256(realpath(binary)) + env_signature`. Clear one entry or all:

```bash
libexec/raptor-sandbox-calibrate --bin <path> --clear
libexec/raptor-sandbox-calibrate --clear-all
```
