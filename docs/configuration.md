# Configuration

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
| `codeql_max_disk_cache_mb` | `0` | CodeQL DB cache cap; 0 = unbounded |
| `joern_enabled` | `true` | Master toggle for Joern CPG |
| `joern_heap_mb` | `"auto"` | JVM heap for Joern; auto = 25% system RAM, min 1024. A proportional value landing in the compressed-oops dead zone (32-48 GiB) clamps down to 31 GiB — more effective capacity than an uncompressed 33-48 GiB heap; above 48 GiB stays proportional |
| `joern_cpg_timeout_s` | `300` | CPG generation timeout |
| `joern_query_timeout_s` | `300` | Per-query timeout |
| `max_llm_workers` | `"auto"` | Parallel LLM API calls; beats the RPM-derived and claudecode caps |
| `throttle_cooldown_s` | `30` | Cooldown after an LLM rate-limit response |
| `max_semgrep_workers` | `"auto"` | Parallel Semgrep packs; auto = half CPUs. Each pack's `--jobs` is divided so concurrent packs share the host instead of each claiming every core |
| `max_codeql_workers` | `"auto"` | Parallel CodeQL DB builds/analyses; auto = half CPUs, capped at 8 and RAM-limited. Per-invocation `-j` is divided between concurrent builds when `codeql_threads` is auto; an explicit numeric `codeql_threads` is never second-guessed |
| `max_fuzz_parallel` | `"auto"` | AFL++ parallel instances ceiling; auto = half CPUs |
| `max_inventory_workers` | `"auto"` | Tree-sitter extractor pool; auto = half CPUs, cap 8 |
| `max_json_memo_mb` | `128` | In-process JSON cache budget |

Unknown keys warn and are ignored.


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
