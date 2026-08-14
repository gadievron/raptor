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
| `joern_heap_mb` | `"auto"` | JVM heap for Joern; auto = 25% system RAM, min 1024, no upper clamp |
| `joern_cpg_timeout_s` | `300` | CPG generation timeout |
| `joern_query_timeout_s` | `300` | Per-query timeout |
| `max_semgrep_workers` | `4` | Parallel Semgrep scans |
| `max_codeql_workers` | `2` | Parallel CodeQL DB builds |
| `max_fuzz_parallel` | `4` | AFL++ parallel instances ceiling |
| `max_inventory_workers` | `"auto"` | Tree-sitter extractor pool; auto = half CPUs, cap 8 |
| `max_json_memo_mb` | `128` | In-process JSON cache budget |

Unknown keys warn and are ignored.


## Environment variables

LLM provider keys and model config are documented in
[LLM Providers](llm.md#environment-variables-summary). The remaining
RAPTOR-specific variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RAPTOR_DIR` | Set by launcher | Installation root; used by libexec scripts |
| `RAPTOR_OUT_DIR` | `out/` | Output directory override |
| `RAPTOR_TARGET_KIND` | `auto` | Target classification: `auto`, `library`, `hybrid`, `application` |
| `RAPTOR_CALLER_DIR` | Set by launcher | User's working directory before RAPTOR switched to repo dir |


## Sandbox calibration cache

**Path:** `~/.cache/raptor/sandbox-profiles/`

Auto-calibration profiles for external binaries (CodeQL, pip, etc.). Cache
key is `sha256(realpath(binary)) + env_signature`. Clear with:

```bash
raptor sandbox calibrate --clear
```
