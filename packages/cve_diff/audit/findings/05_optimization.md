# Phase 05 — Optimization Probes

`re.compile` inside function bodies: **0** (prefer module-level)
Disk I/O inside loops: **1** (review for caching)

## Findings by file

### `cve_diff/report/flow.py`
- `.write_text()` at line 68 inside a loop (cache or batch?)
