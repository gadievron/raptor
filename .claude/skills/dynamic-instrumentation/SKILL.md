# Dynamic Instrumentation (Frida) - SKILL

Spawn-and-instrument support for `/frida`. Backend: Frida (the `frida` Python
binding + agent JS). The deterministic mechanics live in
`packages/dynamic_instrumentation/` and are reached through
`libexec/raptor-frida` so this skill stays declarative.

## Execution model (read before running)

- **Spawn, not attach.** The driver (`frida_driver.py`) runs *inside* the
  sandbox as the parent and `frida.spawn()`s the target as a descendant, so
  `ptrace_scope=1` authorises the trace - the same model gdb/rr use under
  `/crash-analysis`. Attaching to a pre-existing PID is **not** the default
  (and does not work under the namespace sandbox).
- **Isolation.** Default sandbox profile is `debug` (full Landlock + seccomp
  *with ptrace* + network block). Frida's spawn loader reads
  `/proc/<pid>/auxv`, which needs `/proc` correctly remounted in the PID
  namespace; on hosts where the mount namespace can't be set up the runner
  detects the failure and transparently falls back to `profile="none"` (no
  isolation) with a warning. The fallback loses network isolation only; the
  target is still operator-chosen and spawn-only.
- **The agent JS is RAPTOR's; the target is untrusted.** Credentials are
  protected by the sandbox (restrict_reads / fake_home semantics of the
  profile); network is blocked by default so an instrumented target can't
  phone home.

## Capability gate

Always probe first - Frida is an optional (`degrades`) dependency:
```
libexec/raptor-frida probe
```
`available: false` → tell the operator `pipx install frida-tools` and stop.

## Sub-skills

- `trace/SKILL.md` - hook named functions, capture entry arguments.
- `coverage/SKILL.md` - Stalker basic-block coverage → drcov → CoverageStore.

## Reuse (don't reinvent)

| Need | Use |
|------|-----|
| Output dir + status | `libexec/raptor-run-lifecycle start/complete/fail` |
| Sandboxed spawn + ptrace | `packages/dynamic_instrumentation/runner.py` (`core.sandbox`, profile `debug`) |
| drcov → source coverage | `core.coverage.collect.import_drcov` (Frida-aware) |
| Coverage store / `/project coverage` | `core.coverage.store.CoverageStore` |
| Debug binary for DWARF | `/project binary add <path>` persisted list |
| Capability + `/doctor` | `RaptorConfig.TOOL_DEPS["frida"]` |

## Programmatic API

```python
from packages.dynamic_instrumentation.api import trace_functions, collect_coverage
trace_functions(binary, ["func"], output_dir=OUT)         # → {trace, unresolved, ...}
collect_coverage(binary, output_dir=OUT, store=store, checklist=cl)  # → marks store
```
