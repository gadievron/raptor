# RAPTOR Dynamic Instrumentation (Frida) - Quick Start Guide

## What It Does

The `/frida` command drives [Frida](https://frida.re) to observe a binary at
runtime, complementing RAPTOR's static analysis:

1. **Function/argument tracing** - hook named functions and capture their
   entry arguments and addresses.
2. **Stalker coverage** - record executed basic blocks and emit a standard
   `drcov` file (loadable in Lighthouse/IDA, and ingested into RAPTOR's
   coverage store alongside gcov/lcov/AFL).

It is **spawn-only by default**: RAPTOR launches the target itself rather than
attaching to a running PID, and the target is always operator-chosen. Runs are
sandboxed; see [Sandbox profiles](#sandbox-profiles).

## Prerequisites

### Install Frida

```bash
# Recommended (isolated CLI install)
pipx install frida-tools

# or
pip install frida-tools

# Verify
frida --version
```

Frida is **optional**. When it is absent, the capability probe reports
unavailable and `/doctor` shows a soft warning - no other command is affected.

### Check capability

```bash
libexec/raptor-frida probe
```

This reports the Frida Python binding, the `frida` CLI, the platform/arch, and
the kernel `ptrace_scope` setting. `ptrace_scope=1` is sufficient for
spawn-only operation (the same model gdb/rr use).

## Quick Test

### 1. Compile a test binary

```bash
cat > /tmp/demo.c <<'EOF'
#include <stdio.h>
int add(int a, int b){ return a + b; }
int main(void){ printf("sum=%d\n", add(2, 3)); return 0; }
EOF
cc -O0 -g -o /tmp/demo /tmp/demo.c
```

### 2. Trace a function

```bash
libexec/raptor-frida trace /tmp/demo --symbols add --out /tmp/frida-out
```

Output is JSON: each hooked call records the function name, its entry
arguments, and address; plus an `events_path` to the per-event JSONL log.

### 3. Collect coverage

```bash
libexec/raptor-frida coverage /tmp/demo --out /tmp/frida-cov
```

Writes `frida.drcov` (DynamoRIO coverage format) and reports the basic-block
count. The drcov file routes through `import_drcov` into the same coverage
store as gcov/lcov/AFL.

## Usage

```
raptor-frida probe
raptor-frida trace    <binary> --symbols <fn1,fn2,...> [--out DIR] [--timeout S] [--profile P]
raptor-frida coverage <binary> [--modules <substr,...>] [--out DIR] [--timeout S] [--profile P]
```

- `--symbols` - comma-separated function names. Resolved via DWARF; a symbol
  only present in a shared library may need the library's name.
- `--modules` - restrict coverage to module-name substrings; default covers
  the main module.
- `--out` - output directory for the JSON/JSONL/drcov artifacts.
- `--timeout` - seconds before the spawned target is killed.
- `--profile` - sandbox profile (see below).

## Sandbox profiles

| Profile | Isolation |
|---|---|
| `debug` (default) | full namespace isolation (mount/PID/network) where the host supports it |
| `network-only` | network denied; filesystem unrestricted |
| `none` | no isolation (Landlock disabled) |

On a host without working mount namespaces, the `debug` profile degrades to no
isolation for the spawn with an explicit warning (network is not blocked, but
the target is still operator-chosen and spawn-only). For full isolation, run on
a host with working user/mount namespaces.

## Notes

- Pointer arguments show as their integer value; dereference in a follow-up
  hook if you need the pointed-to data.
- Stalker cannot enumerate a spawned target's threads until the loader has run,
  so very early startup blocks may be missed.
- See the LLM-facing skills for deeper detail:
  `.claude/skills/dynamic-instrumentation/SKILL.md` (gates, model, isolation),
  `.../trace/SKILL.md`, and `.../coverage/SKILL.md`.
