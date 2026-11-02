---
name: rr-debugger
description: Deterministic debugging with rr record-replay. Use when debugging crashes, ASAN faults, or when reverse execution is needed. Provides reverse-next, reverse-step, reverse-continue commands and crash trace extraction.
user-invocable: false
---

# rr Deterministic Debugger

rr provides deterministic record-replay debugging with full reverse execution capabilities.

## Core Workflow

1. **Record** using the dedicated analysis workspace:
   ```bash
   libexec/raptor-rr record --workspace <workspace> --trace rr-trace --cwd repo -- ./program <args>
   ```
   Add `--stdin attachments/<input>` before `--` for a stdin-fed reproducer. Input paths are workspace-relative; program arguments are relative to `--cwd`. Recording requires the dedicated Linux rr policy. Keep targets, inputs and non-system dependencies in the analysis workspace. It remains writable by the untrusted target. The helper checks the terminal event and performs a complete confined replay before reporting a usable recording. Continue only when its replay consistency check passed; retain verification failures for diagnosis, never as confirmed evidence.
2. **Pack** only the selected trace:
   ```bash
   libexec/raptor-rr pack --workspace <workspace> --trace rr-trace
   ```
   Packing reads the declared workspace and system/runtime files; it cannot discover extra read roots from paths embedded in a recording. Its normal untrusted policy needs no counter or ptrace exception. The record helper returns 0 for a verified capture even when the target crashed; preserve the underlying target status from its diagnostics. Do not treat a partial trace from a failed or timed-out recording as confirmed evidence.
3. **Replay**: `libexec/raptor-rr replay <workspace>/rr-trace` opens contained GDB reverse execution. The launcher disables initialization and automatic symbol scripts before loading the recording. Never retry any stage outside containment after refusal.

## Reverse Execution Commands

All standard gdb commands work, plus reverse variants:

- `reverse-next` / `rn`: Step back over function calls
- `reverse-step` / `rs`: Step back into functions
- `reverse-continue` / `rc`: Continue backward to previous breakpoint
- `reverse-stepi` / `rsi`: Step back one instruction
- `reverse-nexti` / `rni`: Step back over one instruction

## Crash Trace Extraction

### Regular Crashes

After recording and packing the crashing program:

```bash
libexec/raptor-rr replay <workspace>/rr-trace
# In gdb:
reverse-next 100    # Go back 100 steps (adjust N as needed)
# Now step forward to see execution leading to crash:
next
next
...
```

### ASAN Crashes

After recording and packing the ASan program:

```bash
libexec/raptor-rr replay <workspace>/rr-trace
# In gdb:
bt                  # View stack trace
up                  # Issue "up" commands until last app frame (before ASAN runtime)
break *$pc          # Set breakpoint at that location
reverse-continue    # Go back to last app instruction before ASAN
# Now step forward to see execution leading to fault:
next
next
...
```

## Inspecting Variables and Memory

Standard gdb commands work at any point:

- `print <var>`: Print variable value
- `print *<ptr>`: Dereference pointer
- `x/<format> <address>`: Examine memory
  - `x/10xb <addr>`: 10 bytes in hex
  - `x/s <addr>`: String at address
- `info locals`: Show local variables
- `info args`: Show function arguments

## Source vs Assembly View

- `list`: Show source code around current location
- `disassemble`: Show assembly around current location
- `layout src`: TUI source view
- `layout asm`: TUI assembly view
- `set disassemble-next-line on`: Show assembly with each step

## Automation Script

Use `scripts/crash_trace.py` to automatically extract execution trace before crash.
