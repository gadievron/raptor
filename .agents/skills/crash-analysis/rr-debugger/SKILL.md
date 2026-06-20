---
name: rr-debugger
description: Deterministic debugging with rr record-replay. Use when debugging crashes, ASAN faults, or when reverse execution is needed. Provides reverse-next, reverse-step, reverse-continue commands and crash trace extraction.
user-invocable: false
---

# rr Deterministic Debugger

rr provides deterministic record-replay debugging with full reverse execution capabilities.

## Core Workflow

1. **Record**: `rr record <program> [args]`
2. **Replay**: `rr replay` (enters gdb interface with reverse execution)

## Reverse Execution Commands

All standard gdb commands work, plus reverse variants:

- `reverse-next` / `rn`: Step back over function calls
- `reverse-step` / `rs`: Step back into functions
- `reverse-continue` / `rc`: Continue backward to previous breakpoint
- `reverse-stepi` / `rsi`: Step back one instruction
- `reverse-nexti` / `rni`: Step back over one instruction

## Crash Trace Extraction

### Regular Crashes

After `rr record <crashing-program>`:

```bash
rr replay
# In gdb:
reverse-next 100    # Go back 100 steps (adjust N as needed)
# Now step forward to see execution leading to crash:
next
next
...
```

### ASAN Crashes

After `rr record <asan-program>`:

```bash
rr replay
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
