# Frida trace - SKILL

Hook named functions in a spawned target and capture entry + the first four
integer-width arguments.

## Run

```
libexec/raptor-frida trace <binary> --symbols funcA,funcB --out $OUTPUT_DIR [--timeout 30] [-- <target args>]
```

- `--symbols` - comma-separated function names. Resolved via DWARF
  (`DebugSymbol.fromName`, works for `-g` static symbols) then exported name.
- `-- <target args>` - everything after `--` is passed to the spawned target.
- `--profile` - sandbox profile (`debug` default; `none` / `network-only`).

## Output (JSON on stdout)

```json
{
  "trace": [{"fn": "secret", "args": [0, ...], "addr": "0x..."}],
  "unresolved": ["names that couldn't be resolved"],
  "call_count": 3,
  "profile_used": "debug",
  "events_path": "<OUTPUT_DIR>/frida-events.jsonl"
}
```

## Presenting

- Summarise `call_count` and show the per-call argument records.
- List `unresolved` symbols explicitly (e.g. typo, stripped binary, or a
  symbol only present in a shared library - try the library's name).
- If `profile_used` is `none`, note the host lacked working mount namespaces
  so the trace ran without network isolation.

## Notes

- Argument width is integer (`args[i].toInt32()`); pointer/string arguments
  show as their integer value - dereference in a follow-up hook if needed.
- For deeper instrumentation (return values, memory reads, replacement),
  extend `packages/dynamic_instrumentation/agents.py` with a new agent
  template rather than hand-writing JS inline.
