# Raptor-Fuzz - Binary Fuzzing with AFL++ (Alias)

Alias for `/fuzz` - Fuzz binary executables with AFL++ to find crashes and generate exploits.

## Usage

`/raptor-fuzz [--binary <path>] [--duration <seconds>] [options]`

## Examples

- `/raptor-fuzz --binary ./myapp`
- `/raptor-fuzz --binary /usr/local/bin/myapp --duration 600`

## Execution

This command is identical to `/fuzz`. See `/fuzz` command documentation for details.

Execute: `python3 raptor.py fuzz --binary <path> [options]`

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation.
