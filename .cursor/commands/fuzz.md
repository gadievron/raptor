# Fuzz - Binary Fuzzing with AFL++

Fuzz binary executables with AFL++ to find crashes and generate exploits.

## Usage

`/fuzz [--binary <path>] [--duration <seconds>] [options]`

## Examples

- `/fuzz --binary ./myapp`
- `/fuzz --binary /usr/local/bin/myapp --duration 600`
- `/fuzz --binary ./myapp --corpus ./seeds --max-crashes 5`

## Execution Steps

1. **Parse arguments**:
   - Extract `--binary` (required)
   - Extract optional: `--duration` (default: 6600 seconds = 110 minutes), `--corpus`, `--max-crashes`, `--input-mode`
   - If `--binary` is missing, ask the user

2. **Validate binary**:
   - Check that binary exists and is executable
   - Verify AFL++ is installed and configured

3. **Execute command**:
   ```bash
   python3 raptor.py fuzz --binary <path> [options]
   ```

4. **Monitor execution**: This is a long-running command. Monitor progress and crashes found.

5. **Read results** from `out/fuzz_<binary>_<timestamp>/`:
   - `afl_output/` - AFL++ output directory
   - `crashes/` - Crash files
   - `exploits/` - Generated exploit PoCs
   - `reports/` - Crash analysis reports

6. **Summarize findings**:
   - Count crashes found
   - List generated exploits
   - Offer to analyze specific crashes

## Workflow

This command:
1. Checks binary exists and is executable
2. Verifies AFL++ configuration (shared memory on macOS)
3. Runs AFL++ fuzzing for specified duration
4. Collects crashes from `afl_output/main/crashes/`
5. Analyzes crashes and generates exploits
6. Generates crash analysis reports

## Prerequisites

- AFL++ installed and configured
- Binary compiled with AFL instrumentation (optional but recommended)

## macOS Setup

If on macOS, run: `sudo afl-system-config` to fix shared memory limits.

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation and examples.
