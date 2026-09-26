---
description: Binary fuzzing with AFL++ integration
dispatch: python3 raptor.py fuzz
---

# /fuzz - RAPTOR Binary Fuzzer

**`--help` / `-h`:** If the user passes only `--help` or `-h`, run `python3 raptor.py fuzz --help` and present its output. That command is side-effect-free (no run, lifecycle, output directory, or LLM dispatcher) and is the complete, authoritative flag list — do NOT start a fuzzing campaign or hand-summarise flags from this doc.

You are helping the user fuzz a binary executable with RAPTOR's AFL++ integration.

## Your Task

1. **Understand the target**: Identify which binary to fuzz
   - Get the full path to the binary
   - Ask about input mode (stdin or file)
   - Ask about fuzzing duration (default: 60 minutes / 3600 seconds)

2. **Check prerequisites**: Before fuzzing, verify:
   - Binary exists and is executable
   - AFL++ is properly configured (shared memory limits on macOS)
   - Binary is ideally compiled with AFL instrumentation and ASAN

3. **Run RAPTOR fuzzing**: Execute the fuzzing command:
   ```bash
   python3 raptor.py fuzz --binary <path> --duration <seconds>
   ```

4. **Monitor and analyze**: After fuzzing:
   - Check how many crashes were found
   - Read the crash analysis reports
   - Show generated exploits
   - Explain the vulnerability types (buffer overflow, use-after-free, etc.)

5. **Help with next steps**:
   - Suggest recompiling with ASAN if not already done
   - Offer to analyze specific crashes in detail
   - Help create patches to fix the vulnerabilities

## Example Commands

Basic fuzzing (60 minutes, stdin mode):
```bash
python3 raptor.py fuzz --binary /path/to/binary --duration 3600
```

Quick fuzz (10 minutes):
```bash
python3 raptor.py fuzz --binary /path/to/binary --duration 600 --max-crashes 5
```

With custom corpus:
```bash
python3 raptor.py fuzz --binary /path/to/binary --corpus /path/to/seeds --duration 3600
```

Python package via atheris (alpha; needs `pip install atheris` and a harness —
`--py-harness <file>` for an operator-written TestOneInput harness, or
`--py-entry module:function` to scaffold the simple bytes/str case):
```bash
python3 raptor.py fuzz --binary /path/to/pypkg --py-entry mypkg.parser:parse --duration 600
```

Rust crate via cargo-fuzz (alpha; needs `cargo install cargo-fuzz` and the
crate's own `fuzz/fuzz_targets/` harnesses — `--fuzz-target <name>` picks one,
auto-selected when the crate has exactly one; the sandboxed build is offline,
so run `cargo fetch` in the crate's fuzz/ dir once in a trusted context first):
```bash
python3 raptor.py fuzz --binary /path/to/crate --fuzz-target parse_input --duration 600
```

Java/Kotlin project via Jazzer (alpha; needs the `jazzer` standalone binary on
PATH plus a JVM, and a harness class with `fuzzerTestOneInput` or `@FuzzTest`
in the tree — `--fuzz-target <class>` picks one, auto-selected when the
project has exactly one; Maven/Gradle builds run sandboxed and offline, so run
`mvn -DskipTests test-compile` or `gradle testClasses` once in a trusted
context first to populate the dependency cache):
```bash
python3 raptor.py fuzz --binary /path/to/project --fuzz-target com.example.ParserFuzz --duration 600
```

## macOS Shared Memory Fix

If fuzzing fails with "shmget() failed", run:
```bash
sudo afl-system-config
```

## Important Notes

- `--project <name>` pins the run to a named project (`-` = explicitly projectless); it wins over the session binding and the last-activated default, and an invalid name is a hard error, never a fallback.
- Fuzzing can take a long time (hours) for good results
- The binary should ideally be compiled with:
  - AFL instrumentation: `afl-clang-fast` or `afl-gcc`
  - ASAN: `-fsanitize=address`
- Crashes are saved to `out/fuzz_<binary>_<timestamp>_pid<N>_<tail>/afl_output/main/crashes/`
- RAPTOR automatically analyzes crashes and generates exploits
- When `--dict` is not passed, an audit-generated `fuzz.dict` is auto-discovered (own run directory first, then the newest sibling run); an explicit `--dict` always wins

Be patient and explain fuzzing concepts clearly!
