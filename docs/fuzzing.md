# Fuzzing

RAPTOR's fuzzing subsystem orchestrates coverage-guided fuzzing campaigns
against compiled binaries and source-level targets.  It detects what kind of
target it is looking at, probes the host for available tooling, selects the
appropriate fuzzing engine, manages corpus generation, and triages crashes into
deduplicated, ranked findings wrapped as `core.witness.Witness` objects for
downstream consumption by [/validate](validation.md) and
[/crash-analysis](crash-analysis.md).

The canonical entry point is `python3 raptor.py fuzz` (or the `/fuzz` slash
command).  The legacy `raptor_fuzzing.py` script is still present but
`raptor.py fuzz` is the recommended path -- it manages the run lifecycle
automatically.

## Supported Engines

### AFL++

The primary engine on Linux.  RAPTOR wraps `afl-fuzz` with support for:

- **CmpLog** (`--cmplog-binary`): input-to-state correspondence for bypassing
  multi-byte comparisons.  Requires a separate CmpLog-instrumented binary
  compiled with `AFL_LLVM_CMPLOG=1`.
- **Power schedules** (`--power-schedule`): `fast` (default), `explore`,
  `exploit`, `seek`, `rare`, `mmopt`, `coe`.
- **Custom mutators** (`--custom-mutator`): path to a shared library loaded by
  AFL++ for domain-specific mutation.
- **Dictionaries** (`--dict`): AFL dictionary files for structured input
  formats (JSON tokens, HTTP keywords, etc.).
- **Deterministic mode** (`--deterministic`): enables AFL++'s deterministic
  mutation stage.  Off by default for faster startup.
- **Extra flags** (`--extra-afl-flags`): pass-through for any AFL++ flag not
  covered above.
- **Parallel instances** (`--parallel N`): runs N AFL++ instances (one main,
  N-1 secondary) for faster coverage.

For best results, compile the target with AFL instrumentation
(`afl-clang-fast` or `afl-clang-lto`) and AddressSanitizer
(`-fsanitize=address`).  Uninstrumented binaries work via QEMU mode but are
significantly slower.

### libFuzzer

The preferred engine on macOS and for clang-instrumented binaries.  libFuzzer
requires the target to be compiled with `-fsanitize=fuzzer,address` using a
clang that ships the libFuzzer runtime.

On macOS, Apple's system clang does **not** include the libFuzzer runtime.
RAPTOR's capability probe automatically detects Homebrew LLVM
(`/opt/homebrew/opt/llvm/bin/clang` or `/usr/local/opt/llvm/bin/clang`) and
uses it when available.

The orchestrator detects libFuzzer-instrumented binaries by scanning for the
`LLVMFuzzerTestOneInput` symbol.

## Target Detection

Before any campaign starts, RAPTOR identifies the target and recommends the
appropriate approach.  The detector (`packages/fuzzing/target_detector.py`)
recognises:

| Kind | Description | Recommended Fuzzer |
|------|-------------|--------------------|
| `elf-linux` | Linux ELF binary | AFL++ |
| `elf-kmod` | Linux kernel module (.ko) | kAFL / Snapchange (not orchestrated) |
| `macho` | macOS Mach-O binary (thin or fat/universal) | libFuzzer |
| `pe-exe` | Windows PE executable | WinAFL (not orchestrated) |
| `pe-dll` | Windows DLL | WinAFL (not orchestrated) |
| `pe-sys` | Windows kernel driver (.sys) | kAFL / Snapchange (not orchestrated) |
| `java-class` | Java class file | Not yet orchestrated |
| `java-archive` | Java JAR archive | Not yet orchestrated |
| `apk` | Android APK archive | Not yet orchestrated |
| `source-c` | C source / header files | Harness generation then libFuzzer |
| `source-cpp` | C++ source / header files | Harness generation then libFuzzer |
| `rust-crate` | Rust crate (Cargo.toml present) | `cargo-fuzz` |
| `python-pkg` | Python package (pyproject.toml / setup.py) | Atheris |

Detection works by reading magic bytes (ELF, Mach-O, PE, PK/ZIP), inspecting
file extensions, and checking for project markers (`Cargo.toml`,
`pyproject.toml`).  Fat Mach-O binaries are distinguished from Java class files
(both share the `0xCAFEBABE` magic) by validating the CPU architecture table.

Each `TargetInfo` result includes `can_fuzz_here` (whether the host can run
this target), `blockers` (what prevents fuzzing), and `hints` (actionable
suggestions).

## Prerequisites

The capability probe (`packages/fuzzing/capability.py`) runs before every
campaign, checking for:

**Fuzzing engines:**

- AFL++ -- `afl-fuzz`, `afl-clang-fast` (or `afl-clang-lto`, `afl-gcc`),
  `afl-showmap`, `afl-cmin`, `afl-tmin`.
- AFL++ version (extracted from `afl-fuzz --help`).
- AFL++ shared memory (macOS only) -- tests whether shmget() works.  If it
  fails, run `sudo afl-system-config`.

**Compiler and sanitiser support:**

- clang with libFuzzer runtime (`-fsanitize=fuzzer`).
- AddressSanitizer (`-fsanitize=address`).
- UndefinedBehaviorSanitizer (`-fsanitize=undefined`).
- MemorySanitizer (`-fsanitize=memory`).

**Coverage tools:**

- `lcov`, `gcov`, `llvm-cov`, `afl-cov`.

**Debuggers and analysis:**

- `gdb`, `rr`.
- `radare2` with `r2pipe` and `r2ghidra` (for binary pre-analysis).

The probe result is a `CapabilityReport` dataclass that the orchestrator and
runner consult when building commands.  Use `--plan-only` to see the probe
output and campaign plan without actually starting a run.

## Usage

```bash
python3 raptor.py fuzz --binary <path> [flags]
```

### Core flags

| Flag | Default | Description |
|------|---------|-------------|
| `--binary <path>` | *required* | Path to binary to fuzz |
| `--corpus <dir>` | built-in / autonomous | Seed corpus directory |
| `--duration <secs>` | 3600 | Fuzzing duration in seconds |
| `--parallel <N>` | 1 | Number of parallel AFL++ instances |
| `--max-crashes <N>` | 10 | Maximum crashes to analyse |
| `--timeout <ms>` | 1000 | Per-execution timeout in milliseconds |
| `--out <dir>` | auto | Output directory |
| `--input-mode <mode>` | stdin | `stdin` or `file` (uses `@@`) |
| `--dict <path>` | none | AFL dictionary file |

### Autonomous mode flags

| Flag | Description |
|------|-------------|
| `--autonomous` | Enable intelligent corpus generation |
| `--goal <text>` | Goal-directed fuzzing objective (e.g. "find heap overflow") |

### Orchestrator flags

| Flag | Description |
|------|-------------|
| `--orchestrator` | Force the orchestrator pipeline (target detection + capability checks + engine selection) |
| `--legacy` | Force the legacy AFL++-only path |
| `--plan-only` | Print the campaign plan and exit without running |

### Witness and exploit flags

| Flag | Description |
|------|-------------|
| `--no-verify-exploits` | Skip compile-verify on LLM-emitted exploits |
| `--no-judge-intent` | Skip intent-match judge on LLM-emitted exploits |
| `--no-record-witnesses` | Skip recording LLM-emitted exploits as Witnesses |
| `--execute-exploits` | Execute each LLM-emitted exploit inside the [sandbox](sandbox.md) |
| `--execute-timeout <secs>` | Per-exploit execution timeout (default 5s) |
| `--execute-sanitizers <list>` | Comma-separated sanitisers to compile exploits with (e.g. `address,undefined`) |

### Other flags

| Flag | Description |
|------|-------------|
| `--check-sanitizers` | Check if the binary is compiled with sanitisers |
| `--recompile-guide` | Print a guide for recompiling with AFL instrumentation and sanitisers |
| `--use-showmap` | Run `afl-showmap` after fuzzing for coverage analysis |
| `--export-seed-corpus <dir>` | Export RAPTOR's built-in seed corpus to a directory and exit |
| `--seed-profile <name>` | Select a built-in seed corpus profile (default: `default`) |

### Goal options

When using `--autonomous --goal "..."`:

| Goal | Seeds Generated | Target Vulnerabilities |
|------|-----------------|----------------------|
| `"find stack overflow"` | 64--1024 byte buffers | Stack buffer overflows |
| `"find heap overflow"` | 1KB--64KB allocations | Heap corruption |
| `"find buffer overflow"` | Mixed sizes + format strings | Any buffer overflow |
| `"find parser bugs"` | Malformed structures, deeply nested | Parser vulnerabilities |
| `"find use-after-free"` | Realloc triggers, mixed allocations | UAF vulnerabilities |
| `"find RCE"` | Command injection patterns | Code execution |
| No goal | Universal seeds only | Any vulnerability |

## Corpus Management

RAPTOR supports three tiers of corpus generation, applied in priority order:

### 1. User-supplied corpus

Pass `--corpus <dir>` to use your own seed inputs.  This takes the highest
priority and is recommended when you have high-quality, domain-specific inputs.
Combine with autonomous mode (`--corpus ./seeds --autonomous`) to augment your
corpus with generated seeds.

### 2. Autonomous generation

Enabled with `--autonomous`.  The generator analyses the binary using `strings`
to detect input formats and commands, then produces three categories of seeds:

- **Basic seeds** (universal): empty input, single bytes, boundary-length
  buffers, null bytes, high bytes, special characters.
- **Format-specific seeds**: tailored to detected formats (JSON, XML, HTTP,
  YAML, CSV, INI, URL-encoded values).
- **Goal-directed seeds**: shaped for the specified `--goal` (large buffers for
  overflow goals, realloc patterns for UAF goals, nested structures for parser
  goals).

For binaries with command-based input (e.g. `COMMAND:DATA`), autonomous mode
detects commands and wraps seeds with appropriate prefixes.

### 3. Built-in seed corpus

When neither `--corpus` nor `--autonomous` is provided, RAPTOR falls back to a
checked-in seed corpus under `packages/fuzzing/data/seed_corpus/`.  This is
deliberately small and reviewable: text, JSON, XML, HTTP, CSV, INI, URL-encoded
values, path-ish strings, integer boundaries, format strings, and RAPTOR-style
command prefixes.

Export the built-in corpus for review or local editing:

```bash
python3 raptor.py fuzz --export-seed-corpus /tmp/raptor-fuzz-seeds
```

## Crash Triage and Replay

The `CrashCollector` (`packages/fuzzing/crash_collector.py`) processes the
`crashes/` directory from AFL++ output:

1. **Deduplication** -- crashes are deduplicated by SHA-256 hash of the input
   file (first 16 hex characters).
2. **Signal parsing** -- crash metadata is extracted from AFL filename
   conventions (`id:NNNNNN,sig:NN,src:NNNNNN,...`).
3. **Exploitability ranking** -- crashes are ranked by signal type:
   - SIGSEGV (11) -- memory access violation (highest priority).
   - SIGABRT (06) -- assertion failure / heap corruption.
   - SIGILL (04) -- invalid instruction.
   - SIGFPE (08) -- floating point exception.
4. **Witness wrapping** -- each crash is wrapped into a `core.witness.Witness`
   object via the witness adapter (`packages/fuzzing/witness_adapter.py`).
   Witnesses are stored under `<out>/witnesses/` and can be consumed by
   [/validate](validation.md) and [/crash-analysis](crash-analysis.md).

After triage, the top N crashes (controlled by `--max-crashes`) are sent to the
LLM for exploitability assessment and PoC generation.  The LLM analysis
produces per-crash JSON reports in `analysis/` and generated exploits in
`analysis/exploits/`.

When `--execute-exploits` is enabled, each LLM-emitted exploit is
compile-verified and then executed inside the [sandbox](sandbox.md) (Landlock +
seccomp + namespaces + network block).  The observed outcome
(`EXIT_SIGNAL`, `SANITIZER_REPORT`, `NO_OBVIOUS_EFFECT`, etc.) is threaded
into the recorded Witness.

## Harness Generation

For source code targets that do not have a fuzzable binary, RAPTOR can scaffold
a libFuzzer harness via `packages/fuzzing/harness_generator.py`.

The `HarnessGenerator` class takes a function specification (header file,
function name, parameter types) and produces a self-contained `.c` or `.cc`
file containing:

- A `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` entry point.
- Input decomposition logic that maps the fuzz input buffer to the target
  function's parameters.
- Proper cleanup and a return value of 0 (libFuzzer expects 0 on both success
  and failure).

Harness generation is LLM-driven: the generator sends the function's
declaration, surrounding context, and any available documentation to the LLM,
which produces the harness code.  A fallback template is used when the LLM is
unavailable.

## Binary Pre-Analysis

When the orchestrator's `binary_understand` option is enabled (the default for
binary targets), RAPTOR runs a radare2-based binary analysis pass before
fuzzing starts.  This produces `binary-context-map.json` containing:

- Function list with addresses, sizes, and call counts.
- Cross-references and call graph edges.
- String references per function.
- Import and export tables.

This context informs the LLM's crash analysis, helping it map crash addresses
to functions and understand the binary's structure.

## Sandbox Integration

All fuzzing operations run inside RAPTOR's [sandbox](sandbox.md).  The sandbox
applies:

- **Landlock** filesystem restrictions (Linux 5.13+).
- **Network deny** -- fuzzing processes cannot make network connections.
- **Resource limits** -- CPU and memory caps prevent runaway processes.

PoC compilation and execution use `libexec/raptor-run-sandboxed`, which
combines namespace isolation with the Landlock policy.  When `--execute-exploits`
is enabled, generated exploits run under the same sandbox with an additional
seccomp filter.

## Platform Notes

### Linux

AFL++ is the primary engine and is fully orchestrated.  libFuzzer also works
when the target is compiled with clang's `-fsanitize=fuzzer`.  Both engines
benefit from:

- Compiling with `afl-clang-fast` or `afl-clang-lto` for AFL++ instrumentation.
- AddressSanitizer (`-fsanitize=address`) for precise crash diagnostics.
- Adjusting `perf_event_paranoid` for AFL++ feedback
  (`echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid`).

### macOS

libFuzzer is the preferred engine.  AFL++ works but requires shared memory
configuration (`sudo afl-system-config`), and macOS's SIP restricts some
AFL++ features.

Apple's system clang does not ship the libFuzzer runtime.  Install Homebrew
LLVM (`brew install llvm`) and RAPTOR will auto-detect it.

## Output Structure

```
out/fuzz_<binary>_<timestamp>/
  autonomous_corpus/          -- Generated seeds (--autonomous only)
    seed_basic_NNN            -- Universal seeds
    seed_json_NNN             -- Format-specific seeds
    seed_goal_NNN             -- Goal-directed seeds
  afl_output/                 -- AFL++ fuzzing results
    main/
      crashes/                -- Crash-triggering inputs
      queue/                  -- Interesting inputs (coverage)
      fuzzer_stats            -- AFL++ statistics
    secondaryNN/              -- Parallel instance results
  analysis/
    crash_*.json              -- Per-crash LLM analysis
    exploits/
      crash_*_exploit.c       -- Generated exploit PoCs
  witnesses/                  -- Crash Witness objects
  binary-context-map.json     -- radare2 binary analysis (when enabled)
  fuzzing_report.json         -- Campaign summary report
```
