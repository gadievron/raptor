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

- **Dictionaries** (`--dict`): AFL dictionary files for structured input
  formats (JSON tokens, HTTP keywords, etc.).  When `--dict` is not passed,
  `/fuzz` auto-discovers an audit-generated `fuzz.dict` (own run directory
  first, then the newest sibling run directory) -- see
  [Dictionary auto-discovery](#dictionary-auto-discovery).
- **Parallel instances** (`--parallel N`): runs N AFL++ instances (one main,
  N-1 secondary) for faster coverage.  N is clamped to the `tuning.json`
  `max_fuzz_parallel` ceiling with a warning.
- **CmpLog, power schedules, custom mutators, deterministic mode**:
  available through the Python API (`AFLRunner` in `packages/fuzzing/`)
  for pipeline callers; no CLI flags.
- **Env build-on-demand** (`--env-build`, `--no-env-build`,
  `--env-asan`, `--env-cmplog`, `--env-target <rel>`,
  `--keep-env-rootfs`): build a source tree AFL-instrumented in the
  pinned AFL++ image and fuzz it from the image's rootfs under the
  sandbox -- see
  [Env Build-on-Demand](#env-build-on-demand-source-trees).

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
appropriate approach.  The detector recognises:

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
| `source-c` | C/C++ sources (file or tree) | Env build-on-demand (trees, trust-gated) or harness generation then libFuzzer |
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

A capability probe runs before every campaign, checking for:

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

Use `--plan-only` to see the probe output and campaign plan without
actually starting a run.

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
| `--parallel <N>` | 1 | Number of parallel AFL++ instances (clamped to the `tuning.json` `max_fuzz_parallel` ceiling) |
| `--max-crashes <N>` | 10 | Maximum crashes to analyse |
| `--rank-crashes` | off | LLM re-rank of collected crashes before the analysis cap (ordering only; runs the campaign to a 3× pool and backfills past stack-hash duplicates; needs an external analysis model) |
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
| `--from-smt-witness <dir>` | Synthesize AFL seeds and dictionary tokens from an audit/validate run's SMT witnesses |
| `--prepare-corpus` / `--seed-out <dir>` / `--seed-max-size <n>` / `--seed-include-lockfiles` | Build a seed corpus from the target repo without fuzzing |

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

### Dictionary auto-discovery

`/audit` writes a fuzz handoff at the end of each run: `fuzz-dict.json`
(structured tokens with provenance, plus seed hints) and `fuzz.dict` -- the
same tokens in AFL `name="value"` format, mined from unique magic constants,
parse-shape string literals, and dispatch/switch keys in the audited code.

When the operator does not pass `--dict`, `/fuzz` picks that dictionary up
automatically: it checks the run's own output directory first (shared-dir
pipelines), then the newest `fuzz.dict` among sibling run directories under
the same parent (project layouts).  An explicit `--dict` always wins.
Discovery is best-effort and bounded -- a missing or oversized (>1 MiB)
dictionary simply means no `-x` flag, exactly as before.

## Crash Triage and Replay

Crash triage processes the `crashes/` directory from AFL++ output:

1. **Deduplication** -- crashes are deduplicated by SHA-256 hash of the input
   file (first 16 hex characters).
2. **Signal parsing** -- crash metadata is extracted from AFL filename
   conventions (`id:NNNNNN,sig:NN,src:NNNNNN,...`).
3. **Exploitability ranking** -- crashes are ranked by signal type:
   - SIGSEGV (11) -- memory access violation (highest priority).
   - SIGABRT (06) -- assertion failure / heap corruption.
   - SIGILL (04) -- invalid instruction.
   - SIGFPE (08) -- floating point exception.
4. **Witness wrapping** -- each crash is wrapped into a Witness object,
   stored under `<out>/witnesses/`, and can be consumed by
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

## Env Build-on-Demand (source trees)

A source tree with no fuzzable binary can be built AFL-instrumented on
demand and fuzzed at native speed -- no harness required for
repo-native executables.

```
/fuzz /path/to/source-repo              # project 'build' marker set
python3 raptor.py fuzz --binary /path/to/source-repo --env-build
```

What happens:

1. **Consent gate.** Building a repo executes repo-influenced code, so
   the build fires only when the project `build` trust marker
   (`/project trust build`) or the per-run `--env-build` flag
   authorises it.  `--no-env-build` disables it for one run even with
   the marker set (negative flag wins).  Without consent the plan
   declines with a hint and the classic harness route is unchanged.
2. **Build command resolution.** Operator setting first
   (`/project set build-command`), detector synthesis otherwise.  A
   synthesised command is used but loudly labelled GUESSED -- the
   provenance record (`env-build.json`) and campaign log both carry it.
3. **Instrumented build.** The repo is copied into a build context and
   built with `CC=afl-clang-fast CXX=afl-clang-fast++` inside the
   pinned AFL++ image (`core.env.build.AFL_BUILD_IMAGE`), network
   disabled.  ELF executables are extracted read-only (0444) with
   SHA-256 checksums.
4. **In-image campaign.** The image is exported to a rootfs under the
   run directory and afl-fuzz runs from it under the sandbox's
   image-rootfs mode: the binary and afl-fuzz share the image's libc
   and AFL version by construction, and the campaign keeps the full
   sandbox observation tier (network deny, Landlock write scoping).
   The output directory is bound at its original path, so crash
   collection, telemetry, and stats work exactly as in host-mode
   campaigns.  Corpus and dictionary are staged under the output
   directory (only the output bind is visible post-pivot).
5. **Cleanup.** The exported rootfs is several GB; it is deleted when
   the campaign ends.  Pass `--keep-env-rootfs` to retain it (e.g. to
   replay crashes in-image), and `--env-target <rel>` to choose among
   multiple built binaries.

### Sanitizer and cmplog variants

- `--env-asan` builds the target with AddressSanitizer via the AFL
  toolchain.  Memory bugs that never crash a plain build (silent
  over-reads, use-after-free without corruption) surface as recorded
  crashes; the campaign automatically runs with `-m none` (ASAN's
  shadow memory is incompatible with AFL's memory limit; `-m` was
  never a security boundary, and the sandbox's isolation -- network
  deny, Landlock write scoping -- is unaffected).
- `--env-cmplog` builds a second, compare-logging twin of the same
  tree (`/src-cmplog` in the image) and attaches it to the main
  instance (`-c`).  Input-to-state guidance cracks magic-number,
  version-check and checksum gates that random mutation practically
  never finds; the flags combine (`--env-asan --env-cmplog` is the
  strongest default posture for unknown source trees).

The AFL++ image is digest-pinned, and RAPTOR carries an in-code
blocklist of AFL builds with known crash-classification defects: after
every env build the image's `afl-fuzz` binary is scanned, and a
blocklisted version refuses the campaign loudly (a fuzzer that
silently drops sanitizer crashes is worse than no fuzzer).  If you see
`broken_afl_version`, the image resolved to a known-bad build -- use
the pinned default.

There is no docker fallback for the campaign: if the sandbox's
image-rootfs mode is unavailable, the env-build path refuses rather
than running the target under a weaker containment tier.

## Harness Generation

For source code targets that do not have a fuzzable binary, RAPTOR can
scaffold a libFuzzer harness from a function specification (header
file, function name, parameter types), producing a self-contained `.c`
or `.cc` file containing:

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

PoC compilation and execution run inside the sandbox, which combines
namespace isolation with the Landlock policy.  When `--execute-exploits`
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
    merged_crashes/           -- All instances' crashes (hardlinked) when a
                                 secondary found any; analysis reads this dir
  analysis/
    crash_*.json              -- Per-crash LLM analysis
    exploits/
      crash_*_exploit.c       -- Generated exploit PoCs
  witnesses/                  -- Crash Witness objects
  binary-context-map.json     -- radare2 binary analysis (when enabled)
  coverage-fuzz.json          -- Function-precise runtime coverage record
                                 (gcov-instrumented targets; reaches the
                                 durable coverage store as reachability
                                 evidence — never counts as review)
  fuzzing_report.json         -- Campaign summary report
```
