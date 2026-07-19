# Fuzzing Guide (`/fuzz`)

The `/fuzz` command combines AFL++ binary fuzzing with LLM-powered crash analysis to:

1. **Fuzz binaries** to find crashes
2. **Analyze crashes** with GDB (or ASan diagnostics, when available) for debugging info
3. **Assess exploitability** using LLM intelligence
4. **Generate exploits** automatically

This guide covers manual/CLI usage of the underlying `raptor.py fuzz` dispatch. For
the conversational `/fuzz` command surface (what Claude does when you type
`/fuzz`), see `.claude/commands/fuzz.md`; full flag reference is always
`python3 raptor.py fuzz --help`.

## Prerequisites

### Install AFL++

```bash
# Ubuntu/Debian
sudo apt install afl++

# Verify installation
which afl-fuzz
```

macOS is supported but not the primary target of this environment — expect to
also run `sudo afl-system-config` there (see [Troubleshooting](#troubleshooting)).

### Install GDB

```bash
sudo apt install gdb
```

### Python Dependencies

```bash
pip3 install -r requirements.txt
```

### LLM Provider (IMPORTANT)

RAPTOR supports multiple LLM providers with different quality levels:

**For Production Exploit Generation:**
```bash
# Anthropic Claude (RECOMMENDED - best exploit quality)
export ANTHROPIC_API_KEY=your_key_here

# OR OpenAI GPT-4 (also excellent)
export OPENAI_API_KEY=your_key_here
```

**Local Models (Ollama):**
- **Crash analysis and triage**: Works well
- **Exploitability assessment**: Acceptable(ish). YMMV here
- **Exploit generation**: Often produces non-compilable C code or doesnt work at all.
- **Use case**: Testing, learning, offline analysis, inspiration?

**Quality Comparison:**

| Task | Anthropic Claude | OpenAI GPT-4 | Ollama (local) |
|------|-----------------|--------------|----------------|
| Crash Analysis | Excellent | Excellent | Good |
| Exploitability | Excellent | Excellent | Acceptable |
| Exploit Code | Compilable ✓ | Compilable ✓ | Often broken ✗ |
| Cost | ~$0.01/crash | ~$0.01/crash | FREE |

**Recommendation**: Use frontier models (Claude/GPT-4) for production exploit generation. Use Ollama for testing or when exploit code quality is not critical.

####  **Pro Tip: Use ASan for Superior Crash Analysis**

RAPTOR automatically detects and uses **AddressSanitizer (ASan)** builds for dramatically better crash diagnostics:

**Why ASan?**
- **Precise Error Types**: Identifies heap/stack overflows, use-after-free, etc.
- **Exact Stack Traces**: Shows source code locations with line numbers
- **Memory Diagnostics**: Reveals buffer sizes, allocation contexts, corruption details
- **No Debugger Needed**: ASan provides forensic-quality output directly

**Compile with ASan:**
```bash
# For AFL fuzzing with ASan
afl-clang-fast -fsanitize=address -g -O2 -o target_asan target.c

# For regular compilation with ASan
clang -fsanitize=address -g -O2 -o target_asan target.c
gcc -fsanitize=address -g -O2 -o target_asan target.c
```

**RAPTOR Enhancement**: When ASan is detected, RAPTOR:
- Uses ASan diagnostics instead of debugger output
- Extracts precise vulnerability types (heap-overflow, stack-overflow, etc.)
- Provides source-level stack traces
- Generates more accurate exploitability assessments

**Example ASan Output:**

```plaintext
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f4
WRITE of size 8 at 0x6020000000f4 thread T0
    #0 0x555555554b2c in vuln_function /src/vuln.c:42:5
    #1 0x555555554c1f in main /src/main.c:23:2
```

**Without ASan**: Generic "SIGSEGV at 0xdeadbeef"
**With ASan**: "heap-buffer-overflow in vuln_function at vuln.c:42"

## Quick Test

The real dispatch is `python3 raptor.py fuzz`, run through the RAPTOR CLI rather
than invoking the underlying fuzzing script directly — this is what wires up
the run lifecycle (`OUTPUT_DIR`, status tracking, coverage) around the fuzzing
workflow. `/fuzz` in Claude Code drives the same entry point.

### 1. Run Fuzzing (1 minute test)

**Option A: With autonomous corpus generation (recommended)**
```bash
python3 raptor.py fuzz \
    --binary /path/to/your/binary \
    --duration 60 \
    --autonomous \
    --max-crashes 3
```

**Option B: Traditional (uses built-in/supplied seeds)**
```bash
python3 raptor.py fuzz \
    --binary /path/to/your/binary \
    --duration 60 \
    --max-crashes 3
```

This repo does not ship a sample vulnerable binary or a compile-it-for-me
script — point `--binary` at a real target you own or have built yourself.

## Usage

### Basic Fuzzing
```bash
python3 raptor.py fuzz \
    --binary /path/to/binary \
    --duration 3600 \
    --max-crashes 10
```

### With Custom Corpus
```bash
python3 raptor.py fuzz \
    --binary ./myapp \
    --corpus ./seeds/ \
    --duration 1800 \
    --max-crashes 5
```

### Built-in Starter Corpus

If you do not pass `--corpus`, RAPTOR falls back to a checked-in starter corpus
instead of a handful of hard-coded seeds. The order is:

1. Use `--corpus` exactly as supplied.
2. Use autonomous corpus generation when `--autonomous` is enabled or the
   orchestrator can generate one.
3. Fall back to RAPTOR's built-in corpus under
   `packages/fuzzing/data/seed_corpus/`.

The built-in corpus is deliberately small and reviewable: text, JSON, XML, HTTP,
CSV, INI, URL-encoded values, path-ish strings, integer boundaries, format
strings, and RAPTOR-style command prefixes such as `STACK:` and `HEAP:`.

To export it for review or local editing:

```bash
python3 raptor.py fuzz --export-seed-corpus /tmp/raptor-fuzz-seeds
```

Then run with it explicitly if you want to add your own local cases:

```bash
python3 raptor.py fuzz \
    --binary ./myapp \
    --corpus /tmp/raptor-fuzz-seeds \
    --duration 1800
```

### Autonomous Mode (Intelligent Corpus Generation)

RAPTOR can automatically generate intelligent seed inputs by analysing your binary, eliminating the need for manual corpus creation.

#### What Is Autonomous Mode?

Instead of requiring hand-crafted seed inputs, autonomous mode:
- **Analyses the binary** using `strings` to detect input formats
- **Detects patterns** like JSON, XML, HTTP, command-based inputs
- **Generates format-specific seeds** tailored to the binary
- **Creates goal-directed seeds** based on your fuzzing objective

#### How to Use

Add `--autonomous` flag (no corpus needed):

```bash
python3 raptor.py fuzz \
    --binary ./target_app \
    --duration 1800 \
    --autonomous
```

#### Goal-Directed Fuzzing

Guide the fuzzer towards specific vulnerability types:

```bash
# Find stack overflows
python3 raptor.py fuzz \
    --binary ./app \
    --autonomous \
    --goal "find stack overflow"

# Find heap corruption
python3 raptor.py fuzz \
    --binary ./app \
    --autonomous \
    --goal "find heap overflow"

# Find parser bugs
python3 raptor.py fuzz \
    --binary ./app \
    --autonomous \
    --goal "find parser bugs"

# Find use-after-free
python3 raptor.py fuzz \
    --binary ./app \
    --autonomous \
    --goal "find use-after-free"
```

#### What Gets Generated

The autonomous corpus generator creates three types of seeds:

**1. Basic Seeds (Universal)**
- Empty input, single byte, small/medium/large buffers
- Null bytes, high bytes, special characters
- Works with any binary

**2. Format-Specific Seeds**
- **JSON detected**: `{}`, `{"key":"value"}`, nested objects, malformed JSON
- **XML detected**: `<?xml?>`, `<root></root>`, nested tags, unclosed tags
- **HTTP detected**: GET/POST requests, headers, malformed HTTP
- **YAML detected**: Key-value pairs, lists, nested structures
- **CSV detected**: Delimited data, quoted values

**3. Goal-Directed Seeds**
- **Stack overflow goal**: Buffers of 64, 100, 256, 1024 bytes
- **Heap overflow goal**: Large allocations (1KB, 4KB, 64KB)
- **Parser goal**: Deeply nested structures, unclosed tags
- **UAF goal**: Realloc triggers, mixed allocations

#### Binary Analysis

When autonomous mode runs, it performs intelligent analysis:

```
[INFO] Analyzing binary for corpus generation hints...
[INFO] Detected format: json
[INFO] Detected format: xml
[INFO] Detected command: PARSE
[INFO] Detected command: PROCESS
[INFO] Binary analysis complete: 2 formats, 2 commands detected
[INFO] Generating basic seed corpus...
[INFO] Generated 12 basic seeds
[INFO] Generating format-specific seeds for: json, xml
[INFO] Generated 16 format-specific seeds
[INFO] Generating goal-directed seeds for: find heap overflow
[INFO] Generated 5 goal-directed seeds
[INFO] Autonomous corpus generation complete: 33 seeds
```

#### Command-Based Input Detection

For binaries with command-based input (e.g., `COMMAND:DATA`), autonomous mode:
- Detects commands in binary strings
- Wraps seeds with appropriate command prefixes
- Matches goals to relevant commands

**Example**: Test bench with 8 commands detected:
```
[INFO] Detected command: STACK
[INFO] Detected command: HEAP
[INFO] Detected command: UAF
[INFO] Detected command: JSON
[INFO] Detected command: XML
[INFO] Binary analysis complete: 5 formats, 8 commands detected
[INFO] Wrapping basic seeds with 8 detected commands
[INFO] Generated 96 basic seeds  (12 × 8 commands)
[INFO] Wrapping goal-directed seeds with STACK command
[INFO] Generated 5 goal-directed seeds
```

**Generated seeds**: `STACK:AAAA...`, `HEAP:BBBB...`, `UAF:trigger`, etc.

#### Performance Comparison

| Approach | Setup Time | Coverage | Crash Discovery |
|----------|-----------|----------|-----------------|
| **Manual corpus** | 15-30 min | Depends on quality | Variable |
| **Empty corpus** | 0 min | ~6% | Very slow |
| **Autonomous mode** | 0 min | ~49% | Fast |

**Real test results** (raptor_testbench):
- Without autonomous: 6.12% coverage, 0 crashes found (60s)
- With autonomous: 48.98% coverage, 1 crash found (70s)

#### When to Use Autonomous Mode

**Use autonomous mode when:**
- You don't have existing test inputs
- You want to quickly test a binary
- The binary has structured input (JSON, XML, etc.)
- You want goal-directed fuzzing
- Starting a new fuzzing campaign

**Use manual corpus when:**
- You have high-quality existing inputs
- The input format is highly specialised
- You need precise control over seeds
- Combining with existing corpus: `--corpus ./seeds --autonomous` (both)

#### Examples by Binary Type

**JSON Parser**
```bash
python3 raptor.py fuzz \
    --binary ./json_parser \
    --autonomous \
    --goal "find parser bugs"

# Generates: {}, {"key":"value"}, malformed JSON, deeply nested
```

**Network Service**
```bash
python3 raptor.py fuzz \
    --binary ./http_server \
    --autonomous \
    --goal "find buffer overflow"

# Generates: HTTP requests, headers, large payloads
```

**Command-Line Tool**
```bash
python3 raptor.py fuzz \
    --binary ./cli_tool \
    --autonomous

# Generates: Various buffer sizes, special chars, format strings
```

**XML Parser**
```bash
python3 raptor.py fuzz \
    --binary ./xml_processor \
    --autonomous \
    --goal "find heap overflow"

# Generates: XML docs, nested tags, large content, malformed XML
```

### Parallel Fuzzing (Faster)
```bash
python3 raptor.py fuzz \
    --binary ./myapp \
    --duration 3600 \
    --parallel 4 \
    --max-crashes 20
```

### Orchestrator vs. Legacy Path

RAPTOR has two fuzzing backends: a newer **orchestrator** pipeline (libFuzzer +
AFL++ with target detection, capability checks, and live telemetry) and the
original **legacy** AFL++-only path. `--orchestrator` and `--legacy` are
mutually exclusive; if you pass neither, RAPTOR picks automatically.

```bash
# Force the orchestrator and just print the plan (no fuzzing runs)
python3 raptor.py fuzz --binary ./target --orchestrator --plan-only

# Force the legacy AFL++-only path (e.g. to reproduce pre-orchestrator behaviour)
python3 raptor.py fuzz --binary ./target --legacy
```

## Parameters

Full authoritative list: `python3 raptor.py fuzz --help`. Core flags:

| Parameter | Default | Description |
|-----------|---------|--------------|
| `--binary` | *required* | Path to binary to fuzz |
| `--corpus` | built-in/autonomous | Seed input directory |
| `--export-seed-corpus DIR` | none | Export RAPTOR's built-in seed corpus into `DIR` and exit |
| `--seed-profile` | `default` | Built-in seed corpus profile |
| `--prepare-corpus PROJECT_DIR` | none | Prepare a deterministic seed corpus from project fixtures and exit |
| `--seed-out` | `out/fuzz_seeds_<project>` | Output directory for `--prepare-corpus` |
| `--seed-max-size` | 1048576 | Max seed file size (bytes) for `--prepare-corpus` |
| `--seed-include-lockfiles` | disabled | Allow lockfiles (e.g. `package-lock.json`) in prepared seed corpora |
| `--autonomous` | disabled | Enable intelligent corpus generation |
| `--goal` | none | Goal-directed fuzzing objective |
| `--duration` | 3600 | Fuzzing duration in seconds |
| `--parallel` | 1 | Number of AFL instances (ceiling: `tuning.json`) |
| `--max-crashes` | 10 | Max crashes to analyse |
| `--timeout` | 1000 | Timeout per execution (ms) |
| `--out` | `out/fuzz_<binary_name>` | Output directory |
| `--dict` | none | Path to an AFL dictionary file for structured input fuzzing |
| `--input-mode` | `stdin` | Input mode: `stdin` or `file` (uses `@@`) |
| `--check-sanitizers` | disabled | Check if the binary is compiled with sanitizers (ASan, etc.) |
| `--recompile-guide` | disabled | Show a guide for recompiling the binary with AFL instrumentation and sanitizers |
| `--use-showmap` | disabled | Run `afl-showmap` after fuzzing for coverage analysis |
| `--memory-file` | `${HOME}/.raptor/fuzzing_memory.json` | Learning-persistence memory file (note: under `sudo -E`, `HOME` resolves to root's home, not the operator's) |
| `--orchestrator` | auto | Force the orchestrator pipeline (mutually exclusive with `--legacy`) |
| `--legacy` | auto | Force the legacy AFL++-only fuzzing path |
| `--plan-only` | disabled | With `--orchestrator`, print the plan and exit without running |

Exploit-verification flags (all secondary to the core loop above — see `--help`
for full text): `--no-verify-exploits`, `--no-judge-intent`,
`--no-record-witnesses`, `--execute-exploits`, `--execute-timeout`,
`--execute-sanitizers`. Sandbox controls common to every RAPTOR entry point
(`--sandbox`, `--no-sandbox`, `--audit`, `--audit-verbose`, `--audit-budget`)
also apply here.

### Goal Options

When using `--autonomous --goal "..."`, supported goals include:

| Goal | Seeds Generated | Target Vulnerabilities |
|------|----------------|----------------------|
| `"find stack overflow"` | 64-1024 byte buffers | Stack buffer overflows |
| `"find heap overflow"` | 1KB-64KB allocations | Heap corruption |
| `"find buffer overflow"` | Mixed sizes + format strings | Any buffer overflow |
| `"find parser bugs"` | Malformed structures | Parser vulnerabilities |
| `"find use-after-free"` | Realloc triggers | UAF vulnerabilities |
| `"find RCE"` | Command injection patterns | Code execution |
| No goal | Universal seeds only | Any vulnerability |

## Output Structure

```
out/fuzz_<binary>_<timestamp>/
├── autonomous_corpus/       # Generated seeds (--autonomous only)
│   ├── seed_basic_000       # Universal seeds
│   ├── seed_json_000        # Format-specific seeds
│   └── seed_goal_000        # Goal-directed seeds
├── afl_output/              # AFL fuzzing results
│   ├── main/
│   │   ├── crashes/         # Crash inputs
│   │   ├── queue/           # Interesting inputs
│   │   └── fuzzer_stats     # Coverage stats
│   └── secondary*/          # Parallel instances
├── analysis/
│   ├── analysis/            # LLM crash analysis
│   │   └── crash_*.json
│   └── exploits/            # Generated exploits
│       └── crash_*_exploit.c
└── fuzzing_report.json      # Summary report
```

## Example: Analysing a Binary

```bash
# Step 1: Quick smoke test with autonomous mode (5 minutes)
python3 raptor.py fuzz \
    --binary ./target_app \
    --duration 300 \
    --autonomous \
    --max-crashes 5

# Step 2: If crashes found, do deeper goal-directed analysis
python3 raptor.py fuzz \
    --binary ./target_app \
    --duration 3600 \
    --autonomous \
    --goal "find heap overflow" \
    --parallel 4 \
    --max-crashes 20

# Step 3: Review generated corpus and results
ls out/fuzz_*/autonomous_corpus/    # View generated seeds
cat out/fuzz_*/fuzzing_report.json  # Summary report
ls out/fuzz_*/analysis/exploits/     # Generated exploits
```

## Understanding the Output

### Phase 1: Fuzzing
```
PHASE 1: AFL++ FUZZING
======================================================================
Duration: 300s (5.0 minutes)
Parallel jobs: 1
Timeout: 1000ms

Fuzzing complete:
  - Duration: 300s
  - Unique crashes: 15
  - Crashes dir: out/fuzz_*/afl_output/main/crashes
```

### Phase 2: Analysis
```
PHASE 2: AUTONOMOUS CRASH ANALYSIS
======================================================================
Collected 15 unique crashes
   Analyzing top 10

CRASH 1/10
======================================================================
Analyzing vulnerability: SIGSEGV
  Signal: SIGSEGV (Segmentation Fault)
  Function: vulnerable_function
GDB analysis complete
Disassembly extracted
Sending crash to LLM for analysis...
LLM analysis complete:
  Exploitable: true
  Crash Type: stack_overflow
  Severity: high
  CVSS: 7.5
Generating exploit PoC
   Exploit generated
```

## Troubleshooting

### "AFL not found"
```bash
sudo apt install afl++  # Ubuntu/Debian
brew install afl++      # macOS
```

### "shmget() failed" (macOS)
```bash
sudo afl-system-config
```

### "Binary not instrumented" Warning
This is OK! RAPTOR will use QEMU mode (slower but works).

For better results, recompile with AFL:
```bash
export CC=afl-clang-fast
export CXX=afl-clang-fast++
make clean && make
```

### "No crashes found"
- **Try autonomous mode**: `--autonomous` for intelligent seed generation
- **Add goal-direction**: `--autonomous --goal "find heap overflow"`
- Increase duration: `--duration 1800`
- Try better seeds: `--corpus /path/to/good/inputs`
- Check binary works: `echo test | ./binary`
- Verify coverage: Look for "Bitmap coverage" in output (>10% is good)

### "GDB analysis failed"
- Install GDB: `sudo apt install gdb`
- macOS: May need to codesign GDB (see AFL docs)

### "Exploit code won't compile"
**Common issue with Ollama models:**
```bash
gcc -o exploit 000000_exploit.c -fno-stack-protector -z execstack
# Error: macro name must be an identifier
# Error: unknown escape sequence
```

**Solution**: Use frontier models for exploit generation:
```bash
# Use Anthropic Claude (best results)
export ANTHROPIC_API_KEY=your_key_here
python3 raptor.py fuzz --binary ./target --duration 300

# OR OpenAI GPT-4
export OPENAI_API_KEY=your_key_here
python3 raptor.py fuzz --binary ./target --duration 300
```

**Why**: Exploit code generation requires:
- Deep understanding of C memory layout
- Correct shellcode encoding
- Valid ROP chain construction
- Proper stack alignment
- This aint point and click at all

## Tips for Best Results

1. **Use autonomous mode** (`--autonomous`) for intelligent corpus generation - saves time and improves coverage
2. **Add goal-direction** (`--goal "find X"`) to target specific vulnerability types
3. **Use AFL-instrumented binaries** when possible (much faster fuzzing)
4. **Compile with ASan** (`-fsanitize=address`) for precise crash diagnostics
5. **Run parallel instances** (`--parallel 4`) for faster coverage
6. **Start with short runs** (5-10 min) to validate setup
7. **Disable mitigations** during testing: compile with `-fno-stack-protector -z execstack`
8. **Combine approaches**: Use `--corpus ./seeds --autonomous` to augment existing corpus

## Source vs Binary Mode

| Mode | Input | Tools | Output |
|------|-------|-------|--------|
| **Source** | `--repo` | Semgrep, CodeQL | SARIF → Patches |
| **Binary** | `--binary` | AFL++, GDB | Crashes → Exploits |

Use source mode for:
- Design flaws
- Logic bugs
- Crypto misuse

Use binary mode for:
- Memory corruption
- Crashes
- Runtime behavior

## Next Steps

1. Try fuzzing a real target
2. Review generated exploits in `out/*/analysis/exploits/`
3. Test exploits in isolated environment
4. Report vulnerabilities responsibly
