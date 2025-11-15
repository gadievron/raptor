# RAPTOR Test Bench - Comprehensive Vulnerability Suite

This test binary contains **8 deliberate vulnerabilities** to validate RAPTOR's autonomous fuzzing capabilities.

## Vulnerabilities Included

| #  | Type | Command | Trigger | Expected Detection |
|----|------|---------|---------|-------------------|
| 1  | **Stack Buffer Overflow** | `STACK:` | Input > 64 bytes | ✅ ASAN, AFL |
| 2  | **Heap Buffer Overflow** | `HEAP:` | Input > 128 bytes | ✅ ASAN, AFL |
| 3  | **Use-After-Free** | `UAF:` | Input > 10 bytes | ✅ ASAN |
| 4  | **JSON Parser Overflow** | `JSON:` | Long key/value | ⚠️  Partial (strncpy limited) |
| 5  | **XML Parser Overflow** | `XML:` | Long tag/content | ⚠️  Partial (strncpy limited) |
| 6  | **Format String** | `FMT:` | Input with `%s`, `%n` | ⚠️  Modern compilers harden |
| 7  | **Integer Overflow** | `INT:` | Large number | ✅ ASAN (heap overflow) |
| 8  | **Null Pointer Deref** | `NULL:` | Input starts with 'N' and > 5 bytes | ✅ ASAN, AFL |

## Building

```bash
cd test/
./build_testbench.sh
```

This creates:
- `raptor_testbench_afl` - AFL instrumented
- `raptor_testbench_asan` - AFL + AddressSanitizer (recommended)
- `raptor_testbench` - Normal build
- `raptor_testbench_debug` - Debug symbols

## Manual Testing

### Stack Overflow
```bash
echo 'STACK:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | ./raptor_testbench_asan
```

**Expected:** ASAN detects stack-buffer-overflow

### Heap Overflow
```bash
echo 'HEAP:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | ./raptor_testbench_asan
```

**Expected:** ASAN detects heap-buffer-overflow

### Use-After-Free
```bash
echo 'UAF:trigger_use_after_free_vulnerability' | ./raptor_testbench_asan
```

**Expected:** ASAN detects heap-use-after-free

### Null Pointer Dereference
```bash
echo 'NULL:NAAAAA' | ./raptor_testbench_asan
```

**Expected:** ASAN detects null pointer dereference

### Integer Overflow → Heap Overflow
```bash
echo 'INT:4294967200' | ./raptor_testbench_asan
```

**Expected:** Integer overflow leads to undersized allocation, then heap overflow

## Autonomous Fuzzing Tests

### Test 1: Find Stack Overflow
```bash
python3 ../raptor_fuzzing.py \
  --binary ./raptor_testbench_asan \
  --duration 60 \
  --max-crashes 5 \
  --autonomous \
  --goal "find stack overflow"
```

**Expected Results:**
- Autonomous corpus generates large buffers
- AFL finds stack overflow crash
- LLM correctly identifies as stack buffer overflow
- Crash prioritization ranks SIGSEGV/SIGABRT highly

### Test 2: Find Heap Overflow
```bash
python3 ../raptor_fuzzing.py \
  --binary ./raptor_testbench_asan \
  --duration 60 \
  --max-crashes 5 \
  --autonomous \
  --goal "find heap overflow"
```

**Expected Results:**
- Corpus includes `HEAP:` + large buffers
- Detects heap-buffer-overflow
- Goal-directed prioritization boosts HEAP crashes

### Test 3: Find Use-After-Free
```bash
python3 ../raptor_fuzzing.py \
  --binary ./raptor_testbench_asan \
  --duration 60 \
  --max-crashes 5 \
  --autonomous \
  --goal "find use-after-free"
```

**Expected Results:**
- Corpus includes UAF trigger patterns
- ASAN detects use-after-free
- LLM analysis identifies UAF correctly

### Test 4: Find Parser Bugs
```bash
python3 ../raptor_fuzzing.py \
  --binary ./raptor_testbench_asan \
  --duration 120 \
  --max-crashes 10 \
  --autonomous \
  --goal "find parser bugs"
```

**Expected Results:**
- Autonomous corpus detects JSON/XML strings in binary
- Generates malformed JSON/XML seeds
- Finds crashes in parser code paths

### Test 5: No Goal - Find Everything
```bash
python3 ../raptor_fuzzing.py \
  --binary ./raptor_testbench_asan \
  --duration 180 \
  --max-crashes 10 \
  --autonomous
```

**Expected Results:**
- Finds multiple distinct crashes (stack, heap, UAF, etc.)
- Deduplication correctly identifies unique crash types
- Memory learns successful patterns

## Validation Checklist

Use this binary to validate RAPTOR's:

- [x] **AFL Integration** - Finds crashes
- [x] **Crash Deduplication** - Stack hashes distinguish different bugs
- [x] **Crash Classification** - Correctly identifies vulnerability types
- [x] **Goal-Directed Fuzzing** - Prioritizes relevant crashes
- [x] **Autonomous Corpus** - Generates format-specific seeds
- [x] **Multi-Turn Analysis** - Deep LLM reasoning
- [x] **Exploit Generation** - Creates PoC exploits (quality varies by LLM)
- [x] **Exploit Validation** - Attempts compilation
- [x] **Memory/Learning** - Records successful strategies
- [x] **Binary Analysis** - Detects formats (JSON, XML)

## Expected Crash Distribution

In a 3-minute autonomous fuzz with ASAN:

| Crash Type | Likelihood | Why |
|------------|-----------|-----|
| Stack Overflow | ⭐⭐⭐⭐⭐ | Easy to trigger, large corpus |
| Heap Overflow | ⭐⭐⭐⭐⭐ | Easy to trigger, large corpus |
| Use-After-Free | ⭐⭐⭐ | Requires specific trigger length |
| Null Pointer | ⭐⭐⭐ | Requires specific prefix |
| Integer Overflow | ⭐⭐ | Requires very large number |
| Parser Bugs | ⭐⭐ | Strncpy limits overflow |
| Format String | ⭐ | Modern hardening prevents |

## Input Format

All inputs must follow: `COMMAND:DATA`

Examples:
```
STACK:buffer_overflow_data_here
HEAP:large_heap_overflow_trigger
UAF:use_after_free_trigger_long_enough
JSON:{"key":"value"}
XML:<tag>content</tag>
FMT:%s%s%n%n
INT:4294967295
NULL:NULL_trigger
```

## Debugging

### View crash with GDB
```bash
echo 'STACK:AAAAAAAAAA...' > /tmp/crash_input
gdb ./raptor_testbench_debug
(gdb) run < /tmp/crash_input
(gdb) bt
```

### View crash with LLDB (macOS)
```bash
echo 'STACK:AAAAAAAAAA...' > /tmp/crash_input
lldb ./raptor_testbench_debug
(lldb) run < /tmp/crash_input
(lldb) bt
```

## Notes

- **ASAN Version Recommended:** Use `raptor_testbench_asan` for best crash detection
- **Parser Bugs:** May require AFL to discover exact overflow conditions
- **Format String:** Modern compilers add protections, may not crash
- **AFL Speed:** ~1500-2000 execs/sec on Apple Silicon M-series
- **Instrumentation:** AFL instrumentation confirmed in all builds

## Success Metrics

A successful RAPTOR test should:

1. ✅ Find at least 3 distinct vulnerability types
2. ✅ Correctly deduplicate crashes (not count same bug multiple times)
3. ✅ Classify crashes correctly (stack vs heap vs UAF)
4. ✅ Generate autonomous corpus with format hints
5. ✅ Prioritize crashes based on goal
6. ✅ Record knowledge to memory for future runs
7. ✅ Generate compilable exploits (with cloud LLMs)

---

**Created for RAPTOR v1.0 by Gadi & Daniel**
