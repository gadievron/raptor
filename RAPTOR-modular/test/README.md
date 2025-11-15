# RAPTOR Fuzzing Test

## Quick Start

### 1. Compile the vulnerable binary

```bash
cd test/
chmod +x compile_test.sh
./compile_test.sh
```

### 2. Test manually

```bash
# Normal input - should work
echo "test" | ./vulnerable_test

# Crash it manually
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | ./vulnerable_test
```

### 3. Run RAPTOR fuzzing

```bash
cd ..
python3 raptor_fuzzing.py \
    --binary ./test/vulnerable_test \
    --duration 60 \
    --max-crashes 5
```

## What the Test Binary Does

The `vulnerable_test.c` program contains:
- **Stack buffer overflow**: `strcpy` with no bounds checking
- **64-byte buffer**: Easily overflowable
- **No stack protector**: Compiled with `-fno-stack-protector`
- **Debug symbols**: Compiled with `-g` for better analysis

## Expected Results

RAPTOR should:
1. **Find crashes** within seconds (AFL is very fast for this)
2. **Analyze crashes** with GDB to get stack traces
3. **Classify** as "stack_overflow" or "memory_access_violation"
4. **LLM assessment** should identify it as exploitable
5. **Generate exploit** PoC using pwntools

## AFL++ Installation

### macOS
```bash
brew install afl++
```

### Ubuntu/Debian
```bash
sudo apt install afl++
```

## Troubleshooting

### "AFL not found"
- Install AFL++ (see above)
- RAPTOR will use QEMU mode for non-instrumented binaries (slower but works)

### "No crashes found"
- The vulnerability is very obvious, AFL should find it quickly
- Try increasing duration: `--duration 120`
- Check binary works: `echo 'test' | ./vulnerable_test`

### "GDB not found"
- Install GDB: `brew install gdb` (macOS) or `apt install gdb` (Ubuntu)
- RAPTOR needs GDB for crash analysis

## Advanced Testing

### With AFL instrumentation
```bash
# Compile with AFL
afl-gcc -o vulnerable_test_afl vulnerable_test.c -g -O0 -fno-stack-protector

# Fuzz with instrumented binary (much faster)
python3 raptor_fuzzing.py \
    --binary ./test/vulnerable_test_afl \
    --duration 300 \
    --max-crashes 10 \
    --parallel 4
```

### With custom corpus
```bash
mkdir corpus
echo "test" > corpus/seed1
echo "ABC" > corpus/seed2

python3 raptor_fuzzing.py \
    --binary ./test/vulnerable_test \
    --corpus ./corpus \
    --duration 60
```
