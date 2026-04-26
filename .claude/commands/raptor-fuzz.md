---
description: Binary fuzzing with AFL++ integration
---

# RAPTOR Binary Fuzzer

You are helping the user fuzz a binary executable with RAPTOR's AFL++ integration.

## Your Task

1. **Understand the target**: Identify which binary to fuzz
   - Get the full path to the binary
   - Ask about input mode (stdin or file)
   - Ask about fuzzing duration (default: 110 minutes)

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

Basic fuzzing (110 minutes, stdin mode):
```bash
python3 raptor.py fuzz --binary /path/to/binary --duration 6600
```

Quick fuzz (10 minutes):
```bash
python3 raptor.py fuzz --binary /path/to/binary --duration 600 --max-crashes 5
```

With custom corpus:
```bash
python3 raptor.py fuzz --binary /path/to/binary --corpus /path/to/seeds --duration 3600
```

## macOS Shared Memory Fix

If fuzzing fails with "shmget() failed", run:
```bash
sudo afl-system-config
```

## Important Notes

- Fuzzing can take a long time (hours) for good results
- The binary should ideally be compiled with:
  - AFL instrumentation: `afl-clang-fast` or `afl-gcc`
  - ASAN: `-fsanitize=address`
- Crashes are saved to `out/fuzz_<binary>_<timestamp>/afl_output/main/crashes/`
- RAPTOR automatically analyzes crashes and generates exploits

Be patient and explain fuzzing concepts clearly!

---
