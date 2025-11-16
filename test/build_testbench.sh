#!/bin/bash
#
# Build RAPTOR Test Bench with different configurations
#

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         RAPTOR Test Bench - Build Script                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if AFL is available
if command -v afl-clang-fast &> /dev/null; then
    AFL_CC="afl-clang-fast"
elif command -v afl-gcc &> /dev/null; then
    AFL_CC="afl-gcc"
else
    echo "⚠️  AFL compiler not found - building without instrumentation"
    AFL_CC="gcc"
fi

# Check if clang is available for ASAN
if command -v clang &> /dev/null; then
    CLANG_CC="clang"
else
    CLANG_CC="gcc"
fi

cd "$(dirname "$0")"

echo "[1/4] Building AFL-instrumented version..."
$AFL_CC -o raptor_testbench_afl raptor_testbench.c
echo "✓ Built: raptor_testbench_afl"

echo ""
echo "[2/4] Building AFL + ASAN version..."
$AFL_CC -fsanitize=address -o raptor_testbench_asan raptor_testbench.c
echo "✓ Built: raptor_testbench_asan"

echo ""
echo "[3/4] Building normal version..."
gcc -o raptor_testbench raptor_testbench.c
echo "✓ Built: raptor_testbench"

echo ""
echo "[4/4] Building debug version with symbols..."
gcc -g -O0 -o raptor_testbench_debug raptor_testbench.c
echo "✓ Built: raptor_testbench_debug"

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                     Build Complete!                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Binaries created:"
echo "  - raptor_testbench_afl    : AFL++ instrumented (for fuzzing)"
echo "  - raptor_testbench_asan   : AFL++ + AddressSanitizer (best for fuzzing)"
echo "  - raptor_testbench        : Normal build"
echo "  - raptor_testbench_debug  : Debug build with symbols"
echo ""
echo "Test with:"
echo "  echo 'STACK:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | ./raptor_testbench_asan"
echo "  echo 'HEAP:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | ./raptor_testbench_asan"
echo "  echo 'UAF:trigger_use_after_free' | ./raptor_testbench_asan"
echo ""
