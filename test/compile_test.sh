#!/bin/bash
# Compile test binaries

echo "Compiling vulnerable test binary..."

# Standard compilation
gcc -o vulnerable_test vulnerable_test.c -g -O0 -fno-stack-protector -Wno-deprecated-declarations 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✓ Standard binary: vulnerable_test"
else
    echo "✗ Standard compilation failed"
fi

# Try AFL instrumentation if available
if command -v afl-gcc &> /dev/null; then
    afl-gcc -o vulnerable_test_afl vulnerable_test.c -g -O0 -fno-stack-protector -Wno-deprecated-declarations 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "✓ AFL-instrumented binary: vulnerable_test_afl"
    fi
else
    echo "⚠ afl-gcc not found, skipping instrumented binary"
    echo "  Install AFL++: brew install afl++ (macOS) or apt install afl++ (Ubuntu)"
fi

echo ""
echo "Test the binary:"
echo "  echo 'test' | ./vulnerable_test"
echo "  echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | ./vulnerable_test"
