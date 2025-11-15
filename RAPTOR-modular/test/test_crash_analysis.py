#!/usr/bin/env python3
"""
Test script for enhanced crash analysis with reverse engineering tools.
"""

import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from packages.binary_analysis.crash_analyser import CrashAnalyser

def test_crash_analysis():
    """Test crash analysis with enhanced reverse engineering."""

    # Test with actual crash file from AFL
    binary_path = "test/vuln_fuzz_target"
    crash_file = Path("test/out/default/crashes/id:000000,sig:05,src:000000,time:27,execs:61,op:havoc,rep:11")
    
    if not Path(binary_path).exists():
        print(f"Binary not found: {binary_path}")
        return

    if not crash_file.exists():
        print(f"Crash file not found: {crash_file}")
        return

    print("=== ENHANCED CRASH ANALYSIS TEST ===")
    print(f"Binary: {binary_path}")
    print(f"Crash Input: {crash_file}")
    print()

    # Initialize analyser
    analyser = CrashAnalyser(binary_path)

    # Show what tools we're using
    print("Available reverse engineering tools:")
    available_tools = analyser._available_tools
    for tool, available in available_tools.items():
        status = "✓" if available else "✗"
        print(f"{status} {tool}")
    print()

    # Analyse crash
    context = analyser.analyse_crash("test_crash_001", crash_file, "11")

    # Display results
    print("=== ANALYSIS RESULTS ===")
    print(f"Signal: {context.signal}")
    print(f"Crash Address: {context.crash_address or 'Not found'}")
    print(f"Crash Instruction: {context.crash_instruction or 'Not found'}")
    print(f"Function Name: {context.function_name or 'Not found'}")
    print(f"Source Location: {context.source_location or 'Not found'}")
    print(f"Registers Found: {len(context.registers)}")
    print(f"Stack Trace Frames: {len(context.stack_trace.split()) if context.stack_trace else 0}")
    print(f"Disassembly Lines: {len(context.disassembly.split()) if context.disassembly else 0}")
    print()

    if context.binary_info:
        print("=== BINARY INFORMATION ===")
        for key, value in context.binary_info.items():
            print(f"{key}: {value}")
        print()

    if context.registers:
        print("=== REGISTER STATE ===")
        for reg, val in context.registers.items():
            print(f"{reg}: {val}")
        print()

    if context.stack_trace:
        print("=== STACK TRACE ===")
        print(context.stack_trace[:1000])
        if len(context.stack_trace) > 1000:
            print("... (truncated)")
        print()

    if context.disassembly:
        print("=== DISASSEMBLY ===")
        print(context.disassembly[:1000])
        if len(context.disassembly) > 1000:
            print("... (truncated)")
        print()

    # Classify crash
    crash_type = analyser.classify_crash_type(context)
    print(f"Crash Classification: {crash_type}")

if __name__ == "__main__":
    test_crash_analysis()