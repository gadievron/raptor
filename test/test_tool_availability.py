#!/usr/bin/env python3
"""
Quick test to show reverse engineering tool availability checking.
"""

import sys
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from packages.binary_analysis.crash_analyser import CrashAnalyser

def test_tool_availability():
    """Test tool availability detection."""

    # Test with a dummy binary path (doesn't need to exist for this test)
    dummy_binary = "test/vuln_fuzz_target"

    print("=== REVERSE ENGINEERING TOOL AVAILABILITY CHECK ===")

    try:
        analyser = CrashAnalyser(dummy_binary)

        print("Tool availability results:")
        for tool, available in analyser._available_tools.items():
            status = "✅ AVAILABLE" if available else "❌ MISSING"
            print(f"  {tool:<12} {status}")

        available_count = sum(analyser._available_tools.values())
        total_count = len(analyser._available_tools)

        print(f"\nSummary: {available_count}/{total_count} tools available")

        if available_count == total_count:
            print("🎉 All reverse engineering tools are available!")
        elif available_count >= 3:
            print("⚠️  Most tools available - reduced functionality possible")
        else:
            print("❌ Limited reverse engineering capabilities")

    except Exception as e:
        print(f"Error testing tool availability: {e}")

if __name__ == "__main__":
    test_tool_availability()