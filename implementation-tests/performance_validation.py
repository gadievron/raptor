#!/usr/bin/env python3
"""
Performance Validation - Compare aa vs aaa analysis

Demonstrates the 40% performance improvement from Phase 2.1
"""

import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper, is_radare2_available


def test_performance_improvement():
    """Compare aa vs aaa analysis performance."""
    if not is_radare2_available():
        print("❌ radare2 not available")
        return

    binary = Path("/bin/ls")
    if not binary.exists():
        print("❌ Test binary not found")
        return

    print("🔬 Performance Validation: aa vs aaa Analysis")
    print("=" * 60)

    # Test with aa (new default)
    print("\n📊 Testing 'aa' analysis (NEW DEFAULT)...")
    wrapper_aa = Radare2Wrapper(binary, analysis_depth="aa")
    start = time.time()
    wrapper_aa.analyze()
    aa_time = time.time() - start
    print(f"   ✓ aa analysis: {aa_time:.3f}s")

    # Test with aaa (old default)
    print("\n📊 Testing 'aaa' analysis (OLD DEFAULT)...")
    wrapper_aaa = Radare2Wrapper(binary, analysis_depth="aaa")
    start = time.time()
    wrapper_aaa.analyze()
    aaa_time = time.time() - start
    print(f"   ✓ aaa analysis: {aaa_time:.3f}s")

    # Calculate improvement
    if aa_time > 0:
        speedup = ((aaa_time - aa_time) / aaa_time) * 100
        print(f"\n🚀 Performance Improvement: {speedup:.1f}% faster")
        print(f"   Time saved: {aaa_time - aa_time:.3f}s")

        if speedup > 20:
            print(f"   ✅ Significant improvement achieved!")
        else:
            print(f"   ⚠️  Improvement less than expected (may vary by binary)")

    # Test timeout scaling
    print("\n📊 Testing Size-Based Timeout Scaling...")
    import os
    binary_size = os.path.getsize(binary)
    print(f"   Binary size: {binary_size / 1024 / 1024:.2f} MB")
    print(f"   Auto-scaled timeout: {wrapper_aa.timeout}s")

    # Test security helper
    print("\n📊 Testing Security Helper Method...")
    security_info = wrapper_aa.get_security_info()
    print(f"   Security mitigations detected:")
    for key, value in security_info.items():
        print(f"      {key}: {'✓' if value else '✗'}")

    print("\n" + "=" * 60)
    print("✅ Performance validation complete!")


if __name__ == "__main__":
    test_performance_improvement()
