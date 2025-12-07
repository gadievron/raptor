#!/usr/bin/env python3
"""
Test with real binary to validate all features work
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import Radare2Wrapper, is_radare2_available


@pytest.fixture(scope="module")
def real_binary():
    """Use vim as a real, complex binary."""
    vim_path = Path("/usr/bin/vim")
    if not vim_path.exists():
        pytest.skip("vim not available")
    return vim_path


@pytest.fixture(scope="module")
def r2(real_binary):
    """Create Radare2Wrapper with real binary."""
    if not is_radare2_available():
        pytest.skip("radare2 not available")

    wrapper = Radare2Wrapper(real_binary)
    wrapper.analyze()  # Run analysis
    return wrapper


class TestRealBinary:
    """Test all features with a real binary."""

    def test_list_functions_finds_functions(self, r2):
        """Test that aa analysis finds functions in real binary."""
        functions = r2.list_functions()

        print(f"\n✓ Found {len(functions)} functions")
        assert len(functions) > 0, "Should find functions in vim binary"

        # Print first few functions
        for func in functions[:5]:
            print(f"  - {func.name} @ {func.offset}")

    def test_disassemble_function_works(self, r2):
        """Test function disassembly."""
        functions = r2.list_functions()
        assert len(functions) > 0

        # Disassemble first function
        func = functions[0]
        disasm = r2.disassemble_function(func.offset)

        print(f"\n✓ Disassembled function: {func.name}")
        assert isinstance(disasm, dict)
        assert "error" not in disasm

    def test_xrefs_work(self, r2):
        """Test cross-reference analysis."""
        functions = r2.list_functions()
        assert len(functions) > 1

        # Try to get xrefs for a function
        func = functions[0]
        xrefs = r2.get_xrefs_to(func.offset)

        print(f"\n✓ Cross-references to {func.name}: {len(xrefs)}")
        assert isinstance(xrefs, list)

    def test_call_graph_works(self, r2):
        """Test call graph generation."""
        functions = r2.list_functions()
        assert len(functions) > 0

        func = functions[0]
        call_graph = r2.get_call_graph(func.offset)

        print(f"\n✓ Call graph for {func.name}")
        assert isinstance(call_graph, (dict, list))

    def test_backward_disassembly_works(self, r2):
        """Test backward disassembly."""
        functions = r2.list_functions()
        assert len(functions) > 0

        func = functions[0]
        # Disassemble with backward context
        instructions = r2.disassemble_at_address(func.offset, count=5, backward=3)

        print(f"\n✓ Backward disassembly: {len(instructions)} instructions")
        assert isinstance(instructions, list)

    def test_security_info_works(self, r2):
        """Test security helper."""
        security = r2.get_security_info()

        print(f"\n✓ Security info:")
        for key, value in security.items():
            print(f"  {key}: {value}")

        assert isinstance(security, dict)
        assert 'canary' in security
        assert 'nx' in security
        assert 'pie' in security

    def test_size_based_timeout(self, real_binary):
        """Test size-based timeout scaling."""
        import os

        wrapper = Radare2Wrapper(real_binary)
        size_mb = os.path.getsize(real_binary) / 1024 / 1024

        print(f"\n✓ Binary size: {size_mb:.2f} MB")
        print(f"✓ Auto-scaled timeout: {wrapper.timeout}s")

        # 5.4MB should get 300s timeout (1-10MB range)
        assert wrapper.timeout == 300


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
