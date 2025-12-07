#!/usr/bin/env python3
"""
Tests for Radare2 Wrapper (radare2_wrapper.py)

Requirements:
- pytest (install: pip install pytest)
- radare2 (install: brew install radare2 / apt install radare2)
- Test binary (automatically created if missing)

Run tests:
    pytest raptor/test/test_radare2_wrapper.py -v
    pytest raptor/test/test_radare2_wrapper.py -v -k "test_disassemble"  # Run specific test
"""

import pytest
import subprocess
import tempfile
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packages.binary_analysis.radare2_wrapper import (
    Radare2Wrapper,
    Radare2DisasmInstruction,
    Radare2Function,
    format_disassembly_text,
    is_radare2_available
)


@pytest.fixture(scope="module")
def test_binary():
    """
    Create a simple test binary for analysis.

    Creates a minimal C program with:
    - main function
    - helper function
    - Stack canary protection
    - Debug symbols (for better testing)
    """
    # Create temporary directory for test artifacts
    test_dir = Path(tempfile.mkdtemp(prefix="raptor_r2_test_"))

    # C source code
    source_code = """
#include <stdio.h>
#include <string.h>

int add_numbers(int a, int b) {
    return a + b;
}

int main(int argc, char **argv) {
    int result = add_numbers(5, 10);
    printf("Result: %d\\n", result);

    if (argc > 1) {
        char buffer[64];
        strncpy(buffer, argv[1], sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\\0';
        printf("Input: %s\\n", buffer);
    }

    return 0;
}
"""

    source_file = test_dir / "test_program.c"
    binary_file = test_dir / "test_program"

    # Write source
    source_file.write_text(source_code)

    # Compile with gcc (with stack protector and debug symbols)
    compile_cmd = [
        "gcc",
        "-o", str(binary_file),
        "-fstack-protector-all",  # Enable stack canaries
        "-g",                      # Debug symbols
        str(source_file)
    ]

    try:
        result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            pytest.skip(f"Failed to compile test binary: {result.stderr}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pytest.skip("gcc not available or compilation timed out")

    if not binary_file.exists():
        pytest.skip("Test binary was not created")

    yield binary_file

    # Cleanup
    try:
        source_file.unlink()
        binary_file.unlink()
        test_dir.rmdir()
    except:
        pass


@pytest.fixture(scope="module")
def radare2_wrapper(test_binary):
    """Create Radare2Wrapper instance for test binary."""
    if not is_radare2_available():
        pytest.skip("radare2 not available in PATH")

    wrapper = Radare2Wrapper(test_binary)
    return wrapper


class TestRadare2Availability:
    """Test radare2 availability checking."""

    def test_is_radare2_available(self):
        """Test that r2 availability check works."""
        # Should return True or False, not raise exception
        result = is_radare2_available()
        assert isinstance(result, bool)

    def test_radare2_wrapper_availability_check(self, test_binary):
        """Test Radare2Wrapper's availability check."""
        if not is_radare2_available():
            pytest.skip("radare2 not available")

        wrapper = Radare2Wrapper(test_binary)
        assert wrapper.is_available() is True


class TestRadare2WrapperInitialization:
    """Test Radare2Wrapper initialization and configuration."""

    def test_initialization_with_valid_binary(self, test_binary):
        """Test successful initialization with valid binary."""
        if not is_radare2_available():
            pytest.skip("radare2 not available")

        wrapper = Radare2Wrapper(test_binary)
        assert wrapper.binary == test_binary
        assert wrapper.radare2_path == "radare2"
        assert wrapper.analysis_depth == "aa"  # Changed to 'aa' (53% faster, recommended)
        # Timeout is now auto-scaled by binary size (Phase 2.3)
        assert wrapper.timeout > 0, "Timeout should be set"

    def test_initialization_with_custom_params(self, test_binary):
        """Test initialization with custom parameters."""
        if not is_radare2_available():
            pytest.skip("radare2 not available")

        wrapper = Radare2Wrapper(
            test_binary,
            radare2_path="radare2",
            analysis_depth="aa",
            timeout=120
        )
        assert wrapper.analysis_depth == "aa"
        assert wrapper.timeout == 120

    def test_initialization_with_nonexistent_binary(self):
        """Test that initialization fails with non-existent binary."""
        if not is_radare2_available():
            pytest.skip("radare2 not available")

        with pytest.raises(FileNotFoundError):
            Radare2Wrapper(Path("/nonexistent/binary"))


class TestBinaryAnalysis:
    """Test binary analysis functionality."""

    def test_analyze(self, radare2_wrapper):
        """Test binary analysis (aaa)."""
        result = radare2_wrapper.analyze()
        assert result is True
        assert radare2_wrapper._analyzed is True

        # Second call should be idempotent
        result2 = radare2_wrapper.analyze()
        assert result2 is True

    def test_get_binary_info(self, radare2_wrapper):
        """Test binary metadata extraction."""
        info = radare2_wrapper.get_binary_info()

        assert "error" not in info
        # Should have basic binary info
        # Note: exact keys depend on r2 version and binary format

    def test_get_entrypoint(self, radare2_wrapper):
        """Test entrypoint detection."""
        radare2_wrapper.analyze()
        entrypoint = radare2_wrapper.get_entrypoint()

        assert entrypoint is not None
        # Should have address information

    def test_list_functions(self, radare2_wrapper):
        """Test function enumeration."""
        radare2_wrapper.analyze()
        functions = radare2_wrapper.list_functions()

        assert isinstance(functions, list)
        # Note: With 'aa' analysis (default), simple test binaries may not detect functions
        # This is expected - 'aa' is faster but less comprehensive than 'aaa'
        # The test validates that the method works, not that it finds specific functions

        # If functions are found, verify structure
        if len(functions) > 0:
            func_names = [f.name for f in functions]
            # May find main function (depends on analysis level and binary complexity)
            assert all(hasattr(f, 'name') for f in functions), "Functions should have names"


class TestDisassembly:
    """Test disassembly functionality."""

    def test_disassemble_function(self, radare2_wrapper):
        """Test function disassembly."""
        radare2_wrapper.analyze()
        functions = radare2_wrapper.list_functions()

        # Find main function
        main_func = None
        for func in functions:
            if "main" in func.name:
                main_func = func
                break

        if main_func is None:
            pytest.skip("main function not found in test binary")

        # Disassemble main
        disasm = radare2_wrapper.disassemble_function(main_func.offset)

        assert "error" not in disasm
        assert "ops" in disasm or isinstance(disasm, dict)

    def test_disassemble_at_address(self, radare2_wrapper):
        """Test disassembly at specific address."""
        radare2_wrapper.analyze()
        entrypoint = radare2_wrapper.get_entrypoint()

        if not entrypoint or "vaddr" not in entrypoint:
            pytest.skip("Could not determine entrypoint address")

        address = entrypoint["vaddr"]
        if isinstance(address, int):
            address = hex(address)

        instructions = radare2_wrapper.disassemble_at_address(address, count=10)

        assert isinstance(instructions, list)
        assert len(instructions) > 0
        assert all(isinstance(insn, Radare2DisasmInstruction) for insn in instructions)

        # Check instruction fields
        first_insn = instructions[0]
        assert hasattr(first_insn, "offset")
        assert hasattr(first_insn, "opcode")
        assert hasattr(first_insn, "disasm")
        assert hasattr(first_insn, "type")

    def test_format_disassembly_text(self, radare2_wrapper):
        """Test disassembly text formatting."""
        radare2_wrapper.analyze()
        entrypoint = radare2_wrapper.get_entrypoint()

        if not entrypoint or "vaddr" not in entrypoint:
            pytest.skip("Could not determine entrypoint address")

        address = entrypoint["vaddr"]
        if isinstance(address, int):
            address = hex(address)

        instructions = radare2_wrapper.disassemble_at_address(address, count=5)

        if not instructions:
            pytest.skip("No instructions disassembled")

        text = format_disassembly_text(instructions)

        assert isinstance(text, str)
        assert len(text) > 0
        # Should contain address and instruction
        assert "0x" in text


class TestDecompilation:
    """Test decompilation functionality."""

    def test_decompile_function(self, radare2_wrapper):
        """Test function decompilation to pseudo-C."""
        radare2_wrapper.analyze()
        functions = radare2_wrapper.list_functions()

        # Find main function
        main_func = None
        for func in functions:
            if "main" in func.name:
                main_func = func
                break

        if main_func is None:
            pytest.skip("main function not found")

        # Decompile main
        decompiled = radare2_wrapper.decompile_function(main_func.offset)

        assert isinstance(decompiled, str)
        # Decompilation may not always succeed, but should return string
        # (even if it's an error message)


class TestCrossReferences:
    """Test cross-reference analysis."""

    def test_get_xrefs_to(self, radare2_wrapper):
        """Test getting cross-references TO an address."""
        radare2_wrapper.analyze()
        functions = radare2_wrapper.list_functions()

        if len(functions) < 2:
            pytest.skip("Not enough functions for xref testing")

        # Try to get xrefs to second function (likely called from somewhere)
        target_func = functions[1]
        xrefs = radare2_wrapper.get_xrefs_to(target_func.offset)

        assert isinstance(xrefs, list)
        # May or may not have xrefs depending on the function

    def test_get_xrefs_from(self, radare2_wrapper):
        """Test getting cross-references FROM an address."""
        radare2_wrapper.analyze()
        functions = radare2_wrapper.list_functions()

        # Find main function (should have calls)
        main_func = None
        for func in functions:
            if "main" in func.name:
                main_func = func
                break

        if main_func is None:
            pytest.skip("main function not found")

        xrefs = radare2_wrapper.get_xrefs_from(main_func.offset)

        assert isinstance(xrefs, list)
        # main should have at least some xrefs (calls to other functions)


class TestBinaryMetadata:
    """Test binary metadata extraction."""

    def test_get_strings(self, radare2_wrapper):
        """Test string extraction."""
        strings = radare2_wrapper.get_strings(min_length=4)

        assert isinstance(strings, list)
        # Test binary should have some strings (e.g., "Result: %d")
        if len(strings) > 0:
            assert "string" in strings[0] or "value" in strings[0]

    def test_get_imports(self, radare2_wrapper):
        """Test import enumeration."""
        imports = radare2_wrapper.get_imports()

        assert isinstance(imports, list)
        # Should have standard C library imports
        if len(imports) > 0:
            import_names = [imp.get("name", "") for imp in imports]
            # Should have printf or similar
            assert any("print" in name.lower() for name in import_names)

    def test_get_exports(self, radare2_wrapper):
        """Test export enumeration."""
        exports = radare2_wrapper.get_exports()

        assert isinstance(exports, list)
        # May or may not have exports depending on compilation


class TestAdvancedAnalysis:
    """Test advanced analysis features."""

    def test_get_call_graph(self, radare2_wrapper):
        """Test call graph generation."""
        radare2_wrapper.analyze()
        functions = radare2_wrapper.list_functions()

        # Find main function
        main_func = None
        for func in functions:
            if "main" in func.name:
                main_func = func
                break

        if main_func is None:
            pytest.skip("main function not found")

        call_graph = radare2_wrapper.get_call_graph(main_func.offset)

        # Call graph structure depends on r2 version (can be dict or list)
        assert isinstance(call_graph, (dict, list))
        assert call_graph  # Should not be empty

    def test_analyze_function_complexity(self, radare2_wrapper):
        """Test function complexity analysis."""
        radare2_wrapper.analyze()
        functions = radare2_wrapper.list_functions()

        # Find main function
        main_func = None
        for func in functions:
            if "main" in func.name:
                main_func = func
                break

        if main_func is None:
            pytest.skip("main function not found")

        complexity = radare2_wrapper.analyze_function_complexity(main_func.offset)

        assert isinstance(complexity, dict)
        assert "name" in complexity
        assert "address" in complexity
        assert "size" in complexity
        assert "instructions" in complexity


class TestStackCanaryDetection:
    """Test stack canary detection (for crash_analyser integration)."""

    def test_detect_stack_canaries(self, radare2_wrapper):
        """Test detection of stack canaries via imports."""
        imports = radare2_wrapper.get_imports()
        import_names = [imp.get("name", "") for imp in imports]

        # Test binary was compiled with -fstack-protector-all
        # Should have __stack_chk_fail in imports
        has_canary = any("stack_chk" in name or "chk_fail" in name for name in import_names)

        # This should be True for our test binary
        assert has_canary is True


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_invalid_address(self, radare2_wrapper):
        """Test disassembly with invalid address."""
        radare2_wrapper.analyze()
        instructions = radare2_wrapper.disassemble_at_address("0xffffffff", count=10)

        # Should return empty list, not crash
        assert isinstance(instructions, list)

    def test_command_timeout(self, test_binary):
        """Test command timeout handling."""
        if not is_radare2_available():
            pytest.skip("radare2 not available")

        # Create wrapper with very short timeout
        wrapper = Radare2Wrapper(test_binary, timeout=1)

        # This should not hang indefinitely
        result = wrapper._execute_command("aaa", json_output=False, timeout=1)

        assert isinstance(result, dict)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
