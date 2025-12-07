#!/usr/bin/env python3
"""
Renaming Validation Tests - r2 → radare2

Tests that verify the renaming from r2 to radare2 is complete:
- Import names updated
- Class names updated
- Function names updated
- Variable names updated
- Config constants updated
- No old "r2" references remain

These tests will FAIL before renaming and PASS after renaming.
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestRenamingImports:
    """Test that new import names work."""

    def test_radare2_wrapper_module_exists(self):
        """UNIT: Verify radare2_wrapper module can be imported."""
        try:
            import packages.binary_analysis.radare2_wrapper
            assert packages.binary_analysis.radare2_wrapper is not None
        except ImportError as e:
            pytest.fail(f"radare2_wrapper module not found: {e}")

    def test_radare2_wrapper_class_exists(self):
        """UNIT: Verify Radare2Wrapper class exists."""
        from packages.binary_analysis.radare2_wrapper import Radare2Wrapper
        assert Radare2Wrapper is not None
        assert Radare2Wrapper.__name__ == "Radare2Wrapper"

    def test_radare2_function_class_exists(self):
        """UNIT: Verify Radare2Function class exists."""
        from packages.binary_analysis.radare2_wrapper import Radare2Function
        assert Radare2Function is not None
        assert Radare2Function.__name__ == "Radare2Function"

    def test_radare2_disasm_instruction_class_exists(self):
        """UNIT: Verify Radare2DisasmInstruction class exists."""
        from packages.binary_analysis.radare2_wrapper import Radare2DisasmInstruction
        assert Radare2DisasmInstruction is not None
        assert Radare2DisasmInstruction.__name__ == "Radare2DisasmInstruction"

    def test_is_radare2_available_function_exists(self):
        """UNIT: Verify is_radare2_available function exists."""
        from packages.binary_analysis.radare2_wrapper import is_radare2_available
        assert is_radare2_available is not None
        assert callable(is_radare2_available)


class TestRenamingConfig:
    """Test that config constants are renamed."""

    def test_radare2_path_constant_exists(self):
        """UNIT: Verify RADARE2_PATH config exists."""
        from core.config import RaptorConfig
        assert hasattr(RaptorConfig, 'RADARE2_PATH')
        assert isinstance(RaptorConfig.RADARE2_PATH, str)

    def test_radare2_timeout_constant_exists(self):
        """UNIT: Verify RADARE2_TIMEOUT config exists."""
        from core.config import RaptorConfig
        assert hasattr(RaptorConfig, 'RADARE2_TIMEOUT')

    def test_radare2_analysis_depth_constant_exists(self):
        """UNIT: Verify RADARE2_ANALYSIS_DEPTH config exists."""
        from core.config import RaptorConfig
        assert hasattr(RaptorConfig, 'RADARE2_ANALYSIS_DEPTH')

    def test_radare2_analysis_timeout_constant_exists(self):
        """UNIT: Verify RADARE2_ANALYSIS_TIMEOUT config exists."""
        from core.config import RaptorConfig
        assert hasattr(RaptorConfig, 'RADARE2_ANALYSIS_TIMEOUT')

    def test_radare2_enable_constant_exists(self):
        """UNIT: Verify RADARE2_ENABLE config exists."""
        from core.config import RaptorConfig
        assert hasattr(RaptorConfig, 'RADARE2_ENABLE')
        assert isinstance(RaptorConfig.RADARE2_ENABLE, bool)

    def test_old_r2_constants_removed(self):
        """UNIT: Verify old R2_* constants are removed."""
        from core.config import RaptorConfig
        # These should NOT exist anymore
        assert not hasattr(RaptorConfig, 'R2_PATH'), "Old R2_PATH constant still exists!"
        assert not hasattr(RaptorConfig, 'R2_TIMEOUT'), "Old R2_TIMEOUT constant still exists!"
        assert not hasattr(RaptorConfig, 'R2_ENABLE'), "Old R2_ENABLE constant still exists!"


class TestRenamingVariables:
    """Test that variable names are updated."""

    def test_crash_analyser_has_radare2_attribute(self):
        """UNIT: Verify CrashAnalyser uses .radare2 attribute."""
        from packages.binary_analysis.crash_analyser import CrashAnalyser

        # Need a test binary
        test_binary = Path("/bin/ls")
        if not test_binary.exists():
            pytest.skip("Test binary /bin/ls not available")

        analyser = CrashAnalyser(test_binary, use_radare2=False)  # Don't actually init radare2

        # Should have 'radare2' attribute (even if None)
        assert hasattr(analyser, 'radare2'), "CrashAnalyser should have 'radare2' attribute"

    def test_crash_analyser_old_r2_attribute_removed(self):
        """UNIT: Verify old .r2 attribute is removed."""
        from packages.binary_analysis.crash_analyser import CrashAnalyser

        test_binary = Path("/bin/ls")
        if not test_binary.exists():
            pytest.skip("Test binary /bin/ls not available")

        analyser = CrashAnalyser(test_binary, use_radare2=False)

        # Should NOT have old 'r2' attribute
        assert not hasattr(analyser, 'r2'), "CrashAnalyser should NOT have old 'r2' attribute!"


class TestRenamingPackageInit:
    """Test that package __init__.py is updated."""

    def test_package_exports_radare2_wrapper(self):
        """UNIT: Verify package exports Radare2Wrapper."""
        from packages.binary_analysis import Radare2Wrapper
        assert Radare2Wrapper is not None

    def test_package_exports_is_radare2_available(self):
        """UNIT: Verify package exports is_radare2_available."""
        from packages.binary_analysis import is_radare2_available
        assert is_radare2_available is not None


class TestRenamingCompleteness:
    """Test that renaming is complete and thorough."""

    def test_no_r2_wrapper_module(self):
        """UNIT: Verify old r2_wrapper module is removed."""
        with pytest.raises(ImportError):
            import packages.binary_analysis.r2_wrapper
            pytest.fail("Old r2_wrapper module still exists!")

    def test_no_r2_wrapper_class(self):
        """UNIT: Verify old R2Wrapper class is removed."""
        from packages.binary_analysis import radare2_wrapper
        assert not hasattr(radare2_wrapper, 'R2Wrapper'), "Old R2Wrapper class still exists!"

    def test_radare2_wrapper_file_exists(self):
        """UNIT: Verify radare2_wrapper.py file exists."""
        wrapper_file = Path(__file__).parent.parent / "packages" / "binary_analysis" / "radare2_wrapper.py"
        assert wrapper_file.exists(), f"radare2_wrapper.py not found at {wrapper_file}"

    def test_old_r2_wrapper_file_removed(self):
        """UNIT: Verify old r2_wrapper.py file is removed."""
        old_file = Path(__file__).parent.parent / "packages" / "binary_analysis" / "r2_wrapper.py"
        assert not old_file.exists(), "Old r2_wrapper.py file still exists!"


class TestRenamingFakeCheck:
    """FAKE-CHECK: Verify tests test BEHAVIOR not just structure."""

    def test_not_fake_imports_actually_work(self):
        """
        FAKE-CHECK: Verify imports actually work, not just exist.

        NOT fake because: Actually instantiates classes and calls functions
        """
        from packages.binary_analysis.radare2_wrapper import (
            Radare2Wrapper,
            Radare2Function,
            Radare2DisasmInstruction,
            is_radare2_available
        )

        # Actually call the function
        result = is_radare2_available()
        assert isinstance(result, bool), "is_radare2_available should return bool"

        # Actually instantiate dataclass
        func = Radare2Function(
            name="test",
            offset="0x1000",
            size=100,
            nbbs=5,
            ninstrs=20,
            calltype="reg"
        )
        assert func.name == "test"

    def test_not_fake_config_values_accessible(self):
        """
        FAKE-CHECK: Verify config values are actually accessible.

        NOT fake because: Actually reads and uses config values
        """
        from core.config import RaptorConfig

        # Actually access the values
        path = RaptorConfig.RADARE2_PATH
        assert isinstance(path, str)
        assert len(path) > 0

        enable = RaptorConfig.RADARE2_ENABLE
        assert isinstance(enable, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
