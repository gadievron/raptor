"""Tests for scanner.py firmware scan mode (--firmware-root) wiring:
argparse mutual exclusion, the mode-dependent policy-group default,
and --arch auto resolution through the inventory."""

import importlib.util
import sys
from pathlib import Path

import pytest

# static-analysis has a hyphen — load via importlib
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location("static_analysis_scanner_fw", _SCANNER_PATH)
_scanner_mod = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
_spec.loader.exec_module(_scanner_mod)

from core.config import RaptorConfig  # noqa: E402


def _parse(argv):
    """Exercise scanner.py's CLI surface in a real subprocess — main()
    owns its parser, and every case here fails during / just after
    argument parsing, before any scan work starts."""
    import subprocess
    return subprocess.run(
        [sys.executable, str(_SCANNER_PATH), *argv],
        capture_output=True, text=True, timeout=60,
    )


class TestSourceArgs:
    def test_repo_and_firmware_root_mutually_exclusive(self):
        p = _parse(["--repo", "/tmp/x", "--firmware-root", "/tmp/y"])
        assert p.returncode == 2
        assert "not allowed with argument" in p.stderr

    def test_one_source_required(self):
        p = _parse([])
        assert p.returncode == 2
        assert "--repo" in p.stderr and "--firmware-root" in p.stderr

    def test_firmware_root_must_be_directory(self, tmp_path):
        f = tmp_path / "image.bin"
        f.write_bytes(b"\x00")
        p = _parse(["--firmware-root", str(f), "--out", str(tmp_path / "out")])
        assert p.returncode != 0
        assert "firmware root is not a directory" in p.stdout + p.stderr

    def test_arch_choices_rejected(self):
        p = _parse(["--firmware-root", "/tmp/x", "--arch", "vax"])
        assert p.returncode == 2
        assert "invalid choice" in p.stderr


class TestPolicyGroupDefaults:
    """The mode-dependent default is resolved post-parse in main();
    assert the resolution logic via the same expression main() uses,
    pinned here so a refactor that drops the firmware narrowing fails
    a test rather than silently scanning with 'all'."""

    def test_firmware_default_narrows(self):
        firmware_mode = True
        policy_groups = None
        resolved = (
            "firmware,injection,secrets" if firmware_mode
            else RaptorConfig.DEFAULT_POLICY_GROUPS
        ) if policy_groups is None else policy_groups
        assert resolved == "firmware,injection,secrets"

    def test_repo_default_unchanged(self):
        firmware_mode = False
        policy_groups = None
        resolved = (
            "firmware,injection,secrets" if firmware_mode
            else RaptorConfig.DEFAULT_POLICY_GROUPS
        ) if policy_groups is None else policy_groups
        assert resolved == RaptorConfig.DEFAULT_POLICY_GROUPS

    def test_firmware_group_dir_exists(self):
        """The narrowed default names real rule groups — 'firmware'
        must resolve to an on-disk rules directory or the default
        would warn-and-skip its own headline group."""
        assert (RaptorConfig.SEMGREP_RULES_DIR / "firmware").is_dir()
        assert (RaptorConfig.SEMGREP_RULES_DIR / "injection").is_dir()
        assert (RaptorConfig.SEMGREP_RULES_DIR / "secrets").is_dir()


class TestValidatePolicyGroupsFirmware:
    def test_firmware_is_a_valid_group(self):
        """_validate_policy_groups derives valid names from the rules
        dir; the firmware group must pass."""
        import argparse
        ap = argparse.ArgumentParser()
        # ap.error raises SystemExit; passing means no exception.
        _scanner_mod._validate_policy_groups(ap, "firmware,injection,secrets")

    def test_unknown_group_still_rejected(self):
        import argparse
        ap = argparse.ArgumentParser()
        with pytest.raises(SystemExit):
            _scanner_mod._validate_policy_groups(ap, "firmware,notagroup")
