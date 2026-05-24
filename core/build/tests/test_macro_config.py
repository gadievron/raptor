"""Tests for the macro-definition config extractor (config-aware #ifdef)."""

from __future__ import annotations

import json

from core.build.macro_config import MacroConfig, extract_macro_config


def _write_cc(tmp_path, entries):
    p = tmp_path / "compile_commands.json"
    p.write_text(json.dumps(entries))
    return tmp_path


def test_absent_when_no_artifacts(tmp_path):
    mc = extract_macro_config(tmp_path)
    assert not mc
    assert mc.source == "absent"
    # Unknown for everything — the load-bearing soundness property.
    assert mc.is_defined("ANYTHING") is None


def test_nonexistent_target():
    assert not extract_macro_config("/no/such/dir")


def test_compile_commands_arguments_array(tmp_path):
    _write_cc(tmp_path, [{
        "file": "a.c", "directory": ".",
        "arguments": ["cc", "-DFOO", "-DBAR=2", "-UBAZ", "-c", "a.c"],
    }])
    mc = extract_macro_config(tmp_path)
    assert mc.source == "compile_commands.json"
    assert mc.is_defined("FOO") is True
    assert mc.value_of("FOO") == "1"        # bare -D defines to 1
    assert mc.value_of("BAR") == "2"
    assert mc.is_defined("BAZ") is False    # -U
    assert mc.is_defined("UNSEEN") is None  # absent => unknown, never False


def test_compile_commands_command_string(tmp_path):
    _write_cc(tmp_path, [{
        "file": "a.c", "directory": ".",
        "command": "cc -DENABLE_X=1 -D SPACED -c a.c",
    }])
    mc = extract_macro_config(tmp_path)
    assert mc.value_of("ENABLE_X") == "1"
    assert mc.is_defined("SPACED") is True   # space-separated -D NAME


def test_conflicting_symbol_dropped_to_unknown(tmp_path):
    # FOO defined in one TU, undefined in another => config-dependent
    # project-wide => must NOT be resolvable (stays unknown).
    _write_cc(tmp_path, [
        {"file": "a.c", "directory": ".", "arguments": ["cc", "-DFOO", "a.c"]},
        {"file": "b.c", "directory": ".", "arguments": ["cc", "-UFOO", "b.c"]},
    ])
    mc = extract_macro_config(tmp_path)
    assert mc.is_defined("FOO") is None


def test_build_subdir_compile_commands(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "compile_commands.json").write_text(
        json.dumps([{"file": "a.c", "directory": ".",
                     "arguments": ["cc", "-DCMAKE_X", "a.c"]}]))
    assert extract_macro_config(tmp_path).is_defined("CMAKE_X") is True


def test_kconfig(tmp_path):
    (tmp_path / ".config").write_text(
        "CONFIG_FOO=y\n"
        "CONFIG_MOD=m\n"
        "# CONFIG_BAR is not set\n"
        "# a comment\n"
    )
    mc = extract_macro_config(tmp_path)
    assert mc.source == "kconfig"
    assert mc.is_defined("CONFIG_FOO") is True
    assert mc.is_defined("CONFIG_MOD") is True   # =m also defined
    assert mc.is_defined("CONFIG_BAR") is False
    assert mc.is_defined("CONFIG_UNSEEN") is None


def test_compile_commands_preferred_over_kconfig(tmp_path):
    _write_cc(tmp_path, [{"file": "a.c", "directory": ".",
                          "arguments": ["cc", "-DFROM_CC", "a.c"]}])
    (tmp_path / ".config").write_text("CONFIG_FROM_KCONFIG=y\n")
    mc = extract_macro_config(tmp_path)
    assert mc.source == "compile_commands.json"
    assert mc.is_defined("FROM_CC") is True


def test_malformed_compile_commands_falls_through(tmp_path):
    (tmp_path / "compile_commands.json").write_text("{not json")
    (tmp_path / ".config").write_text("CONFIG_OK=y\n")
    mc = extract_macro_config(tmp_path)
    assert mc.source == "kconfig"
    assert mc.is_defined("CONFIG_OK") is True


def test_empty_macroconfig_is_falsy():
    assert not MacroConfig()
    assert MacroConfig(defined={"X": "1"})
