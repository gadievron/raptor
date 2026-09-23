"""Tests for the macro-definition config extractor (config-aware #ifdef)."""

from __future__ import annotations

import json

import pytest

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
    # =m defines only the _MODULE spelling — autoconf.h never defines
    # CONFIG_MOD itself for tristate modules, so the bare name must be
    # known-undefined (the #else arm is what every TU compiles).
    assert mc.is_defined("CONFIG_MOD") is False
    assert mc.is_defined("CONFIG_MOD_MODULE") is True
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


def test_extract_build_tus_none_when_no_manifest(tmp_path):
    from core.build.macro_config import extract_build_tus
    assert extract_build_tus(tmp_path) is None  # no compile_commands → unknown


def test_extract_build_tus_collects_resolved_paths(tmp_path):
    import json
    from core.build.macro_config import extract_build_tus
    (tmp_path / "compile_commands.json").write_text(json.dumps([
        {"directory": str(tmp_path), "file": "a.c",
         "arguments": ["cc", "-c", "a.c"]},                     # relative
        {"directory": str(tmp_path), "file": str(tmp_path / "b.c"),
         "command": "cc -c b.c"},                               # absolute
    ]))
    tus = extract_build_tus(tmp_path)
    assert str((tmp_path / "a.c").resolve()) in tus
    assert str((tmp_path / "b.c").resolve()) in tus


def test_extract_build_tus_empty_manifest_is_none(tmp_path):
    # An empty/degenerate manifest → unknown, NOT "everything excluded".
    from core.build.macro_config import extract_build_tus
    (tmp_path / "compile_commands.json").write_text("[]")
    assert extract_build_tus(tmp_path) is None


def test_extract_build_tus_malformed_is_none(tmp_path):
    from core.build.macro_config import extract_build_tus
    (tmp_path / "compile_commands.json").write_text("{not json")
    assert extract_build_tus(tmp_path) is None


# --- hardened read: symlink refusal + byte budgets --------------------------


def test_symlinked_compile_commands_out_of_tree_refused(tmp_path):
    # Containment gate: a symlink resolving outside the target is
    # never read. In-tree symlinks (the clangd root-symlink layout)
    # are accepted via their resolved path — see
    # TestCompileCommandsCandidates below.
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps([{
        "file": "a.c", "directory": ".",
        "arguments": ["cc", "-DFOO", "-c", "a.c"],
    }]))
    target = tmp_path / "repo"
    target.mkdir()
    (target / "compile_commands.json").symlink_to(outside)
    mc = extract_macro_config(target)
    assert not mc
    assert mc.source == "absent"


def test_symlinked_kconfig_refused(tmp_path):
    real = tmp_path / "elsewhere.config"
    real.write_text("CONFIG_FOO=y\n")
    (tmp_path / ".config").symlink_to(real)
    mc = extract_macro_config(tmp_path)
    assert not mc
    assert mc.source == "absent"


def test_oversize_compile_commands_refused(tmp_path, monkeypatch):
    import core.build.macro_config as mod
    _write_cc(tmp_path, [{
        "file": "a.c", "directory": ".",
        "arguments": ["cc", "-DFOO", "-c", "a.c"],
    }])
    monkeypatch.setattr(mod, "_MAX_COMPILE_COMMANDS_BYTES", 8)
    assert not extract_macro_config(tmp_path)
    assert mod.extract_build_tus(tmp_path) is None


def test_oversize_kconfig_refused(tmp_path, monkeypatch):
    import core.build.macro_config as mod
    (tmp_path / ".config").write_text("CONFIG_FOO=y\n" * 100)
    monkeypatch.setattr(mod, "_MAX_KCONFIG_BYTES", 8)
    assert not extract_macro_config(tmp_path)


def test_within_budget_still_parses(tmp_path):
    _write_cc(tmp_path, [{
        "file": "a.c", "directory": ".",
        "arguments": ["cc", "-DFOO", "-c", "a.c"],
    }])
    mc = extract_macro_config(tmp_path)
    assert mc.is_defined("FOO") is True


def test_read_bounded_fifo_refused_without_blocking(tmp_path):
    """A FIFO planted at a config-artifact path must be REFUSED, not
    block open(). The reader's contract is FIFO-safe (fstat refuses
    non-regular files), but the fstat gate only runs after open()
    returns — a writer-less FIFO opened without O_NONBLOCK hangs the
    unsandboxed parent forever. Callers pre-gate with is_file(), so
    the exposure is the check-to-open swap race in an
    attacker-writable scanned repo; the reader itself must hold the
    contract it documents.
    """
    import os
    import threading

    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo not available on this platform")
    from core.build.macro_config import _read_bounded

    fifo = tmp_path / "compile_commands.json"
    os.mkfifo(fifo)
    outcome: list = []

    def _attempt() -> None:
        try:
            _read_bounded(fifo, 1024)
            outcome.append("read")
        except (OSError, ValueError):
            outcome.append("refused")

    t = threading.Thread(target=_attempt, daemon=True)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "_read_bounded blocked opening a FIFO"
    assert outcome == ["refused"]


class TestNestingBombs:
    """compile_commands.json is repo content read BECAUSE it is repo
    content: a planted nesting bomb must degrade like malformed JSON
    (the module's never-raises contract), never raise RecursionError
    into the unwrapped inventory-stage consumers."""

    def _plant(self, tmp_path, raw):
        (tmp_path / "compile_commands.json").write_text(raw)

    def test_leading_bomb_degrades_all_three_extractors(self, tmp_path):
        from core.build.build_flags import extract_flags
        from core.build.macro_config import extract_build_tus

        self._plant(tmp_path, "[" * 100_000 + "]" * 100_000)
        mc = extract_macro_config(tmp_path)
        assert not mc
        assert extract_build_tus(tmp_path) is None
        assert extract_flags(tmp_path).extraction_confidence == "absent"

    def test_bomb_past_the_scan_window_is_caught(self, tmp_path):
        """A deep tail buried past the pre-gate's bounded prefix scan
        exercises the RecursionError rows in the catch tuples — the
        gate is an optimization, the catch tuple the guarantee."""
        from core.build.build_flags import extract_flags
        from core.build.macro_config import extract_build_tus

        flat = '{"x":1},' * 140_000            # > the 1 MiB scan window
        deep = "[" * 60_000 + "]" * 60_000
        self._plant(tmp_path, "[" + flat + deep + "]")
        mc = extract_macro_config(tmp_path)
        assert not mc
        assert extract_build_tus(tmp_path) is None
        assert extract_flags(tmp_path).extraction_confidence == "absent"

    def test_legitimately_nested_manifest_still_extracts(self, tmp_path):
        """Real depth (array of dicts with arguments arrays, strings
        full of brackets and escapes) stays far under the gate."""
        entries = [
            {"directory": "/src", "file": "a.c",
             "arguments": ["cc", "-D_FORTIFY_SOURCE=2", "-DF\\\"[{OO",
                           "-c", "a.c"]},
        ]
        self._plant(tmp_path, json.dumps(entries))
        mc = extract_macro_config(tmp_path)
        assert mc.is_defined("_FORTIFY_SOURCE") is True


class TestCompileCommandsCandidates:
    """The clangd root-symlink layout and candidate iteration."""

    _ENTRIES = [{"directory": "/src", "file": "a.c",
                 "command": "cc -D_FORTIFY_SOURCE=2 -DFEATURE_X a.c"}]

    def _build_layout(self, tmp_path, root_symlink=True):
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "compile_commands.json").write_text(
            json.dumps(self._ENTRIES))
        if root_symlink:
            import os
            os.symlink("build/compile_commands.json",
                       tmp_path / "compile_commands.json")

    def test_root_symlink_layout_feeds_all_three_extractors(self, tmp_path):
        """`ln -s build/compile_commands.json .` is the canonical
        clangd layout; it used to zero macro config, hardening
        evidence, and the TU set silently (root candidate won, the
        O_NOFOLLOW read failed, the fallback was never tried)."""
        from core.build.build_flags import extract_flags
        from core.build.macro_config import extract_build_tus

        self._build_layout(tmp_path)
        mc = extract_macro_config(tmp_path)
        assert mc.is_defined("FEATURE_X") is True
        assert extract_flags(tmp_path).fortify_source_level == 2
        tus = extract_build_tus(tmp_path)
        assert tus is not None and any(t.endswith("a.c") for t in tus)

    def test_out_of_tree_symlink_refused_fallback_still_wins(self, tmp_path):
        """The acceptance is containment-gated: a symlink escaping
        the target is skipped (INFO), and iteration still reaches the
        real build/ candidate."""
        import os
        outside = tmp_path / "outside"
        outside.mkdir()
        target = tmp_path / "repo"
        target.mkdir()
        (outside / "cc.json").write_text(json.dumps(
            [{"file": "evil.c", "command": "cc -DEVIL evil.c"}]))
        (target / "build").mkdir()
        (target / "build" / "compile_commands.json").write_text(
            json.dumps(self._ENTRIES))
        os.symlink(outside / "cc.json",
                   target / "compile_commands.json")
        mc = extract_macro_config(target)
        assert mc.is_defined("EVIL") is None      # never read
        assert mc.is_defined("FEATURE_X") is True  # fallback used

    def test_malformed_root_candidate_does_not_veto_fallback(self, tmp_path):
        self._build_layout(tmp_path, root_symlink=False)
        (tmp_path / "compile_commands.json").write_text("{not json")
        mc = extract_macro_config(tmp_path)
        assert mc.is_defined("FEATURE_X") is True
