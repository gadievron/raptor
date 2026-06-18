"""Tests for the central sanitizer-cut config (review #4 on PR #794).

Covers the 4-state mode → (value_bound, lexical, parity) mapping, the
two footgun fixes (NO_LEXICAL-without-CUT; PARITY_LOG=1 → file named
'1'), CLI/env precedence, and the default parity-log path placement.
"""
from __future__ import annotations

import argparse
import os

import pytest

from core.dataflow import sanitizer_cut_config as cfg


_ENV_VARS = (
    "RAPTOR_SANITIZER_CUT",
    "RAPTOR_SANITIZER_CUT_NO_LEXICAL",
    "RAPTOR_SANITIZER_CUT_PARITY_LOG",
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    # Each test starts from no explicit config + no env vars. Snapshot
    # so we can restore on teardown — configure(export_env=True) writes
    # os.environ DIRECTLY (not via monkeypatch), so it would otherwise
    # leak into other test files and flip their suppression mode.
    saved = {v: os.environ.get(v) for v in _ENV_VARS}
    cfg.reset()
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield
    cfg.reset()
    for var, val in saved.items():
        if val is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = val


class TestModeMapping:
    def test_off_is_default(self):
        c = cfg.config_for_mode("off")
        assert (c.value_bound_enabled, c.lexical_fallback_enabled) == (
            False, True,
        )
        assert c.parity_log_path is None

    def test_on_enables_gate_keeps_lexical(self):
        c = cfg.config_for_mode("on")
        assert (c.value_bound_enabled, c.lexical_fallback_enabled) == (
            True, True,
        )

    def test_strict_enables_gate_drops_lexical(self):
        c = cfg.config_for_mode("strict")
        assert (c.value_bound_enabled, c.lexical_fallback_enabled) == (
            True, False,
        )

    def test_shadow_behaves_off_but_logs(self, tmp_path):
        c = cfg.config_for_mode("shadow", run_dir=str(tmp_path))
        # Suppression behaviour identical to off …
        assert (c.value_bound_enabled, c.lexical_fallback_enabled) == (
            False, True,
        )
        # … but telemetry is on at the default path under the run dir.
        assert c.parity_log_path == str(
            tmp_path / cfg.DEFAULT_PARITY_LOG_NAME
        )

    def test_no_mode_disables_both(self):
        # The footgun-1 guarantee: no mode yields gate off AND lexical
        # off simultaneously.
        for mode in cfg.VALID_MODES:
            c = cfg.config_for_mode(mode)
            assert c.value_bound_enabled or c.lexical_fallback_enabled

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError):
            cfg.config_for_mode("bogus")


class TestParityLogFootgun:
    def test_boolean_value_becomes_default_path(self, tmp_path):
        # Footgun 2: "1" must NOT become a file literally named '1'.
        c = cfg.config_for_mode("on", parity_log="1", run_dir=str(tmp_path))
        assert c.parity_log_path == str(
            tmp_path / cfg.DEFAULT_PARITY_LOG_NAME
        )

    def test_explicit_path_preserved(self, tmp_path):
        p = str(tmp_path / "custom.jsonl")
        c = cfg.config_for_mode("on", parity_log=p)
        assert c.parity_log_path == p

    def test_default_path_falls_back_to_cwd(self):
        c = cfg.config_for_mode("shadow")
        assert c.parity_log_path == os.path.join(
            ".", cfg.DEFAULT_PARITY_LOG_NAME
        )


class TestEnvBackCompat:
    def test_cut_on_maps_to_on(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        assert cfg.current().mode == "on"

    def test_cut_plus_no_lexical_maps_to_strict(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", "1")
        assert cfg.current().mode == "strict"

    def test_no_lexical_without_cut_warns_and_ignored(
        self, monkeypatch, capsys,
    ):
        # Footgun 1.
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", "1")
        c = cfg.current()
        assert c.mode == "off"
        assert c.lexical_fallback_enabled is True
        assert "ignoring it" in capsys.readouterr().err

    def test_env_parity_log_boolean_uses_default(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_PARITY_LOG", "1")
        assert cfg.current().parity_log_path == os.path.join(
            ".", cfg.DEFAULT_PARITY_LOG_NAME
        )

    def test_env_parity_log_path_preserved(self, monkeypatch):
        monkeypatch.setenv(
            "RAPTOR_SANITIZER_CUT_PARITY_LOG", "/tmp/p.jsonl",
        )
        assert cfg.current().parity_log_path == "/tmp/p.jsonl"


class TestExplicitOverridesEnv:
    def test_configure_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        cfg.configure("off")
        assert cfg.current().mode == "off"
        assert cfg.value_bound_enabled() is False

    def test_reset_restores_env_fallback(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        cfg.configure("off")
        cfg.reset()
        assert cfg.current().mode == "on"


class TestPersistReload:
    def test_persist_then_load_roundtrips(self, tmp_path):
        cfg.configure("strict", run_dir=str(tmp_path))
        path = cfg.persist(str(tmp_path))
        assert path is not None and os.path.isfile(path)
        cfg.reset()
        assert cfg.current().mode == "off"  # reset → env fallback
        loaded = cfg.load_persisted(str(tmp_path), export_env=False)
        assert loaded is not None
        assert loaded.mode == "strict"
        assert cfg.current().mode == "strict"

    def test_persist_noop_without_explicit_config(self, tmp_path):
        # No configure() → nothing to persist.
        assert cfg.persist(str(tmp_path)) is None

    def test_load_absent_is_noop(self, tmp_path):
        assert cfg.load_persisted(str(tmp_path)) is None

    def test_shadow_parity_path_persists(self, tmp_path):
        cfg.configure("shadow", run_dir=str(tmp_path))
        cfg.persist(str(tmp_path))
        cfg.reset()
        loaded = cfg.load_persisted(str(tmp_path), export_env=False)
        assert loaded.parity_log_path == str(
            tmp_path / cfg.DEFAULT_PARITY_LOG_NAME
        )


class TestEnvExport:
    def test_export_sets_canonical_env_for_strict(self, monkeypatch):
        cfg.configure("strict", export_env=True)
        assert os.environ["RAPTOR_SANITIZER_CUT"] == "1"
        assert os.environ["RAPTOR_SANITIZER_CUT_NO_LEXICAL"] == "1"

    def test_export_clears_no_lexical_for_on(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_NO_LEXICAL", "1")
        cfg.configure("on", export_env=True)
        assert os.environ["RAPTOR_SANITIZER_CUT"] == "1"
        assert "RAPTOR_SANITIZER_CUT_NO_LEXICAL" not in os.environ

    def test_exported_env_reconstructs_same_mode(self, monkeypatch, tmp_path):
        # The transport contract: export → a child resolving from env
        # gets the same mode.
        cfg.configure("shadow", run_dir=str(tmp_path), export_env=True)
        cfg.reset()  # simulate a fresh child process
        c = cfg.current()  # resolves from the exported env
        assert c.parity_log_path == str(
            tmp_path / cfg.DEFAULT_PARITY_LOG_NAME
        )


class TestCliPlumbing:
    def _parse(self, argv):
        p = argparse.ArgumentParser()
        cfg.add_cli_arguments(p)
        return p.parse_args(argv)

    def test_flag_absent_leaves_env_fallback(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT", "1")
        args = self._parse([])
        assert cfg.configure_from_args(args) is None
        assert cfg.current().mode == "on"  # env still active

    def test_flag_sets_mode_and_run_dir_default_log(self, tmp_path):
        args = self._parse(["--sanitizer-cut", "shadow"])
        c = cfg.configure_from_args(args, run_dir=str(tmp_path))
        assert c.mode == "shadow"
        assert c.parity_log_path == str(
            tmp_path / cfg.DEFAULT_PARITY_LOG_NAME
        )

    def test_explicit_parity_log_flag(self, tmp_path):
        p = str(tmp_path / "x.jsonl")
        args = self._parse(
            ["--sanitizer-cut", "on", "--sanitizer-cut-parity-log", p],
        )
        c = cfg.configure_from_args(args, run_dir=str(tmp_path))
        assert c.parity_log_path == p

    def test_invalid_choice_rejected(self):
        with pytest.raises(SystemExit):
            self._parse(["--sanitizer-cut", "bogus"])
