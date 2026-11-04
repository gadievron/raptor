"""Operator resource-limit config is read from one bounded descriptor."""

import math
import os
from unittest.mock import Mock

import pytest

from core.sandbox import preexec, state
from core.security import capped_read


class TestLimitsConfigIO:
    @pytest.fixture(autouse=True)
    def isolated_config(self, tmp_path, monkeypatch):
        self.path = tmp_path / "sandbox.json"
        monkeypatch.setattr(preexec, "_CONFIG_PATH", self.path)
        monkeypatch.setattr(state, "_user_limits_cache", None)
        monkeypatch.setattr(state, "_user_limits_cache_decided_at", 0.0)

    def test_operator_symlink_still_loads(self, tmp_path):
        actual = tmp_path / "actual.json"
        actual.write_text('{"memory_mb": 128, "cpu_seconds": 0}')
        self.path.symlink_to(actual)
        assert preexec._load_user_limits() == {"memory_mb": 128, "cpu_seconds": 0}

    def test_file_replaced_after_stat_still_reads_pinned_content(self, monkeypatch):
        self.path.write_text('{"memory_mb": 128}')
        real_fstat = os.fstat
        replaced = []

        def replace_after_stat(fd):
            metadata = real_fstat(fd)
            self.path.unlink()
            self.path.mkdir()
            replaced.append(True)
            return metadata

        monkeypatch.setattr(capped_read.os, "fstat", replace_after_stat)
        assert preexec._load_user_limits() == {"memory_mb": 128}
        assert replaced == [True]
        assert self.path.is_dir()

    def test_growth_past_cap_is_refused(self, monkeypatch):
        self.path.write_text('{"memory_mb": 128}')
        real_fstat = os.fstat

        def grow(fd):
            metadata = real_fstat(fd)
            with self.path.open("ab") as stream:
                stream.write(b" " * (64 * 1024))
            return metadata

        monkeypatch.setattr(capped_read.os, "fstat", grow)
        assert preexec._load_user_limits() == {}
        assert not math.isinf(state._user_limits_cache_decided_at)

    @pytest.mark.parametrize("failure_type", [ValueError, RecursionError])
    def test_decoder_errors_fall_back_and_remain_retryable(self, monkeypatch, failure_type):
        self.path.write_text('{"memory_mb": 128}')
        with monkeypatch.context() as patch:
            patch.setattr(preexec.json, "loads", Mock(side_effect=failure_type("bad JSON")))
            assert preexec._load_user_limits() == {}
        assert not math.isinf(state._user_limits_cache_decided_at)
        state._user_limits_cache_decided_at = 0.0
        assert preexec._load_user_limits() == {"memory_mb": 128}

    def test_oversized_config_is_rejected_before_json_parsing(self, monkeypatch):
        self.path.write_bytes(b" " * (64 * 1024 + 1))
        loads = Mock(side_effect=AssertionError("oversized config must not be parsed"))
        monkeypatch.setattr(preexec.json, "loads", loads)
        assert preexec._load_user_limits() == {}
        loads.assert_not_called()

    def test_stat_failure_falls_back(self, monkeypatch):
        self.path.write_text('{"memory_mb": 128}')
        monkeypatch.setattr(capped_read.os, "fstat", Mock(side_effect=OSError("stat failed")))
        assert preexec._load_user_limits() == {}

    def test_missing_config_is_silent(self, caplog):
        assert preexec._load_user_limits() == {}
        assert "could not parse" not in caplog.text

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFO support")
    @pytest.mark.parametrize("symlink", [False, True])
    def test_fifo_config_is_refused(self, tmp_path, symlink):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo, 0o600)
        if symlink:
            self.path.symlink_to(fifo)
        else:
            fifo.rename(self.path)
        assert preexec._load_user_limits() == {}
