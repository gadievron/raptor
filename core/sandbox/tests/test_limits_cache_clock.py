"""Failure-cache retries follow elapsed time despite wall-clock adjustments."""

import math

import pytest

from core.sandbox import preexec, state


class TestLimitsCacheClock:
    @pytest.fixture(autouse=True)
    def isolate(self, tmp_path, monkeypatch):
        self.path = tmp_path / "sandbox.json"
        self.clock = {"monotonic": 100.0, "wall": 1000.0}
        monkeypatch.setattr(preexec, "_CONFIG_PATH", self.path)
        monkeypatch.setattr(state, "_user_limits_cache", None)
        monkeypatch.setattr(state, "_user_limits_cache_decided_at", 0.0)
        monkeypatch.setattr(preexec.time, "monotonic", lambda: self.clock["monotonic"])
        monkeypatch.setattr(preexec.time, "time", lambda: self.clock["wall"])

    @pytest.mark.parametrize("wall_jump", [-86400, 86400])
    def test_corrected_config_retries_at_elapsed_deadline(self, wall_jump):
        assert preexec._load_user_limits() == {}
        assert state._user_limits_cache_decided_at == 100.0
        self.path.write_text('{"cpu_seconds": 7}')
        self.clock["wall"] += wall_jump
        self.clock["monotonic"] += preexec._FAIL_TTL_S - 0.01
        assert preexec._load_user_limits() == {}
        self.clock["monotonic"] = 100.0 + preexec._FAIL_TTL_S
        assert preexec._load_user_limits() == {"cpu_seconds": 7}

    def test_repeated_failures_receive_a_new_elapsed_retry_window(self):
        self.path.write_text("{invalid")
        assert preexec._load_user_limits() == {}
        self.clock["monotonic"] += preexec._FAIL_TTL_S
        assert preexec._load_user_limits() == {}
        assert state._user_limits_cache_decided_at == self.clock["monotonic"]
        self.path.write_text('{"cpu_seconds": 7}')
        self.clock["monotonic"] += 1
        assert preexec._load_user_limits() == {}
        self.clock["monotonic"] += preexec._FAIL_TTL_S
        assert preexec._load_user_limits() == {"cpu_seconds": 7}

    @pytest.mark.parametrize("original", [{}, {"cpu_seconds": 0}])
    def test_successful_empty_and_nonempty_configs_remain_session_cached(self, original):
        import json

        self.path.write_text(json.dumps(original))
        assert preexec._load_user_limits() == original
        assert math.isinf(state._user_limits_cache_decided_at)
        self.path.write_text('{"cpu_seconds": 7}')
        self.clock["monotonic"] = 1e9
        self.clock["wall"] = -1e12
        assert preexec._load_user_limits() == original
