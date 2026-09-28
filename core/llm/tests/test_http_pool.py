"""Tests for the pooled SDK HTTP transport (``core.llm.http_pool``).

httpx's default pool expires idle keepalive connections after 5
seconds — shorter than RAPTOR's typical inter-call gap, so every LLM
call re-established its connection (and, behind chained proxies, paid
CONNECT negotiation per hop). The factory pins a keepalive window
that outlives the gap and gives every SDK the same tunable pool.
"""

from __future__ import annotations

import sys
import time
import types

import httpx
import pytest

from core.llm import http_pool

_KNOB_VARS = (
    "RAPTOR_HTTP_KEEPALIVE_S",
    "RAPTOR_HTTP_MAX_KEEPALIVE",
    "RAPTOR_HTTP_MAX_CONNECTIONS",
    "RAPTOR_HTTP2",
    "RAPTOR_HTTP2_SHARDS",
    "RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD",
    "RAPTOR_HTTP2_SHARD_MAX_AGE_S",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _KNOB_VARS:
        monkeypatch.delenv(var, raising=False)


class TestPoolLimits:

    def test_defaults_outlive_inter_call_gap(self):
        limits = http_pool.pool_limits()
        # The whole point: idle keepalive must comfortably exceed
        # httpx's 5s default, which is shorter than the think-time
        # gap between RAPTOR LLM calls.
        assert limits.keepalive_expiry == 60.0
        assert limits.max_keepalive_connections == 20
        assert limits.max_connections == 100

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP_KEEPALIVE_S", "120")
        monkeypatch.setenv("RAPTOR_HTTP_MAX_KEEPALIVE", "8")
        monkeypatch.setenv("RAPTOR_HTTP_MAX_CONNECTIONS", "16")
        limits = http_pool.pool_limits()
        assert limits.keepalive_expiry == 120.0
        assert limits.max_keepalive_connections == 8
        assert limits.max_connections == 16

    @pytest.mark.parametrize("bad", ["", "abc", "0", "-5", "nan", "inf"])
    def test_invalid_env_falls_back(self, monkeypatch, bad):
        # nan/inf parse as floats and pass the strictly-positive
        # check (nan comparisons are all False; inf is positive) —
        # they must fall back like the unparseable shapes instead of
        # leaking a non-finite expiry into the pool limits.
        monkeypatch.setenv("RAPTOR_HTTP_KEEPALIVE_S", bad)
        limits = http_pool.pool_limits()
        assert limits.keepalive_expiry == 60.0

    @pytest.mark.parametrize("var", [
        "RAPTOR_HTTP_MAX_KEEPALIVE",
        "RAPTOR_HTTP_MAX_CONNECTIONS",
    ])
    @pytest.mark.parametrize("bad", ["nan", "inf"])
    def test_non_finite_count_falls_back_not_crash(
        self, monkeypatch, var, bad,
    ):
        # Pre-guard, these CRASHED: nan/inf passed _env_number's
        # positivity check and int() then raised ValueError /
        # OverflowError out of _env_count — an uncaught exception at
        # every pool build while the variable was set.
        monkeypatch.setenv(var, bad)
        limits = http_pool.pool_limits()
        assert limits.max_keepalive_connections == 20
        assert limits.max_connections == 100

    @pytest.mark.parametrize("var, default", [
        ("RAPTOR_HTTP_MAX_KEEPALIVE", 20),
        ("RAPTOR_HTTP_MAX_CONNECTIONS", 100),
    ])
    def test_fractional_count_below_one_falls_back(
        self, monkeypatch, var, default,
    ):
        # 0.5 passes the strictly-positive check but truncates to 0
        # connections — a pool that stalls every request. Anything
        # that truncates below 1 must fall back to the default.
        monkeypatch.setenv(var, "0.5")
        limits = http_pool.pool_limits()
        assert limits.max_keepalive_connections >= 1
        assert limits.max_connections >= 1
        got = (limits.max_keepalive_connections
               if var == "RAPTOR_HTTP_MAX_KEEPALIVE"
               else limits.max_connections)
        assert got == default

    def test_valid_integer_count_still_honoured(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP_MAX_CONNECTIONS", "8")
        assert http_pool.pool_limits().max_connections == 8


class TestSdkHttpClient:

    def test_returns_httpx_client_with_pool_limits(self):
        client = http_pool.sdk_http_client(30)
        try:
            assert isinstance(client, httpx.Client)
            assert client.timeout.read == 30.0
        finally:
            client.close()

    def test_trust_env_passthrough(self):
        trusted = http_pool.sdk_http_client(10)
        pinned = http_pool.sdk_http_client(10, trust_env=False)
        try:
            assert trusted.trust_env is True
            assert pinned.trust_env is False
        finally:
            trusted.close()
            pinned.close()


class TestHttp2Gate:
    """HTTP/2 is opt-in AND conditional on the h2 stack being
    installed — httpx raises at client construction otherwise."""

    @pytest.fixture(autouse=True)
    def _reset_warn_flag(self, monkeypatch):
        monkeypatch.setattr(http_pool, "_http2_missing_warned", False)

    def test_off_by_default(self):
        assert http_pool.http2_enabled() is False

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
    def test_non_truthy_values_stay_off(self, monkeypatch, value):
        monkeypatch.setenv("RAPTOR_HTTP2", value)
        assert http_pool.http2_enabled() is False

    def test_opted_in_with_h2_installed(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP2", "1")
        monkeypatch.setattr(
            http_pool.importlib.util, "find_spec",
            lambda name: object() if name == "h2" else None,
        )
        assert http_pool.http2_enabled() is True

    def test_opted_in_without_h2_warns_once_and_stays_http1(
        self, monkeypatch, caplog,
    ):
        monkeypatch.setenv("RAPTOR_HTTP2", "1")
        monkeypatch.setattr(
            http_pool.importlib.util, "find_spec", lambda name: None,
        )
        with caplog.at_level("WARNING", logger="core.llm.http_pool"):
            assert http_pool.http2_enabled() is False
            assert http_pool.http2_enabled() is False
        warnings = [r for r in caplog.records if "h2" in r.getMessage()]
        assert len(warnings) == 1

    def test_client_construction_honours_gate(self, monkeypatch):
        """With the gate closed the client must be constructible even
        when h2 is absent — the whole point of gating."""
        monkeypatch.setenv("RAPTOR_HTTP2", "1")
        monkeypatch.setattr(
            http_pool.importlib.util, "find_spec", lambda name: None,
        )
        client = http_pool.sdk_http_client(10)
        client.close()


class TestProviderWiring:
    """The provider constructors must hand the SDK the pooled client
    on their env-direct (non-dispatcher) paths."""

    @pytest.fixture(autouse=True)
    def _no_dispatcher(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)

    def _spy_factory(self, monkeypatch):
        built = []
        real = http_pool.sdk_http_client

        def spy(timeout, **kwargs):
            client = real(timeout, **kwargs)
            built.append((timeout, kwargs, client))
            return client

        monkeypatch.setattr(http_pool, "sdk_http_client", spy)
        return built

    def test_anthropic_direct_uses_pooled_client(self, monkeypatch):
        anthropic_mod = pytest.importorskip("anthropic")
        del anthropic_mod
        from core.llm.config import ModelConfig
        from core.llm.providers import AnthropicProvider

        built = self._spy_factory(monkeypatch)
        provider = AnthropicProvider(ModelConfig(
            provider="anthropic", model_name="claude-test",
            api_key="k", timeout=33,
        ))
        assert len(built) == 1
        timeout, _, client = built[0]
        assert timeout == 33
        assert provider.client._client is client

    def test_openai_remote_keeps_trust_env(self, monkeypatch):
        pytest.importorskip("openai")
        from core.llm.config import ModelConfig
        from core.llm.providers import OpenAICompatibleProvider

        built = self._spy_factory(monkeypatch)
        OpenAICompatibleProvider(ModelConfig(
            provider="openai", model_name="gpt-test",
            api_key="k", timeout=20,
        ))
        assert len(built) == 1
        _, kwargs, client = built[0]
        assert kwargs == {"trust_env": True}
        assert client.trust_env is True

    def test_openai_loopback_pins_trust_env_false(self, monkeypatch):
        pytest.importorskip("openai")
        from core.llm.config import ModelConfig
        from core.llm.providers import OpenAICompatibleProvider

        built = self._spy_factory(monkeypatch)
        OpenAICompatibleProvider(ModelConfig(
            provider="ollama", model_name="llama-test",
            api_base="http://localhost:11434/v1", timeout=20,
        ))
        assert len(built) == 1
        _, kwargs, client = built[0]
        assert kwargs == {"trust_env": False}
        assert client.trust_env is False


class TestGeminiHttpOptions:
    """Feature detection for google-genai's httpx_client injection
    point — pooled when the field exists, SDK-default otherwise."""

    def test_none_when_sdk_absent(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "google", None)
        from core.llm.providers import _pooled_gemini_http_options
        assert _pooled_gemini_http_options(30) is None

    def _stub_genai_types(self, monkeypatch, fields):
        class HttpOptions:
            model_fields = dict.fromkeys(fields)

            def __init__(self, **kwargs):
                self.kwargs = kwargs

        genai_types = types.ModuleType("google.genai.types")
        genai_types.HttpOptions = HttpOptions
        genai = types.ModuleType("google.genai")
        genai.types = genai_types
        google = types.ModuleType("google")
        google.genai = genai
        monkeypatch.setitem(sys.modules, "google", google)
        monkeypatch.setitem(sys.modules, "google.genai", genai)
        monkeypatch.setitem(sys.modules, "google.genai.types", genai_types)
        return HttpOptions

    def test_none_when_field_missing(self, monkeypatch):
        self._stub_genai_types(monkeypatch, fields=("base_url",))
        from core.llm.providers import _pooled_gemini_http_options
        assert _pooled_gemini_http_options(30) is None

    def test_pooled_client_when_field_present(self, monkeypatch):
        HttpOptions = self._stub_genai_types(
            monkeypatch, fields=("base_url", "httpx_client"),
        )
        from core.llm.providers import _pooled_gemini_http_options
        opts = _pooled_gemini_http_options(30)
        assert isinstance(opts, HttpOptions)
        client = opts.kwargs["httpx_client"]
        try:
            assert isinstance(client, httpx.Client)
        finally:
            client.close()


class TestUpstreamShardCount:
    """The forwarding-leg shard knob: default 4 under HTTP/2 (one
    multiplexed connection otherwise carries every concurrent call —
    a single point of failure), 1 with HTTP/2 off (HTTP/1.1 pools
    per-connection already; extra clients are pure overhead)."""

    def _force_h2(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP2", "1")
        monkeypatch.setattr(
            http_pool.importlib.util, "find_spec",
            lambda name: object() if name == "h2" else None,
        )

    def test_default_one_when_http2_off(self):
        assert http_pool.upstream_shard_count() == 1

    def test_default_four_under_http2(self, monkeypatch):
        self._force_h2(monkeypatch)
        assert http_pool.upstream_shard_count() == 4

    def test_explicit_count_honoured_in_either_mode(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP2_SHARDS", "6")
        assert http_pool.upstream_shard_count() == 6
        self._force_h2(monkeypatch)
        assert http_pool.upstream_shard_count() == 6

    def test_garbage_warns_and_falls_back(self, monkeypatch, caplog):
        self._force_h2(monkeypatch)
        monkeypatch.setenv("RAPTOR_HTTP2_SHARDS", "lots")
        with caplog.at_level("WARNING", logger="core.llm.http_pool"):
            assert http_pool.upstream_shard_count() == 4
        assert any(
            "RAPTOR_HTTP2_SHARDS" in r.getMessage() for r in caplog.records
        )

    @pytest.mark.parametrize("bad", ["0", "-2", "0.5"])
    def test_floor_at_one_shard(self, monkeypatch, bad):
        # A zero-shard pool could never carry a request; anything
        # truncating below 1 falls back to the mode default.
        monkeypatch.setenv("RAPTOR_HTTP2_SHARDS", bad)
        assert http_pool.upstream_shard_count() == 1
        self._force_h2(monkeypatch)
        assert http_pool.upstream_shard_count() == 4

    @pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
    def test_non_finite_falls_back_not_crash(self, monkeypatch, bad):
        # nan/inf parse as floats and pass the strictly-positive
        # check (every nan comparison is False; inf is positive), and
        # pre-guard int() then raised ValueError/OverflowError out of
        # the resolver — an uncaught crash on the relay hot path that
        # failed every forwarded request while the variable was set.
        # Non-finite must warn + fall back like any other garbage.
        monkeypatch.setenv("RAPTOR_HTTP2_SHARDS", bad)
        assert http_pool.upstream_shard_count() == 1
        self._force_h2(monkeypatch)
        assert http_pool.upstream_shard_count() == 4

    def test_default_bounds_both_directions(self):
        # Direction 1: below 2 shards there is no blast-radius
        # reduction at all — the pool degenerates to the single
        # multiplexed connection the shards exist to avoid.
        assert http_pool._DEFAULT_HTTP2_SHARDS >= 2
        # Direction 2: each shard is an independent connection paying
        # its own CONNECT chain + TLS handshake; past a handful the
        # collateral reduction plateaus while the setup overhead
        # keeps growing.
        assert http_pool._DEFAULT_HTTP2_SHARDS <= 8


class TestClientShards:
    """Least-in-flight shard selection over independent clients."""

    def _shards(self, count):
        return http_pool.ClientShards(
            lambda: httpx.Client(timeout=5.0), count,
        )

    def test_rejects_zero_shards(self):
        with pytest.raises(ValueError):
            self._shards(0)

    def test_builder_called_once_per_shard(self):
        built = []

        def build():
            client = httpx.Client(timeout=5.0)
            built.append(client)
            return client

        shards = http_pool.ClientShards(build, 3)
        try:
            assert len(shards) == 3
            assert shards.clients == tuple(built)
            assert len({id(c) for c in built}) == 3
        finally:
            shards.close()

    def test_least_loaded_selection(self):
        shards = self._shards(2)
        try:
            _, first = shards.acquire()
            _, second = shards.acquire()
            # Two concurrent holds land on different shards.
            assert {first, second} == {0, 1}
            assert shards.in_flight == (1, 1)
            _, third = shards.acquire()
            assert shards.in_flight in ((2, 1), (1, 2))
            assert third in (0, 1)
        finally:
            shards.close()

    def test_release_rebalances(self):
        shards = self._shards(2)
        try:
            _, a = shards.acquire()
            _, b = shards.acquire()
            shards.release(a)
            assert shards.in_flight[a] == 0
            _, again = shards.acquire()
            # The freed shard is the least loaded — it must be reused
            # before stacking a second hold on the busy one.
            assert again == a
            del b
        finally:
            shards.close()

    def test_release_never_goes_negative(self):
        shards = self._shards(1)
        try:
            _, index = shards.acquire()
            shards.release(index)
            shards.release(index)  # double release: clamp, don't skew
            assert shards.in_flight == (0,)
        finally:
            shards.close()

    def test_single_shard_degenerate(self):
        shards = self._shards(1)
        try:
            client_a, index_a = shards.acquire()
            client_b, index_b = shards.acquire()
            assert index_a == index_b == 0
            assert client_a is client_b
        finally:
            shards.close()

    def test_close_is_idempotent_and_closes_all(self):
        shards = self._shards(2)
        clients = shards.clients
        shards.close()
        shards.close()  # second call is a no-op, not an error
        assert all(client.is_closed for client in clients)
        with pytest.raises(RuntimeError):
            shards.acquire()


class TestShardLifecycleKnobs:
    """The drain-and-rebuild threshold and the proactive rotation
    age, validated like every other pool knob (warn + fallback)."""

    def _force_h2(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_HTTP2", "1")
        monkeypatch.setattr(
            http_pool.importlib.util, "find_spec",
            lambda name: object() if name == "h2" else None,
        )

    def test_failure_threshold_default_and_override(self, monkeypatch):
        assert (
            http_pool.shard_failure_threshold()
            == http_pool._DEFAULT_SHARD_FAIL_THRESHOLD
        )
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", "5")
        assert http_pool.shard_failure_threshold() == 5

    @pytest.mark.parametrize("bad", ["never", "0", "-1", "0.5"])
    def test_failure_threshold_invalid_falls_back(self, monkeypatch, bad):
        # Floor at 1: a zero threshold would drain a shard that has
        # never failed.
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", bad)
        assert (
            http_pool.shard_failure_threshold()
            == http_pool._DEFAULT_SHARD_FAIL_THRESHOLD
        )

    @pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
    def test_failure_threshold_non_finite_falls_back_not_crash(
        self, monkeypatch, bad,
    ):
        # Pre-guard, nan/inf passed _env_number's positivity check
        # and int() then raised ValueError/OverflowError out of
        # _env_count — an uncaught crash at pool build on the relay
        # hot path. Non-finite must warn + fall back like any other
        # garbage.
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_FAIL_THRESHOLD", bad)
        assert (
            http_pool.shard_failure_threshold()
            == http_pool._DEFAULT_SHARD_FAIL_THRESHOLD
        )

    def test_failure_threshold_default_bounds_both_directions(self):
        # Direction 1: at 1, every isolated transport blip (ordinary
        # keepalive churn after an idle gap) rebuilds the shard —
        # constant CONNECT + TLS churn for connections that were
        # never sick.
        assert http_pool._DEFAULT_SHARD_FAIL_THRESHOLD >= 2
        # Direction 2: every extra strike required is another relay
        # aborted on a client already known to be failing.
        assert http_pool._DEFAULT_SHARD_FAIL_THRESHOLD <= 5

    def test_max_age_off_without_http2(self):
        # HTTP/1.1 pools manage per-connection lifetime already;
        # rotating whole clients there churns for nothing.
        assert http_pool.shard_max_age_s() is None

    def test_max_age_default_and_override_under_http2(self, monkeypatch):
        self._force_h2(monkeypatch)
        assert (
            http_pool.shard_max_age_s()
            == http_pool._DEFAULT_SHARD_MAX_AGE_S
        )
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_MAX_AGE_S", "900")
        assert http_pool.shard_max_age_s() == 900.0

    def test_max_age_below_floor_warns_and_falls_back(
        self, monkeypatch, caplog,
    ):
        self._force_h2(monkeypatch)
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_MAX_AGE_S", "5")
        with caplog.at_level("WARNING", logger="core.llm.http_pool"):
            assert (
                http_pool.shard_max_age_s()
                == http_pool._DEFAULT_SHARD_MAX_AGE_S
            )
        assert any(
            "RAPTOR_HTTP2_SHARD_MAX_AGE_S" in r.getMessage()
            for r in caplog.records
        )

    def test_max_age_garbage_falls_back(self, monkeypatch):
        self._force_h2(monkeypatch)
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_MAX_AGE_S", "forever")
        assert (
            http_pool.shard_max_age_s()
            == http_pool._DEFAULT_SHARD_MAX_AGE_S
        )

    @pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
    def test_max_age_non_finite_falls_back(self, monkeypatch, bad):
        # nan sails past both the positivity check and the floor
        # comparison (every nan comparison is False) and would leak
        # into the age check, where ``now - born >= nan`` is always
        # False — rotation silently never fires; inf disables it the
        # same way. Both must fall back to the (finite) default.
        self._force_h2(monkeypatch)
        monkeypatch.setenv("RAPTOR_HTTP2_SHARD_MAX_AGE_S", bad)
        assert (
            http_pool.shard_max_age_s()
            == http_pool._DEFAULT_SHARD_MAX_AGE_S
        )

    def test_max_age_default_bounds_both_directions(self):
        # Direction 1: rotating faster than a few minutes churns
        # handshakes and degenerates toward per-request clients — the
        # pool stops pooling.
        assert http_pool._DEFAULT_SHARD_MAX_AGE_S >= 600.0
        # Direction 2: middleboxes impose hard lifetimes on
        # long-lived tunnels under load; a rotation age past an hour
        # loses that race and protects nothing.
        assert http_pool._DEFAULT_SHARD_MAX_AGE_S <= 3600.0
        assert http_pool._SHARD_MAX_AGE_FLOOR_S >= 60.0


class TestClientShardsLifecycle:
    """Drain-shaped repair: sick or overdue shards stop being
    selected, are never closed with live holds, and are replaced
    fresh the moment they idle."""

    def _shards(self, count, **kwargs):
        return http_pool.ClientShards(
            lambda: httpx.Client(timeout=5.0), count, **kwargs,
        )

    def test_failures_below_threshold_keep_the_shard(self):
        shards = self._shards(1, failure_threshold=2)
        try:
            client, index = shards.acquire()
            shards.report_failure(index)
            shards.release(index)
            again, _ = shards.acquire()
            assert again is client
            assert not client.is_closed
        finally:
            shards.close()

    def test_threshold_drains_and_replaces_when_idle(self):
        shards = self._shards(1, failure_threshold=2)
        try:
            client, index = shards.acquire()
            shards.report_failure(index)
            shards.release(index)
            _, index = shards.acquire()
            shards.report_failure(index)  # second consecutive strike
            shards.release(index)
            # Retired at idle: old client closed, slot refilled fresh.
            assert client.is_closed
            replacement, _ = shards.acquire()
            assert replacement is not client
            assert not replacement.is_closed
            assert len(shards) == 1
        finally:
            shards.close()

    def test_success_resets_the_counter(self):
        shards = self._shards(1, failure_threshold=2)
        try:
            client, index = shards.acquire()
            shards.report_failure(index)
            shards.report_success(index)  # clean completion in between
            shards.report_failure(index)
            shards.release(index)
            # Never two CONSECUTIVE failures — the shard stays.
            again, _ = shards.acquire()
            assert again is client
            assert not client.is_closed
        finally:
            shards.close()

    def test_never_rebuilds_with_live_holds(self):
        # The drain shape: a shard at the threshold stops being
        # selected but its client is NOT closed under an in-flight
        # stream — closing would abort the very relay it still
        # carries.
        shards = self._shards(1, failure_threshold=1)
        try:
            client, first = shards.acquire()
            _, second = shards.acquire()  # second hold, same shard
            assert second == first
            shards.report_failure(first)  # threshold hit: draining
            shards.release(first)
            assert not client.is_closed  # one hold still live
            shards.release(second)
            assert client.is_closed  # last hold gone: retired
        finally:
            shards.close()

    def test_age_rotation_replaces_idle_shard(self):
        shards = self._shards(1, max_age_s=0.05)
        try:
            client, index = shards.acquire()
            shards.release(index)
            time.sleep(0.06)
            replacement, index = shards.acquire()
            assert replacement is not client
            assert client.is_closed
            shards.release(index)
            # The replacement's birth clock is fresh — it must not
            # rotate again immediately.
            again, index = shards.acquire()
            assert again is replacement
            shards.release(index)
        finally:
            shards.close()

    def test_no_rotation_when_disabled(self):
        shards = self._shards(1)  # max_age_s=None
        try:
            client, index = shards.acquire()
            shards.release(index)
            time.sleep(0.06)
            again, index = shards.acquire()
            assert again is client
            shards.release(index)
        finally:
            shards.close()

    def test_all_draining_provisions_fresh_instead_of_blocking(self):
        # Invariant: at least one selectable shard. The only shard is
        # draining but still held — acquire must hand out a FRESH
        # client immediately, never block on the drain and never
        # route onto the condemned connection.
        shards = self._shards(1, failure_threshold=1)
        try:
            condemned, first = shards.acquire()
            shards.report_failure(first)  # draining, hold still live
            fresh, second = shards.acquire()
            assert second != first
            assert fresh is not condemned
            assert not fresh.is_closed
            shards.release(first)
            # The drained slot retires; the pool converges back to
            # its target size with only the fresh shard live.
            assert condemned.is_closed
            assert len(shards) == 1
            assert shards.clients == (fresh,)
            shards.release(second)
            assert shards.in_flight == (0,)
        finally:
            shards.close()


class TestNegotiatedProtocolTelemetry:
    """RAPTOR_HTTP2 requested HTTP/2, but nothing recorded what ALPN
    actually negotiated — h2 service could not be proven from run
    artifacts. Every pooled client installs a response hook that
    feeds a process-wide protocol registry the telemetry reads."""

    @pytest.fixture(autouse=True)
    def _fresh_registry(self, monkeypatch):
        monkeypatch.setattr(http_pool, "_last_http_version", None)
        monkeypatch.setattr(http_pool, "_protocol_counts", {})

    def test_note_normalizes_h1_h2(self):
        assert http_pool.last_http_version() is None
        http_pool.note_http_version("HTTP/2")
        assert http_pool.last_http_version() == "h2"
        http_pool.note_http_version("HTTP/1.1")
        assert http_pool.last_http_version() == "h1"
        assert http_pool.protocol_counts() == {"h2": 1, "h1": 1}

    def test_unknown_version_kept_lowercased(self):
        http_pool.note_http_version("HTTP/3")
        assert http_pool.last_http_version() == "http/3"
        http_pool.note_http_version("")
        assert http_pool.last_http_version() == "unknown"

    def test_sdk_client_installs_response_hook(self):
        client = http_pool.sdk_http_client(timeout=5.0)
        try:
            assert http_pool._response_hook in client.event_hooks["response"]
        finally:
            client.close()

    def test_response_feeds_registry(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, extensions={"http_version": b"HTTP/1.1"},
            ),
        )
        with httpx.Client(
            transport=transport,
            event_hooks=http_pool.response_event_hooks(),
        ) as client:
            client.get("http://unit.test/x")
        assert http_pool.last_http_version() == "h1"
        assert http_pool.protocol_counts() == {"h1": 1}

    def test_client_emit_sites_carry_http_version(self):
        """Every per-attempt telemetry emit in the LLM client attaches
        the negotiated protocol (source-level wiring check: 2 ok sites
        + 2 attempt_failed sites)."""
        from pathlib import Path

        import core.llm.client as client_mod

        src = Path(client_mod.__file__).read_text()
        assert src.count("http_version=_transport_http_version()") == 4

    def test_transport_http_version_helper(self):
        from core.llm.client import _transport_http_version

        assert _transport_http_version() is None
        http_pool.note_http_version("HTTP/2")
        assert _transport_http_version() == "h2"
