"""Chunked differential parameter mining (no network)."""

from __future__ import annotations

from types import SimpleNamespace

from packages.web.discovery.param_mining import (
    DEFAULT_PARAM_SEEDS,
    ParamMiningResult,
    mine_parameters,
)


class _StubClient:
    """Deterministic server double: responds differently when any
    'responsive' parameter is present in the probe."""

    def __init__(self, responsive: set[str], unstable: bool = False):
        self.responsive = responsive
        self.unstable = unstable
        self.requests = 0

    def get(self, url: str, params: dict | None = None):
        self.requests += 1
        params = params or {}
        if self.unstable:
            # Every response differs in length.
            return SimpleNamespace(status_code=200, content=b"x" * self.requests)
        if any(name in self.responsive for name in params):
            return SimpleNamespace(status_code=200, content=b"different response")
        return SimpleNamespace(status_code=200, content=b"baseline")


def test_mining_isolates_responsive_parameters_by_bisection():
    client = _StubClient(responsive={"debug", "redirect"})

    result = mine_parameters(client, "https://example.test/app")

    assert sorted(result.discovered) == ["debug", "redirect"]
    assert result.stable is True
    # Chunking + bisection: far fewer requests than one per candidate.
    assert result.requests_used < len(DEFAULT_PARAM_SEEDS) / 2


def test_unstable_target_refuses_to_mine():
    client = _StubClient(responsive={"debug"}, unstable=True)

    result = mine_parameters(client, "https://example.test/app")

    assert result.stable is False
    assert result.discovered == []
    assert result.requests_used <= 2


def test_known_parameters_are_excluded():
    client = _StubClient(responsive={"debug"})

    result = mine_parameters(
        client, "https://example.test/app", known={"debug"},
    )

    assert result.discovered == []


def test_budget_cap_is_honoured():
    client = _StubClient(responsive=set(DEFAULT_PARAM_SEEDS))

    result = mine_parameters(
        client, "https://example.test/app", max_requests=5,
    )

    assert result.requests_used <= 5
    assert result.exhausted_budget is True


def test_probe_failure_degrades_to_no_findings():
    class _Failing(_StubClient):
        def get(self, url, params=None):
            raise OSError("boom")

    result = mine_parameters(
        _Failing(responsive=set()), "https://example.test/app",
    )

    assert isinstance(result, ParamMiningResult)
    assert result.stable is False
    assert result.discovered == []
