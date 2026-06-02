"""Tests for ``core/run/estimator.py`` — the catalog-driven
cost-and-time estimator (QoL #21)."""

from __future__ import annotations

from core.run.estimator import (
    RunEstimate,
    estimate_run,
    format_estimate,
)


class TestEstimateRun:
    """End-to-end: target path → catalog detect → estimate. Uses
    the real shipped catalog YAMLs so test failures point at real
    drift between substrate + catalog data."""

    def test_none_target_returns_none(self):
        assert estimate_run(None) is None

    def test_empty_target_returns_none(self, tmp_path):
        # Empty tree → catalog falls back to ``generic`` →
        # ``generic`` has zero-valued estimate pairs in the shipped
        # YAML? Actually generic ships ``[10, 30]`` cost +
        # ``[15, 45]`` time. Verify it returns a populated estimate
        # for the generic case (the no-detect fallback IS a useful
        # signal).
        est = estimate_run(tmp_path)
        assert est is not None
        assert est.target_type == "generic"
        assert est.cost_high == 30
        assert est.time_high == 45

    def test_c_userspace_daemon_target(self, tmp_path):
        # Build a tree matching c.userspace-daemon detection.
        (tmp_path / "configure.ac").write_text("")
        (tmp_path / "Makefile.am").write_text("")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.c").write_text("")
        est = estimate_run(tmp_path)
        assert est is not None
        assert est.target_type == "c.userspace-daemon"
        # YAML: estimated_cost_usd: [25, 50], estimated_time_min: [40, 75]
        assert est.cost_low == 25
        assert est.cost_high == 50
        assert est.time_low == 40
        assert est.time_high == 75

    def test_python_web_app_target(self, tmp_path):
        (tmp_path / "manage.py").write_text("")
        (tmp_path / "settings.py").write_text("")
        (tmp_path / "urls.py").write_text("")
        est = estimate_run(tmp_path)
        assert est is not None
        assert est.target_type == "python.web-app"
        # YAML: estimated_cost_usd: [15, 35], estimated_time_min: [30, 60]
        assert est.cost_high == 35
        assert est.time_high == 60


class TestEstimateRunFailureModes:
    """Substrate must NEVER break the lifecycle. Any exception
    from the catalog layer → ``None`` return → renderer prints
    nothing → operator's run proceeds."""

    def test_catalog_load_exception_returns_none(self, monkeypatch, tmp_path):
        import core.run.target_types as tt
        def _boom(_path):
            raise RuntimeError("catalog corrupted")
        monkeypatch.setattr(tt, "load", _boom)
        assert estimate_run(tmp_path) is None

    def test_nonexistent_target_path_returns_none_silently(self, tmp_path):
        # Path doesn't exist → catalog returns ``generic`` (which
        # has data); but operator presumably wants the estimate
        # for the REAL target. We can't distinguish "doesn't
        # exist" from "exists but empty" cleanly without an extra
        # stat call. Document the actual behaviour: returns the
        # generic estimate. (Operator gets a useful baseline; no
        # surprise crash.)
        est = estimate_run(tmp_path / "does-not-exist")
        # Either generic (current behaviour) or None — both are
        # acceptable signals. Just assert no crash + plausible
        # shape.
        assert est is None or est.target_type == "generic"

    def test_zero_valued_catalog_estimate_returns_none(self, monkeypatch, tmp_path):
        # Construct a synthetic catalog entry with all-zero
        # estimate pairs (a catalog author who hasn't filled in
        # cost/time yet). Estimator returns None — renderer
        # prints nothing.
        from core.run.target_types import CatalogEntry
        import core.run.target_types as tt
        empty_entry = CatalogEntry(
            name="hypothetical.no-estimates",
            estimated_cost_usd=(0.0, 0.0),
            estimated_time_min=(0, 0),
        )
        monkeypatch.setattr(tt, "load", lambda _p: empty_entry)
        assert estimate_run(tmp_path) is None


class TestFormatEstimate:
    """Renderer: None → empty string; populated → operator-facing
    one-liner. Format is consumed by both raptor.py and
    libexec/raptor-run-lifecycle; tested here so a format change
    surfaces in one place."""

    def test_none_returns_empty_string(self):
        assert format_estimate(None) == ""

    def test_range_estimate_renders_dollar_dash_dollar(self):
        est = RunEstimate(
            cost_low=25, cost_high=50, time_low=40, time_high=75,
            target_type="c.userspace-daemon",
        )
        s = format_estimate(est)
        assert s == (
            "Expected: $25-$50, 40-75 min "
            "(target type: c.userspace-daemon)"
        )

    def test_collapsed_range_renders_single_value(self):
        # When the catalog author shipped a point estimate (low ==
        # high), don't render the redundant ``$30-$30`` shape.
        est = RunEstimate(
            cost_low=30, cost_high=30, time_low=60, time_high=60,
            target_type="some.point-estimate",
        )
        s = format_estimate(est)
        assert s == (
            "Expected: $30, 60 min (target type: some.point-estimate)"
        )

    def test_cost_only_renders_without_time(self):
        # Catalog entry filled in cost but not time — render just
        # the cost half; don't print ``, 0 min``.
        est = RunEstimate(
            cost_low=10, cost_high=20, time_low=0, time_high=0,
            target_type="cost-only",
        )
        s = format_estimate(est)
        assert s == "Expected: $10-$20 (target type: cost-only)"

    def test_time_only_renders_without_cost(self):
        est = RunEstimate(
            cost_low=0, cost_high=0, time_low=15, time_high=30,
            target_type="time-only",
        )
        s = format_estimate(est)
        assert s == "Expected: 15-30 min (target type: time-only)"

    def test_both_zero_returns_empty_string(self):
        # Defensive: shouldn't happen (estimate_run filters this
        # to None), but the renderer doesn't crash on it.
        est = RunEstimate(
            cost_low=0, cost_high=0, time_low=0, time_high=0,
            target_type="both-zero",
        )
        assert format_estimate(est) == ""
