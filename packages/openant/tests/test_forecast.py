"""Tests for the OpenAnt pre-spend cost forecast estimator."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

from packages.openant.forecast import (
    forecast_scan_cost,
    format_forecast_line,
    unit_sizes_from_dataset,
)

_PRICED = ("core.llm.model_data.price_for", lambda *_a, **_k: (3.0, 15.0))
_UNPRICED = ("core.llm.model_data.price_for", lambda *_a, **_k: (0.0, 0.0))


def _forecast(enhance=None, analyze=None, verify=False, **kw):
    return forecast_scan_cost(
        enhance_sizes=enhance if enhance is not None else [],
        analyze_sizes=analyze if analyze is not None else [],
        verify=verify,
        model_id=kw.pop("model_id", "test-model-a"),
        **kw,
    )


class TestUnitSizes(unittest.TestCase):
    def test_sizes_include_code_and_dependencies(self):
        dataset = {"units": [
            {"id": "a.py:f", "code": {"primary_code": "x" * 100,
                                      "dependencies": {"d1": "y" * 50}}},
            {"id": "a.py:g", "code": {"primary_code": "x" * 10}},
        ]}
        sizes = unit_sizes_from_dataset(dataset)
        self.assertEqual(sizes, {"a.py:f": 150, "a.py:g": 10})

    def test_hostile_shapes_degrade_to_zero_not_crash(self):
        dataset = {"units": [
            {"id": "ok", "code": "not-a-dict"},
            {"id": "deps-bad", "code": {"primary_code": None,
                                        "dependencies": ["x"]}},
            {"id": ""},           # empty id dropped
            {"no_id": True},      # missing id dropped
            "bare-string",        # non-dict unit dropped
            {"id": 7},            # non-string id dropped
        ]}
        sizes = unit_sizes_from_dataset(dataset)
        self.assertEqual(sizes, {"ok": 0, "deps-bad": 0})

    def test_non_dict_dataset_is_empty(self):
        self.assertEqual(unit_sizes_from_dataset([]), {})
        self.assertEqual(unit_sizes_from_dataset({"units": "nope"}), {})


class TestForecastDirections(unittest.TestCase):
    """Two-direction tests: the estimate must move WITH the census."""

    def test_more_units_cost_more(self):
        with patch(*_PRICED):
            small = _forecast(enhance=[1000] * 5, analyze=[1000] * 5)
            large = _forecast(enhance=[1000] * 50, analyze=[1000] * 50)
        for key in ("usd_low", "usd_central", "usd_high",
                    "input_tokens_central"):
            self.assertGreater(large[key], small[key], key)

    def test_bigger_units_cost_more(self):
        with patch(*_PRICED):
            small = _forecast(enhance=[500] * 10, analyze=[500] * 10)
            large = _forecast(enhance=[40_000] * 10, analyze=[40_000] * 10)
        self.assertGreater(large["usd_central"], small["usd_central"])

    def test_fewer_remaining_units_cost_less(self):
        # The resume direction: a remainder census shrinks the forecast.
        with patch(*_PRICED):
            full = _forecast(enhance=[2000] * 20, analyze=[2000] * 20)
            remainder = _forecast(enhance=[], analyze=[2000] * 6)
        self.assertLess(remainder["usd_central"], full["usd_central"])
        self.assertEqual(remainder["units"], {"enhance": 0, "analyze": 6})

    def test_empty_census_leaves_only_app_context(self):
        with patch(*_PRICED):
            fc = _forecast(enhance=[], analyze=[])
        self.assertEqual(fc["units"], {"enhance": 0, "analyze": 0})
        self.assertEqual(fc["phases"]["enhance"]["input_tokens"], 0)
        self.assertEqual(fc["phases"]["analyze"]["input_tokens"], 0)
        self.assertGreater(fc["phases"]["app_context"]["input_tokens"], 0)

    def test_enhance_char_cap_saturates(self):
        # The per-iteration regression caps its size term: a unit far
        # past the prompt cap must not forecast unboundedly.
        with patch(*_PRICED):
            at_cap = _forecast(enhance=[60_000], analyze=[])
            past_cap = _forecast(enhance=[600_000], analyze=[])
        self.assertEqual(at_cap["phases"]["enhance"]["input_tokens"],
                         past_cap["phases"]["enhance"]["input_tokens"])


class TestForecastShape(unittest.TestCase):
    def test_range_ordering(self):
        with patch(*_PRICED):
            fc = _forecast(enhance=[3000] * 10, analyze=[3000] * 10)
        self.assertLess(fc["usd_low"], fc["usd_central"])
        self.assertLess(fc["usd_central"], fc["usd_high"])
        self.assertLess(fc["input_tokens_low"], fc["input_tokens_central"])
        self.assertLess(fc["input_tokens_central"], fc["input_tokens_high"])

    def test_verify_is_noted_never_priced(self):
        with patch(*_PRICED):
            plain = _forecast(enhance=[3000] * 10, analyze=[3000] * 10)
            with_verify = _forecast(enhance=[3000] * 10,
                                    analyze=[3000] * 10, verify=True)
        self.assertFalse(plain["verify_enabled"])
        self.assertTrue(with_verify["verify_enabled"])
        # No invented Stage-2 coefficient: the USD figures are equal.
        self.assertEqual(plain["usd_central"], with_verify["usd_central"])
        self.assertIn("uncalibrated", format_forecast_line(with_verify))
        self.assertNotIn("uncalibrated", format_forecast_line(plain))

    def test_unpriced_model_yields_tokens_not_fabricated_zero(self):
        with patch(*_UNPRICED):
            fc = _forecast(enhance=[3000] * 10, analyze=[3000] * 10,
                           model_id="unknown-model-z")
        self.assertFalse(fc["priced"])
        self.assertNotIn("usd_central", fc)
        line = format_forecast_line(fc)
        self.assertIn("input tokens", line)
        self.assertIn("unknown-model-z", line)
        self.assertNotIn("$", line)

    def test_line_is_informational_vocabulary(self):
        with patch(*_PRICED):
            fc = _forecast(enhance=[3000] * 7, analyze=[3000] * 9)
        line = format_forecast_line(fc)
        self.assertIn("Cost forecast:", line)
        self.assertIn("not a cap", line)
        self.assertIn("enhance 7 unit(s)", line)
        self.assertIn("analyze 9 unit(s)", line)
        self.assertIn("app-context 1 call(s)", line)

    def test_line_renders_actual_app_context_call_count(self):
        # The census accepts a variable call count — the line must
        # render it, not a hardcoded 1.
        with patch(*_PRICED):
            fc = _forecast(enhance=[3000], analyze=[3000],
                           app_context_calls=3)
        self.assertEqual(fc["app_context_calls"], 3)
        self.assertIn("app-context 3 call(s)", format_forecast_line(fc))
        # A forecast document predating the census key reads as the
        # single call every such document was built with.
        legacy = {k: v for k, v in fc.items() if k != "app_context_calls"}
        self.assertIn("app-context 1 call(s)",
                      format_forecast_line(legacy))


if __name__ == "__main__":
    unittest.main()
