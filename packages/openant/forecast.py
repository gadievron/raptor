"""OpenAnt pre-spend cost forecasting.

Estimates the LLM spend of a scan BEFORE any token is bought, from the
unit census the pinned CLI's free ``parse`` step produces. Two
consumers: the ``--forecast`` mode (parse-only run, $0 LLM spend,
prints the forecast and exits) and the informational forecast line
every gateway-minted run prints before its child token is minted.

The forecast is a RANGE, never a point: the enhance phase is agentic
(tool-use iterations), and the iteration count per unit is not
knowable up front — the band is the honest shape. Informational only:
nothing here gates or caps a run (the gateway budget does that).

MEASURED CALIBRATION (revisitable): the coefficients below were fitted
from the per-unit checkpoint usage of a real-world ~200-unit PHP
web-application scan (agentic enhance mode, reachable-level analyze):

* enhance input tokens are ITERATION-dominated — per agent iteration
  they regress on the prompt-capped unit size as
  ``4622 + 0.4016 * min(chars, 60000)`` with r^2 ~ 0.95, while the
  iteration count itself is not size-predictable (median 2, mean ~2.8,
  p90 4). The band therefore comes from the iteration multiplier.
* analyze input tokens track unit size almost exactly
  (``~6100 + 0.42 * chars``, r^2 ~ 1.0 — the Stage-1 prompt embeds the
  unit code + dependencies verbatim), so its band is narrow.
* app-context is one small fixed call.

Re-fit these whenever OPENANT_PINNED_COMMIT advances with changed
prompts, prompt caps, or enhance-mode defaults.
"""

from __future__ import annotations

from typing import Any

# --- enhance (agentic): per-iteration input regression + iteration band ---
ENHANCE_IN_PER_ITER_BASE = 4622.0
ENHANCE_IN_PER_ITER_PER_CHAR = 0.4016
ENHANCE_PROMPT_CHAR_CAP = 60_000
ENHANCE_OUT_PER_ITER = 1130.0
ENHANCE_ITER_CENTRAL = 2.8
ENHANCE_ITER_LOW = 2.0
ENHANCE_ITER_HIGH = 4.5

# --- analyze (Stage 1): near-exact linear in unit size ---
ANALYZE_IN_BASE = 6100.0
ANALYZE_IN_PER_CHAR = 0.42
ANALYZE_OUT_PER_UNIT = 1100.0
ANALYZE_BAND = (0.8, 1.25)

# --- app-context: one small call per scan (regenerated on resume too) ---
APP_CONTEXT_IN = 5000.0
APP_CONTEXT_OUT = 2000.0
APP_CONTEXT_BAND = (0.5, 3.0)


def unit_sizes_from_dataset(dataset: dict) -> dict[str, int]:
    """Per-unit prompt-relevant size (chars of code + dependencies),
    keyed by unit id, from a parse-step ``dataset.json`` document.

    Malformed/hostile shapes degrade to size 0 for that unit rather
    than crashing — the dataset is produced over an untrusted repo.
    """
    sizes: dict[str, int] = {}
    units = dataset.get("units") if isinstance(dataset, dict) else None
    if not isinstance(units, list):
        return sizes
    for u in units:
        if not isinstance(u, dict):
            continue
        uid = u.get("id")
        if not isinstance(uid, str) or not uid:
            continue
        n = 0
        code = u.get("code")
        if isinstance(code, dict):
            primary = code.get("primary_code")
            if isinstance(primary, str):
                n += len(primary)
            deps = code.get("dependencies")
            if isinstance(deps, dict):
                n += sum(len(d) for d in deps.values() if isinstance(d, str))
        sizes[uid] = n
    return sizes


def _enhance_tokens(sizes: list[int]) -> dict[str, float]:
    per_iter_in = sum(
        ENHANCE_IN_PER_ITER_BASE
        + ENHANCE_IN_PER_ITER_PER_CHAR * min(s, ENHANCE_PROMPT_CHAR_CAP)
        for s in sizes
    )
    per_iter_out = ENHANCE_OUT_PER_ITER * len(sizes)
    return {
        "input_tokens": per_iter_in * ENHANCE_ITER_CENTRAL,
        "output_tokens": per_iter_out * ENHANCE_ITER_CENTRAL,
        "input_low": per_iter_in * ENHANCE_ITER_LOW,
        "input_high": per_iter_in * ENHANCE_ITER_HIGH,
        "output_low": per_iter_out * ENHANCE_ITER_LOW,
        "output_high": per_iter_out * ENHANCE_ITER_HIGH,
    }


def _analyze_tokens(sizes: list[int]) -> dict[str, float]:
    t_in = sum(ANALYZE_IN_BASE + ANALYZE_IN_PER_CHAR * s for s in sizes)
    t_out = ANALYZE_OUT_PER_UNIT * len(sizes)
    lo, hi = ANALYZE_BAND
    return {
        "input_tokens": t_in, "output_tokens": t_out,
        "input_low": t_in * lo, "input_high": t_in * hi,
        "output_low": t_out * lo, "output_high": t_out * hi,
    }


def _app_context_tokens(calls: int) -> dict[str, float]:
    lo, hi = APP_CONTEXT_BAND
    t_in, t_out = APP_CONTEXT_IN * calls, APP_CONTEXT_OUT * calls
    return {
        "input_tokens": t_in, "output_tokens": t_out,
        "input_low": t_in * lo, "input_high": t_in * hi,
        "output_low": t_out * lo, "output_high": t_out * hi,
    }


def forecast_scan_cost(
    *,
    enhance_sizes: list[int],
    analyze_sizes: list[int],
    verify: bool,
    model_id: str,
    app_context_calls: int = 1,
) -> dict[str, Any]:
    """Forecast the LLM spend of the scan work described by the census.

    ``enhance_sizes`` / ``analyze_sizes`` are the per-unit sizes of the
    units each phase will actually PAY for — on a resume, pass only the
    remainder (the seeded checkpoints' completed units are restored at
    zero LLM cost). An empty list forecasts that phase at zero (e.g.
    ``--no-enhance`` runs, or a resume whose enhance completed).

    ``verify`` is NOTED, never priced: this calibration has no verify
    data, and inventing a Stage-2 coefficient would present as measured.

    Pricing resolves through RAPTOR's model catalog for ``model_id``
    (the id the run will actually bill — gateway-routed or pinned
    direct). An uncataloged model yields ``priced: False`` and
    token-only figures instead of a fabricated $0.
    """
    app_calls = max(0, int(app_context_calls))
    phases = {
        "enhance": _enhance_tokens(list(enhance_sizes)),
        "analyze": _analyze_tokens(list(analyze_sizes)),
        "app_context": _app_context_tokens(app_calls),
    }
    totals = {
        k: sum(p[k] for p in phases.values())
        for k in ("input_tokens", "output_tokens",
                  "input_low", "input_high", "output_low", "output_high")
    }

    from core.llm.model_data import price_for
    price_in, price_out = price_for(model_id)
    priced = (price_in, price_out) != (0.0, 0.0)

    result: dict[str, Any] = {
        "estimator": "measured-calibration-v1",
        "model_id": model_id,
        "units": {"enhance": len(enhance_sizes),
                  "analyze": len(analyze_sizes)},
        "app_context_calls": app_calls,
        "phases": {
            name: {k: round(v) for k, v in p.items()}
            for name, p in phases.items()
        },
        "input_tokens_central": round(totals["input_tokens"]),
        "output_tokens_central": round(totals["output_tokens"]),
        "input_tokens_low": round(totals["input_low"]),
        "input_tokens_high": round(totals["input_high"]),
        "priced": priced,
        "verify_enabled": bool(verify),
    }
    if priced:
        def _usd(t_in: float, t_out: float) -> float:
            return round((t_in * price_in + t_out * price_out) / 1e6, 2)
        result["price_in_per_mtok"] = price_in
        result["price_out_per_mtok"] = price_out
        result["usd_low"] = _usd(totals["input_low"], totals["output_low"])
        result["usd_central"] = _usd(totals["input_tokens"],
                                     totals["output_tokens"])
        result["usd_high"] = _usd(totals["input_high"], totals["output_high"])
    return result


def _fmt_mtok(tokens: float) -> str:
    return f"{tokens / 1e6:.1f}M"


def format_forecast_line(fc: dict[str, Any]) -> str:
    """One human line for the forecast — printed before any spend.

    Informational vocabulary by design: never "budget", "cap", or
    "limit" — the gateway budget is the enforcement surface, this line
    is a pre-spend estimate.
    """
    units = fc.get("units") or {}
    parts = (f"enhance {units.get('enhance', 0)} unit(s), "
             f"analyze {units.get('analyze', 0)} unit(s), "
             # Older forecast documents predate the census key; they
             # were all built with the default single call.
             f"app-context {fc.get('app_context_calls', 1)} call(s)")
    if fc.get("priced"):
        body = (f"${fc['usd_low']:.2f}-${fc['usd_high']:.2f} "
                f"(central ~${fc['usd_central']:.2f}) — {parts}")
    else:
        body = (f"~{_fmt_mtok(fc.get('input_tokens_low', 0))}-"
                f"{_fmt_mtok(fc.get('input_tokens_high', 0))} input tokens "
                f"— {parts} (model {fc.get('model_id')} is not in RAPTOR's "
                f"price catalog; no USD estimate)")
    line = f"Cost forecast: {body} [measured-calibration estimate, not a cap]"
    if fc.get("verify_enabled"):
        line += (" — verify enabled: adds an uncalibrated Stage-2 pass on "
                 "flagged units, not included above")
    return line
