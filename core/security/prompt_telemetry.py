"""Runtime telemetry for the prompt defense stack.

Tracks three signals during a run:

1. **Nonce leakage**: the model echoed the per-call nonce in its output,
   meaning it treated the envelope structure as content rather than
   honouring the data/instruction boundary. Any occurrence is a critical
   warning — the envelope contract is broken for that model+profile.

2. **Schema rejection rate**: validate_response rejected the model's
   output and had to retry (or gave up). A high rate means the envelope
   is confusing the model's ability to produce structured output. The
   operator should downgrade the profile.

3. **Preflight hit rate**: preflight() flagged injection indicators in
   the target content. A high rate means the target repository contains
   content that looks like deliberate injection attempts — the operator
   should be aware they're scanning a potentially adversarial codebase.

Usage:
    from core.security.prompt_telemetry import defense_telemetry

    # After each LLM response:
    defense_telemetry.record_response(
        model_id="gemini-2.5-pro",
        profile_name="google-gemini",
        nonce="abc123...",
        raw_response="...",
        schema_accepted=True,
        schema_retried=False,
    )

    # After each preflight:
    defense_telemetry.record_preflight(hit=result.has_injection_indicators)

    # At run completion:
    summary = defense_telemetry.summary()
    defense_telemetry.write_summary(output_dir)
    defense_telemetry.reset()

Warnings are emitted to the 'raptor.security' logger when thresholds
are crossed. The summary is a plain dict suitable for JSON serialisation.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


logger = logging.getLogger("raptor.security")
logger.propagate = True

_SCHEMA_REJECTION_WARN_THRESHOLD = 0.30
_PREFLIGHT_HIT_WARN_THRESHOLD = 0.20


@dataclass
class _ModelStats:
    responses: int = 0
    schema_accepted: int = 0
    schema_retried: int = 0
    schema_failed: int = 0
    nonce_leaks: int = 0


@dataclass
class _PreflightStats:
    checked: int = 0
    hits: int = 0


class DefenseTelemetry:
    """Thread-safe, per-run telemetry for the prompt defense stack."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._models: dict[str, _ModelStats] = {}
        self._preflight = _PreflightStats()
        self._nonce_leak_warned: set[str] = set()
        self._schema_warned: set[str] = set()
        self._preflight_warned = False
        self._probe_results: dict[str, bool] = {}
        self._weakened_overrides: dict[str, str] = {}

    def reset(self) -> None:
        """Clear all counters. Call at the start of each run."""
        with self._lock:
            self._models.clear()
            self._preflight = _PreflightStats()
            self._nonce_leak_warned.clear()
            self._schema_warned.clear()
            self._preflight_warned = False
            self._probe_results.clear()
            self._weakened_overrides.clear()

    def _get_model(self, model_id: str) -> _ModelStats:
        if model_id not in self._models:
            self._models[model_id] = _ModelStats()
        return self._models[model_id]

    def record_response(
        self,
        *,
        model_id: str,
        profile_name: str,
        nonce: str,
        raw_response: str,
        schema_accepted: bool,
        schema_retried: bool,
    ) -> None:
        """Record the outcome of one LLM response.

        Call this after validate_response() completes (or after raw
        free-form generation if no schema validation is used).
        """
        with self._lock:
            stats = self._get_model(model_id)
            stats.responses += 1

            if schema_accepted:
                stats.schema_accepted += 1
            elif schema_retried:
                stats.schema_retried += 1
            else:
                stats.schema_failed += 1

            from core.security.prompt_envelope import nonce_leaked_in
            if nonce_leaked_in(nonce, raw_response):
                stats.nonce_leaks += 1
                if model_id not in self._nonce_leak_warned:
                    self._nonce_leak_warned.add(model_id)
                    logger.warning(
                        "DEFENSE ALERT: model %s leaked the per-call envelope "
                        "nonce in its output. The envelope contract may be "
                        "broken for this model — consider switching to a "
                        "different model or downgrading the defense profile "
                        "(%s).",
                        model_id,
                        profile_name,
                    )

            rejection_rate = self._rejection_rate(stats)
            if (
                rejection_rate is not None
                and rejection_rate > _SCHEMA_REJECTION_WARN_THRESHOLD
                and model_id not in self._schema_warned
                and stats.responses >= 5
            ):
                self._schema_warned.add(model_id)
                logger.warning(
                    "DEFENSE WARNING: model %s has a %.0f%% schema rejection "
                    "rate (%d/%d responses rejected). The defense envelope "
                    "may be interfering with structured output for this "
                    "model. Consider downgrading the defense profile (%s) — "
                    "e.g. disabling base64 or datamarking.",
                    model_id,
                    rejection_rate * 100,
                    stats.schema_retried + stats.schema_failed,
                    stats.responses,
                    profile_name,
                )

    def record_preflight(self, *, hit: bool) -> None:
        """Record one preflight check result."""
        with self._lock:
            self._preflight.checked += 1
            if hit:
                self._preflight.hits += 1

            hit_rate = self._preflight_hit_rate()
            if (
                hit_rate is not None
                and hit_rate > _PREFLIGHT_HIT_WARN_THRESHOLD
                and not self._preflight_warned
                and self._preflight.checked >= 5
            ):
                self._preflight_warned = True
                logger.warning(
                    "DEFENSE ALERT: %.0f%% of scanned content (%d/%d) "
                    "contains injection indicators. This target repository "
                    "may contain adversarial content designed to manipulate "
                    "analysis results. Treat findings with increased "
                    "skepticism.",
                    hit_rate * 100,
                    self._preflight.hits,
                    self._preflight.checked,
                )

    @staticmethod
    def _rejection_rate(stats: _ModelStats) -> Optional[float]:
        if stats.responses == 0:
            return None
        return (stats.schema_retried + stats.schema_failed) / stats.responses

    def _preflight_hit_rate(self) -> Optional[float]:
        if self._preflight.checked == 0:
            return None
        return self._preflight.hits / self._preflight.checked

    def record_weakened_override(self, model_id: str, reason: str) -> None:
        """Record that the operator accepted weakened defenses for a model."""
        with self._lock:
            self._weakened_overrides[model_id] = reason

    def summary(self) -> dict:
        """Return a JSON-serialisable summary of the current run's telemetry."""
        with self._lock:
            models = {}
            for model_id, stats in self._models.items():
                rejection_rate = self._rejection_rate(stats)
                entry: dict = {
                    "responses": stats.responses,
                    "schema_accepted": stats.schema_accepted,
                    "schema_retried": stats.schema_retried,
                    "schema_failed": stats.schema_failed,
                    "nonce_leaks": stats.nonce_leaks,
                }
                if rejection_rate is not None:
                    entry["schema_rejection_rate"] = round(rejection_rate, 3)
                models[model_id] = entry

            preflight: dict = {
                "checked": self._preflight.checked,
                "hits": self._preflight.hits,
            }
            hit_rate = self._preflight_hit_rate()
            if hit_rate is not None:
                preflight["hit_rate"] = round(hit_rate, 3)

            warnings = []
            if self._nonce_leak_warned:
                warnings.append({
                    "level": "critical",
                    "type": "nonce_leakage",
                    "models": sorted(self._nonce_leak_warned),
                    "action": "Switch model or downgrade defense profile",
                })
            if self._schema_warned:
                warnings.append({
                    "level": "warning",
                    "type": "high_schema_rejection",
                    "models": sorted(self._schema_warned),
                    "action": "Downgrade defense profile (disable base64 or datamarking)",
                })
            if self._preflight_warned:
                warnings.append({
                    "level": "critical",
                    "type": "adversarial_content",
                    "action": "Target may contain adversarial content — treat findings with skepticism",
                })
            if self._weakened_overrides:
                warnings.append({
                    "level": "warning",
                    "type": "weakened_defenses",
                    "models": sorted(self._weakened_overrides.keys()),
                    "reasons": dict(sorted(self._weakened_overrides.items())),
                    "action": "Model-dependent defenses disabled via --accept-weakened-defenses",
                })

            return {
                "defense_telemetry": {
                    "models": models,
                    "preflight": preflight,
                    "warnings": warnings,
                }
            }

    def write_summary(self, output_dir: str | Path) -> Path:
        """Write the summary to defense-telemetry.json in output_dir."""
        path = Path(output_dir) / "defense-telemetry.json"
        data = self.summary()
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    @property
    def has_warnings(self) -> bool:
        with self._lock:
            return bool(
                self._nonce_leak_warned
                or self._schema_warned
                or self._preflight_warned
                or self._weakened_overrides
            )

    @property
    def has_critical_warnings(self) -> bool:
        with self._lock:
            return bool(self._nonce_leak_warned or self._preflight_warned)

    def set_probe_result(self, model_id: str, compatible: bool) -> None:
        """Cache the result of a pre-run envelope compatibility probe."""
        with self._lock:
            self._probe_results[model_id] = compatible

    def probe_passed(self, model_id: str) -> bool | None:
        """Return the cached probe result, or None if not probed yet."""
        with self._lock:
            return self._probe_results.get(model_id)


defense_telemetry = DefenseTelemetry()
