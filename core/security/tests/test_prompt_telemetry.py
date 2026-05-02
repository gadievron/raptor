"""Tests for prompt defense telemetry."""

from __future__ import annotations

import io
import json
import logging

import pytest

from core.security.prompt_telemetry import DefenseTelemetry


@pytest.fixture
def telemetry():
    t = DefenseTelemetry()
    yield t
    t.reset()


@pytest.fixture
def log_capture():
    """Capture log output from the raptor.security logger."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.WARNING)
    logger = logging.getLogger("raptor.security")
    logger.addHandler(handler)
    yield stream
    logger.removeHandler(handler)


# --- Basic recording ---

class TestRecordResponse:

    def test_counts_accepted_responses(self, telemetry):
        telemetry.record_response(
            model_id="gemini-2.5-flash",
            profile_name="google-gemini",
            nonce="abc123",
            raw_response='{"safe": true}',
            schema_accepted=True,
            schema_retried=False,
        )
        s = telemetry.summary()
        stats = s["defense_telemetry"]["models"]["gemini-2.5-flash"]
        assert stats["responses"] == 1
        assert stats["schema_accepted"] == 1
        assert stats["schema_retried"] == 0
        assert stats["nonce_leaks"] == 0

    def test_counts_retried_responses(self, telemetry):
        telemetry.record_response(
            model_id="gpt-5",
            profile_name="openai-gpt",
            nonce="abc123",
            raw_response="fixed json",
            schema_accepted=False,
            schema_retried=True,
        )
        stats = telemetry.summary()["defense_telemetry"]["models"]["gpt-5"]
        assert stats["schema_retried"] == 1

    def test_counts_failed_responses(self, telemetry):
        telemetry.record_response(
            model_id="gpt-5",
            profile_name="openai-gpt",
            nonce="abc123",
            raw_response="garbage",
            schema_accepted=False,
            schema_retried=False,
        )
        stats = telemetry.summary()["defense_telemetry"]["models"]["gpt-5"]
        assert stats["schema_failed"] == 1

    def test_tracks_multiple_models_independently(self, telemetry):
        for model in ("claude-opus-4-7", "gpt-5"):
            telemetry.record_response(
                model_id=model,
                profile_name="test",
                nonce="x",
                raw_response="ok",
                schema_accepted=True,
                schema_retried=False,
            )
        models = telemetry.summary()["defense_telemetry"]["models"]
        assert "claude-opus-4-7" in models
        assert "gpt-5" in models


class TestRecordPreflight:

    def test_counts_clean_checks(self, telemetry):
        telemetry.record_preflight(hit=False)
        telemetry.record_preflight(hit=False)
        pf = telemetry.summary()["defense_telemetry"]["preflight"]
        assert pf["checked"] == 2
        assert pf["hits"] == 0
        assert pf["hit_rate"] == 0.0

    def test_counts_hits(self, telemetry):
        telemetry.record_preflight(hit=True)
        telemetry.record_preflight(hit=False)
        pf = telemetry.summary()["defense_telemetry"]["preflight"]
        assert pf["checked"] == 2
        assert pf["hits"] == 1
        assert pf["hit_rate"] == 0.5


# --- Nonce leakage detection ---

class TestNonceLeakage:

    def test_detects_nonce_in_response(self, telemetry):
        telemetry.record_response(
            model_id="test-model",
            profile_name="test",
            nonce="deadbeef12345678",
            raw_response='Here is the data from deadbeef12345678',
            schema_accepted=True,
            schema_retried=False,
        )
        stats = telemetry.summary()["defense_telemetry"]["models"]["test-model"]
        assert stats["nonce_leaks"] == 1

    def test_no_false_positive_when_nonce_absent(self, telemetry):
        telemetry.record_response(
            model_id="test-model",
            profile_name="test",
            nonce="deadbeef12345678",
            raw_response='{"safe": true, "reasoning": "no issues"}',
            schema_accepted=True,
            schema_retried=False,
        )
        stats = telemetry.summary()["defense_telemetry"]["models"]["test-model"]
        assert stats["nonce_leaks"] == 0

    def test_nonce_leak_triggers_critical_warning(self, telemetry):
        telemetry.record_response(
            model_id="leaky-model",
            profile_name="test",
            nonce="deadbeef12345678",
            raw_response="leaked deadbeef12345678",
            schema_accepted=True,
            schema_retried=False,
        )
        assert telemetry.has_critical_warnings
        warnings = telemetry.summary()["defense_telemetry"]["warnings"]
        nonce_warnings = [w for w in warnings if w["type"] == "nonce_leakage"]
        assert len(nonce_warnings) == 1
        assert nonce_warnings[0]["level"] == "critical"
        assert "leaky-model" in nonce_warnings[0]["models"]

    def test_nonce_leak_logs_warning(self, telemetry, log_capture):
        telemetry.record_response(
            model_id="leaky-model",
            profile_name="test-profile",
            nonce="deadbeef12345678",
            raw_response="leaked deadbeef12345678",
            schema_accepted=True,
            schema_retried=False,
        )
        output = log_capture.getvalue()
        assert "DEFENSE ALERT" in output
        assert "leaky-model" in output
        assert "nonce" in output.lower()

    def test_nonce_leak_warned_only_once_per_model(self, telemetry, log_capture):
        for _ in range(5):
            telemetry.record_response(
                model_id="leaky-model",
                profile_name="test",
                nonce="deadbeef12345678",
                raw_response="leaked deadbeef12345678",
                schema_accepted=True,
                schema_retried=False,
            )
        assert log_capture.getvalue().count("DEFENSE ALERT") == 1

    def test_empty_nonce_does_not_trigger(self, telemetry):
        telemetry.record_response(
            model_id="test-model",
            profile_name="test",
            nonce="",
            raw_response="anything",
            schema_accepted=True,
            schema_retried=False,
        )
        assert not telemetry.has_critical_warnings


# --- Schema rejection rate warnings ---

class TestSchemaRejectionWarning:

    def _record_n(self, telemetry, n_ok, n_fail):
        for _ in range(n_ok):
            telemetry.record_response(
                model_id="confused-model",
                profile_name="vendor-profile",
                nonce="x",
                raw_response="ok",
                schema_accepted=True,
                schema_retried=False,
            )
        for _ in range(n_fail):
            telemetry.record_response(
                model_id="confused-model",
                profile_name="vendor-profile",
                nonce="x",
                raw_response="garbage",
                schema_accepted=False,
                schema_retried=True,
            )

    def test_low_rejection_rate_no_warning(self, telemetry):
        self._record_n(telemetry, n_ok=9, n_fail=1)
        assert not telemetry.has_warnings

    def test_high_rejection_rate_triggers_warning(self, telemetry):
        self._record_n(telemetry, n_ok=3, n_fail=5)
        assert telemetry.has_warnings
        warnings = telemetry.summary()["defense_telemetry"]["warnings"]
        schema_warnings = [w for w in warnings if w["type"] == "high_schema_rejection"]
        assert len(schema_warnings) == 1
        assert "confused-model" in schema_warnings[0]["models"]

    def test_warning_requires_minimum_sample_size(self, telemetry):
        """Don't warn on 1/2 rejections — need at least 5 responses."""
        self._record_n(telemetry, n_ok=0, n_fail=4)
        assert not telemetry.has_warnings

    def test_schema_warning_logs(self, telemetry, log_capture):
        self._record_n(telemetry, n_ok=2, n_fail=6)
        output = log_capture.getvalue()
        assert "DEFENSE WARNING" in output
        assert "confused-model" in output
        assert "rejection" in output.lower()


# --- Preflight hit rate warnings ---

class TestPreflightHitRateWarning:

    def test_low_hit_rate_no_warning(self, telemetry):
        for _ in range(9):
            telemetry.record_preflight(hit=False)
        telemetry.record_preflight(hit=True)
        assert not telemetry.has_warnings

    def test_high_hit_rate_triggers_critical_warning(self, telemetry):
        for _ in range(4):
            telemetry.record_preflight(hit=True)
        telemetry.record_preflight(hit=False)
        assert telemetry.has_critical_warnings
        warnings = telemetry.summary()["defense_telemetry"]["warnings"]
        pf_warnings = [w for w in warnings if w["type"] == "adversarial_content"]
        assert len(pf_warnings) == 1
        assert pf_warnings[0]["level"] == "critical"

    def test_warning_requires_minimum_sample_size(self, telemetry):
        for _ in range(4):
            telemetry.record_preflight(hit=True)
        # Only 4 checked — below the 5 minimum
        assert not telemetry.has_warnings

    def test_preflight_warning_logs(self, telemetry, log_capture):
        for _ in range(5):
            telemetry.record_preflight(hit=True)
        output = log_capture.getvalue()
        assert "DEFENSE ALERT" in output
        assert "adversarial" in output.lower()


# --- Summary and persistence ---

class TestSummaryAndPersistence:

    def test_summary_is_json_serialisable(self, telemetry):
        telemetry.record_response(
            model_id="test",
            profile_name="test",
            nonce="abc",
            raw_response="ok",
            schema_accepted=True,
            schema_retried=False,
        )
        telemetry.record_preflight(hit=False)
        s = telemetry.summary()
        serialised = json.dumps(s)
        assert json.loads(serialised) == s

    def test_write_summary_creates_file(self, telemetry, tmp_path):
        telemetry.record_response(
            model_id="test",
            profile_name="test",
            nonce="abc",
            raw_response="ok",
            schema_accepted=True,
            schema_retried=False,
        )
        path = telemetry.write_summary(tmp_path)
        assert path.exists()
        assert path.name == "defense-telemetry.json"
        data = json.loads(path.read_text())
        assert "defense_telemetry" in data
        assert data["defense_telemetry"]["models"]["test"]["responses"] == 1

    def test_reset_clears_everything(self, telemetry):
        telemetry.record_response(
            model_id="test",
            profile_name="test",
            nonce="abc",
            raw_response="leaked abc",
            schema_accepted=True,
            schema_retried=False,
        )
        telemetry.record_preflight(hit=True)
        assert telemetry.has_critical_warnings

        telemetry.reset()

        assert not telemetry.has_warnings
        s = telemetry.summary()
        assert s["defense_telemetry"]["models"] == {}
        assert s["defense_telemetry"]["preflight"]["checked"] == 0
        assert s["defense_telemetry"]["warnings"] == []

    def test_empty_summary_has_no_warnings(self, telemetry):
        s = telemetry.summary()
        assert s["defense_telemetry"]["warnings"] == []
        assert s["defense_telemetry"]["models"] == {}

    def test_schema_rejection_rate_in_summary(self, telemetry):
        for _ in range(7):
            telemetry.record_response(
                model_id="m",
                profile_name="p",
                nonce="x",
                raw_response="ok",
                schema_accepted=True,
                schema_retried=False,
            )
        for _ in range(3):
            telemetry.record_response(
                model_id="m",
                profile_name="p",
                nonce="x",
                raw_response="bad",
                schema_accepted=False,
                schema_retried=False,
            )
        stats = telemetry.summary()["defense_telemetry"]["models"]["m"]
        assert stats["schema_rejection_rate"] == 0.3


# --- has_warnings / has_critical_warnings ---

class TestWarningFlags:

    def test_no_warnings_initially(self, telemetry):
        assert not telemetry.has_warnings
        assert not telemetry.has_critical_warnings

    def test_schema_warning_is_not_critical(self, telemetry):
        for _ in range(3):
            telemetry.record_response(
                model_id="m", profile_name="p", nonce="x",
                raw_response="ok", schema_accepted=True, schema_retried=False,
            )
        for _ in range(5):
            telemetry.record_response(
                model_id="m", profile_name="p", nonce="x",
                raw_response="bad", schema_accepted=False, schema_retried=True,
            )
        assert telemetry.has_warnings
        assert not telemetry.has_critical_warnings

    def test_nonce_leak_is_critical(self, telemetry):
        telemetry.record_response(
            model_id="m", profile_name="p", nonce="secret123",
            raw_response="I see secret123", schema_accepted=True,
            schema_retried=False,
        )
        assert telemetry.has_critical_warnings

    def test_preflight_warning_is_critical(self, telemetry):
        for _ in range(5):
            telemetry.record_preflight(hit=True)
        assert telemetry.has_critical_warnings


# --- Weakened defenses override ---

class TestWeakenedOverride:

    def test_record_weakened_override_surfaces_in_summary(self, telemetry):
        telemetry.record_weakened_override("ollama/llama3", "Model failed canary probe")
        s = telemetry.summary()
        warnings = s["defense_telemetry"]["warnings"]
        wd = [w for w in warnings if w["type"] == "weakened_defenses"]
        assert len(wd) == 1
        assert wd[0]["level"] == "warning"
        assert "ollama/llama3" in wd[0]["models"]
        assert wd[0]["reasons"]["ollama/llama3"] == "Model failed canary probe"

    def test_weakened_override_sets_has_warnings(self, telemetry):
        assert not telemetry.has_warnings
        telemetry.record_weakened_override("test-model", "probe failed")
        assert telemetry.has_warnings

    def test_weakened_override_is_not_critical(self, telemetry):
        telemetry.record_weakened_override("test-model", "probe failed")
        assert not telemetry.has_critical_warnings

    def test_reset_clears_weakened_overrides(self, telemetry):
        telemetry.record_weakened_override("test-model", "probe failed")
        telemetry.reset()
        assert not telemetry.has_warnings
        s = telemetry.summary()
        assert s["defense_telemetry"]["warnings"] == []

    def test_weakened_override_serialisable(self, telemetry):
        telemetry.record_weakened_override("model-a", "reason a")
        telemetry.record_weakened_override("model-b", "reason b")
        s = telemetry.summary()
        serialised = json.dumps(s)
        parsed = json.loads(serialised)
        wd = [w for w in parsed["defense_telemetry"]["warnings"]
              if w["type"] == "weakened_defenses"]
        assert len(wd) == 1
        assert set(wd[0]["models"]) == {"model-a", "model-b"}
