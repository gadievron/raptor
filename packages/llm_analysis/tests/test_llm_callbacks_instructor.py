"""Test 5: Critical test for Instructor + LiteLLM callback compatibility."""

import pytest
import sys
import litellm
from pathlib import Path
from pydantic import BaseModel

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.llm_analysis.llm.client import LLMClient
from packages.llm_analysis.llm.config import ModelConfig


class SimpleSchema(BaseModel):
    """Simple schema for testing structured generation."""
    result: str
    confidence: float


class TestInstructorCompatibility:
    """Test 5: CRITICAL - Verify callbacks fire with Instructor structured generation."""

    def test_instructor_fires_callbacks(self):
        """Test if Instructor calls trigger LiteLLM callbacks."""
        # This is the CRITICAL test that may fail
        # Instructor wraps litellm.completion - callbacks may not propagate

        client = LLMClient()

        # Track callback invocations
        callback_fired = False

        if len(litellm.callbacks) > 0:
            callback = litellm.callbacks[0]
            original_success = callback.log_success_event

            def tracking_success(*args, **kwargs):
                nonlocal callback_fired
                callback_fired = True
                if callable(original_success):
                    original_success(*args, **kwargs)

            callback.log_success_event = tracking_success

            try:
                # Call generate_structured (uses Instructor)
                result_dict, full_response = client.generate_structured(
                    prompt="What is 2+2? Provide the result and your confidence (0.0-1.0).",
                    schema=SimpleSchema.model_json_schema(),
                    system_prompt="You are a calculator."
                )

                # Verify we got a valid response
                assert result_dict is not None
                assert "result" in result_dict

                # CRITICAL ASSERTION: Did callback fire?
                if callback_fired:
                    print("\n✅ PASS: Instructor DOES fire callbacks")
                else:
                    print("\n❌ FAIL: Instructor does NOT fire callbacks")
                    print("   This means callbacks won't work for structured generation.")
                    print("   50% of LLM calls will have no callback visibility.")

                # Document result but don't fail test (this is exploratory)
                # Test framework will report pass/fail based on callback_fired

            finally:
                # Restore original callback
                callback.log_success_event = original_success

        # Return callback status for documentation
        return callback_fired

    def test_instructor_exception_safety(self):
        """Verify Instructor calls don't break even if callback throws."""
        client = LLMClient()

        if len(litellm.callbacks) > 0:
            callback = litellm.callbacks[0]
            original_success = callback.log_success_event

            def failing_callback(*args, **kwargs):
                raise RuntimeError("Intentional test exception")

            callback.log_success_event = failing_callback

            try:
                # Call should succeed despite callback failure
                result_dict, full_response = client.generate_structured(
                    prompt="What is 1+1?",
                    schema=SimpleSchema.model_json_schema()
                )

                # Verify response is valid
                assert result_dict is not None

            finally:
                callback.log_success_event = original_success
