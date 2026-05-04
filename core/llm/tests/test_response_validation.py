"""Tests for core.llm.response_validation — per-field LLM response validation."""

import pytest

from core.llm.response_validation import (
    FieldResult,
    ValidatedResponse,
    validate_structured_response,
    quality_retry_prompt,
    _coerce_value,
    _get_field_type,
    _get_properties,
    _get_required,
    _is_nullable,
    _resolve_weights,
    _ANALYSIS_WEIGHTS,
    _FINDING_RESULT_WEIGHTS,
    _DATAFLOW_VALIDATION_WEIGHTS,
)
from packages.llm_analysis.prompts.schemas import (
    ANALYSIS_SCHEMA,
    DATAFLOW_VALIDATION_SCHEMA,
    FINDING_RESULT_SCHEMA,
)


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

class TestGetProperties:
    def test_simple_schema(self):
        schema = {"field_a": "boolean", "field_b": "string"}
        props = _get_properties(schema)
        assert set(props.keys()) == {"field_a", "field_b"}
        assert props["field_a"] == "boolean"

    def test_json_schema(self):
        schema = {
            "type": "object",
            "properties": {
                "x": {"type": "string"},
                "y": {"type": "number"},
            },
        }
        props = _get_properties(schema)
        assert props == {"x": {"type": "string"}, "y": {"type": "number"}}

    def test_empty_schema(self):
        assert _get_properties({}) == {}


class TestGetRequired:
    def test_simple_schema_all_required(self):
        schema = {"a": "bool", "b": "string"}
        assert _get_required(schema) == {"a", "b"}

    def test_json_schema_explicit_required(self):
        schema = {
            "properties": {"a": {}, "b": {}, "c": {}},
            "required": ["a", "c"],
        }
        assert _get_required(schema) == {"a", "c"}

    def test_json_schema_no_required(self):
        schema = {"properties": {"a": {}, "b": {}}}
        assert _get_required(schema) == set()


class TestGetFieldType:
    def test_simple_string_descriptions(self):
        assert _get_field_type("boolean") == "boolean"
        assert _get_field_type("bool something") == "boolean"
        assert _get_field_type("float (0.0-1.0)") == "number"
        assert _get_field_type("int count") == "integer"
        assert _get_field_type("string or null") == "string"
        assert _get_field_type("str name") == "string"

    def test_json_schema_type(self):
        assert _get_field_type({"type": "boolean"}) == "boolean"
        assert _get_field_type({"type": "number"}) == "number"
        assert _get_field_type({"type": "string"}) == "string"

    def test_json_schema_nullable_type(self):
        assert _get_field_type({"type": ["string", "null"]}) == "string"
        assert _get_field_type({"type": ["null", "number"]}) == "number"

    def test_fallback(self):
        assert _get_field_type(42) == "string"
        assert _get_field_type({"no_type": True}) == "string"


class TestIsNullable:
    def test_simple_string_nullable(self):
        assert _is_nullable("string or null") is True
        assert _is_nullable("float or null") is True
        assert _is_nullable("string - reason when null") is True

    def test_simple_string_not_nullable(self):
        assert _is_nullable("boolean") is False
        assert _is_nullable("string") is False

    def test_json_schema_nullable(self):
        assert _is_nullable({"type": ["string", "null"]}) is True

    def test_json_schema_not_nullable(self):
        assert _is_nullable({"type": "string"}) is False
        assert _is_nullable({"type": ["string", "number"]}) is False


# ---------------------------------------------------------------------------
# Weight resolution
# ---------------------------------------------------------------------------

class TestResolveWeights:
    def test_analysis_schema(self):
        weights = _resolve_weights(ANALYSIS_SCHEMA)
        assert weights is _ANALYSIS_WEIGHTS

    def test_finding_result_schema(self):
        weights = _resolve_weights(FINDING_RESULT_SCHEMA)
        assert weights is _FINDING_RESULT_WEIGHTS

    def test_dataflow_validation_schema(self):
        weights = _resolve_weights(DATAFLOW_VALIDATION_SCHEMA)
        assert weights is _DATAFLOW_VALIDATION_WEIGHTS

    def test_unknown_schema_uniform(self):
        schema = {"custom_a": "string", "custom_b": "int"}
        weights = _resolve_weights(schema)
        assert weights == {"custom_a": 0.5, "custom_b": 0.5}


# ---------------------------------------------------------------------------
# Type coercion
# ---------------------------------------------------------------------------

class TestCoerceValue:
    def test_boolean_native(self):
        assert _coerce_value(True, "boolean") == (True, False)
        assert _coerce_value(False, "boolean") == (False, False)

    def test_boolean_from_string(self):
        assert _coerce_value("true", "boolean") == (True, True)
        assert _coerce_value("yes", "boolean") == (True, True)
        assert _coerce_value("1", "boolean") == (True, True)
        assert _coerce_value("false", "boolean") == (False, True)
        assert _coerce_value("no", "boolean") == (False, True)

    def test_boolean_from_int(self):
        assert _coerce_value(1, "boolean") == (True, True)
        assert _coerce_value(0, "boolean") == (False, True)

    def test_number_native(self):
        assert _coerce_value(3.14, "number") == (3.14, False)
        assert _coerce_value(42, "number") == (42, False)

    def test_number_from_string(self):
        assert _coerce_value("3.14", "number") == (3.14, True)

    def test_number_from_bad_string(self):
        val, coerced = _coerce_value("not_a_number", "number")
        assert val is None
        assert coerced is True

    def test_integer_native(self):
        assert _coerce_value(42, "integer") == (42, False)

    def test_integer_from_string(self):
        assert _coerce_value("42", "integer") == (42, True)

    def test_integer_bool_not_native(self):
        val, coerced = _coerce_value(True, "integer")
        assert coerced is True

    def test_string_native(self):
        assert _coerce_value("hello", "string") == ("hello", False)

    def test_string_from_none(self):
        assert _coerce_value(None, "string") == ("", True)

    def test_string_from_int(self):
        assert _coerce_value(42, "string") == ("42", True)

    def test_array_native(self):
        assert _coerce_value([1, 2], "array") == ([1, 2], False)

    def test_array_from_string(self):
        assert _coerce_value("item", "array") == (["item"], True)

    def test_array_from_other(self):
        assert _coerce_value(42, "array") == ([], True)

    def test_object_native(self):
        assert _coerce_value({"a": 1}, "object") == ({"a": 1}, False)

    def test_object_from_other(self):
        assert _coerce_value("nope", "object") == ({}, True)

    def test_unknown_type_passthrough(self):
        assert _coerce_value("val", "custom") == ("val", False)


# ---------------------------------------------------------------------------
# Full validation — simple schema (ANALYSIS_SCHEMA style)
# ---------------------------------------------------------------------------

class TestValidateSimpleSchema:
    SCHEMA = {
        "is_exploitable": "boolean",
        "reasoning": "string",
        "confidence": f"string (high/medium/low)",
        "vuln_type": "string - vulnerability category",
        "cvss_vector": "string - CVSS v3.1 vector",
        "cwe_id": "string - CWE-NNN",
        "exploitability_score": "float (0.0-1.0)",
    }

    def test_perfect_response(self):
        raw = {
            "is_exploitable": True,
            "reasoning": "The input reaches the sink unsanitised.",
            "confidence": "high",
            "vuln_type": "command_injection",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": "CWE-78",
            "exploitability_score": 0.95,
        }
        result = validate_structured_response(raw, self.SCHEMA)
        assert result.quality == 1.0
        assert result.incomplete == []
        assert result.coerced == []
        assert all(f.status == "ok" for f in result.fields.values())

    def test_coerced_boolean(self):
        raw = {
            "is_exploitable": "true",
            "reasoning": "Valid text",
            "confidence": "high",
            "vuln_type": "xss",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe_id": "CWE-79",
            "exploitability_score": 0.7,
        }
        result = validate_structured_response(raw, self.SCHEMA)
        assert result.fields["is_exploitable"].status == "coerced"
        assert result.data["is_exploitable"] is True
        assert "is_exploitable" in result.coerced
        assert result.quality < 1.0

    def test_missing_required_field(self):
        raw = {
            "is_exploitable": True,
            # "reasoning" missing
            "confidence": "high",
            "vuln_type": "xss",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe_id": "CWE-79",
            "exploitability_score": 0.7,
        }
        result = validate_structured_response(raw, self.SCHEMA)
        assert "reasoning" in result.incomplete
        assert result.data["reasoning"] is None
        assert result.quality < 1.0

    def test_invalid_vuln_type(self):
        raw = {
            "is_exploitable": True,
            "reasoning": "text",
            "confidence": "high",
            "vuln_type": "totally_fake_vuln",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": "CWE-78",
            "exploitability_score": 0.5,
        }
        result = validate_structured_response(raw, self.SCHEMA)
        assert "vuln_type" in result.incomplete
        assert result.quality < 1.0

    def test_vuln_type_alias_normalised(self):
        raw = {
            "is_exploitable": True,
            "reasoning": "text",
            "confidence": "high",
            "vuln_type": "null_pointer_dereference",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "cwe_id": "CWE-476",
            "exploitability_score": 0.6,
        }
        result = validate_structured_response(raw, self.SCHEMA)
        assert result.data["vuln_type"] == "null_deref"
        assert result.fields["vuln_type"].status == "coerced"

    def test_invalid_cvss_vector(self):
        raw = {
            "is_exploitable": True,
            "reasoning": "text",
            "confidence": "medium",
            "vuln_type": "xss",
            "cvss_vector": "not-a-cvss-vector",
            "cwe_id": "CWE-79",
            "exploitability_score": 0.5,
        }
        result = validate_structured_response(raw, self.SCHEMA)
        assert "cvss_vector" in result.incomplete

    def test_invalid_cwe_id(self):
        raw = {
            "is_exploitable": True,
            "reasoning": "text",
            "confidence": "medium",
            "vuln_type": "xss",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe_id": "79",
            "exploitability_score": 0.5,
        }
        result = validate_structured_response(raw, self.SCHEMA)
        assert "cwe_id" in result.incomplete

    def test_score_out_of_range(self):
        raw = {
            "is_exploitable": True,
            "reasoning": "text",
            "confidence": "high",
            "vuln_type": "xss",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe_id": "CWE-79",
            "exploitability_score": 1.5,
        }
        result = validate_structured_response(raw, self.SCHEMA)
        assert "exploitability_score" in result.incomplete

    def test_severity_normalised(self):
        schema = {"severity_assessment": "string (critical/high/medium/low/informational)"}
        raw = {"severity_assessment": "HIGH"}
        result = validate_structured_response(raw, schema)
        assert result.data["severity_assessment"] == "high"
        assert result.fields["severity_assessment"].status == "coerced"

    def test_confidence_normalised(self):
        schema = {"confidence": "string (high/medium/low)"}
        raw = {"confidence": "Medium"}
        result = validate_structured_response(raw, schema)
        assert result.data["confidence"] == "medium"

    def test_non_dict_input(self):
        result = validate_structured_response("garbage", self.SCHEMA)
        assert result.quality == 0.0
        assert result.data == {}
        assert len(result.incomplete) == len(self.SCHEMA)

    def test_empty_dict(self):
        result = validate_structured_response({}, self.SCHEMA)
        assert result.quality < 1.0
        assert len(result.incomplete) > 0


# ---------------------------------------------------------------------------
# Full validation — JSON Schema (FINDING_RESULT_SCHEMA style)
# ---------------------------------------------------------------------------

class TestValidateJsonSchema:
    def test_perfect_finding_result(self):
        raw = {
            "finding_id": "FIND-001",
            "is_true_positive": True,
            "is_exploitable": True,
            "reasoning": "Clear dataflow from user input to exec().",
            "confidence": "high",
            "severity_assessment": "critical",
            "ruling": "validated",
            "vuln_type": "command_injection",
            "exploitability_score": 0.95,
            "attack_scenario": "Attacker submits crafted input.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score_estimate": 9.8,
            "cwe_id": "CWE-78",
            "dataflow_summary": "user_input → exec()",
            "remediation": "Use parameterised API",
            "false_positive_reason": None,
            "tool": "semgrep",
            "rule_id": "python.injection.exec",
            "exploit_code": None,
            "patch_code": None,
        }
        result = validate_structured_response(raw, FINDING_RESULT_SCHEMA)
        assert result.quality == 1.0
        assert result.incomplete == []
        assert result.coerced == []

    def test_minimal_required_only(self):
        raw = {
            "finding_id": "FIND-002",
            "is_true_positive": False,
            "is_exploitable": False,
            "reasoning": "Dead code path.",
        }
        result = validate_structured_response(raw, FINDING_RESULT_SCHEMA)
        assert "finding_id" not in result.incomplete
        assert "reasoning" not in result.incomplete
        assert result.quality > 0.0

    def test_nullable_fields_accepted(self):
        raw = {
            "finding_id": "FIND-003",
            "is_true_positive": True,
            "is_exploitable": False,
            "reasoning": "Sanitiser effective.",
            "confidence": None,
            "attack_scenario": None,
            "exploit_code": None,
            "patch_code": None,
            "cvss_vector": None,
            "vuln_type": None,
            "cwe_id": None,
            "false_positive_reason": None,
            "tool": None,
            "rule_id": None,
        }
        result = validate_structured_response(raw, FINDING_RESULT_SCHEMA)
        for field_name in ("confidence", "attack_scenario", "exploit_code"):
            assert result.fields[field_name].status == "ok"
            assert result.data[field_name] is None

    def test_invalid_ruling_value(self):
        raw = {
            "finding_id": "FIND-004",
            "is_true_positive": True,
            "is_exploitable": True,
            "reasoning": "text",
            "ruling": "DEFINITELY_BAD",
        }
        result = validate_structured_response(raw, FINDING_RESULT_SCHEMA)
        assert "ruling" in result.incomplete or result.fields["ruling"].status in ("invalid", "coerced")


# ---------------------------------------------------------------------------
# Full validation — dataflow schema
# ---------------------------------------------------------------------------

class TestValidateDataflowSchema:
    def test_perfect_dataflow(self):
        raw = {
            "source_type": "user_input",
            "source_attacker_controlled": True,
            "source_reasoning": "HTTP parameter",
            "sanitizers_found": 1,
            "sanitizers_effective": False,
            "sanitizer_details": [{"name": "htmlEscape", "purpose": "XSS", "bypass_possible": True, "bypass_method": "attribute context"}],
            "path_reachable": True,
            "reachability_barriers": [],
            "is_exploitable": True,
            "exploitability_confidence": 0.9,
            "exploitability_reasoning": "Direct flow to innerHTML",
            "attack_complexity": "low",
            "attack_prerequisites": ["authenticated user"],
            "attack_payload_concept": "<img onerror=alert(1)>",
            "impact_if_exploited": "XSS → session hijack",
            "cvss_estimate": 7.5,
            "false_positive": False,
            "false_positive_reason": "",
        }
        result = validate_structured_response(raw, DATAFLOW_VALIDATION_SCHEMA)
        assert result.quality == 1.0
        assert result.incomplete == []

    def test_exploitability_confidence_out_of_range(self):
        raw = {
            "source_type": "user_input",
            "source_attacker_controlled": True,
            "source_reasoning": "HTTP param",
            "sanitizers_found": 0,
            "sanitizers_effective": False,
            "sanitizer_details": [],
            "path_reachable": True,
            "reachability_barriers": [],
            "is_exploitable": True,
            "exploitability_confidence": 1.5,
            "exploitability_reasoning": "text",
            "attack_complexity": "low",
            "attack_prerequisites": [],
            "attack_payload_concept": "payload",
            "impact_if_exploited": "RCE",
            "cvss_estimate": 9.0,
            "false_positive": False,
            "false_positive_reason": "",
        }
        result = validate_structured_response(raw, DATAFLOW_VALIDATION_SCHEMA)
        assert "exploitability_confidence" in result.incomplete

    def test_cvss_estimate_out_of_range(self):
        raw = {
            "source_type": "config",
            "source_attacker_controlled": False,
            "source_reasoning": "hardcoded",
            "sanitizers_found": 0,
            "sanitizers_effective": True,
            "sanitizer_details": [],
            "path_reachable": False,
            "reachability_barriers": ["auth required"],
            "is_exploitable": False,
            "exploitability_confidence": 0.2,
            "exploitability_reasoning": "not reachable",
            "attack_complexity": "high",
            "attack_prerequisites": ["admin access"],
            "attack_payload_concept": "",
            "impact_if_exploited": "none",
            "cvss_estimate": 15.0,
            "false_positive": True,
            "false_positive_reason": "unreachable",
        }
        result = validate_structured_response(raw, DATAFLOW_VALIDATION_SCHEMA)
        assert "cvss_estimate" in result.incomplete


# ---------------------------------------------------------------------------
# Quality scoring
# ---------------------------------------------------------------------------

class TestQualityScoring:
    def test_all_present_correct_is_1(self):
        schema = {"a": "boolean", "b": "string"}
        raw = {"a": True, "b": "hello"}
        result = validate_structured_response(raw, schema)
        assert result.quality == 1.0

    def test_all_missing_required_is_low(self):
        schema = {"a": "boolean", "b": "string"}
        result = validate_structured_response({}, schema)
        assert result.quality < 0.5

    def test_coerced_field_slightly_penalised(self):
        schema = {"a": "boolean", "b": "string"}
        raw_perfect = {"a": True, "b": "text"}
        raw_coerced = {"a": "true", "b": "text"}
        q_perfect = validate_structured_response(raw_perfect, schema).quality
        q_coerced = validate_structured_response(raw_coerced, schema).quality
        assert q_perfect > q_coerced
        assert q_coerced > 0.8

    def test_quality_bounded_0_1(self):
        schema = {"x": "string"}
        for raw in [{}, {"x": "ok"}, {"x": 42}]:
            result = validate_structured_response(raw, schema)
            assert 0.0 <= result.quality <= 1.0

    def test_weighted_fields(self):
        schema = ANALYSIS_SCHEMA
        raw_high_weight = {
            "is_exploitable": True,
            "reasoning": "text",
            "is_true_positive": True,
        }
        raw_low_weight = {
            "false_positive_reason": "test",
            "remediation": "fix it",
            "prerequisites": ["none"],
        }
        q_high = validate_structured_response(raw_high_weight, schema).quality
        q_low = validate_structured_response(raw_low_weight, schema).quality
        assert q_high > q_low


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_nan_score_rejected(self):
        schema = {"exploitability_score": "float (0.0-1.0)"}
        raw = {"exploitability_score": float("nan")}
        result = validate_structured_response(raw, schema)
        assert "exploitability_score" in result.incomplete

    def test_inf_score_rejected(self):
        schema = {"exploitability_score": "float (0.0-1.0)"}
        raw = {"exploitability_score": float("inf")}
        result = validate_structured_response(raw, schema)
        assert "exploitability_score" in result.incomplete

    def test_extra_fields_ignored(self):
        schema = {"a": "string"}
        raw = {"a": "hello", "extra": "ignored"}
        result = validate_structured_response(raw, schema)
        assert "extra" not in result.data
        assert result.quality == 1.0

    def test_raw_preserved(self):
        schema = {"a": "string"}
        raw = {"a": "hello", "extra": "kept"}
        result = validate_structured_response(raw, schema)
        assert result.raw == {"a": "hello", "extra": "kept"}

    def test_original_preserved_on_coercion(self):
        schema = {"a": "boolean"}
        raw = {"a": "yes"}
        result = validate_structured_response(raw, schema)
        assert result.fields["a"].original == "yes"
        assert result.data["a"] is True

    def test_null_required_field_invalid(self):
        schema = {
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        raw = {"name": None}
        result = validate_structured_response(raw, schema)
        assert "name" in result.incomplete
        assert result.fields["name"].status == "invalid"

    def test_null_nullable_field_ok(self):
        schema = {
            "properties": {"name": {"type": ["string", "null"]}},
            "required": ["name"],
        }
        raw = {"name": None}
        result = validate_structured_response(raw, schema)
        assert result.fields["name"].status == "ok"
        assert result.data["name"] is None


# ---------------------------------------------------------------------------
# quality_retry_prompt
# ---------------------------------------------------------------------------

class TestQualityRetryPrompt:
    def test_incomplete_fields(self):
        prompt = quality_retry_prompt("Analyze this.", ["reasoning", "vuln_type"], [])
        assert "reasoning" in prompt
        assert "vuln_type" in prompt
        assert "Missing or invalid" in prompt
        assert "Analyze this." in prompt

    def test_coerced_fields(self):
        prompt = quality_retry_prompt("Analyze this.", [], ["is_exploitable"])
        assert "is_exploitable" in prompt
        assert "type coercion" in prompt

    def test_both(self):
        prompt = quality_retry_prompt("Analyze.", ["cwe_id"], ["confidence"])
        assert "cwe_id" in prompt
        assert "confidence" in prompt

    def test_empty_no_crash(self):
        prompt = quality_retry_prompt("Analyze.", [], [])
        assert "Analyze." in prompt


# ---------------------------------------------------------------------------
# Real-schema integration
# ---------------------------------------------------------------------------

class TestRealSchemaIntegration:
    def test_analysis_schema_good_response(self):
        raw = {
            "is_true_positive": True,
            "is_exploitable": True,
            "exploitability_score": 0.85,
            "confidence": "high",
            "severity_assessment": "critical",
            "ruling": "validated",
            "reasoning": "Direct user input flows to os.system() without sanitisation.",
            "attack_scenario": "Attacker sends `; rm -rf /` in the name field.",
            "prerequisites": ["Network access to web app"],
            "impact": "Remote code execution",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score_estimate": 9.8,
            "vuln_type": "command_injection",
            "cwe_id": "CWE-78",
            "dataflow_summary": "request.params['name'] → os.system(cmd)",
            "remediation": "Use subprocess.run with list args",
            "false_positive_reason": None,
        }
        result = validate_structured_response(raw, ANALYSIS_SCHEMA)
        assert result.quality >= 0.95
        assert result.incomplete == []

    def test_analysis_schema_typical_llm_sloppiness(self):
        raw = {
            "is_true_positive": "yes",
            "is_exploitable": "True",
            "exploitability_score": "0.7",
            "confidence": "HIGH",
            "severity_assessment": "High",
            "ruling": "Validated",
            "reasoning": "Input reaches sink.",
            "attack_scenario": "Craft malicious input.",
            "prerequisites": "Network access",
            "impact": "RCE",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score_estimate": 9.8,
            "vuln_type": "RCE",
            "cwe_id": "CWE-78",
            "dataflow_summary": "input → exec",
            "remediation": "Fix it",
            "false_positive_reason": None,
        }
        result = validate_structured_response(raw, ANALYSIS_SCHEMA)
        assert result.data["is_true_positive"] is True
        assert result.data["is_exploitable"] is True
        assert result.data["confidence"] == "high"
        assert result.data["severity_assessment"] == "high"
        assert result.data["vuln_type"] == "command_injection"
        assert result.data["prerequisites"] == ["Network access"]
        assert result.quality > 0.5

    def test_finding_result_schema_weight_detection(self):
        weights = _resolve_weights(FINDING_RESULT_SCHEMA)
        assert weights is _FINDING_RESULT_WEIGHTS

    def test_dataflow_schema_weight_detection(self):
        weights = _resolve_weights(DATAFLOW_VALIDATION_SCHEMA)
        assert weights is _DATAFLOW_VALIDATION_WEIGHTS
