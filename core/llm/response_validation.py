"""Boundary validation for LLM structured responses.

Validates, normalises, and scores LLM-returned dicts field-by-field
rather than all-or-nothing.  Runs at the generate_structured boundary
so consumers receive a quality-scored response with bad fields nulled
and flagged, instead of either a raw unchecked dict or an exception.

Works with both schema formats used in the codebase:
  - Simple: {"field": "type description"}
  - JSON Schema: {"properties": {...}, "required": [...]}
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.schema_constants import (
    AGENTIC_RULING_VALUES,
    CONFIDENCE_LEVELS,
    SEVERITY_LEVELS,
    VULN_TYPES,
    normalise_vuln_type,
)

_CVSS_RE = re.compile(
    r"^CVSS:3\.[01]/"
    r"AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:[NLH]/I:[NLH]/A:[NLH]$"
)
_CWE_RE = re.compile(r"^CWE-\d+$")


@dataclass
class FieldResult:
    """Outcome of validating a single field."""
    status: str   # "ok", "coerced", "missing", "invalid"
    original: Any = None


@dataclass
class ValidatedResponse:
    """Result of validate_structured_response."""
    data: Dict[str, Any]
    quality: float
    incomplete: List[str] = field(default_factory=list)
    coerced: List[str] = field(default_factory=list)
    fields: Dict[str, FieldResult] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


# ---- Field weights per schema ------------------------------------------------
# Keyed by a schema identifier (first required field tuple as a proxy).
# Unknown schemas get uniform weights.

_ANALYSIS_WEIGHTS: Dict[str, float] = {
    "is_true_positive": 1.0,
    "is_exploitable": 1.0,
    "reasoning": 1.0,
    "confidence": 0.8,
    "severity_assessment": 0.8,
    "ruling": 0.8,
    "vuln_type": 0.7,
    "exploitability_score": 0.6,
    "attack_scenario": 0.5,
    "cvss_vector": 0.5,
    "cwe_id": 0.4,
    "dataflow_summary": 0.3,
    "remediation": 0.3,
    "false_positive_reason": 0.2,
    "impact": 0.3,
    "prerequisites": 0.2,
}

_FINDING_RESULT_WEIGHTS: Dict[str, float] = {
    "finding_id": 1.0,
    "is_true_positive": 1.0,
    "is_exploitable": 1.0,
    "reasoning": 1.0,
    "confidence": 0.8,
    "severity_assessment": 0.8,
    "ruling": 0.8,
    "vuln_type": 0.7,
    "exploitability_score": 0.6,
    "attack_scenario": 0.5,
    "cvss_vector": 0.5,
    "cwe_id": 0.4,
    "dataflow_summary": 0.3,
    "remediation": 0.3,
    "false_positive_reason": 0.2,
    "tool": 0.1,
    "rule_id": 0.1,
    "exploit_code": 0.1,
    "patch_code": 0.1,
}

_DATAFLOW_VALIDATION_WEIGHTS: Dict[str, float] = {
    "is_exploitable": 1.0,
    "source_attacker_controlled": 1.0,
    "sanitizers_effective": 0.9,
    "path_reachable": 0.9,
    "exploitability_confidence": 0.8,
    "exploitability_reasoning": 0.8,
    "false_positive": 0.7,
    "attack_complexity": 0.6,
    "source_type": 0.5,
    "source_reasoning": 0.5,
    "sanitizers_found": 0.4,
    "sanitizer_details": 0.3,
    "reachability_barriers": 0.3,
    "attack_prerequisites": 0.3,
    "attack_payload_concept": 0.3,
    "impact_if_exploited": 0.4,
    "cvss_estimate": 0.3,
    "false_positive_reason": 0.2,
}

# Registry: recognise schema by its field set and return the right weights.
_WEIGHT_REGISTRY: List[tuple[Set[str], Dict[str, float]]] = [
    ({"finding_id", "is_true_positive", "is_exploitable", "reasoning"}, _FINDING_RESULT_WEIGHTS),
    ({"source_attacker_controlled", "sanitizers_effective", "path_reachable"}, _DATAFLOW_VALIDATION_WEIGHTS),
    ({"is_true_positive", "is_exploitable", "reasoning"}, _ANALYSIS_WEIGHTS),
]

_DEFAULT_WEIGHT = 0.5


def _resolve_weights(schema: Dict[str, Any]) -> Dict[str, float]:
    """Pick the right weight table for a schema, or fall back to uniform."""
    props = _get_properties(schema)
    field_names = set(props.keys())
    for signature, weights in _WEIGHT_REGISTRY:
        if signature <= field_names:
            return weights
    return {f: _DEFAULT_WEIGHT for f in field_names}


# ---- Schema helpers ----------------------------------------------------------

def _get_properties(schema: Dict[str, Any]) -> Dict[str, Any]:
    if "properties" in schema:
        return schema.get("properties", {})
    # Simple schema: values are description strings like "boolean" or
    # "float (0.0-1.0)".  Return as-is — _get_field_type and _is_nullable
    # both handle string descriptions.
    return schema


def _get_required(schema: Dict[str, Any]) -> Set[str]:
    if "properties" in schema:
        return set(schema.get("required", []))
    return set(schema.keys())


def _get_field_type(field_spec: Any) -> str:
    """Extract the primary type from a JSON Schema property or simple description."""
    if isinstance(field_spec, str):
        token = field_spec.split()[0].strip().lower()
        return {"bool": "boolean", "str": "string", "int": "integer",
                "float": "number", "list": "array"}.get(token, token)
    if isinstance(field_spec, dict):
        t = field_spec.get("type", "string")
        if isinstance(t, list):
            return next((x for x in t if x != "null"), "string")
        return t
    return "string"


def _is_nullable(field_spec: Any) -> bool:
    if isinstance(field_spec, str):
        return "or null" in field_spec.lower() or "null" in field_spec.lower()
    if isinstance(field_spec, dict):
        t = field_spec.get("type")
        if isinstance(t, list) and "null" in t:
            return True
    return False


# ---- Domain normalisers ------------------------------------------------------
# Each returns (normalised_value, was_coerced).

def _normalise_vuln_type(value: Any) -> tuple[Any, bool]:
    if not isinstance(value, str) or not value:
        return value, False
    normalised = normalise_vuln_type(value)
    return normalised, normalised != value


def _normalise_status_field(value: Any) -> tuple[Any, bool]:
    from packages.exploitability_validation.orchestrator import normalize_status
    if not isinstance(value, str) or not value:
        return value, False
    normalised = normalize_status(value)
    return normalised, normalised != value


def _normalise_severity(value: Any) -> tuple[Any, bool]:
    if not isinstance(value, str) or not value:
        return value, False
    lower = value.lower().strip()
    if lower in SEVERITY_LEVELS:
        return lower, lower != value
    return value, False


def _normalise_confidence(value: Any) -> tuple[Any, bool]:
    if not isinstance(value, str) or not value:
        return value, False
    lower = value.lower().strip()
    if lower in CONFIDENCE_LEVELS:
        return lower, lower != value
    return value, False


_DOMAIN_NORMALISERS: Dict[str, Any] = {
    "vuln_type": _normalise_vuln_type,
    "ruling": _normalise_status_field,
    "severity_assessment": _normalise_severity,
    "confidence": _normalise_confidence,
    "final_status": _normalise_status_field,
    "status": _normalise_status_field,
}


# ---- Domain validators -------------------------------------------------------
# Each returns True if the value is acceptable after normalisation.

def _validate_vuln_type(value: Any) -> bool:
    return isinstance(value, str) and value in VULN_TYPES


def _validate_ruling(value: Any) -> bool:
    return isinstance(value, str) and value in AGENTIC_RULING_VALUES


def _validate_severity(value: Any) -> bool:
    return isinstance(value, str) and value in SEVERITY_LEVELS


def _validate_confidence(value: Any) -> bool:
    return isinstance(value, str) and value in CONFIDENCE_LEVELS


def _validate_cvss_vector(value: Any) -> bool:
    return isinstance(value, str) and bool(_CVSS_RE.match(value))


def _validate_cwe_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_CWE_RE.match(value))


def _validate_score_0_1(value: Any) -> bool:
    if not isinstance(value, (int, float)):
        return False
    if math.isnan(value) or math.isinf(value):
        return False
    return 0.0 <= value <= 1.0


def _validate_score_0_10(value: Any) -> bool:
    if not isinstance(value, (int, float)):
        return False
    if math.isnan(value) or math.isinf(value):
        return False
    return 0.0 <= value <= 10.0


_DOMAIN_VALIDATORS: Dict[str, Any] = {
    "vuln_type": _validate_vuln_type,
    "ruling": _validate_ruling,
    "severity_assessment": _validate_severity,
    "confidence": _validate_confidence,
    "cvss_vector": _validate_cvss_vector,
    "cwe_id": _validate_cwe_id,
    "exploitability_score": _validate_score_0_1,
    "exploitability_confidence": _validate_score_0_1,
    "cvss_score_estimate": _validate_score_0_10,
    "cvss_estimate": _validate_score_0_10,
}


# ---- Type coercion -----------------------------------------------------------

def _coerce_value(value: Any, field_type: str) -> tuple[Any, bool]:
    """Coerce a value to the target type.  Returns (value, was_coerced)."""
    if field_type == "boolean":
        if isinstance(value, bool):
            return value, False
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1"), True
        if isinstance(value, (int, float)):
            return bool(value), True
        return False, True

    if field_type == "number":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value, False
        try:
            return float(value), True
        except (ValueError, TypeError):
            return None, True

    if field_type == "integer":
        if isinstance(value, int) and not isinstance(value, bool):
            return value, False
        try:
            return int(value), True
        except (ValueError, TypeError):
            return None, True

    if field_type == "string":
        if isinstance(value, str):
            return value, False
        if value is None:
            return "", True
        return str(value), True

    if field_type == "array":
        if isinstance(value, list):
            return value, False
        if isinstance(value, str):
            return [value], True
        return [], True

    if field_type == "object":
        if isinstance(value, dict):
            return value, False
        return {}, True

    return value, False


# ---- Main entry point --------------------------------------------------------

def validate_structured_response(
    raw: Dict[str, Any],
    schema: Dict[str, Any],
) -> ValidatedResponse:
    """Validate and normalise an LLM response dict against a schema.

    Per-field: coerce types, apply domain normalisers, validate domain
    constraints, score quality.  Keeps good fields, nulls bad ones,
    flags everything.
    """
    if not isinstance(raw, dict):
        return ValidatedResponse(
            data={}, quality=0.0,
            incomplete=list(_get_properties(schema).keys()),
            raw={},
        )

    properties = _get_properties(schema)
    required = _get_required(schema)
    weights = _resolve_weights(schema)

    data: Dict[str, Any] = {}
    fields: Dict[str, FieldResult] = {}
    incomplete: List[str] = []
    coerced_fields: List[str] = []

    weighted_score = 0.0
    total_weight = 0.0

    for field_name, field_spec in properties.items():
        weight = weights.get(field_name, _DEFAULT_WEIGHT)
        total_weight += weight
        field_type = _get_field_type(field_spec)
        nullable = _is_nullable(field_spec)

        if field_name not in raw:
            if nullable or field_name not in required:
                data[field_name] = None
                fields[field_name] = FieldResult(status="missing")
                # Optional missing fields don't penalise quality
                weighted_score += weight * 0.5
            else:
                data[field_name] = None
                fields[field_name] = FieldResult(status="missing")
                incomplete.append(field_name)
            continue

        value = raw[field_name]
        original = value
        was_coerced = False

        # Null handling
        if value is None:
            if nullable:
                data[field_name] = None
                fields[field_name] = FieldResult(status="ok", original=original)
                weighted_score += weight
                continue
            else:
                data[field_name] = None
                fields[field_name] = FieldResult(status="invalid", original=original)
                incomplete.append(field_name)
                continue

        # Type coercion
        value, type_coerced = _coerce_value(value, field_type)
        was_coerced = was_coerced or type_coerced

        if value is None and not nullable:
            data[field_name] = None
            fields[field_name] = FieldResult(status="invalid", original=original)
            incomplete.append(field_name)
            continue

        # Domain normalisation
        normaliser = _DOMAIN_NORMALISERS.get(field_name)
        if normaliser is not None and value is not None:
            value, norm_coerced = normaliser(value)
            was_coerced = was_coerced or norm_coerced

        # Domain validation
        validator = _DOMAIN_VALIDATORS.get(field_name)
        if validator is not None and value is not None:
            if not validator(value):
                data[field_name] = value
                status = "coerced" if was_coerced else "invalid"
                fields[field_name] = FieldResult(status=status, original=original)
                if was_coerced:
                    coerced_fields.append(field_name)
                    weighted_score += weight * 0.5
                else:
                    incomplete.append(field_name)
                    weighted_score += weight * 0.25
                continue

        # Passed
        data[field_name] = value
        if was_coerced:
            fields[field_name] = FieldResult(status="coerced", original=original)
            coerced_fields.append(field_name)
            weighted_score += weight * 0.9
        else:
            fields[field_name] = FieldResult(status="ok", original=original)
            weighted_score += weight

    quality = weighted_score / total_weight if total_weight > 0 else 0.0
    quality = max(0.0, min(1.0, quality))

    # Deep-copy `raw` so a downstream caller mutating
    # `validated.raw["nested"]["field"]` doesn't reach back through
    # the shallow `dict(raw)` and mutate the original LLM response —
    # which OTHER readers (telemetry, retry-prompt construction,
    # judge dispatch) may still be reading. Cheap relative to the
    # LLM call cost; necessary for isolation.
    from copy import deepcopy
    return ValidatedResponse(
        data=data,
        quality=quality,
        incomplete=incomplete,
        coerced=coerced_fields,
        fields=fields,
        raw=deepcopy(raw),
    )


def quality_retry_prompt(original_prompt: str, incomplete: List[str],
                         coerced: List[str]) -> str:
    """Build a retry prompt that tells the LLM which fields need fixing."""
    problems = []
    if incomplete:
        problems.append(
            f"Missing or invalid fields: {', '.join(incomplete)}")
    if coerced:
        problems.append(
            f"Fields that needed type coercion (please return correct types): "
            f"{', '.join(coerced)}")
    fix_section = "\n".join(f"- {p}" for p in problems)
    return (
        f"{original_prompt}\n\n"
        f"IMPORTANT: Your previous response had these problems:\n"
        f"{fix_section}\n\n"
        f"Please fix these fields and return the complete JSON again."
    )
