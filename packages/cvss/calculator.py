"""CVSS v3.1 base score calculator.

Implements the base score formula from the CVSS v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document

No external dependencies. LLM picks the 8 categorical metrics,
this module computes the numeric score.
"""

import math
import re
from typing import Optional

# Metric value weights from CVSS v3.1 specification tables.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                           # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}             # Privileges Required (Scope Unchanged)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}             # Privileges Required (Scope Changed)
_UI = {"N": 0.85, "R": 0.62}                           # User Interaction
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}               # Confidentiality, Integrity, Availability

_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
_VALID_VALUES = {
    "AV": set(_AV), "AC": set(_AC),
    "PR": {"N", "L", "H"}, "UI": set(_UI),
    "S": {"U", "C"},
    "C": set(_CIA), "I": set(_CIA), "A": set(_CIA),
}

_SEVERITY = [
    (0.0, "None"), (0.1, "Low"), (4.0, "Medium"),
    (7.0, "High"), (9.0, "Critical"),
]

_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/"
    r"AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:[NLH]/I:[NLH]/A:[NLH]"
    # Optional temporal (E, RL, RC) and environmental
    # (CR/IR/AR, MAV/MAC/MPR/MUI/MS, MC/MI/MA) segments. Real-world
    # OSV records routinely include these — Log4Shell ships
    # ``…/A:H/E:H`` — and rejecting them silently degraded scoring to
    # ``None``. Each extension is ``METRIC:VALUE`` where the metric is
    # alphabetic and the value is a single token; we accept any such
    # suffix. ``compute_base_score`` ignores keys it doesn't recognise.
    r"(?:/[A-Za-z]+:[A-Za-z0-9]+)*"
    r"$"
)


def validate_vector(vector: str) -> bool:
    """Check if a CVSS v3.1 vector string is well-formed.

    Accepts base-only vectors and vectors carrying optional temporal /
    environmental extensions (``/E:H``, ``/RL:O``, ``/CR:H`` …). Only
    the base segments contribute to the numeric score; the extensions
    are tolerated, not consumed.
    """
    return bool(_VECTOR_RE.match(vector))


def parse_vector(vector: str) -> dict:
    """Parse a CVSS v3.1 vector string into a metric dict.

    Returns dict like ``{"AV": "N", "AC": "L", "PR": "N", ...}``.
    Raises ValueError if the vector is malformed.

    The eight base metrics (``AV``, ``AC``, ``PR``, ``UI``, ``S``,
    ``C``, ``I``, ``A``) are always present on a valid vector. When
    the input carries optional temporal (``E``, ``RL``, ``RC``) or
    environmental (``CR``, ``IR``, ``AR``, ``MAV``…``MA``) extensions,
    those keys are also returned in the dict — callers iterating
    ``items()`` will see them. ``compute_base_score`` looks up each
    base metric by name and ignores extras, so extension keys never
    influence the numeric output.
    """
    if not validate_vector(vector):
        raise ValueError(f"Invalid CVSS v3.1 vector: {vector}")

    parts = vector.split("/")[1:]  # Skip "CVSS:3.1" prefix
    metrics = {}
    for part in parts:
        key, value = part.split(":")
        metrics[key] = value
    return metrics


def compute_base_score(vector: str) -> tuple[float, str]:
    """Compute the CVSS v3.1 base score from a vector string.

    Returns (score, severity_label) where score is 0.0-10.0 and
    severity_label is one of: None, Low, Medium, High, Critical.

    Raises ValueError if the vector is malformed.
    """
    m = parse_vector(vector)

    # Impact Sub-Score (ISS)
    iss = 1.0 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))

    if iss <= 0:
        return 0.0, "None"

    # Exploitability
    pr_weights = _PR_C if m["S"] == "C" else _PR_U
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_weights[m["PR"]] * _UI[m["UI"]]

    # Impact
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    if impact <= 0:
        return 0.0, "None"

    # Base Score
    if m["S"] == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    # Round up to nearest 0.1
    score = math.ceil(score * 10) / 10

    # Severity label
    label = "None"
    for threshold, name in _SEVERITY:
        if score >= threshold:
            label = name

    return score, label


def compute_score_safe(vector: Optional[str]) -> tuple[Optional[float], Optional[str]]:
    """Compute CVSS score, returning (None, None) for missing or invalid vectors."""
    if not vector:
        return None, None
    try:
        return compute_base_score(vector)
    except ValueError:
        return None, None


def score_finding(finding: dict) -> None:
    """Compute CVSS score for a single finding dict. Modifies in place.

    If the finding has a cvss_vector, computes the numeric score and
    sets cvss_score_estimate and severity_assessment.
    """
    vec = finding.get("cvss_vector")
    if vec:
        score, label = compute_score_safe(vec)
        if score is not None:
            finding["cvss_score_estimate"] = score
            finding["severity_assessment"] = label.lower()


def score_findings(findings: list[dict]) -> None:
    """Compute CVSS scores for a list of finding dicts. Modifies in place."""
    for f in findings:
        score_finding(f)
