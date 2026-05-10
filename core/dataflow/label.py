"""Ground-truth labels for the dataflow corpus.

A :class:`GroundTruth` record sits beside each :class:`~core.dataflow.Finding`
in ``core/dataflow/corpus/findings/`` as a sibling
``<finding_id>.label.json`` file. The corpus runner (``run_corpus.py``)
matches each finding to its label by ``finding_id`` and diffs the
validator's output against ``verdict`` to compute precision/recall.

``fp_category`` exists so the corpus run can tell us *which* FP class
is moving when a feature ships. The pivot gate in the design doc
rejects building PR1+ if ``missing_sanitizer_model`` doesn't dominate
the FP distribution — without categories we can't enforce that.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Mapping, Optional


SCHEMA_VERSION = 1


VERDICT_TRUE_POSITIVE = "true_positive"
VERDICT_FALSE_POSITIVE = "false_positive"
VALID_VERDICTS: FrozenSet[str] = frozenset(
    {VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE}
)


FP_MISSING_SANITIZER_MODEL = "missing_sanitizer_model"
FP_INFEASIBLE_BRANCH = "infeasible_branch"
FP_FRAMEWORK_MITIGATION = "framework_mitigation"
FP_DEAD_CODE = "dead_code"
FP_TYPE_CONSTRAINT = "type_constraint"
FP_REFLECTION_IMPRECISION = "reflection_imprecision"
VALID_FP_CATEGORIES: FrozenSet[str] = frozenset(
    {
        FP_MISSING_SANITIZER_MODEL,
        FP_INFEASIBLE_BRANCH,
        FP_FRAMEWORK_MITIGATION,
        FP_DEAD_CODE,
        FP_TYPE_CONSTRAINT,
        FP_REFLECTION_IMPRECISION,
    }
)


_GROUND_TRUTH_KEYS: FrozenSet[str] = frozenset(
    {
        "schema_version",
        "finding_id",
        "verdict",
        "fp_category",
        "rationale",
        "labeler",
        "labeled_at",
    }
)


_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _check_extra_fields(name: str, data: Mapping[str, Any], allowed: FrozenSet[str]) -> None:
    extras = set(data.keys()) - allowed
    if extras:
        raise ValueError(f"unknown fields in {name} JSON: {sorted(extras)}")


def _require_nonempty(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


@dataclass(frozen=True)
class GroundTruth:
    """One labeled corpus entry.

    ``fp_category`` is required when ``verdict == "false_positive"``
    and must be ``None`` when ``verdict == "true_positive"`` —
    enforced in :meth:`__post_init__`. Categories are validated
    against :data:`VALID_FP_CATEGORIES` so the corpus distribution
    is auditable.

    ``labeled_at`` must match ``YYYY-MM-DD``; ``finding_id``,
    ``rationale``, and ``labeler`` must be non-empty.
    """

    finding_id: str
    verdict: str
    rationale: str
    labeler: str
    labeled_at: str
    fp_category: Optional[str] = None

    def __post_init__(self) -> None:
        _require_nonempty("GroundTruth.finding_id", self.finding_id)
        _require_nonempty("GroundTruth.rationale", self.rationale)
        _require_nonempty("GroundTruth.labeler", self.labeler)
        if not _ISO_DATE_RE.match(self.labeled_at or ""):
            raise ValueError(
                f"GroundTruth.labeled_at must be ISO YYYY-MM-DD, "
                f"got {self.labeled_at!r}"
            )
        if self.verdict not in VALID_VERDICTS:
            raise ValueError(
                f"verdict {self.verdict!r} not in {sorted(VALID_VERDICTS)!r}"
            )
        if self.verdict == VERDICT_TRUE_POSITIVE and self.fp_category is not None:
            raise ValueError(
                "fp_category must be None for true_positive verdicts"
            )
        if self.verdict == VERDICT_FALSE_POSITIVE:
            if self.fp_category is None:
                raise ValueError(
                    "fp_category required for false_positive verdicts"
                )
            if self.fp_category not in VALID_FP_CATEGORIES:
                raise ValueError(
                    f"fp_category {self.fp_category!r} not in "
                    f"{sorted(VALID_FP_CATEGORIES)!r}"
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "fp_category": self.fp_category,
            "rationale": self.rationale,
            "labeler": self.labeler,
            "labeled_at": self.labeled_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GroundTruth":
        _check_extra_fields("GroundTruth", data, _GROUND_TRUTH_KEYS)
        version = data["schema_version"]
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"GroundTruth schema_version {version!r} != expected "
                f"{SCHEMA_VERSION!r}; corpus upgrade required"
            )
        return cls(
            finding_id=data["finding_id"],
            verdict=data["verdict"],
            rationale=data["rationale"],
            labeler=data["labeler"],
            labeled_at=data["labeled_at"],
            fp_category=data.get("fp_category"),
        )

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_json(cls, text: str) -> "GroundTruth":
        return cls.from_dict(json.loads(text))
