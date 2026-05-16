"""Structured sanitizer evidence for dataflow findings.

The shapes here are the **evidence** PR1's path annotator hands to
the existing dataflow validator's LLM prompts — *not* a verdict.
The earlier draft of this design tried a ``verdict`` field with
short-circuit behaviour; it was rejected because collapsing the
suppression decision to a single LLM call is the worst class of
failure for security tooling. See ``~/design/dataflow-sanitizer-bypass.md``
for the rationale.

Three records:

* :class:`CandidateValidator` — one project-specific
  validator/sanitizer extracted from source. Tagged with a closed
  semantics class (``sql_escape``, ``url_allowlist``, ...) and a
  confidence the extractor (LLM, framework catalog, source
  annotation) attached.

* :class:`StepAnnotation` — per-step record of which candidates were
  called, which variables were referenced, and which helpers we
  did NOT follow into. The third field is the honest caveat: every
  consumer must treat the annotation as incomplete past those
  helpers.

* :class:`SanitizerEvidence` — the bundle the validator sees. It
  carries the candidate pool, the per-step annotations, a
  description of how thoroughly the pool was gathered, and a list
  of extraction failures so the LLM downstream knows where the
  evidence is thin.

All three are frozen and validated in ``__post_init__``: closed
enums for ``semantics_tag`` and ``extraction_provenance``, non-empty
required strings, ``confidence`` in ``[0, 1]``, ``source_line >= 1``,
``step_index >= 0``. Strict ``from_dict`` rejects unknown fields.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple


SCHEMA_VERSION = 1


SEMANTICS_SQL_ESCAPE = "sql_escape"
SEMANTICS_HTML_ESCAPE = "html_escape"
SEMANTICS_URL_ALLOWLIST = "url_allowlist"
SEMANTICS_PATH_NORMALIZE = "path_normalize"
SEMANTICS_AUTH_CHECK = "auth_check"
SEMANTICS_TYPE_COERCE = "type_coerce"
SEMANTICS_RATE_LIMIT = "rate_limit"
SEMANTICS_OTHER = "other"
VALID_SEMANTICS_TAGS: FrozenSet[str] = frozenset(
    {
        SEMANTICS_SQL_ESCAPE,
        SEMANTICS_HTML_ESCAPE,
        SEMANTICS_URL_ALLOWLIST,
        SEMANTICS_PATH_NORMALIZE,
        SEMANTICS_AUTH_CHECK,
        SEMANTICS_TYPE_COERCE,
        SEMANTICS_RATE_LIMIT,
        SEMANTICS_OTHER,
    }
)


PROVENANCE_LLM = "llm"
PROVENANCE_ANNOTATION = "annotation"
PROVENANCE_FRAMEWORK_CATALOG = "framework_catalog"
VALID_EXTRACTION_PROVENANCE: FrozenSet[str] = frozenset(
    {PROVENANCE_LLM, PROVENANCE_ANNOTATION, PROVENANCE_FRAMEWORK_CATALOG}
)


_CANDIDATE_KEYS: FrozenSet[str] = frozenset(
    {
        "name",
        "qualified_name",
        "semantics_tag",
        "semantics_text",
        "confidence",
        "source_file",
        "source_line",
        "extraction_provenance",
    }
)
_STEP_ANNOTATION_KEYS: FrozenSet[str] = frozenset(
    {
        "step_index",
        "on_path_validators",
        "variables_referenced",
        "inlined_helpers",
    }
)
_EVIDENCE_KEYS: FrozenSet[str] = frozenset(
    {
        "schema_version",
        "candidate_pool",
        "step_annotations",
        "pool_completeness",
        "extraction_failures",
    }
)


def _check_extra_fields(name: str, data: Mapping[str, Any], allowed: FrozenSet[str]) -> None:
    extras = set(data.keys()) - allowed
    if extras:
        raise ValueError(f"unknown fields in {name} JSON: {sorted(extras)}")


def _require_nonempty(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


@dataclass(frozen=True)
class CandidateValidator:
    """One project-specific validator/sanitizer extracted from source.

    ``semantics_tag`` is the closed-enum class label
    (``sql_escape``, ``url_allowlist``, ...). ``semantics_text`` is
    free-form prose the extractor produced; consumers display it but
    must not parse it. The two fields together let the downstream
    LLM judge whether the validator's actual semantics cover the
    sink's attack class — not a question this schema decides.
    """

    name: str
    qualified_name: str
    semantics_tag: str
    semantics_text: str
    confidence: float
    source_file: str
    source_line: int
    extraction_provenance: str

    def __post_init__(self) -> None:
        _require_nonempty("CandidateValidator.name", self.name)
        _require_nonempty("CandidateValidator.qualified_name", self.qualified_name)
        _require_nonempty("CandidateValidator.semantics_text", self.semantics_text)
        _require_nonempty("CandidateValidator.source_file", self.source_file)
        if self.semantics_tag not in VALID_SEMANTICS_TAGS:
            raise ValueError(
                f"semantics_tag {self.semantics_tag!r} not in "
                f"{sorted(VALID_SEMANTICS_TAGS)!r}"
            )
        if self.extraction_provenance not in VALID_EXTRACTION_PROVENANCE:
            raise ValueError(
                f"extraction_provenance {self.extraction_provenance!r} not in "
                f"{sorted(VALID_EXTRACTION_PROVENANCE)!r}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be in [0, 1], got {self.confidence!r}"
            )
        if self.source_line < 1:
            raise ValueError(
                f"source_line must be >= 1, got {self.source_line!r}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "qualified_name": self.qualified_name,
            "semantics_tag": self.semantics_tag,
            "semantics_text": self.semantics_text,
            "confidence": self.confidence,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "extraction_provenance": self.extraction_provenance,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CandidateValidator":
        _check_extra_fields("CandidateValidator", data, _CANDIDATE_KEYS)
        return cls(
            name=data["name"],
            qualified_name=data["qualified_name"],
            semantics_tag=data["semantics_tag"],
            semantics_text=data["semantics_text"],
            confidence=float(data["confidence"]),
            source_file=data["source_file"],
            source_line=int(data["source_line"]),
            extraction_provenance=data["extraction_provenance"],
        )


@dataclass(frozen=True)
class StepAnnotation:
    """Per-step record from path-traversal annotation.

    ``on_path_validators`` are the qualified names of candidates
    matched against function calls in the step's snippet.
    ``variables_referenced`` is the set of identifiers the snippet
    reads — important for the dataflow caveat
    (``was the validator called on the *tainted variable*?``).
    ``inlined_helpers`` records calls the annotator did NOT follow
    into; consumers know the annotation is incomplete past those.
    """

    step_index: int
    on_path_validators: Tuple[str, ...] = ()
    variables_referenced: Tuple[str, ...] = ()
    inlined_helpers: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.step_index < 0:
            raise ValueError(
                f"step_index must be >= 0, got {self.step_index!r}"
            )
        for label, value in (
            ("on_path_validators", self.on_path_validators),
            ("variables_referenced", self.variables_referenced),
            ("inlined_helpers", self.inlined_helpers),
        ):
            if not isinstance(value, tuple):
                object.__setattr__(self, label, tuple(value))
            for item in getattr(self, label):
                if not isinstance(item, str) or not item.strip():
                    raise ValueError(
                        f"StepAnnotation.{label} entries must be non-empty strings"
                    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "on_path_validators": list(self.on_path_validators),
            "variables_referenced": list(self.variables_referenced),
            "inlined_helpers": list(self.inlined_helpers),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StepAnnotation":
        _check_extra_fields("StepAnnotation", data, _STEP_ANNOTATION_KEYS)
        return cls(
            step_index=int(data["step_index"]),
            on_path_validators=tuple(data.get("on_path_validators", [])),
            variables_referenced=tuple(data.get("variables_referenced", [])),
            inlined_helpers=tuple(data.get("inlined_helpers", [])),
        )


@dataclass(frozen=True)
class SanitizerEvidence:
    """The full evidence bundle for one :class:`Finding`.

    The validator pipeline reads this *before* its existing LLM call
    and folds it into the prompt as a structured block. There is no
    verdict field — by design. Suppression decisions stay with the
    existing LLM gate; this just gives it cleaner inputs.

    ``pool_completeness`` is a free-form description (e.g.
    ``"scoped_to_5_files"`` or ``"project_wide"``) so the downstream
    LLM knows how exhaustively the pool was gathered.
    ``extraction_failures`` lists files / steps that the extractor
    couldn't parse or where the LLM call errored.
    """

    candidate_pool: Tuple[CandidateValidator, ...] = ()
    step_annotations: Tuple[StepAnnotation, ...] = ()
    pool_completeness: str = "unknown"
    extraction_failures: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty("SanitizerEvidence.pool_completeness", self.pool_completeness)
        for label, value, ty in (
            ("candidate_pool", self.candidate_pool, CandidateValidator),
            ("step_annotations", self.step_annotations, StepAnnotation),
        ):
            if not isinstance(value, tuple):
                object.__setattr__(self, label, tuple(value))
            for item in getattr(self, label):
                if not isinstance(item, ty):
                    raise TypeError(
                        f"SanitizerEvidence.{label} must contain {ty.__name__} instances"
                    )
        if not isinstance(self.extraction_failures, tuple):
            object.__setattr__(self, "extraction_failures", tuple(self.extraction_failures))
        for f in self.extraction_failures:
            if not isinstance(f, str) or not f.strip():
                raise ValueError(
                    "SanitizerEvidence.extraction_failures entries must be non-empty strings"
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "candidate_pool": [c.to_dict() for c in self.candidate_pool],
            "step_annotations": [s.to_dict() for s in self.step_annotations],
            "pool_completeness": self.pool_completeness,
            "extraction_failures": list(self.extraction_failures),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SanitizerEvidence":
        _check_extra_fields("SanitizerEvidence", data, _EVIDENCE_KEYS)
        version = data["schema_version"]
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"SanitizerEvidence schema_version {version!r} != expected "
                f"{SCHEMA_VERSION!r}; consumer upgrade required"
            )
        return cls(
            candidate_pool=tuple(
                CandidateValidator.from_dict(c)
                for c in data.get("candidate_pool", [])
            ),
            step_annotations=tuple(
                StepAnnotation.from_dict(s)
                for s in data.get("step_annotations", [])
            ),
            pool_completeness=data.get("pool_completeness", "unknown"),
            extraction_failures=tuple(data.get("extraction_failures", [])),
        )

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_json(cls, text: str) -> "SanitizerEvidence":
        return cls.from_dict(json.loads(text))
