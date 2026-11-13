"""Evidence collection fields must not deserialize strings or mappings."""

import pytest

from core.dataflow.sanitizer_evidence import SanitizerEvidence, StepAnnotation


def test_evidence_collection_shapes():
    shapes = (
        (StepAnnotation, {"step_index": 0}, ("on_path_validators", "variables_referenced", "inlined_helpers")),
        (SanitizerEvidence, {"schema_version": 1}, ("candidate_pool", "step_annotations", "extraction_failures")),
    )
    for cls, base, fields in shapes:
        for field in fields:
            for valid in ([], (), iter(())):
                assert getattr(cls.from_dict({**base, field: valid}), field) == ()
            for invalid in ("", "escape", b"", {}, {"escape": 1}):
                with pytest.raises(ValueError, match=field):
                    cls.from_dict({**base, field: invalid})
    names = ["escape", "validate"]
    annotation = StepAnnotation.from_dict({"step_index": 0, "on_path_validators": names})
    assert annotation.on_path_validators == ("escape", "validate")
    evidence = SanitizerEvidence.from_dict({"schema_version": 1, "extraction_failures": ["fixture.py: parse failed"]})
    assert evidence.extraction_failures == ("fixture.py: parse failed",)
