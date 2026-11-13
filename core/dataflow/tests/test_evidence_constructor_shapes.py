"""Evidence constructor containers follow the wire intake contract."""

import pytest

from core.dataflow.sanitizer_evidence import SanitizerEvidence, StepAnnotation


def test_direct_evidence_constructors_refuse_scalar_and_mapping_collections():
    for cls, base, fields in (
        (StepAnnotation, {"step_index": 0}, ("on_path_validators", "variables_referenced", "inlined_helpers")),
        (SanitizerEvidence, {}, ("candidate_pool", "step_annotations", "extraction_failures")),
    ):
        for field in fields:
            for invalid in ("", "escape", b"", {}, {"escape": "ignored"}):
                with pytest.raises(ValueError, match=field):
                    cls(**base, **{field: invalid})
            for valid in ([], (), iter(())):
                assert getattr(cls(**base, **{field: valid}), field) == ()
    annotation = StepAnnotation(0, on_path_validators=["escape"], variables_referenced=("value",), inlined_helpers=iter(["helper"]))
    assert annotation.on_path_validators == ("escape",)
    assert annotation.inlined_helpers == ("helper",)
    evidence = SanitizerEvidence(step_annotations=[annotation], extraction_failures=iter(["fixture.py: parse failed"]))
    assert evidence.step_annotations == (annotation,)
    assert evidence.extraction_failures == ("fixture.py: parse failed",)
