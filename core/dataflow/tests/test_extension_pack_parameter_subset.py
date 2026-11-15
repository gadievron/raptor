"""Unrepresented propagator parameters must remain explicit conversion loss."""

import pytest

from core.dataflow.extension_pack import rows_from_taint_specs, write_extension_pack
from core.evidence import EvidenceTier
from core.iris.specs import TaintSpec


_LAYOUTS = [
    ("cpp", "proj::wrap", True),
    ("cpp", "proj::wrap", False),
    ("python", "pkg.wrap", True),
    ("javascript", "decodeURIComponent", True),
    ("javascript", "lodash.wrap", True),
]


def _spec(function, params, **overrides):
    values = dict(
        function=function, file="src/owned", role="propagator",
        params_affected=list(params), return_tainted=False,
        confidence=0.9, evidence_tier=EvidenceTier.XREF_BACKED,
    )
    values.update(overrides)
    return TaintSpec(**values)


@pytest.mark.parametrize("language,function,deref", _LAYOUTS)
@pytest.mark.parametrize("params", [[0, 1], [1, 0], [0, 1, 0], [2, 2, 1, 2]])
def test_distinct_parameter_loss_is_rejected(language, function, deref, params):
    spec = _spec(function, params, return_tainted=True)
    before = tuple(spec.params_affected)
    result = rows_from_taint_specs([spec], language=language, deref_cpp_args=deref)
    assert result.rows == ()
    (rejected,) = result.rejected
    assert rejected.row == f"propagator:{function}"
    assert "multiple distinct affected parameters" in rejected.reason
    assert tuple(spec.params_affected) == before


@pytest.mark.parametrize("language,function,deref", _LAYOUTS)
@pytest.mark.parametrize("params", [[], [0], [1], [1, 1], [0, 0, 0]])
def test_single_input_legacy_shapes_survive_emission(
    tmp_path, language, function, deref, params,
):
    spec = _spec(function, params)  # Explicit false return flag remains compatible.
    result = rows_from_taint_specs([spec], language=language, deref_cpp_args=deref)
    assert not result.rejected
    (row,) = result.rows
    index = params[0] if params else 0
    expected = f"Argument[*{index}]" if language == "cpp" and deref else f"Argument[{index}]"
    assert row.access_input == expected
    assert row.access_output == "ReturnValue"
    assert row.provenance == "iris_refined"
    if language == "cpp":
        assert row.namespace == "proj" and row.name == "wrap"
    elif language == "python":
        assert row.type_name == "pkg" and row.path == "Member[wrap]"
    elif function == "decodeURIComponent":
        assert row.type_name == "global" and row.path == "Member[decodeURIComponent]"
    else:
        assert row.type_name == "lodash" and row.path == "Member[wrap]"
    emitted = write_extension_pack(result.rows, language=language, out_dir=tmp_path)
    assert emitted.rows_written == 1 and not emitted.rejected
    assert emitted.model_file.is_file()
    assert spec.return_tainted is False


@pytest.mark.parametrize("gate", ["tier", "confidence"])
def test_existing_admission_gates_precede_subset_refusal(gate):
    values = ({"evidence_tier": EvidenceTier.HEURISTIC}
              if gate == "tier" else {"confidence": 0.2})
    result = rows_from_taint_specs(
        [_spec("proj::wrap", [0, 1], **values)], language="cpp",
    )
    assert not result.rows
    (rejected,) = result.rejected
    assert gate in rejected.reason and "below" in rejected.reason
    assert "multiple distinct" not in rejected.reason


@pytest.mark.parametrize("mixed", [False, True])
def test_conversion_result_retains_all_rejected_and_mixed_loss(tmp_path, mixed):
    specs = [_spec("proj::wrap", [0, 1])]
    if mixed:
        specs.append(_spec("proj::keep", [0]))
    converted = rows_from_taint_specs(specs, language="cpp")
    assert len(converted.rows) == int(mixed)
    (rejected,) = converted.rejected
    assert rejected.row == "propagator:proj::wrap"
    assert "multiple distinct affected parameters" in rejected.reason
    if mixed:
        (row,) = converted.rows
        assert row.name == "keep" and row.access_input == "Argument[*0]"
        emitted = write_extension_pack(converted.rows, language="cpp", out_dir=tmp_path)
        assert emitted.rows_written == 1 and not emitted.rejected
    else:
        assert converted.rows == ()
