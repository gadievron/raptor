"""Malformed row confidence is a reported rejection, not a pack-wide crash."""

from decimal import Decimal
from fractions import Fraction

import pytest

from core.dataflow.extension_pack import ModelRow, _validate_common, write_extension_pack


def _row(name, confidence):
    return ModelRow(role="sink", provenance="mechanical", name=name,
                    access_input="Argument[*0]", model_kind="command-injection",
                    confidence=confidence)


@pytest.mark.parametrize("confidence", ["high", None, True, [], complex(0.5, 0), Decimal("NaN"), float("nan"), float("inf"), -0.1, 1.1],
                         ids=["text", "none", "bool", "array", "complex", "decimal-nan", "nan", "infinity", "negative", "over-one"])
def test_malformed_confidence_does_not_discard_valid_rows(tmp_path, confidence):
    result = write_extension_pack([_row("owned_bad", confidence), _row("owned_good", 0.5)],
                                  language="cpp", out_dir=tmp_path)
    assert result.rows_written == 1
    assert len(result.rejected) == 1
    assert "confidence" in result.rejected[0].reason
    model = result.model_file.read_text(encoding="utf-8")
    assert "owned_good" in model
    assert "owned_bad" not in model


@pytest.mark.parametrize("confidence", [0, 1, 0.5, Decimal("0.5"), Fraction(1, 2)],
                         ids=["zero", "one", "float", "decimal", "fraction"])
def test_existing_numeric_confidence_remains_supported(confidence):
    assert _validate_common(_row("owned_good", confidence)) is None
