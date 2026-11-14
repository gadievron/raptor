"""C++/Java subtype cells retain boolean schema types."""

import json
from dataclasses import replace

import pytest

from core.dataflow.extension_pack import ModelRow, write_extension_pack


def _row():
    return ModelRow(role="sink", provenance="mechanical", namespace="owned", type_name="Inert",
                    name="owned_good", access_input="Argument[*0]", model_kind="command-injection")


@pytest.mark.parametrize("language,value", [
    ("cpp", "false"), ("java", "false"), ("cpp", 0), ("java", 1),
    ("cpp", None), ("java", None), ("cpp", [False]), ("java", [True]),
], ids=["cpp-text", "java-text", "cpp-number", "java-number", "cpp-null", "java-null", "cpp-array", "java-array"])
def test_nonboolean_subtype_rejected_with_valid_neighbor(tmp_path, language, value):
    good = _row()
    bad = replace(good, name="owned_bad", subtypes=value)
    result = write_extension_pack([bad, good], language=language, out_dir=tmp_path)
    assert result.rows_written == 1
    assert len(result.rejected) == 1
    assert "subtypes" in result.rejected[0].reason
    text = result.model_file.read_text(encoding="utf-8")
    assert "owned_good" in text
    assert "owned_bad" not in text


@pytest.mark.parametrize("language", ["cpp", "java"])
@pytest.mark.parametrize("subtypes", [False, True], ids=["false", "true"])
def test_boolean_subtype_cell_preserved(tmp_path, language, subtypes):
    result = write_extension_pack([replace(_row(), subtypes=subtypes)], language=language, out_dir=tmp_path)
    assert result.rows_written == 1
    assert result.rejected == ()
    rows = [json.loads(line.removeprefix("      - ")) for line in
            result.model_file.read_text(encoding="utf-8").splitlines() if line.startswith("      - ")]
    assert rows[0][2] is subtypes
