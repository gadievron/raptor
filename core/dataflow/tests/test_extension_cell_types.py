"""Nontext emitted cells are rejected before grammar or set operations."""

from dataclasses import replace

import pytest

from core.dataflow.extension_pack import ModelRow, write_extension_pack


@pytest.mark.parametrize("language,field,value", [
    ("cpp", "namespace", 1), ("cpp", "type_name", ["owned"]),
    ("cpp", "access_input", ["Argument[*0]"]),
    ("java", "namespace", ["owned"]), ("java", "name", 42),
    ("python", "type_name", ["owned"]), ("python", "path", 42),
    ("javascript", "type_name", ["owned"]), ("javascript", "path", ["Member[run]"]),
], ids=["cpp-namespace", "cpp-type", "cpp-access", "java-package", "java-name", "python-type", "python-path", "javascript-type", "javascript-path"])
def test_nontext_cell_does_not_discard_valid_neighbor(tmp_path, language, field, value):
    good = ModelRow(role="sink", provenance="mechanical", namespace="owned", type_name="owned",
                    name="owned_good", path="Member[run]", access_input="Argument[*0]",
                    model_kind="command-injection")
    bad = replace(good, **{field: value})
    result = write_extension_pack([bad, good], language=language, out_dir=tmp_path)
    assert result.rows_written == 1
    assert len(result.rejected) == 1
    assert "cell" in result.rejected[0].reason
