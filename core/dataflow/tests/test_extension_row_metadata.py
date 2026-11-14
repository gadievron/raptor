"""Malformed common metadata is isolated to its rejected extension row."""

from dataclasses import replace

import pytest

from core.dataflow.extension_pack import ModelRow, write_extension_pack


@pytest.mark.parametrize("field,value", [
    ("provenance", ["mechanical"]), ("provenance", {"mechanical": True}),
    ("provenance", 1), ("role", ["sink"]), ("role", {"sink": True}),
    ("model_kind", ["command-injection"]), ("model_kind", 1),
], ids=["provenance-array", "provenance-object", "provenance-number", "role-array", "role-object", "kind-array", "kind-number"])
def test_malformed_common_metadata_retains_valid_neighbor(tmp_path, field, value):
    good = ModelRow(role="sink", provenance="mechanical", name="owned_good",
                    access_input="Argument[*0]", model_kind="command-injection")
    bad = replace(good, name="owned_bad", **{field: value})
    result = write_extension_pack([bad, good], language="cpp", out_dir=tmp_path)
    assert result.rows_written == 1
    assert len(result.rejected) == 1
    assert ("kind" if field == "model_kind" else field) in result.rejected[0].reason
    model = result.model_file.read_text(encoding="utf-8")
    assert "owned_good" in model
    assert "owned_bad" not in model
