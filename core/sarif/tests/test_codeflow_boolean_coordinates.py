"""Code-flow coordinate emission excludes boolean integer subclasses."""

from copy import deepcopy

import pytest

from core.sarif import import_normalizer as normalizer


@pytest.fixture(autouse=True)
def no_source_resolution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("direct step converter entered source resolution")

    for name in ("normalize_imported_findings", "_resolve_uri",
                 "_read_snippet_lines", "_build_file_index", "_infer_cwe"):
        monkeypatch.setattr(normalizer, name, forbidden)


@pytest.mark.parametrize("line, column, coordinates", [
    (True, 5, {"startColumn": 5}),
    (3, True, {"startLine": 3}),
    (True, True, {}),
    (False, False, {}),
    (3, 5, {"startLine": 3, "startColumn": 5}),
    (0, -1, {}),
    (3.0, 5.0, {}),
    (None, None, {}),
], ids=["boolean-line", "boolean-column", "both-true", "both-false",
        "integers", "nonpositive", "floats", "absent"])
def test_coordinate_types_preserve_other_step_fields(line, column, coordinates):
    step = {
        "file": "owned.py", "line": line, "column": column,
        "snippet": "owned marker", "label": "owned label",
        "properties": {"tier": "resolved_static"},
    }
    before = deepcopy(step)
    result = normalizer._step_to_threadflow_location(step)
    physical = result["location"]["physicalLocation"]
    assert physical["region"] == {**coordinates, "snippet": {"text": "owned marker"}}
    for name in coordinates:
        assert type(physical["region"][name]) is int
    assert physical["artifactLocation"] == {"uri": "owned.py"}
    assert result["location"]["message"] == {"text": "owned label"}
    assert result["properties"] == {"tier": "resolved_static"}
    assert step == before
