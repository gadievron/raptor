"""Portable legacy conversion retains JSON summaries without object stringification."""
from copy import deepcopy
import json

import pytest

from core.reporting.builders import document_from_spec
from core.reporting.document import ReportContext
from core.reporting.renderer import render_report
from core.reporting.renderers import render_document
from core.reporting.spec import ReportSpec


def test_nested_json_legacy_summary_remains_portably_renderable():
    summary = {"Count": 2, "Coverage": {"attempted": 3, "skipped": ["captured"]}}
    original = deepcopy(summary)
    spec = ReportSpec(summary=summary)
    assert "attempted" in render_report(spec)
    document = document_from_spec(spec, ReportContext("fixture", "captured"))
    rendered = render_document(document).content
    assert b"attempted" in rendered and b"captured" in rendered
    assert document.summary == {"Count": 2}
    block = next(block for block in document.blocks if block.title == "Structured legacy summary")
    assert json.loads(block.text) == {"Coverage": original["Coverage"]}
    assert spec.summary == original


@pytest.mark.parametrize("format", ["json", "xml"])
def test_structured_legacy_summary_is_portable_across_data_formats(format):
    spec = ReportSpec(summary={"Items": [{"name": "captured", "value": None}], "Empty": []})
    document = document_from_spec(spec, ReportContext("fixture", "captured"))
    rendered = render_document(document, format).content
    assert b"Structured legacy summary" in rendered and b"captured" in rendered
    assert json.loads(document.blocks[0].text) == spec.summary


def test_scalar_legacy_summary_stays_in_existing_summary_field():
    summary = {"Count": 2, "Cost": 0.25, "Available": False, "Unknown": None, "Label": "captured"}
    document = document_from_spec(ReportSpec(summary=summary), ReportContext("fixture", "captured"))
    assert document.summary == summary
    assert not any(block.title == "Structured legacy summary" for block in document.blocks)
    assert b"Summary" in render_document(document).content


def test_arbitrary_python_object_summary_is_never_stringified():
    class Unserializable:
        def __str__(self):
            raise AssertionError("portable conversion must not stringify arbitrary objects")

    with pytest.raises(ValueError, match="unsupported reporting value"):
        document_from_spec(ReportSpec(summary={"Object": Unserializable()}), ReportContext("fixture", "captured"))
