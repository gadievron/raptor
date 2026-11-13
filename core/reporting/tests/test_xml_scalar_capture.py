"""Published report XML distinguishes scalar types and nested empty values."""
import json
from xml.etree import ElementTree

import pytest

from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, publish_report


def _field(parent, name):
    matches = [node for node in parent if node.attrib.get("name") == name]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("number", [7, 2**64 + 3], ids=["ordinary", "large-integer"])
def test_xml_types_and_order_survive_publication_with_exact_json_capture(tmp_path, number):
    values = {"zero": 0, "false": False, "unknown": None, "empty": "", "text": "False",
              "integer": number, "fraction": 1.25}
    payload = {"values": values, "nested": [{"flag": False}, 0, "0", None, [], {}, ""]}
    source = tmp_path / "saved-values.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    source_bytes = source.read_bytes()
    captured = json.loads(source_bytes)
    context = ReportContext("fixture", "saved", extensions={"fixture.raw": captured},
                            artifacts=[{"path": str(source)}])
    document = build_document(context)
    document.metadata.update(captured["values"])
    document.extensions["fixture.typed"] = captured
    original_context, original_document = context.to_dict(), document.to_dict()
    output = tmp_path / "report"
    publication = publish_report(context, document, output, options=ReportOptions(formats=("xml", "json")))
    assert publication.committed and not publication.failed_formats
    restored, saved_document, manifest = load_committed_report(output)
    assert restored.to_dict() == original_context == context.to_dict()
    assert saved_document.to_dict() == original_document == document.to_dict()
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == original_document
    root = ElementTree.fromstring((generation / "report.xml").read_bytes())
    assert root.tag == "raptor-report" and root.attrib == {"schema-version": "1"}
    metadata = _field(root, "metadata")
    assert metadata.attrib["type"] == "object"
    for name, kind, text in (("zero", "int", "0"), ("false", "bool", "False"),
                              ("unknown", "null", None), ("empty", "str", None),
                              ("text", "str", "False"), ("integer", "int", str(number)),
                              ("fraction", "float", "1.25")):
        node = _field(metadata, name)
        assert node.attrib["type"] == kind and node.text == text and len(node) == 0
    typed = _field(_field(root, "extensions"), "fixture.typed")
    nested = _field(typed, "nested")
    assert nested.attrib["type"] == "array"
    assert [node.attrib for node in nested] == [
        {"name": "item", "type": kind} for kind in ("object", "int", "str", "null", "array", "object", "str")]
    assert _field(nested[0], "flag").attrib["type"] == "bool"
    assert _field(nested[0], "flag").text == "False"
    assert [node.text for node in list(nested)[1:]] == ["0", "0", None, None, None, None]
    assert all(len(node) == 0 for node in list(nested)[1:])
    assert type(restored.extensions["fixture.raw"]["values"]["integer"]) is int
    assert saved_document.metadata["false"] is False and saved_document.metadata["unknown"] is None
    assert source.read_bytes() == source_bytes and captured == payload
