"""Saved escaped Unicode retains raw strings and safe text presentations."""
from copy import deepcopy
import hashlib
from io import StringIO
import json
from xml.etree import ElementTree

import pytest

from core.reporting.options import ReportOptions
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("scalar", ["\ud800", "\udfff", "caf\u00e9 \U0001f642"],
                         ids=["lone-high", "lone-low", "ordinary-unicode"])
def test_saved_unicode_capture_preserves_raw_and_escapes_presentation(tmp_path, scalar):
    key = "field-" + scalar
    payload = {key: "value-" + scalar, "nested": [{"recorded": scalar}]}
    source = tmp_path / "native.json"
    source.write_text(json.dumps(payload, ensure_ascii=True), encoding="ascii")
    source_bytes = source.read_bytes()
    captured = json.loads(source_bytes)
    original = deepcopy(captured)
    output = tmp_path / "report"
    result = complete_native_result(NativeResult("fixture", "owned", "saved", captured,
                                                 artifacts=[{"path": str(source)}]), output, stem="report",
                                    options=ReportOptions(("json", "markdown", "xml")), stream=StringIO())
    assert not result.errors and result.publication and result.publication.committed
    context, document, manifest = load_committed_report(output)
    assert context.extensions["raptor.result"] == captured == original == payload
    assert context.extensions["raptor.result"][key] == "value-" + scalar
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report-context.json").read_bytes())["extensions"]["raptor.result"] == payload
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    markdown = (generation / "report.md").read_text(encoding="utf-8")
    xml_bytes = (generation / "report.xml").read_bytes()
    root = ElementTree.fromstring(xml_bytes)
    assert root.tag == "raptor-report"
    lone = len(scalar) == 1 and 0xD800 <= ord(scalar) <= 0xDFFF
    visible = f"\\u{ord(scalar):04x}" if lone else scalar
    assert visible in markdown and visible in xml_bytes.decode("utf-8")
    assert any(field.get("type") == "array" and [child.text for child in field.findall("field")] ==
               ["field-" + visible, "value-" + visible] for field in root.iter("field"))
    if lone:
        assert scalar not in markdown and scalar not in xml_bytes.decode("utf-8")
    for filename in ("report.json", "report.md", "report.xml"):
        content = (generation / filename).read_bytes()
        assert (output / filename).read_bytes() == content
        assert manifest["files"][filename] == {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    assert source.read_bytes() == source_bytes
