"""Existing export directories retain directory semantics through publication."""
import hashlib
import io
import json

import pytest

from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("name", ["exports", "summary.json", "report-context.json"],
                         ids=["ordinary", "summary-name", "context-name"])
def test_reserved_named_directory_exports_match_committed_capture(tmp_path, name):
    source = tmp_path / "native.json"
    source.write_text(json.dumps({"saved": [0, False, None], "label": "owned saved record"}))
    original_source = source.read_bytes()
    context = ReportContext("fixture", "saved", state="unknown", artifacts=[{"path": str(source)}],
                            extensions={"fixture.raw": json.loads(original_source), "raptor.findings_available": False})
    captured = tmp_path / "capture"
    captured.mkdir()
    saved_context = captured / "context.json"
    saved_context.write_text(json.dumps(context.to_dict()))
    original_context_file = saved_context.read_bytes()
    context = ReportContext.from_dict(json.loads(original_context_file))
    original_context = context.to_dict()
    destination = tmp_path / name
    destination.mkdir()
    sentinel = destination / "keep.txt"
    sentinel.write_bytes(b"existing directory content")
    output = tmp_path / "report"
    result = complete_reporting(context, output, options=ReportOptions(("json", "markdown"), destination), stream=io.StringIO())
    assert not result.errors and result.publication and result.publication.committed
    restored, document, manifest = load_committed_report(output)
    assert restored.to_dict() == original_context == context.to_dict()
    assert restored.extensions["fixture.raw"] == json.loads(original_source)
    generation = output / ".reporting" / manifest["generation"]
    assert destination.is_dir() and sentinel.read_bytes() == b"existing directory content"
    assert manifest["outputs"] == {"json": str(destination / "report.json"), "markdown": str(destination / "report.md")}
    for filename in ("report.json", "report.md"):
        content = (destination / filename).read_bytes()
        assert content == (generation / filename).read_bytes()
        assert manifest["files"][filename] == {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    assert json.loads((destination / "report.json").read_text()) == document.to_dict()
    assert source.read_bytes() == original_source
    assert saved_context.read_bytes() == original_context_file
    assert not (output / "report.json").exists() and not (output / "report.md").exists()
