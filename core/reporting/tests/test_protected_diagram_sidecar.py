"""Diagram sidecars remain committed when the root mirror is native input."""
import hashlib
from io import StringIO
import json

import pytest

from core.reporting.builders import build_document
from core.reporting.document import Block, ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, load_context


@pytest.mark.parametrize("unsupported", [False, True], ids=["safe-source", "literal-fallback"])
def test_json_publication_captures_sidecar_without_replacing_source(tmp_path, unsupported):
    source = "flowchart LR\nA[before]-->B[after]"
    if unsupported:
        source += "\nclassDef owned fill:#fff\nclass A owned"
    output = tmp_path / "report"
    output.mkdir()
    native = output / "diagrams.md"
    native.write_text("# Owned original diagram artifact\n" + source + "\n")
    native_bytes = native.read_bytes()
    saved = tmp_path / "context.json"
    context = ReportContext("fixture", "saved", state="unknown",
                            artifacts=[{"path": str(native)}, {"path": str(saved)}],
                            extensions={"fixture.source": source, "raptor.findings_available": False})
    saved.write_text(json.dumps(context.to_dict()))
    saved_bytes = saved.read_bytes()
    context = load_context(saved)
    original = context.to_dict()
    document = build_document(context, blocks=[Block("diagram", title="Saved graph", text="Recorded edge before to after.",
                                                     extensions={"mermaid": context.extensions["fixture.source"]})])
    original_document = document.to_dict()
    result = complete_reporting(context, output, document=document, options=ReportOptions(("json",)), stream=StringIO())
    assert not result.errors and result.publication and result.publication.committed
    restored, captured, manifest = load_committed_report(output)
    assert context.to_dict() == restored.to_dict() == original
    assert document.to_dict() == captured.to_dict() == original_document
    assert manifest["formats"] == ["json"] and set(result.publication.outputs) == {"json"}
    assert any("Compatibility mirror diagrams.md skipped: input artifact preserved" in note for note in result.diagnostics)
    generation = output / ".reporting" / manifest["generation"]
    sidecar = (generation / "diagrams.md").read_bytes()
    assert manifest["files"]["diagrams.md"] == {"size": len(sidecar), "sha256": hashlib.sha256(sidecar).hexdigest()}
    assert b"Saved graph" in sidecar and b"before" in sidecar and b"after" in sidecar
    assert (b"```mermaid" in sidecar) is (not unsupported)
    if unsupported:
        assert b"```text" in sidecar and b"classDef owned" in sidecar
        assert b"Diagram visual unavailable; textual equivalent retained" in sidecar
    assert json.loads((generation / "report.json").read_bytes()) == captured.to_dict()
    assert (output / "report.json").read_bytes() == (generation / "report.json").read_bytes()
    assert native.read_bytes() == native_bytes and saved.read_bytes() == saved_bytes
    assert sidecar != native_bytes
