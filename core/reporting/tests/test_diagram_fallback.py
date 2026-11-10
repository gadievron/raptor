"""Unsupported Mermaid remains inspectable as inert, bounded source text."""
import pytest

from core.reporting.builders import build_document
from core.reporting.document import Block, ReportContext
from core.reporting.renderers import render_document


@pytest.mark.parametrize("source", [
    'flowchart LR\nA["before"]-->B["after"]\nclassDef owned fill:#fff\nclass A owned',
    'flowchart LR\nA["before"]\nclick A "javascript:owned"',
    'flowchart LR\nA["before"]\n```html\n<img src=https://example.invalid/image>\n```',
])
def test_unsupported_diagram_retains_labels_without_active_fences(source):
    context = ReportContext("diagrams", "owned")
    document = build_document(context, blocks=[Block("diagram", text="Recorded graph", extensions={"mermaid": source})])
    rendered = render_document(document, "markdown")
    assert b"before" in rendered.content and b"Recorded graph" in rendered.content
    assert b"```text\n" in rendered.content and b"```mermaid" not in rendered.content
    assert b"```html\n" not in rendered.content
    assert any("Diagram visual unavailable" in note for note in rendered.diagnostics)
