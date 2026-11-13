"""Bounded native payload views retain omitted data in committed context."""
from copy import deepcopy
from io import StringIO
import json

import pytest

from core.reporting.options import ReportOptions
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.writer import load_committed_report


def _payload(case):
    if case == "breadth":
        return {**{f"field-{index}": index for index in range(5000)},
                "omitted-tail": "retained-tail-sentinel"}
    if case == "depth":
        value = {"omitted-deep": "retained-deep-sentinel"}
        for _ in range(14):
            value = {"nested": value}
        return value
    return {"count": 0, "enabled": False, "unknown": None,
            "details": ["retained-small-sentinel"]}


@pytest.mark.parametrize("case", ["breadth", "depth", "small"])
def test_saved_native_payload_survives_bounded_presentation(tmp_path, case):
    source = tmp_path / "native.json"
    source.write_text(json.dumps(_payload(case)), encoding="utf-8")
    original_bytes = source.read_bytes()
    payload = json.loads(original_bytes)
    original = deepcopy(payload)
    output = tmp_path / "report"
    console = StringIO()
    result = complete_native_result(
        NativeResult("fixture", "captured", "one", payload, state="unknown",
                     artifacts=[{"path": str(source)}]),
        output, stem="native", options=ReportOptions(formats=("json", "markdown")),
        stream=console,
    )
    assert not result.errors
    assert result.publication is not None and result.publication.committed
    context, document, manifest = load_committed_report(output)
    assert context.extensions["raptor.result"] == original == payload
    assert source.read_bytes() == original_bytes
    assert context.snapshot_id == document.snapshot_id
    assert context.completion_state == result.summary.state == "unknown"
    assert context.findings == [] and result.summary.findings_available is False
    assert "does not supply a finding population" in console.getvalue()

    generation = output / ".reporting" / manifest["generation"]
    rendered = (generation / "native.md").read_text(encoding="utf-8")
    saved_document = json.loads((generation / "native.json").read_bytes())
    assert saved_document == document.to_dict()
    if case == "breadth":
        assert "Additional fields omitted from presentation" in rendered
        assert "retained-tail-sentinel" not in rendered
        assert context.extensions["raptor.result"]["omitted-tail"] == "retained-tail-sentinel"
    elif case == "depth":
        assert "Presentation truncated; complete structured data is retained" in rendered
        assert "retained-deep-sentinel" not in rendered
        value = context.extensions["raptor.result"]
        for _ in range(14):
            value = value["nested"]
        assert value["omitted-deep"] == "retained-deep-sentinel"
    else:
        assert "retained-small-sentinel" in rendered
        assert "Additional fields omitted" not in rendered
        assert "Presentation truncated" not in rendered
