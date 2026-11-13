"""A refused native capture refreshes the handoff without replacing old exports."""
from io import StringIO
import json

import pytest

from core.reporting.options import ReportOptions
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.writer import load_committed_report


def _tree(directory):
    return {path.relative_to(directory): None if path.is_dir() else path.read_bytes()
            for path in directory.rglob("*")}


@pytest.mark.parametrize("previous", [False, True], ids=["fresh", "prior-report"])
def test_depth_refusal_keeps_native_source_and_fresh_unavailable_summary(tmp_path, previous):
    output = tmp_path / "report"
    options = ReportOptions(formats=("json", "markdown"))
    if previous:
        prior = complete_native_result(NativeResult("fixture", "before", "before", {"label": "prior capture"},
                                                   findings=[{"id": "F", "message": "prior observation"}],
                                                   triage=True, state="completed"),
                                       output, stem="native", options=options, stream=StringIO())
        assert not prior.errors and prior.publication.committed
        prior_context, prior_document, prior_manifest = load_committed_report(output)
        immutable = _tree(output / ".reporting")
        pointer = (output / "reporting-manifest.json").read_bytes()
        exports = {name: (output / name).read_bytes() for name in ("native.json", "native.md", "report-context.json", "report-document.json")}
    payload = {"private-depth-sentinel": "retained only in original source"}
    for _ in range(42):
        payload = {"nested": payload}
    source = tmp_path / "too-deep-native.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    source_bytes = source.read_bytes()
    captured = json.loads(source_bytes)
    console = StringIO()
    result = complete_native_result(NativeResult("fixture", "after", "after", captured,
                                                artifacts=[{"path": str(source)}]),
                                    output, stem="native", options=options, stream=console)
    message = "Structured report capture failed (ValueError); original command results are retained"
    assert result.publication is None and result.errors == [message]
    assert result.summary.run_id == "after" and result.summary.target == "after"
    assert result.summary.state == "partial" and result.summary.findings_available is False
    assert result.summary.total == 0 and result.summary.counts == {} and result.summary.rows == []
    saved = json.loads((output / "summary.json").read_bytes())
    assert saved == result.summary.to_dict() and message in saved["diagnostics"]
    markdown = (output / "summary.md").read_text(encoding="utf-8")
    for rendered in (console.getvalue(), markdown):
        assert message in rendered and "does not supply a finding population" in rendered
        assert "No findings in captured results" not in rendered
        assert "private-depth-sentinel" not in rendered
        assert ("prior report artifacts were not refreshed" in rendered) is previous
    assert source.read_bytes() == source_bytes and captured == payload
    if previous:
        restored, document, manifest = load_committed_report(output)
        assert restored.to_dict() == prior_context.to_dict()
        assert document.to_dict() == prior_document.to_dict() and manifest == prior_manifest
        assert (output / "reporting-manifest.json").read_bytes() == pointer
        assert _tree(output / ".reporting") == immutable
        assert {name: (output / name).read_bytes() for name in exports} == exports
    else:
        assert not (output / "reporting-manifest.json").exists()
        assert not (output / "native.json").exists() and not (output / "native.md").exists()
