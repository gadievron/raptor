"""Direct saved-SARIF captures retain source anchors beyond their capture CWD."""
import hashlib
from io import StringIO
import json

import pytest

from core.reporting.adapters import context_from_sarif
from core.reporting.lifecycle import find_input_snapshot, input_digest
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, regenerate


def _tree(directory):
    return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()}


@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
@pytest.mark.parametrize("duplicate", [False, True], ids=["one-input", "duplicate-bytes"])
def test_direct_sarif_source_anchors_survive_cwd_change(tmp_path, monkeypatch, absolute, duplicate):
    origin = tmp_path / "origin"
    output = origin / "run"
    later = tmp_path / "later"
    output.mkdir(parents=True)
    later.mkdir()
    data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}},
            "results": [{"ruleId": "fixture/rule", "message": {"text": "captured source claim"}}]}]}
    raw = json.dumps(data).encode()
    sources = [output / "combined.sarif"]
    if duplicate:
        sources.append(output / "duplicate.sarif")
    for source in sources:
        source.write_bytes(raw)
    monkeypatch.chdir(origin)
    arguments = sources if absolute else [source.relative_to(origin) for source in sources]
    context = context_from_sarif(arguments, run_id="saved")
    result = complete_reporting(context, output, options=ReportOptions(formats=("json", "markdown")), stream=StringIO())
    assert not result.errors and result.publication.committed
    saved, document, manifest = load_committed_report(output)
    original_capture = _tree(output)
    monkeypatch.chdir(later)
    for source in sources:
        with pytest.raises(ValueError, match="source artifact"):
            regenerate(output, source, format="json")
        assert source.read_bytes() == raw
    assert _tree(output) == original_capture
    assert [item["path"] for item in saved.artifacts] == [str(source.resolve()) for source in sources]
    assert document.extensions["raptor.artifacts"] == saved.artifacts
    raw_digest = hashlib.sha256(raw).hexdigest()
    assert {item["digest"] for item in saved.artifacts} == {raw_digest}
    assert {item["canonical_digest"] for item in saved.artifacts} == {input_digest(data)}
    finding, = saved.findings
    assert finding["occurrence_ref"] == f"sarif:{raw_digest}:0:0"
    assert finding["status"] == "Unconfirmed"
    assert saved.extensions["raptor.accounting"] == {"observed_results": 1, "captured_results": 1}
    binding = find_input_snapshot(sources[0], data)
    assert binding["positions"][(0, 0)]["occurrence_ref"] == finding["occurrence_ref"]
    destination = later / "regenerated.json"
    assert regenerate(output, destination, format="json") == []
    assert destination.read_bytes() == (output / ".reporting" / manifest["generation"] / "report.json").read_bytes()
    assert all(source.read_bytes() == raw for source in sources) and _tree(output) == original_capture
