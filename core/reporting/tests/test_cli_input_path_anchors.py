"""New offline CLI captures keep source paths anchored across working directories."""
import hashlib
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.writer import load_committed_report, regenerate


def _tree(directory):
    return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()}


@pytest.mark.parametrize("kind", ["native", "sarif"])
@pytest.mark.parametrize("absolute", [False, True], ids=["relative-input", "absolute-input"])
def test_cli_source_refs_stay_anchored_for_later_regeneration(tmp_path, monkeypatch, kind, absolute):
    payload = {"findings": [{"id": "F", "message": "captured claim"}]} if kind == "native" else {
        "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}},
                                     "results": [{"ruleId": "fixture/rule", "message": {"text": "captured claim"}}]}]}
    origin = tmp_path / "origin"
    later = tmp_path / "later"
    origin.mkdir()
    later.mkdir()
    source = origin / "input.json"
    source.write_text(json.dumps(payload))
    original = source.read_bytes()
    output = tmp_path / "capture"
    monkeypatch.chdir(origin)
    assert main([kind, str(source) if absolute else source.name, "--out", str(output),
                 "--report-format", "json"]) == 0
    context, document, manifest = load_committed_report(output)
    captured_tree = _tree(output)
    monkeypatch.chdir(later)
    for selected in (output, output / "report-document.json"):
        with pytest.raises(ValueError, match="source artifact"):
            regenerate(selected, source, format="json")
        assert source.read_bytes() == original and _tree(output) == captured_tree
    assert context.artifacts[0]["path"] == str(source.resolve())
    assert document.extensions["raptor.artifacts"] == context.artifacts
    assert len(context.findings) == 1 and context.findings[0]["status"] == "Unconfirmed"
    if kind == "native":
        assert context.extensions["raptor.imported"] == payload
        assert context.findings[0]["native"] == payload["findings"][0]
    else:
        assert context.artifacts[0]["digest"] == hashlib.sha256(original).hexdigest()
    separate = later / "regenerated.json"
    assert regenerate(output, separate, format="json") == []
    assert separate.read_bytes() == (output / ".reporting" / manifest["generation"] / "report.json").read_bytes()
    assert source.read_bytes() == original and _tree(output) == captured_tree
