"""Equivalent CodeQL URI escapes retain finding identity and source lookup."""

from types import SimpleNamespace
from urllib.parse import quote

from core.dataflow.adapters.codeql import from_dataflow_path, from_sarif_result
from packages.codeql.dataflow_validator import DataflowValidator
from core.dataflow.finding_diff import diff_sarif_data
from core.dataflow.llm_extractor import extract_from_files


def test_codeql_uri_identity_and_source_lookup_decode_once(tmp_path):
    def record(uri):
        loc = {"location": {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}}
        return {"ruleId": "fixture", "message": {"text": "fixture"}, "codeFlows": [{"threadFlows": [{"locations": [loc, loc]}]}]}

    upper, lower = record("case%3Bname.py"), record("case%3bname.py")
    a, b = from_sarif_result(upper), from_sarif_result(lower)
    assert a.finding_id == b.finding_id
    diff = diff_sarif_data({"runs": [{"results": [upper]}]}, {"runs": [{"results": [lower]}]})
    assert diff.suppressed_ids == ()
    assert diff.new_ids == ()
    assert diff.still_flagged_ids == (a.finding_id,)
    calls = []

    def extractor(bundle):
        calls.append(bundle)
        return '{"validators": []}'

    for name in ("case;name.py", "space 100%.py", "unicodé.py", "literal%2F.py", "plain.py"):
        (tmp_path / name).write_text("inert text\n", encoding="utf-8")
        raw = record(quote(name, safe="/"))
        value = from_sarif_result(raw)
        assert value.source.file_path == name
        assert value.sink.file_path == name
        assert value.raw == raw
        # Parse only: bypass client construction and all validation paths.
        legacy = DataflowValidator._path_from_locations(
            None, raw["codeFlows"][0]["threadFlows"][0]["locations"], "fixture", "fixture",
        )
        assert from_dataflow_path(legacy).finding_id == value.finding_id
        literal = SimpleNamespace(source=value.source, sink=value.sink, intermediate_steps=(), rule_id="fixture", message="fixture", sanitizers=[])
        assert from_dataflow_path(literal).source.file_path == name
        before = len(calls)
        _, errors = extract_from_files(file_paths=[value.source.file_path], repo_root=tmp_path, extractor=extractor)
        assert not errors
        assert len(calls) == before + 1
    before = len(calls)
    escaping = from_sarif_result(record("%2E%2E%2Foutside.py"))
    _, errors = extract_from_files(file_paths=[escaping.source.file_path], repo_root=tmp_path, extractor=extractor)
    assert any("escapes repo root" in error for error in errors)
    assert len(calls) == before
