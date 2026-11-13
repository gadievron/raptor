"""Native SARIF URI encoding must round-trip local source identity once."""

from urllib.parse import quote

from core.dataflow.adapters.taint_native import from_sarif_result
from core.dataflow.llm_extractor import extract_from_files


def test_native_uri_paths_reach_source_reader_without_double_decoding(tmp_path):
    calls = []

    def extractor(bundle):
        calls.append(bundle)
        return '{"validators": []}'

    def finding(uri):
        loc = {"location": {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}}
        result = {"ruleId": "fixture", "message": {"text": "fixture"}, "codeFlows": [{"threadFlows": [{"locations": [loc, loc]}]}]}
        value = from_sarif_result(result)
        assert value is not None
        assert value.raw == result
        return value

    for name in ("space 100%.py", "unicodé.py", "literal%2F.py", "plain.py"):
        (tmp_path / name).write_text("inert fixture text\n", encoding="utf-8")
        value = finding(quote(name, safe="/"))
        assert value.source.file_path == name
        assert value.sink.file_path == name
        before = len(calls)
        _, errors = extract_from_files(file_paths=[value.source.file_path], repo_root=tmp_path, extractor=extractor)
        assert not errors
        assert len(calls) == before + 1
    before = len(calls)
    escaping = finding("%2E%2E%2Foutside.py")
    _, errors = extract_from_files(file_paths=[escaping.source.file_path], repo_root=tmp_path, extractor=extractor)
    assert any("escapes repo root" in error for error in errors)
    assert len(calls) == before
