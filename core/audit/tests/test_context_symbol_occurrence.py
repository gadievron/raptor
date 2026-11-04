"""Review metadata must belong to the exact source occurrence."""

from core.audit.context import _extract_metadata


def inventory():
    return {"files": [{"path": "codec.go", "items": [
        {"name": "Decode", "line_start": 10, "line_end": 14,
         "signature": "Decode(r: *TextReader, input: any) -> error",
         "metadata": {"class_name": "TextReader", "parameters": [["r", "*TextReader"]]}},
        {"name": "Decode", "line_start": 30, "line_end": 34,
         "signature": "Decode(r: *NumberReader, input: any) -> error",
         "metadata": {"class_name": "NumberReader", "parameters": [["r", "*NumberReader"]]}},
    ]}]}


def test_source_occurrence_selects_matching_receiver():
    data = inventory()
    metadata = _extract_metadata(data, "codec.go", "Decode", 30)
    assert metadata["class_name"] == "NumberReader"
    assert metadata["parameters"] == [["r", "*NumberReader"]]
    assert "TextReader" not in metadata["signature"]


def test_ambiguous_bare_name_does_not_borrow_a_receiver():
    assert _extract_metadata(inventory(), "codec.go", "Decode") == {}


def test_qualified_name_can_disambiguate_without_a_span():
    metadata = _extract_metadata(inventory(), "codec.go", "NumberReader.Decode")
    assert metadata["class_name"] == "NumberReader"


def test_stale_span_does_not_fall_back_to_first_name_match():
    assert _extract_metadata(inventory(), "codec.go", "Decode", 20) == {}


def test_qualified_receiver_and_span_must_agree():
    assert _extract_metadata(inventory(), "codec.go", "TextReader.Decode", 30) == {}
