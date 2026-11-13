"""Saved reporting snapshots retain exact integers with optional JSON backends."""
import json

import pytest

from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, load_context, load_document, publish_report, regenerate


@pytest.mark.parametrize("reader", ["context", "document"])
def test_saved_report_keeps_exact_large_integer_with_orjson(tmp_path, reader):
    orjson = pytest.importorskip("orjson")
    from core.json import utils

    assert utils._orjson is orjson
    number = 2**64 + 3
    context = ReportContext("fixture", "captured", extensions={"fixture.integer": number})
    document = build_document(context)
    document.metadata["Recorded integer"] = number
    publication = publish_report(context, document, tmp_path, options=ReportOptions(formats=("json",)))
    assert publication.committed
    committed_context, committed_document, _ = load_committed_report(tmp_path)
    assert committed_context.to_dict() == context.to_dict()
    assert committed_document.to_dict() == document.to_dict()
    source = tmp_path / f"report-{reader}.json"
    original = source.read_bytes()
    if reader == "context":
        restored = load_context(source)
        assert restored.to_dict() == context.to_dict()
        assert restored.snapshot_id == context.snapshot_id
        assert type(restored.extensions["fixture.integer"]) is int
    else:
        restored = load_document(source)
        assert restored.to_dict() == document.to_dict()
        assert type(restored.metadata["Recorded integer"]) is int
        destination = tmp_path / "regenerated.json"
        regenerate(source, destination, format="json")
        assert json.loads(destination.read_bytes()) == document.to_dict()
    assert source.read_bytes() == original


def _saved_value(reader):
    values = {"large": 2**64 + 3, "zero": 0, "false": False, "unknown": None}
    context = ReportContext("fixture", "captured", extensions=values)
    if reader is load_context:
        return context.to_dict()
    document = build_document(context)
    document.metadata.update(values)
    return document.to_dict()


@pytest.mark.parametrize("reader", [load_context, load_document])
def test_standalone_readers_keep_values_without_optional_backend(tmp_path, monkeypatch, reader):
    from core.json import utils

    monkeypatch.setattr(utils, "_orjson", None)
    expected = _saved_value(reader)
    source = tmp_path / "saved.json"
    source.write_text(json.dumps(expected), encoding="utf-8")
    assert reader(source).to_dict() == expected


@pytest.mark.parametrize("reader", [load_context, load_document])
@pytest.mark.parametrize("failure", ["missing", "malformed", "nonfinite"])
def test_standalone_reader_refusals_remain_typed(tmp_path, reader, failure):
    source = tmp_path / "saved.json"
    if failure != "missing":
        source.write_bytes(b"{" if failure == "malformed" else b'{"bad":NaN}')
    with pytest.raises(ValueError):
        reader(source)
    if failure != "missing":
        assert source.read_bytes() == (b"{" if failure == "malformed" else b'{"bad":NaN}')


@pytest.mark.parametrize("reader", [load_context, load_document])
def test_standalone_readers_keep_bom_and_explicit_symlink_inputs(tmp_path, reader):
    expected = _saved_value(reader)
    source = tmp_path / "saved.json"
    original = b"\xef\xbb\xbf" + json.dumps(expected).encode()
    source.write_bytes(original)
    alias = tmp_path / "selected.json"
    alias.symlink_to(source)
    assert reader(alias).to_dict() == expected
    assert alias.is_symlink() and source.read_bytes() == original


@pytest.mark.parametrize("reader", [load_context, load_document])
def test_standalone_readers_keep_byte_budget(tmp_path, monkeypatch, reader):
    from core.reporting import writer
    from core.source.gated import ReadBudgetExceededError

    expected = _saved_value(reader)
    source = tmp_path / "saved.json"
    original = json.dumps(expected).encode()
    assert len(original) > 64
    source.write_bytes(original)
    monkeypatch.setattr(writer, "MAX_JSON_BYTES", 64)
    with pytest.raises(ValueError, match="could not be loaded") as caught:
        reader(source)
    assert isinstance(caught.value.__cause__, ReadBudgetExceededError)
    assert source.read_bytes() == original


@pytest.mark.parametrize("reader", [load_context, load_document])
def test_standalone_readers_refuse_invalid_utf8_without_replacement(tmp_path, reader):
    source = tmp_path / "saved.json"
    original = json.dumps(_saved_value(reader)).encode().replace(b"fixture", b"fi\xffxture")
    assert b"\xff" in original
    source.write_bytes(original)
    with pytest.raises(ValueError):
        reader(source)
    assert source.read_bytes() == original
