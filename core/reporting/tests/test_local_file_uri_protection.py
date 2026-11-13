"""Local file URI spellings protect captured inputs from report replacement."""
import json
from urllib.parse import quote

import pytest

from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.writer import publish_report, regenerate


@pytest.mark.parametrize("mode,prefix", [
    pytest.param("publish", "file:", id="publish-single-slash"),
    pytest.param("publish", "FiLe:", id="publish-mixed-case"),
    pytest.param("publish", "file://", id="publish-triple-slash"),
    pytest.param("regenerate", "file:", id="regenerate-single-slash"),
    pytest.param("regenerate", "FiLe:", id="regenerate-mixed-case"),
    pytest.param("regenerate", "file://", id="regenerate-triple-slash"),
])
def test_local_uri_input_cannot_be_replaced(tmp_path, mode, prefix):
    source = tmp_path / "captured source #.json"
    source.write_bytes(b"retained captured source")
    original = source.read_bytes()
    context = ReportContext("scan", "saved", artifacts=[{"uri": prefix + quote(source.as_posix(), safe="/")}])
    document = build_document(context)
    output = tmp_path / "report"
    if mode == "regenerate":
        publish_report(context, document, output)
        with pytest.raises(ValueError, match="source artifact"):
            regenerate(output, source, format="json")
    else:
        with pytest.raises(ValueError, match="input artifact"):
            publish_report(context, document, output, options=ReportOptions(formats=("json",), output=source))
        assert not output.exists()
    assert source.read_bytes() == original


def test_literal_path_with_file_prefix_stays_protected(tmp_path):
    source = tmp_path / "file:notes.json"
    source.write_bytes(b"literal local path")
    context = ReportContext("scan", "saved", artifacts=[{"path": source.name}])
    with pytest.raises(ValueError, match="input artifact"):
        publish_report(context, build_document(context), tmp_path,
                       options=ReportOptions(formats=("json",), output=source))
    assert source.read_bytes() == b"literal local path"


@pytest.mark.parametrize("scheme", ["file", "https"])
def test_remote_uri_does_not_claim_same_spelling_local_path(tmp_path, scheme):
    destination = tmp_path / "output.json"
    uri = f"{scheme}://remote.invalid{quote(destination.as_posix(), safe='/')}"
    context = ReportContext("scan", "saved", artifacts=[{"uri": uri}])
    publication = publish_report(context, build_document(context), tmp_path / "report",
                                 options=ReportOptions(formats=("json",), output=destination))
    assert publication.committed
    assert json.loads(destination.read_text())["snapshot_id"] == context.snapshot_id
