"""Malformed optional renderer returns cannot abort other report formats."""
import pytest

from core.reporting import renderers
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting


def test_missing_renderer_result_isolated_from_valid_json_export(tmp_path, monkeypatch):
    monkeypatch.setitem(renderers._RENDERERS, "invalid", renderers.Renderer(
        "invalid", ".bad", "application/test", lambda document: None))
    result = complete_reporting(ReportContext("fixture", "captured"), tmp_path,
                                options=ReportOptions(formats=("invalid", "json")))
    assert result.publication.committed
    assert result.publication.failed_formats == ["invalid"]
    assert (tmp_path / "report.json").is_file()
    assert not (tmp_path / "report.bad").exists()


@pytest.mark.parametrize("returned", [
    renderers.RenderedReport("not bytes"),
    renderers.RenderedReport(bytearray(b"mutable content")),
    renderers.RenderedReport(b"bytes", ["not a tuple"]),
    renderers.RenderedReport(b"bytes", (42,)),
])
def test_malformed_result_fields_isolated_from_other_formats(tmp_path, monkeypatch, returned):
    monkeypatch.setitem(renderers._RENDERERS, "invalid", renderers.Renderer(
        "invalid", ".bad", "application/test", lambda document: returned))
    result = complete_reporting(ReportContext("fixture", "captured"), tmp_path,
                                options=ReportOptions(formats=("invalid", "json")))
    assert result.publication.committed and result.publication.failed_formats == ["invalid"]
    assert (tmp_path / "report.json").is_file() and not (tmp_path / "report.bad").exists()


def test_valid_extension_result_and_diagnostics_remain_supported(tmp_path, monkeypatch):
    returned = renderers.RenderedReport(b"captured local view", ("captured renderer note",))
    monkeypatch.setitem(renderers._RENDERERS, "valid", renderers.Renderer(
        "valid", ".good", "application/test", lambda document: returned))
    result = complete_reporting(ReportContext("fixture", "captured"), tmp_path,
                                options=ReportOptions(formats=("valid", "json")))
    assert result.publication.committed and not result.publication.failed_formats
    assert (tmp_path / "report.good").read_bytes() == returned.content
    assert "captured renderer note" in result.diagnostics
