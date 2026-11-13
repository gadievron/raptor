"""Offline native capture retains exact source IDs and raw workflow values."""
import json
import sys

import pytest

from core.reporting import __main__ as cli
from core.reporting.writer import load_committed_report
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("number,bom", [
    pytest.param(2**64 + 3, False, id="large"),
    pytest.param(7, False, id="ordinary"),
    pytest.param(2**64 + 3, True, id="bom-large"),
])
def test_native_import_retains_integer_identity_and_original_payload(tmp_path, capsys, number, bom):
    payload = {"findings": [{"finding_id": number, "id": "fallback", "file": "a.c", "line": 1},
                            {"id": 0, "file": "b.c", "line": 2}],
               "metadata": {"sequence": number, "zero": 0, "available": False, "unknown": None}}
    source = tmp_path / "workflow.json"
    original = (b"\xef\xbb\xbf" if bom else b"") + json.dumps(payload).encode()
    source.write_bytes(original)
    output = tmp_path / "report"
    assert cli.main(["native", str(source), "--out", str(output), "--run-id", "captured",
                     "--report-format", "json", "--report-format", "markdown"]) == 0
    context, document, _ = load_committed_report(output)
    assert context.extensions["raptor.imported"] == payload
    assert type(context.extensions["raptor.imported"]["metadata"]["sequence"]) is int
    assert [finding["source_id"] for finding in context.findings] == [number, 0]
    assert all(type(finding["source_id"]) is int for finding in context.findings)
    assert document.extensions["raptor.summary"]["counts"] == {"Unconfirmed": 2}
    assert context.snapshot_id == document.snapshot_id
    assert "Captured findings: 2" in capsys.readouterr().out
    assert source.read_bytes() == original


@pytest.mark.parametrize("content", [None, b"{", b'{"findings":[],"label":"bad\xff"}',
                                      b'{"findings":[],"number":NaN}'],
                         ids=["missing", "malformed", "invalid-utf8", "nonfinite"])
def test_native_import_keeps_typed_input_refusal_without_output(tmp_path, capsys, content):
    source = tmp_path / "workflow.json"
    if content is not None:
        source.write_bytes(content)
    output = tmp_path / "report"
    assert cli.main(["native", str(source), "--out", str(output), "--report-format", "json"]) == 1
    assert "Reporting failed:" in capsys.readouterr().err
    assert not output.exists()
    assert source.read_bytes() == content if content is not None else not source.exists()


def test_native_import_still_applies_the_caller_byte_budget(tmp_path, capsys):
    source = tmp_path / "workflow.json"
    original = json.dumps({"findings": [], "padding": "x" * 100}).encode()
    source.write_bytes(original)
    output = tmp_path / "report"
    view = module_function_view(cli, bindings={"MAX_JSON_BYTES": 64})
    assert view.main(["native", str(source), "--out", str(output), "--report-format", "json"]) == 1
    assert "Reporting failed:" in capsys.readouterr().err
    assert not output.exists() and source.read_bytes() == original


def test_native_import_refuses_decoder_recursion_without_a_traceback(tmp_path, capsys):
    source = tmp_path / "workflow.json"
    depth = sys.getrecursionlimit() + 100
    original = b'{"findings":[],"nested":' + b"[" * depth + b"0" + b"]" * depth + b"}"
    source.write_bytes(original)
    output = tmp_path / "report"
    assert cli.main(["native", str(source), "--out", str(output), "--report-format", "json"]) == 1
    assert "Reporting failed:" in capsys.readouterr().err
    assert not output.exists() and source.read_bytes() == original


def test_native_import_translates_injected_decoder_recursion_privately(tmp_path, capsys):
    source = tmp_path / "workflow.json"
    original = b'{"findings":[]}'
    source.write_bytes(original)
    output = tmp_path / "report"
    calls = []
    parser = cli.loads_bounded

    def refuse(text, *, max_bytes):
        assert text == original.decode() and max_bytes == cli.MAX_JSON_BYTES
        calls.append(True)
        raise RecursionError("fixture decoder refusal")

    view = module_function_view(cli, bindings={"loads_bounded": refuse})
    assert view.main(["native", str(source), "--out", str(output), "--report-format", "json"]) == 1
    assert calls == [True] and cli.loads_bounded is parser
    error = capsys.readouterr().err
    assert "Workflow JSON nesting limit exceeded" in error and "fixture decoder refusal" not in error
    assert not output.exists() and source.read_bytes() == original
