"""Capability kinds must describe the actual completion producer contract."""
import ast
from pathlib import Path


from core.reporting.adapters import context_from_sarif
from core.reporting.builders import build_document
from core.reporting.capabilities import command_capabilities
from core.reporting.document import ReportContext


def _producer_kind(relative_path, constructor):
    source = Path(__file__).resolve().parents[3] / relative_path
    kinds = set()
    for call in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != constructor:
            continue
        node = next((keyword.value for keyword in call.keywords if keyword.arg == "kind"), None)
        if node is None and constructor == "ReportContext" and call.args:
            node = call.args[0]
        assert isinstance(node, ast.Constant) and isinstance(node.value, str), "Review the producer kind contract"
        kinds.add(node.value)
    assert len(kinds) == 1, "Completion producer must have one declared kind for this capability"
    return kinds.pop()


def _assert_sarif_kind(tmp_path, command, producer_path):
    kind = _producer_kind(producer_path, "context_from_sarif")
    source = tmp_path / "captured.sarif"
    source.write_text('{"version":"2.1.0","runs":[]}')
    context = context_from_sarif([source], kind=kind, run_id="captured")
    document = build_document(context)
    capability = next(row for row in command_capabilities() if row["command"] == command)
    assert capability["document_kind"] == document.to_dict()["kind"]


def test_scan_capability_matches_captured_document_kind(tmp_path):
    _assert_sarif_kind(tmp_path, "scan", "packages/static-analysis/scanner.py")


def test_codeql_capability_matches_captured_document_kind(tmp_path):
    _assert_sarif_kind(tmp_path, "codeql", "packages/codeql/agent.py")


def test_validation_capability_matches_completion_context_kind():
    kind = _producer_kind("packages/exploitability_validation/report.py", "ReportContext")
    document = build_document(ReportContext(kind, "captured"))
    capability = next(row for row in command_capabilities() if row["command"] == "validate")
    assert capability["document_kind"] == document.to_dict()["kind"]
