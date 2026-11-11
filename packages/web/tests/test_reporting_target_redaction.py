"""Portable receipts redact captured targets without constructing a scan."""
from copy import deepcopy

from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report
from core.security.redaction import redact_secrets
from packages.web.scanner import WebScanner


def test_captured_web_target_uses_the_portable_redaction_boundary(tmp_path, capsys):
    target = "https://owned-user:owned-password@example.invalid/?api_key=" + "owned-token-" + "x" * 24
    # Exercise only the captured-result hook; the scanner constructor creates
    # clients and is deliberately outside this reporting fixture's scope.
    scanner = object.__new__(WebScanner)
    scanner.base_url = target
    scanner.out_dir = tmp_path / "receipt"
    scanner.out_dir.mkdir()
    scanner.report_options = ReportOptions(formats=("json",))
    scanner.reveal_secrets = True
    payload = {"target": target, "findings": [], "phases_completed": []}
    before = deepcopy(payload)
    scanner._capture_reporting(payload)
    context, document, _ = load_committed_report(scanner.out_dir)
    assert context.target == redact_secrets(target)
    assert document.metadata["Target"] == context.target
    assert context.extensions["raptor.result"]["target"] == context.target
    stderr = capsys.readouterr().err
    for secret in ("owned-password", "owned-token-" + "x" * 24):
        assert secret not in stderr
        for path in scanner.out_dir.rglob("*"):
            if path.is_file():
                assert secret.encode() not in path.read_bytes()
    assert payload == before and scanner.base_url == target
    assert not hasattr(scanner, "client")
