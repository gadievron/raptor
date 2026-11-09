"""CVE reports retain native compatibility and current auxiliary receipts."""
import json

from core.reporting.writer import load_committed_report
from packages.sca import update
from packages.sca.cli import _dispatch_fix
from packages.sca.resolvers import ResolverResult
from packages.sca.update import UpgradeChange


def _subject(tmp_path, *, actionable=True):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("owned==1.0.0\n")
    source = tmp_path / "findings.json"
    source.write_text(json.dumps([{
        "vuln_type": "sca:vulnerable_dependency", "file": str(manifest), "severity": "high",
        "sca": {"ecosystem": "PyPI", "name": "owned", "version": "1.0.0", "pin_style": "exact",
                "is_lockfile": False, "fixed_version": "2.0.0",
                "advisory": {"id": "TEST-1", "aliases": [], "fixed_versions": ["2.0.0"]}},
    }] if actionable else []))
    return manifest, source


def test_cve_dispatch_report_preserves_compatibility_and_native_inputs(tmp_path, capsys):
    manifest, source = _subject(tmp_path)
    original = source.read_bytes()
    output = tmp_path / "receipt.json"
    out_dir = tmp_path / "out"
    assert _dispatch_fix(["--cve-only", "--findings", str(source), "--offline", "--allow-major", "--out", str(out_dir),
                          "--report-format", "json", "--report-output", str(output)]) == 0
    assert source.read_bytes() == original and manifest.read_text() == "owned==1.0.0\n"
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    payload = context.extensions["raptor.result"]
    assert payload["mode"] == "proposed export"
    assert payload["findings source"] == str(source)
    native = json.loads((out_dir / "changes.json").read_text())
    assert payload["changes"] == native
    assert any(risk["kind"] == "semver_major" for risk in payload["changes"][0]["compat_risks"])
    assert "Summary" in capsys.readouterr().err


def test_current_external_receipt_is_returned_without_second_resolution(tmp_path, monkeypatch, capsys):
    manifest, source = _subject(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "validate-against.json").write_text('{"verdict":"stale success"}')
    calls = []

    class OwnedResolver:
        def is_available(self):
            return True

        def dry_run(self, project_dir):
            calls.append(project_dir)
            return ResolverResult("PyPI", False, True, error="owned conflict")

    monkeypatch.setattr("packages.sca.resolvers.get_resolver", lambda eco, *, project_dir: OwnedResolver())
    output = tmp_path / "receipt.json"
    assert update.main(["--findings", str(source), "--offline", "--allow-major", "--out", str(out_dir),
                        "--validate-against", str(manifest), "--report-format", "json", "--report-output", str(output)]) == 0
    assert calls == [manifest.parent]
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    auxiliary = context.extensions["raptor.result"]["auxiliary operations"]["external validation"]
    native = json.loads((out_dir / "validate-against.json").read_text())
    assert auxiliary["requested"] and auxiliary["attempted"]
    assert auxiliary["result"] == native and native["verdict"] == "conflict"
    assert any("resolver conflict" in note for note in context.diagnostics)


def test_unavailable_external_validation_is_not_replaced_by_stale_file(tmp_path, monkeypatch, capsys):
    _, source = _subject(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "validate-against.json").write_text('{"verdict":"stale success"}')
    unknown = tmp_path / "unknown.manifest"
    unknown.write_text("owned")
    output = tmp_path / "receipt.json"
    assert update.main(["--findings", str(source), "--offline", "--allow-major", "--out", str(out_dir),
                        "--validate-against", str(unknown), "--report-format", "json", "--report-output", str(output)]) == 0
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    auxiliary = context.extensions["raptor.result"]["auxiliary operations"]["external validation"]
    assert auxiliary["attempted"] and auxiliary["result"] is None
    assert context.state == "partial"


def test_no_actionable_cve_receipt_is_not_clean_scan(tmp_path, capsys):
    _, source = _subject(tmp_path, actionable=False)
    output = tmp_path / "receipt.json"
    assert update.main(["--findings", str(source), "--offline", "--out", str(tmp_path / "out"),
                        "--report-format", "json", "--report-output", str(output)]) == 0
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    assert context.extensions["raptor.result"]["mode"] == "no actionable changes"
    assert any("not a clean-scan" in note for note in context.diagnostics)


def test_cve_report_cannot_replace_input_findings(tmp_path, capsys):
    _, source = _subject(tmp_path)
    original = source.read_bytes()
    assert update.main(["--findings", str(source), "--offline", "--allow-major", "--out", str(tmp_path / "out"),
                        "--report-format", "json", "--report-output", str(source)]) == 0
    assert source.read_bytes() == original
    assert "failed" in capsys.readouterr().err.lower()


def test_cascade_returns_the_same_native_receipt_without_extra_resolution(tmp_path, monkeypatch, capsys):
    manifest, _ = _subject(tmp_path)
    out = tmp_path / "out"
    (out / "proposed").mkdir(parents=True)
    calls = []

    class OwnedResolver:
        def is_available(self):
            return True

        def dry_run(self, project_dir, **kwargs):
            calls.append(project_dir)
            return ResolverResult("PyPI", False, True, error="owned conflict")

    monkeypatch.setattr("packages.sca.resolvers.get_resolver", lambda eco, *, project_dir: OwnedResolver())
    change = UpgradeChange("PyPI", "owned", "1.0.0", "2.0.0", manifest, ("TEST-1",))
    receipt = update._run_cascade_validation([change], out)
    assert receipt == json.loads((out / "cascade.json").read_text())
    assert len(calls) == 1 and receipt[0]["verdict"] == "conflict"
