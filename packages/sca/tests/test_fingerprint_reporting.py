"""Fingerprint exports preserve drift gates and never compute twice."""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.binary import CapabilityFingerprint, save_fingerprint
from core.binary.fingerprint import FINGERPRINT_SCHEMA_VERSION
from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.sca import fingerprint_cli


def _fingerprint(source):
    return CapabilityFingerprint(FINGERPRINT_SCHEMA_VERSION, str(source), "a" * 64,
                                 "x86", 64, "elf", {"exec": ["execve"]})


@pytest.mark.parametrize("mode,expected", [("compute", 0), ("save", 0), ("same", 0), ("drift", 1), ("missing", 2), ("failed", 3)])
@isolated_cli_logging()
def test_fingerprint_receipt_reuses_current_and_actual_baseline(tmp_path, monkeypatch, capsys, mode, expected):
    source = tmp_path / "binary"
    source.write_bytes(b"owned test input")
    current = _fingerprint(source)
    cache = tmp_path / "cache"
    baseline = replace(current, binary_sha256="b" * 64, capability_buckets={}) if mode == "drift" else current
    if mode in ("same", "drift"):
        assert save_fingerprint(cache / "fingerprints", "owned", baseline) is not None
    calls = []

    def compute(path):
        calls.append(path)
        return None if mode == "failed" else current

    monkeypatch.setattr("core.binary.capability_fingerprint", compute)
    args = [str(source), "--ref", "owned", "--cache-root", str(cache),
            "--report-format", "json", "--report-output", str(tmp_path / "receipt.json")]
    if mode == "save":
        args.append("--save")
    elif mode in ("same", "drift", "missing"):
        args.append("--check")
    assert fingerprint_cli.main(args) == expected
    assert calls == [source]
    streams = capsys.readouterr()
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    payload = context.extensions["raptor.result"]
    assert payload["native exit status"] == expected
    assert context.extensions["raptor.findings_available"] is False
    if mode == "compute":
        assert json.loads(streams.out) == current.to_dict()
    if mode == "drift":
        assert json.loads(streams.out)["high_severity"] is True
        assert payload["baseline used"]["binary_sha256"] == "b" * 64
        assert payload["drift"]["new_buckets"] == {"exec": ["execve"]}
    if mode == "same":
        assert payload["drift"]["new_buckets"] == {} and "no drift" in streams.out
    if mode == "save":
        assert Path(payload["baseline written"]).is_file()
    if mode == "missing":
        assert payload["drift"] is None and context.state == "partial"
    if mode == "failed":
        assert payload["current fingerprint"] is None and context.state == "failed"


@isolated_cli_logging()
def test_fingerprint_report_cannot_replace_stored_baseline(tmp_path, monkeypatch, capsys):
    source = tmp_path / "binary"
    source.write_bytes(b"owned")
    fingerprint = _fingerprint(source)
    cache = tmp_path / "cache"
    baseline = save_fingerprint(cache / "fingerprints", "owned", fingerprint)
    before = baseline.read_bytes()
    monkeypatch.setattr("core.binary.capability_fingerprint", lambda path: fingerprint)
    assert fingerprint_cli.main([str(source), "--check", "--ref", "owned", "--cache-root", str(cache),
                                 "--report-format", "json", "--report-output", str(baseline)]) == 0
    assert baseline.read_bytes() == before
    assert "Report persistence failed" in capsys.readouterr().err


def test_fingerprint_report_preflight_before_binary_analysis(monkeypatch, tmp_path):
    monkeypatch.setattr("core.binary.capability_fingerprint", lambda path: pytest.fail("must preflight"))
    with pytest.raises(SystemExit) as error:
        fingerprint_cli.main([str(tmp_path / "missing"), "--report-format", "json"])
    assert error.value.code == 2
