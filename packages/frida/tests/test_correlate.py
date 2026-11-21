"""Tests for the template combinator and the io-correlation
post-processor: external input reappearing in later call arguments."""

from __future__ import annotations

import json
from pathlib import Path

from packages.frida import cli
from packages.frida.correlate import correlate_run


def _event(seq_ts: float, payload: dict) -> str:
    return json.dumps({"ts": seq_ts, "type": "send", "payload": payload})


def _write(run_dir: Path, lines: list[str]) -> None:
    (run_dir / "events.jsonl").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def _ingest(data: bytes) -> dict:
    return {"category": "ingest", "fn": "read",
            "args": {"len": len(data), "data_hex": data.hex()}, "tid": 1}


def _exec(argv: list[str]) -> dict:
    return {"category": "exec", "fn": "execve",
            "args": {"path": argv[0], "argv": argv}, "tid": 1}


class TestCorrelateRun:
    def test_ingest_bytes_reappearing_in_argv_matches(self, tmp_path):
        _write(tmp_path, [
            _event(1.0, _ingest(b"GET /run?cmd=weird-canary-token&x=1")),
            _event(2.0, _exec(["/bin/sh", "-c", "weird-canary-token"])),
        ])
        manifest = correlate_run(tmp_path)
        assert manifest["match_count"] == 1
        match = manifest["matches"][0]
        assert match["source"]["fn"] == "read"
        assert match["sink"]["fn"] == "execve"
        assert "weird-canary-token" in match["match"]
        assert (tmp_path / "io-correlation.json").is_file()

    def test_order_matters_sink_before_ingest_no_match(self, tmp_path):
        _write(tmp_path, [
            _event(1.0, _exec(["/bin/sh", "-c", "weird-canary-token"])),
            _event(2.0, _ingest(b"weird-canary-token")),
        ])
        manifest = correlate_run(tmp_path)
        assert manifest["match_count"] == 0
        assert not (tmp_path / "io-correlation.json").exists()

    def test_match_manifest_carries_verification_receipt(self, tmp_path):
        # The io-correlation receipt is the ATTRIBUTED execution fact
        # of the frida family: ingest bytes reappeared in a later
        # sink/exec argument of the same run. Its grade is read live
        # from the evidence_grade exact-spelling registry so every
        # consumer sees one vocabulary.
        from core.audit import evidence_grade as eg

        _write(tmp_path, [
            _event(1.0, _ingest(b"GET /run?cmd=sentinel-token-xyz&x=1")),
            _event(2.0, _exec(["/bin/sh", "-c", "sentinel-token-xyz"])),
        ])
        manifest = correlate_run(tmp_path)
        assert manifest["match_count"] == 1
        assert manifest["receipt_stamp"] == "frida:token-at-sink"
        assert manifest["evidence_role"] == "verification"
        assert manifest["evidence_role"] == (
            eg.registered_spelling_role(manifest["receipt_stamp"]))
        assert eg.is_verification_evidence(manifest["receipt_stamp"])
        # The written artifact carries the same grade.
        on_disk = json.loads(
            (tmp_path / "io-correlation.json").read_text(encoding="utf-8"))
        assert on_disk["receipt_stamp"] == "frida:token-at-sink"

    def test_matchless_run_mints_no_stamp(self, tmp_path):
        # Direction two of the receipt discipline: a run that proved
        # no flow has NO grade keys at all — there is no spelling for
        # "no flow observed", so an absence claim is unrepresentable.
        _write(tmp_path, [
            _event(1.0, _ingest(b"just-input-here-nothing")),
            _event(2.0, _exec(["/bin/ls", "-la"])),
        ])
        manifest = correlate_run(tmp_path)
        assert manifest["match_count"] == 0
        assert "receipt_stamp" not in manifest
        assert "evidence_role" not in manifest

    def test_short_overlaps_do_not_match(self, tmp_path):
        # Sub-threshold shared substrings are coincidence.
        _write(tmp_path, [
            _event(1.0, _ingest(b"abcdefg-payload-one")),
            _event(2.0, _exec(["/bin/ls", "-la"])),
        ])
        assert correlate_run(tmp_path)["match_count"] == 0

    def test_ingest_only_run_yields_nothing(self, tmp_path):
        _write(tmp_path, [_event(1.0, _ingest(b"just-input-here-nothing"))])
        assert correlate_run(tmp_path)["match_count"] == 0

    def test_caps_are_counted_not_silent(self, tmp_path):
        lines = [_event(float(i), _ingest(bytes([65 + i % 26]) * 16))
                 for i in range(200)]
        _write(tmp_path, lines)
        manifest = correlate_run(tmp_path)
        assert manifest["ingest_payloads_indexed"] == 128
        assert manifest["dropped_payloads_over_cap"] == 72

    def test_missing_events_file(self, tmp_path):
        assert correlate_run(tmp_path)["match_count"] == 0


class TestCliAutoCorrelate:
    def test_prints_summary_when_matched(self, tmp_path, capsys):
        _write(tmp_path, [
            _event(1.0, _ingest(b"payload-canary-abcdef")),
            _event(2.0, _exec(["/bin/sh", "-c", "payload-canary-abcdef"])),
        ])
        cli._maybe_correlate_io(tmp_path)
        out = capsys.readouterr().out
        assert "1 I/O correlation" in out

    def test_silent_when_nothing_matches(self, tmp_path, capsys):
        _write(tmp_path, [_event(1.0, _ingest(b"only-input-no-sinks"))])
        cli._maybe_correlate_io(tmp_path)
        captured = capsys.readouterr()
        assert "correlation" not in captured.out
        assert captured.err == ""


class TestWorkBudget:
    def test_budget_field_reported(self, tmp_path):
        _write(tmp_path, [
            _event(1.0, _ingest(b"payload-canary-abcdef")),
            _event(2.0, _exec(["/bin/sh", "-c", "payload-canary-abcdef"])),
        ])
        manifest = correlate_run(tmp_path)
        assert manifest["dropped_work_over_budget"] == 0
