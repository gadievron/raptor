"""Public corpus command exports its captured profile without another pass."""
import json

import pytest

from core.testing.logging_state import isolated_cli_logging
from packages.binary_analysis import cli


def _profile(out):
    return {"summary": {"samples_seen": 120, "samples_profiled": 110, "samples_skipped": 10,
                        "skipped": [{"path": "PRIVATE-SAMPLE-NAME"}], "family_count": 101, "caps_hit": ["sample_limit"]},
            "options": {"max_samples": 110}, "provenance": {"tier": "corpus_statistic"},
            "families": [{"id": str(i), "key": "owned", "sample_count": 1, "size_field_candidates": [], "endianness_vote": "unknown", "entropy": {"classification": "mixed"}, "tlv": {"likelihood": "unknown"}, "samples": ["PRIVATE-BYTES"]} for i in range(101)],
            "artifacts": {"seed_count": 0, "seed_dir": str(out / "seeds"), "fuzz_dict": None, "dict_entries": 0, "profile_json": str(out / "corpus-profile.json"), "report": str(out / "corpus-profile.md")}}


@isolated_cli_logging()
def test_corpus_export_preserves_counts_and_omissions_without_second_profile(tmp_path, monkeypatch, capsys):
    samples = tmp_path / "samples"
    samples.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    calls = []
    profile = _profile(out)
    native = out / "corpus-profile.json"
    native.write_text(json.dumps(profile))
    original = native.read_bytes()
    monkeypatch.setattr(cli, "start_run", lambda *args, **kwargs: out)
    monkeypatch.setattr(cli, "complete_run", lambda *args: None)
    monkeypatch.setattr(cli, "profile_corpus", lambda options: calls.append(options) or profile)
    assert cli.main(["corpus", str(samples), "--out", str(out), "--report-format", "json"]) == 0
    assert len(calls) == 1 and native.read_bytes() == original
    context = json.loads((out / "report-context.json").read_text())
    result = context["extensions"]["raptor.result"]
    assert result["summary"]["samples_skipped"] == 10
    assert result["summary"]["caps_hit"] == ["sample_limit"]
    assert result["families_omitted"] == 1 and len(result["families"]) == 100
    assert "PRIVATE-" not in (out / "report-context.json").read_text()
    assert not context["findings"] and context["run_id"] == "unknown"
    assert "120 seen" in capsys.readouterr().out


@isolated_cli_logging()
def test_corpus_report_refuses_sample_destination_but_preserves_native_success(tmp_path, monkeypatch, capsys):
    samples = tmp_path / "samples"
    samples.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(cli, "start_run", lambda *args, **kwargs: out)
    monkeypatch.setattr(cli, "complete_run", lambda *args: None)
    monkeypatch.setattr(cli, "profile_corpus", lambda options: _profile(out))
    assert cli.main(["corpus", str(samples), "--out", str(out), "--report-format", "json", "--report-output", str(samples / "receipt.json")]) == 0
    assert not (samples / "receipt.json").exists()
    assert "native profile retained" in capsys.readouterr().err


def test_corpus_invalid_report_options_refuse_before_profiling(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "profile_corpus", lambda options: pytest.fail("invalid options reached profiler"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["corpus", str(tmp_path), "--no-report", "--report-format", "json"])
    assert exc.value.code == 2
