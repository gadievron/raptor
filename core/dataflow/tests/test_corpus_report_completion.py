"""Corpus snapshot exports preserve source state and never rerun analysis."""
from copy import deepcopy

import pytest

from core.dataflow import trust_corpus_report as module
from core.dataflow.tests.test_trust_corpus_report import _make_db, _row
from core.reporting.document import digest
from core.reporting.writer import load_committed_report, regenerate


def _reader(tmp_path, monkeypatch, *, missing=False, empty=False):
    source = tmp_path / "source?#%.json"
    if not missing:
        _make_db(source, [] if empty else [
            _row("f1", "CWE-78", "CVE-1", "Python", "sound", "smt"),
            _row("f2", "CWE-78", "CVE-2", "Python", "sound", "library"),
            _row("f3", "CWE-78", "CVE-3", "Python", "not_sound", "codeql", "preserve_tp_failed"),
            _row("f4", "CWE-78", "CVE-4", "Python", "future_error", ""),
        ])
    original = module.analyze
    calls = []
    def capture(path):
        assert path == source
        result = original(path)
        calls.append((result, deepcopy(result)))
        return result
    monkeypatch.setattr(module, "analyze", capture)
    return source, calls


@pytest.mark.parametrize("flags,exported", [([], False), (["--no-report"], False),
                                         (["--report-format", "json", "--report-format", "xml"], True)])
def test_single_snapshot_native_display_and_optional_exports(tmp_path, monkeypatch, capsys, flags, exported):
    source, calls = _reader(tmp_path, monkeypatch)
    before = source.read_bytes()
    root = tmp_path / "chosen-reports"
    if exported:
        flags = [*flags, "--report-output", str(root)]
    assert module.main(["--synth-db", str(source), *flags]) is None
    shown = capsys.readouterr()
    assert "Trust-witness corpus report" in shown.out and "source snapshot" in shown.out
    assert len(calls) == 1 and calls[0][0] == calls[0][1] and source.read_bytes() == before
    if flags:
        assert "source-read" in shown.err and "Optional trust-corpus report unavailable" not in shown.err
    if exported:
        context, document, _ = load_committed_report(root)
        assert context.state == "partial"  # observed pipeline-error row
        assert context.stages[0].stage_id == "source-read" and context.stages[0].state == "completed"
        assert context.stages[0].extensions["raptor.metrics"]["captured_rows"] == 4
        assert context.extensions["raptor.corpus_completion"] == "unknown"
        captured = deepcopy(context.extensions["raptor.corpus_capture"])
        identity = captured["snapshot_id"]
        captured["snapshot_id"] = ""
        assert digest(captured) == identity
        assert document.snapshot_id == context.snapshot_id
        xml = (root / "trust-corpus.xml").read_bytes()
        source.unlink()
        regenerate(root, tmp_path / "offline.xml", format="xml")
        assert (tmp_path / "offline.xml").read_bytes() == xml
    else:
        assert not root.exists() and not (tmp_path / "portable-reports").exists()


@pytest.mark.parametrize("missing", [False, True])
def test_completed_empty_query_is_distinct_from_unavailable_source(tmp_path, monkeypatch, capsys, missing):
    source, calls = _reader(tmp_path, monkeypatch, missing=missing, empty=True)
    root = tmp_path / "reports"
    assert module.main(["--synth-db", str(source), "--report-format", "json", "--report-output", str(root)]) is None
    context, document, _ = load_committed_report(root)
    assert context.stages[0].state == ("failed" if missing else "completed")
    assert context.stages[0].extensions["raptor.metrics"]["captured_rows"] == (None if missing else 0)
    assert context.extensions["raptor.corpus_completion"] == "unknown"
    assert document.metadata["Whole corpus completion"] == "not supplied"
    assert len(calls) == 1 and source.exists() is not missing
    assert "source-read" in capsys.readouterr().err


@pytest.mark.parametrize("failure", ["destination", "source", "format", "conflict"])
def test_preflight_refusal_precedes_query(tmp_path, monkeypatch, capsys, failure):
    source, calls = _reader(tmp_path, monkeypatch)
    flags = {"destination": ["--report-format", "json"],
             "source": ["--report-format", "json", "--report-output", str(source)],
             "format": ["--report-format", "unavailable-format", "--report-output", str(tmp_path / "reports")],
             "conflict": ["--no-report", "--report-format", "json"]}[failure]
    with pytest.raises(SystemExit) as error:
        module.main(["--synth-db", str(source), *flags])
    assert error.value.code == 2 and not calls
    if failure == "source":
        assert "cannot replace the source database" in capsys.readouterr().err


def test_publisher_fault_preserves_native_snapshot_and_no_return_status(tmp_path, monkeypatch, capsys):
    source, calls = _reader(tmp_path, monkeypatch)
    from core.dataflow import corpus_report_completion
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("private fault")
    monkeypatch.setattr(corpus_report_completion, "complete_reporting", fail)
    assert module.main(["--synth-db", str(source), "--report-format", "json", "--report-output", str(tmp_path / "reports")]) is None
    shown = capsys.readouterr()
    assert "Trust-witness corpus report" in shown.out and "native snapshot retained" in shown.err
    assert "private fault" not in shown.err and reached == [True] and len(calls) == 1


def test_disabled_export_keeps_prior_manifest_unparsed(tmp_path, monkeypatch, capsys):
    source, calls = _reader(tmp_path, monkeypatch)
    root = tmp_path / "portable-reports" / "trust-corpus"
    root.mkdir(parents=True)
    manifest = root / "reporting-manifest.json"
    manifest.write_text("old unparsed receipt")
    assert module.main(["--synth-db", str(source), "--no-report"]) is None
    assert "not refreshed" in capsys.readouterr().err
    assert manifest.read_text() == "old unparsed receipt" and not (root / "summary.json").exists()
    assert len(calls) == 1


def test_native_sampling_loss_is_separate_from_portable_projection_loss(tmp_path, monkeypatch):
    source = tmp_path / "samples.json"
    count = module._NOT_SOUND_SAMPLES_CAP + 2
    _make_db(source, [_row(f"f{index}", "CWE-78", f"CVE-{index}", "Python", "not_sound", "codeql", "preserve_tp_failed") for index in range(count)])
    root = tmp_path / "reports"
    assert module.main(["--synth-db", str(source), "--report-output", str(root)]) is None
    context, _, _ = load_committed_report(root)
    capture = context.extensions["raptor.corpus_capture"]
    assert capture["extensions"]["raptor.native_sample_rows_not_retained"] == 2
    assert capture["extensions"]["raptor.rows_omitted"]["not_sound samples"] == 0
    assert capture["extensions"]["raptor.native_sample_detail_completeness"] == "not supplied"
