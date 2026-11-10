"""Sample exports reuse the selected read without granting policy authority."""
from copy import deepcopy
from pathlib import Path

import pytest

from core.llm.scorecard import cli
from core.llm.scorecard.tests.test_render_scrub import _stat
from core.reporting.writer import load_committed_report, regenerate


def _reader(tmp_path, monkeypatch, *, cells=None):
    source = tmp_path / "scorecard.json"
    source.write_text("owned source bytes")
    if cells is None:
        stat = _stat("owned-class", "owned-model")
        stat.trusted = False
        stat.disagreement_samples = [{"note": "recorded observation"}]
        cells = [stat]
    calls = []
    class ReadOnlyScorecard:
        def __init__(self, path):
            assert Path(path) == source
            calls.append("open")
        def get_stats(self):
            calls.append("read")
            return cells
    monkeypatch.setattr(cli, "ModelScorecard", ReadOnlyScorecard)
    return source, calls, cells


@pytest.mark.parametrize("flags,exported", [([], False), (["--no-report"], False),
                                         (["--report-format", "json", "--report-format", "xml"], True)])
def test_native_view_and_portable_snapshot_share_one_read(tmp_path, monkeypatch, capsys, flags, exported):
    source, calls, cells = _reader(tmp_path, monkeypatch)
    before = deepcopy(cells)
    if exported:
        flags = [*flags, "--report-output", str(tmp_path / "portable-reports" / "scorecard-samples")]
    assert cli.main(["--path", str(source), "samples", "owned-class", *flags]) == 0
    shown = capsys.readouterr()
    assert "recorded observation" in shown.out and "unverified" in shown.out
    assert calls == ["open", "read"] and source.read_text() == "owned source bytes"
    root = tmp_path / "portable-reports" / "scorecard-samples"
    if exported:
        context, document, _ = load_committed_report(root)
        assert context.state == "partial" and context.run_id == "unknown"
        assert document.snapshot_id == context.snapshot_id
        assert context.extensions["raptor.metrics"]["Unverified matched cells"] == 1
        assert "Matched cells: 1" in shown.err
        xml = (root / "scorecard-samples.xml").read_bytes()
        source.unlink()
        regenerate(root, tmp_path / "offline.xml", format="xml")
        assert (tmp_path / "offline.xml").read_bytes() == xml
    else:
        assert not root.exists()
    assert cells == before


@pytest.mark.parametrize("failure", ["source", "options"])
def test_preflight_refuses_before_opening_scorecard(tmp_path, monkeypatch, failure):
    source, calls, _ = _reader(tmp_path, monkeypatch)
    flags = (["--report-format", "json", "--report-output", str(source)] if failure == "source"
             else ["--no-report", "--report-format", "json"])
    with pytest.raises(SystemExit) as error:
        cli.main(["--path", str(source), "samples", "owned-class", *flags])
    assert error.value.code == 2 and not calls
    assert source.read_text() == "owned source bytes"


def test_mutating_leaf_does_not_accept_sample_export_controls(tmp_path, monkeypatch):
    source, calls, _ = _reader(tmp_path, monkeypatch)
    with pytest.raises(SystemExit) as error:
        cli.main(["--path", str(source), "pin", "owned-class", "--model", "owned-model", "--as", "auto", "--report-format", "json"])
    assert error.value.code == 2 and not calls


def test_empty_selection_preserves_native_status_and_discloses_scope(tmp_path, monkeypatch, capsys):
    source, calls, _ = _reader(tmp_path, monkeypatch)
    assert cli.main(["--path", str(source), "samples", "other-class", "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-samples")]) == 1
    context, _, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-samples")
    assert context.state == "failed"
    assert context.extensions["raptor.metrics"]["Matched cells"] == 0
    assert any("does not establish" in note for note in context.diagnostics)
    assert "Native exit status: 1" in capsys.readouterr().err
    assert calls == ["open", "read"]


def test_publisher_failure_preserves_native_view_and_status(tmp_path, monkeypatch, capsys):
    source, calls, _ = _reader(tmp_path, monkeypatch)
    from core.llm.scorecard import sample_completion
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("private detail")
    monkeypatch.setattr(sample_completion, "complete_reporting", fail)
    assert cli.main(["--path", str(source), "samples", "owned-class", "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-samples")]) == 0
    shown = capsys.readouterr()
    assert "recorded observation" in shown.out
    assert "native sample view retained" in shown.err and "private detail" not in shown.err
    assert reached == [True] and calls == ["open", "read"]


def test_disabled_export_does_not_refresh_prior_receipts(tmp_path, monkeypatch, capsys):
    source, _, _ = _reader(tmp_path, monkeypatch)
    root = tmp_path / "portable-reports" / "scorecard-samples"
    root.mkdir(parents=True)
    manifest = root / "reporting-manifest.json"
    manifest.write_text("old unparsed receipt")
    assert cli.main(["--path", str(source), "samples", "owned-class", "--no-report"]) == 0
    assert "not refreshed" in capsys.readouterr().err
    assert manifest.read_text() == "old unparsed receipt" and not (root / "summary.json").exists()


def test_cell_capture_limit_preserves_matched_counts_and_source_cells(tmp_path, monkeypatch):
    cells = [_stat("owned-class", f"model-{index}") for index in range(26)]
    source, calls, original = _reader(tmp_path, monkeypatch, cells=cells)
    before = deepcopy(original)
    assert cli.main(["--path", str(source), "samples", "owned-class", "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-samples")]) == 0
    context, _, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-samples")
    assert context.state == "partial"
    assert context.extensions["raptor.metrics"]["Matched cells"] == 26
    assert context.extensions["raptor.omitted_sample_cells"] == 1
    assert len(context.extensions["raptor.captured_sample_cells"]) == 25
    assert original == before and calls == ["open", "read"]


def test_field_loss_reaches_context_and_operator_summary(tmp_path, monkeypatch, capsys):
    cell = _stat("owned-class", "owned-model")
    cell.disagreement_samples = [{"note": "recorded long reasoning " * 1000}]
    source, calls, _ = _reader(tmp_path, monkeypatch, cells=[cell])
    assert cli.main(["--path", str(source), "samples", "owned-class", "--report-format", "json", "--report-output", str(tmp_path / "portable-reports" / "scorecard-samples")]) == 0
    context, _, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-samples")
    assert context.state == "partial" and context.extensions["raptor.sample_capture_limited"] is True
    assert "sample fields or records were truncated" in capsys.readouterr().err
    assert len(cell.disagreement_samples[0]["note"]) > 4000 and calls == ["open", "read"]
