"""Dashboard/comparison exports use the native single-read calculation."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from core.llm.scorecard import cli
from core.llm.scorecard.tests.test_render_scrub import _stat
from core.reporting.writer import load_committed_report, regenerate


def _reader(tmp_path, monkeypatch, *, empty=False):
    source = tmp_path / "scorecard.json"
    source.write_text("owned source bytes")
    stats = []
    if not empty:
        for model in ("model-a", "model-b"):
            usage = _stat("_usage", model)
            usage.calls, usage.cost_usd = 10, 2.0
            subset = _stat("_structured", model)
            subset.calls, subset.cost_usd = 6, 1.0
            cell = _stat("owned-class", model)
            cell.calls = 4
            cell.trusted = False
            stats.extend([usage, subset, cell])
    calls = []
    class ReadOnlyScorecard:
        def __init__(self, path):
            assert Path(path) == source
        def get_stats(self, **kwargs):
            calls.append(kwargs)
            return stats
    monkeypatch.setattr(cli, "ModelScorecard", ReadOnlyScorecard)
    return source, stats, calls


@pytest.mark.parametrize("kind,selection", [("summary", []), ("compare", ["model-a", "model-b"])])
def test_native_json_and_single_read_are_preserved_with_export(tmp_path, monkeypatch, capsys, kind, selection):
    source, stats, calls = _reader(tmp_path, monkeypatch)
    before = deepcopy(stats)
    base = ["--path", str(source), "--json", kind, *selection]
    assert cli.main(base) == 0
    native = json.loads(capsys.readouterr().out)
    calls.clear()
    assert cli.main([*base, "--report-format", "json", "--report-format", "xml"]) == 0
    shown = capsys.readouterr()
    assert json.loads(shown.out) == native and len(calls) == 1
    root = tmp_path / "portable-reports" / ("scorecard-" + kind)
    context, document, _ = load_committed_report(root)
    assert context.state == "partial" and context.run_id == "unknown"
    assert document.snapshot_id == context.snapshot_id
    assert document.metadata["Freshness half-life days"] == "unweighted CLI view"
    assert "unverified cells" in shown.err
    data = context.extensions["raptor.scorecard_read"]
    if kind == "summary":
        assert data["total_spend_usd"] == native["total_spend_usd"] == 4.0
        assert data["model_rows"] == [["model-a", 2.0, 10], ["model-b", 2.0, 10]]
    else:
        assert len(data["shared"]) == len(native["shared"])
        assert document.metadata["Model A"] == "model-a"
    assert stats == before and source.read_text() == "owned source bytes"
    xml = (root / ("scorecard-" + kind + ".xml")).read_bytes()
    source.unlink()
    regenerate(root, tmp_path / "offline.xml", format="xml")
    assert (tmp_path / "offline.xml").read_bytes() == xml


def test_freshness_value_and_computed_lens_are_retained(tmp_path, monkeypatch, capsys):
    source, _, calls = _reader(tmp_path, monkeypatch)
    assert cli.main(["--path", str(source), "summary", "--freshness", "30", "--report-format", "json"]) == 0
    context, document, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-summary")
    assert calls == [{"freshness_half_life_days": 30.0}]
    assert context.extensions["raptor.freshness_half_life_days"] == 30.0
    assert document.metadata["Freshness half-life days"] == 30.0
    assert "total spend:" in capsys.readouterr().out


def test_empty_read_keeps_native_text_and_does_not_invent_historical_spend(tmp_path, monkeypatch, capsys):
    source, _, calls = _reader(tmp_path, monkeypatch, empty=True)
    assert cli.main(["--path", str(source), "summary", "--report-format", "json"]) == 0
    context, _, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-summary")
    assert context.extensions["raptor.metrics"]["total_spend_usd"] is None
    assert any("unavailable, not established as zero" in note for note in context.diagnostics)
    assert "scorecard is empty" in capsys.readouterr().out and len(calls) == 1


@pytest.mark.parametrize("kind,selection", [("summary", []), ("compare", ["model-a", "model-b"])])
def test_source_collision_precedes_read(tmp_path, monkeypatch, kind, selection):
    source, _, calls = _reader(tmp_path, monkeypatch)
    with pytest.raises(SystemExit) as error:
        cli.main(["--path", str(source), kind, *selection, "--report-format", "json", "--report-output", str(source)])
    assert error.value.code == 2 and not calls
    assert source.read_text() == "owned source bytes"


def test_disabled_summary_does_not_refresh_prior_receipts(tmp_path, monkeypatch, capsys):
    source, _, calls = _reader(tmp_path, monkeypatch)
    root = tmp_path / "portable-reports" / "scorecard-summary"
    root.mkdir(parents=True)
    manifest = root / "reporting-manifest.json"
    manifest.write_text("old unparsed receipt")
    assert cli.main(["--path", str(source), "summary", "--no-report"]) == 0
    assert "not refreshed" in capsys.readouterr().err
    assert manifest.read_text() == "old unparsed receipt" and not (root / "summary.json").exists()
    assert len(calls) == 1


def test_publisher_fault_does_not_change_native_json(tmp_path, monkeypatch, capsys):
    source, _, calls = _reader(tmp_path, monkeypatch)
    from core.llm.scorecard import read_report
    reached = []
    def fail(*args, **kwargs):
        reached.append(True)
        raise OSError("private fault")
    monkeypatch.setattr(read_report, "complete_reporting", fail)
    assert cli.main(["--path", str(source), "--json", "summary", "--report-format", "json"]) == 0
    shown = capsys.readouterr()
    assert json.loads(shown.out)["total_spend_usd"] == 4.0
    assert "native view retained" in shown.err and "private fault" not in shown.err
    assert reached == [True] and len(calls) == 1


def test_redacted_truncated_model_labels_do_not_merge_usage_rows(tmp_path, monkeypatch):
    source, stats, calls = _reader(tmp_path, monkeypatch)
    token = "z" * 24
    prefix = "Bearer " + token + " model-" + "k" * 2100
    for index, cell in enumerate(stats):
        cell.model = prefix + ("A" if index < 3 else "B")
    stats[3].cost_usd = 3.0
    assert cli.main(["--path", str(source), "summary", "--report-format", "json"]) == 0
    context, document, _ = load_committed_report(tmp_path / "portable-reports" / "scorecard-summary")
    data = context.extensions["raptor.scorecard_read"]
    assert len(data["model_rows"]) == 2
    assert data["model_rows"][0][0] == data["model_rows"][1][0]
    assert [row[1] for row in data["model_rows"]] == [2.0, 3.0]
    assert data["total_spend_usd"] == 5.0
    table = next(block for block in document.blocks if block.title == "Recorded model usage")
    assert [row[0] for row in table.rows] == [1, 2]
    assert table.rows[0][1] == table.rows[1][1]
    assert token not in json.dumps(context.to_dict())
    assert context.state == "partial" and context.extensions["raptor.capture_limited"] is True
    assert len(calls) == 1
