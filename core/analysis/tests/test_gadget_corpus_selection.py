"""CLI selection cannot count the same corpus as independent observations."""
import pytest

from core.analysis import gadget_oracle_precision as precision


@pytest.mark.parametrize("names, expected", [
    (["synthetic", "synthetic"], ["synthetic"]),
    (["library", "synthetic", "library"], ["library", "synthetic"]),
    ([], ["synthetic"]),
])
def test_corpus_selection_is_unique_in_first_seen_order(monkeypatch, tmp_path, capsys, names, expected):
    calls = []
    reports_written = []

    def forbidden(*args, **kwargs):
        pytest.fail("corpus generation/scanning/cloning must remain fenced")

    monkeypatch.setattr(precision.SyntheticCorpusDriver, "prepare", forbidden)
    monkeypatch.setattr(precision.LibraryCorpusDriver, "prepare", forbidden)
    monkeypatch.setattr(precision, "scan_tree", forbidden)
    monkeypatch.setattr(precision, "_git", forbidden)

    def measure(driver, work_dir):
        calls.append(driver.name)
        return precision.CorpusReport(
            corpus_name=driver.name, corpus_mode=driver.mode, n_rows=1,
            false_absence_denominator=1,
        )

    def write(reports, out_dir):
        reports_written.extend(reports)
        return tmp_path / "report.json"

    monkeypatch.setattr(precision, "run_corpus", measure)
    monkeypatch.setattr(precision, "write_report", write)
    argv = ["--out", str(tmp_path)]
    for name in names:
        argv.extend(["--corpus", name])
    assert precision.main(argv) == 0
    assert calls == expected
    assert len(reports_written) == len(expected)
    assert f"false-absence: 0/{len(expected)}" in capsys.readouterr().out
