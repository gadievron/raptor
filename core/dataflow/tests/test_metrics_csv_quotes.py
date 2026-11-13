"""Broken CSV quoting must not produce a successful metric summary."""

import csv

import pytest

from core.dataflow.corpus_metrics import compute


def test_metrics_refuse_broken_quotes_but_keep_quoted_fields(tmp_path):
    path = tmp_path / "results.csv"
    header = "finding_id,label_verdict,validator_label,fp_category"
    path.write_text(header + '\nfixture,true_positive,true_positive,"', encoding="utf-8")
    with pytest.raises(csv.Error):
        compute(path)
    path.write_text(header + ',comment\nfixture,true_positive,true_positive,,"note"junk\n', encoding="utf-8")
    with pytest.raises(csv.Error):
        compute(path)
    path.write_text(header + ',comment\n"fixture,one",true_positive,true_positive,,"line one\nline two"\n', encoding="utf-8")
    metrics = compute(path)
    assert metrics.total == metrics.tp == 1
