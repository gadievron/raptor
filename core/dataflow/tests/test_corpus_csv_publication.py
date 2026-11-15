"""A failed corpus measurement run cannot publish a valid-looking prefix."""

import os
import stat

import pytest

from core.dataflow.corpus_metrics import compute
from core.dataflow.run_corpus import run
from core.dataflow.tests.test_run_corpus import _seed_corpus
from core.dataflow.validator import TrivialValidator, ValidatorVerdict


def test_failed_runs_preserve_complete_or_absent_output(tmp_path):
    for existing in (False, True):
        for failure in ("validator", "interrupt", "parse"):
            folder = tmp_path / f"{existing}-{failure}"
            folder.mkdir()
            corpus = _seed_corpus(folder)
            output = folder / "results.csv"
            if existing:
                assert run(corpus, TrivialValidator(), output) == 2
                output.chmod(0o640)
                previous = output.read_bytes()
            else:
                previous = None
            error = KeyboardInterrupt("owned interrupt") if failure == "interrupt" else RuntimeError("owned failure")
            calls = []

            class FailingValidator:
                def validate(self, finding):
                    calls.append(finding.finding_id)
                    if len(calls) == 2:
                        raise error
                    return ValidatorVerdict.EXPLOITABLE

            label = corpus / "f2.label.json"
            original_label = label.read_bytes()
            if failure == "parse":
                label.write_text("{", encoding="utf-8")
                validator = TrivialValidator()
                expected = ValueError
            else:
                validator = FailingValidator()
                expected = type(error)
            with pytest.raises(expected) as caught:
                run(corpus, validator, output)
            if failure != "parse":
                assert caught.value is error
                assert calls == ["f1", "f2"]
            if previous is None:
                assert not output.exists()
            else:
                assert output.read_bytes() == previous
                if os.name == "posix":
                    assert stat.S_IMODE(output.stat().st_mode) == 0o640
            assert not list(folder.glob(".atomic-*"))
            label.write_bytes(original_label)
            assert run(corpus, TrivialValidator(), output) == 2
            assert compute(output).total == 2
            if os.name == "posix":
                assert stat.S_IMODE(output.stat().st_mode) == (0o640 if existing else 0o600)


def test_corpus_output_alias_and_parent_contracts(tmp_path):
    corpus = _seed_corpus(tmp_path)
    target = tmp_path / "owned.csv"
    alias = tmp_path / "alias.csv"
    alias.symlink_to(target)
    assert run(corpus, TrivialValidator(), alias) == 2
    assert alias.is_symlink()
    assert target.read_bytes() == alias.read_bytes()
    assert compute(alias).total == 2
    missing = tmp_path / "missing" / "results.csv"
    with pytest.raises(FileNotFoundError):
        run(corpus, TrivialValidator(), missing)
    assert not missing.parent.exists()
