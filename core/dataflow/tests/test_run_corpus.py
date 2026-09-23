"""Tests for ``core.dataflow.run_corpus``."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from core.dataflow import (
    FP_MISSING_SANITIZER_MODEL,
    Finding,
    GroundTruth,
    Step,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)
from core.dataflow.run_corpus import (
    CSV_HEADER,
    iter_corpus,
    load_validator,
    main,
    run,
    verdict_to_label,
)
from core.dataflow.validator import TrivialValidator, ValidatorVerdict


def _seed_corpus(tmp_path: Path) -> Path:
    """Create a 2-entry corpus (1 TP, 1 FP) under tmp_path."""
    corpus = tmp_path / "findings"
    corpus.mkdir()

    def _step(role: str, line: int) -> Step:
        return Step(file_path="a.py", line=line, column=0, snippet="x", label=role)

    f1 = Finding(
        finding_id="f1",
        producer="codeql",
        rule_id="py/x",
        message="m",
        source=_step("source", 1),
        sink=_step("sink", 5),
    )
    f2 = Finding(
        finding_id="f2",
        producer="codeql",
        rule_id="py/y",
        message="m",
        source=_step("source", 1),
        sink=_step("sink", 5),
    )
    (corpus / "f1.json").write_text(f1.to_json())
    (corpus / "f2.json").write_text(f2.to_json())
    (corpus / "f1.label.json").write_text(
        GroundTruth(
            finding_id="f1",
            verdict=VERDICT_TRUE_POSITIVE,
            rationale="r",
            labeler="t",
            labeled_at="2026-05-10",
        ).to_json()
    )
    (corpus / "f2.label.json").write_text(
        GroundTruth(
            finding_id="f2",
            verdict=VERDICT_FALSE_POSITIVE,
            fp_category=FP_MISSING_SANITIZER_MODEL,
            rationale="r",
            labeler="t",
            labeled_at="2026-05-10",
        ).to_json()
    )
    return corpus


def test_iter_corpus_yields_finding_label_pairs(tmp_path: Path):
    corpus = _seed_corpus(tmp_path)
    pairs = list(iter_corpus(corpus))
    assert len(pairs) == 2
    ids = {f.finding_id for f, _ in pairs}
    assert ids == {"f1", "f2"}


def test_verdict_to_label_maps_correctly():
    assert verdict_to_label(ValidatorVerdict.EXPLOITABLE) == VERDICT_TRUE_POSITIVE
    assert verdict_to_label(ValidatorVerdict.NOT_EXPLOITABLE) == VERDICT_FALSE_POSITIVE
    assert verdict_to_label(ValidatorVerdict.UNCERTAIN) == "uncertain"


def test_run_emits_csv_header_and_one_row_per_finding(tmp_path: Path):
    corpus = _seed_corpus(tmp_path)
    out = tmp_path / "result.csv"
    rows = run(corpus, TrivialValidator(), out)
    assert rows == 2
    with out.open() as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header == CSV_HEADER
        body = list(reader)
        assert len(body) == 2


def test_run_records_agreement_for_trivial_validator(tmp_path: Path):
    """TrivialValidator says exploitable for all → agrees with TPs,
    disagrees with FPs."""
    corpus = _seed_corpus(tmp_path)
    out = tmp_path / "result.csv"
    run(corpus, TrivialValidator(), out)
    with out.open() as f:
        rows = list(csv.DictReader(f))
    by_id = {r["finding_id"]: r for r in rows}
    assert by_id["f1"]["agreement"] == "agree"     # TP, validator says exploitable → agree
    assert by_id["f2"]["agreement"] == "disagree"  # FP, validator says exploitable → disagree


def test_run_records_fp_category_when_label_is_fp(tmp_path: Path):
    corpus = _seed_corpus(tmp_path)
    out = tmp_path / "result.csv"
    run(corpus, TrivialValidator(), out)
    with out.open() as f:
        rows = list(csv.DictReader(f))
    by_id = {r["finding_id"]: r for r in rows}
    assert by_id["f1"]["fp_category"] == ""
    assert by_id["f2"]["fp_category"] == FP_MISSING_SANITIZER_MODEL


def test_load_validator_parses_module_class_spec():
    v = load_validator("core.dataflow.validator:TrivialValidator")
    assert isinstance(v, TrivialValidator)


def test_load_validator_rejects_malformed_spec():
    with pytest.raises(ValueError, match="module.path:ClassName"):
        load_validator("no_colon_here")
    with pytest.raises(ValueError, match="module.path:ClassName"):
        load_validator(":no_module")


def test_load_validator_rejects_class_not_implementing_protocol():
    # `dict` is callable, returns dict() — has no .validate method
    with pytest.raises(TypeError, match="Validator protocol"):
        load_validator("builtins:dict")


def test_main_writes_csv_with_default_validator(tmp_path: Path):
    corpus = _seed_corpus(tmp_path)
    out = tmp_path / "result.csv"
    rc = main(["--corpus-dir", str(corpus), "--output", str(out)])
    assert rc == 0
    assert out.exists()


def test_main_returns_2_when_corpus_dir_missing(tmp_path: Path):
    out = tmp_path / "result.csv"
    missing = tmp_path / "nope"
    rc = main(["--corpus-dir", str(missing), "--output", str(out)])
    assert rc == 2


def test_main_with_custom_validator_spec(tmp_path: Path):
    corpus = _seed_corpus(tmp_path)
    out = tmp_path / "result.csv"
    rc = main([
        "--corpus-dir", str(corpus),
        "--output", str(out),
        "--validator", "core.dataflow.validator:TrivialValidator",
    ])
    assert rc == 0


class TestPinnedSourceVerification:
    """Labels are sha-bound; the runner must verify present pinned
    clones against SOURCES.md (the pins' single home) before it
    proceeds, and duplicated pin constants must equal the documented
    pin."""

    def test_sources_md_parses_and_pins_are_full_shape(self):
        from core.dataflow.corpus_sources import load_pinned_sources
        sources = {s.name: s for s in load_pinned_sources()}
        assert "OWASP Benchmark Java" in sources
        owasp = sources["OWASP Benchmark Java"]
        assert len(owasp.pinned_sha) == 40
        assert owasp.local_path.startswith("out/dataflow-corpus-fixtures/")
        # Every entry that documents a pin documents its clone path.
        for s in sources.values():
            assert s.pinned_sha and s.local_path, s.name

    def test_owasp_manifest_constant_matches_sources_md(self):
        """owasp_manifest duplicates the sha with a 'must match
        SOURCES.md' comment and no gate kept them equal — this is the
        gate."""
        from core.dataflow.corpus_sources import load_pinned_sources
        from core.recall.owasp_manifest import (
            OWASP_DEFAULT_CLONE,
            OWASP_PINNED_SHA,
        )
        owasp = {s.name: s for s in load_pinned_sources()}[
            "OWASP Benchmark Java"]
        assert OWASP_PINNED_SHA == owasp.pinned_sha
        assert OWASP_DEFAULT_CLONE.rstrip("/") == owasp.local_path

    def test_absent_clones_are_skipped(self, tmp_path):
        from core.dataflow.corpus_sources import (
            verify_present_pinned_clones,
        )
        assert verify_present_pinned_clones(repo_root=tmp_path) == []

    def test_present_clone_at_wrong_sha_refuses(self, tmp_path, monkeypatch):
        import os
        import subprocess
        from core.dataflow import corpus_sources as cs
        if subprocess.run(["git", "--version"], capture_output=True,
                          check=False).returncode != 0:
            pytest.skip("git unavailable")
        clone = tmp_path / "out" / "dataflow-corpus-fixtures" / "owasp-benchmark-java"
        clone.mkdir(parents=True)
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
               "HOME": str(tmp_path), "PATH": os.environ.get("PATH", "")}
        for cmd in (["git", "init", "-q", "."],
                    ["git", "commit", "-q", "--allow-empty", "-m", "x"]):
            subprocess.run(cmd, cwd=clone, env=env, check=True,
                           capture_output=True)
        with pytest.raises(cs.CorpusPinError, match="pinned"):
            cs.verify_present_pinned_clones(repo_root=tmp_path)

    def test_runner_main_refuses_on_pin_mismatch(self, tmp_path, monkeypatch):
        import core.dataflow.run_corpus as rc
        from core.dataflow import corpus_sources as cs

        def boom():
            raise cs.CorpusPinError("clone drifted")

        monkeypatch.setattr(
            "core.dataflow.corpus_sources.verify_present_pinned_clones",
            boom,
        )
        corpus = tmp_path / "findings"
        corpus.mkdir()
        rv = rc.main(["--corpus-dir", str(corpus),
                      "--output", str(tmp_path / "out.csv")])
        assert rv == 2
        assert not (tmp_path / "out.csv").exists()
