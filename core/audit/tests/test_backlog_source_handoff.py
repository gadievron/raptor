"""Backlog synthesis receipts cannot migrate to a later source version."""

import json
import hashlib

import pytest

from core.audit import backlog_drain, checker_synthesis
from core.audit.findings_export import export_findings, write_graded_findings
from core.json import load_json


def test_changed_source_cannot_leave_backlog_as_witnessed(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    source = "// owned context\n" * 100 + "int f(int n) { return n; }\n"
    path = target / "a.c"
    path.write_text(source, encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    (run / backlog_drain.BACKLOG_FILENAME).write_text(json.dumps({
        "total": 1, "clusters": [{"class": "CWE-252", "count": 1,
            "sites": [{"id": "owned", "file": "a.c", "function": "f", "line": 101,
                       "title": "discarded conversion error"}]}],
    }), encoding="utf-8")
    calls = []

    def produce(outcome, config, **kwargs):
        calls.append(kwargs["source_snippet"])
        path.write_text(source.replace("return n;", "return n + 0;"), encoding="utf-8")
        return checker_synthesis.OnDemandSynthesisResult(confirmed=True,
            stamp="semgrep:synth-a.c.f.CWE-252.0", rule_id="owned", tool="semgrep", cost_usd=0.03)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    report = backlog_drain.drain(run, target, 1.0)
    assert len(calls) == 1
    assert report.witnessed == 0
    assert report.attempted == 1
    assert report.spent_usd == 0.03
    artifact = json.loads((run / backlog_drain.BACKLOG_FILENAME).read_text())
    assert artifact["clusters"][0]["sites"]
    journal = run / "review-journal.jsonl"
    assert not journal.exists() or not journal.read_text().strip()


def _subject(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    source = "// owned context\n" * 100 + "int f(int n) { return n; }\n"
    path = target / "a.c"
    path.write_text(source, encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    (run / backlog_drain.BACKLOG_FILENAME).write_text(json.dumps({
        "total": 1, "clusters": [{"class": "CWE-252", "count": 1,
            "sites": [{"id": "owned", "file": "a.c", "function": "f", "line": 101,
                       "title": "discarded conversion error"}]}],
    }), encoding="utf-8")
    return target, run, path, source


def _confirmed():
    return checker_synthesis.OnDemandSynthesisResult(confirmed=True,
        stamp="semgrep:synth-a.c.f.CWE-252.0", rule_id="owned", tool="semgrep", cost_usd=0.03)


def _checks(run):
    write_graded_findings(export_findings([]), run)
    return load_json(run / "verification-checks.json")["checks"]


def test_healthy_window_binds_its_origin_separately_from_claim_line(tmp_path, monkeypatch):
    target, run, path, source = _subject(tmp_path)
    snippets = []

    def produce(outcome, config, **kwargs):
        assert outcome.line == 101
        snippets.append(kwargs["source_snippet"])
        return _confirmed()

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    report = backlog_drain.drain(run, target, 1.0)
    assert report.witnessed == report.dispatched == 1
    assert len(snippets) == 1 and snippets[0].endswith("int f(int n) { return n; }")
    assert len(snippets[0].split("\n")) == 41
    record = report.rows[0]
    assert record["verification_scope"]["line_start"] == 101
    assert record["excerpt_line_start"] == 61
    assert record["verification_scope"]["source_identity"]["sha256"] == hashlib.sha256(source.encode()).hexdigest()
    entries = [json.loads(line) for line in (run / "review-journal.jsonl").read_text().splitlines()]
    assert len(entries) == 1 and entries[0]["verdict"] == "suspicious"
    assert entries[0]["source_hash"]
    assert not entries[0]["evidence_tools"]  # self-matched receipt stays non-promoting


@pytest.mark.parametrize("change", ["delete", "restore"])
def test_known_identity_loss_retains_attempt_cost_and_row(tmp_path, monkeypatch, change):
    target, run, path, source = _subject(tmp_path)
    calls = []

    def produce(*args, **kwargs):
        calls.append("producer")
        if change == "delete":
            path.unlink()
        else:
            path.write_text(source + "\n// intermediate revision", encoding="utf-8")
            path.write_text(source, encoding="utf-8")
        return _confirmed()

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    report = backlog_drain.drain(run, target, 1.0)
    assert calls == ["producer"] and report.witnessed == 0 and report.attempted == 1
    assert report.spent_usd == pytest.approx(0.03)
    record = report.rows[0]
    assert record["reason"] == "source-version-drift" and record["journal"] == "not-appended"
    sites = load_json(run / backlog_drain.BACKLOG_FILENAME)["clusters"][0]["sites"]
    assert len(sites) == 1 and sites[0]["drain_attempts"] == 1
    withdrawal = next(c for c in _checks(run) if c["rule_id"] == "source-version-drift")
    assert withdrawal["scope"]["line_start"] == 101
    assert withdrawal["scope"]["source_identity"] is not None
    assert withdrawal["outcome"] == "inconclusive"


def test_stale_excerpt_refuses_before_dispatch_without_fresh_substitution(tmp_path, monkeypatch):
    target, run, path, source = _subject(tmp_path)
    read = backlog_drain._read_snippet
    calls = []

    def stale(*args):
        excerpt = read(*args)
        path.write_text(source.replace("return n;", "return n + 0;"), encoding="utf-8")
        return excerpt

    def unexpected_producer(*args, **kwargs):
        calls.append("producer")
        return _confirmed()

    monkeypatch.setattr(backlog_drain, "_read_snippet", stale)
    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", unexpected_producer)
    report = backlog_drain.drain(run, target, 1.0)
    assert calls == [] and report.dispatched == report.attempted == report.witnessed == 0
    assert report.spent_usd == 0 and report.rows[0]["action"] == "not-attempted"
    assert load_json(run / backlog_drain.BACKLOG_FILENAME)["clusters"][0]["sites"]
    rejection = next(c for c in _checks(run) if c["rule_id"] == "source-input-unbound")
    assert rejection["result"]["data"]["details"]["checker_execution"] == "not_run"


@pytest.mark.parametrize("field", ["file", "function", "line", "hypothesis", "review_hypothesis"])
def test_revised_producer_claim_cannot_be_journaled_under_original_row(tmp_path, monkeypatch, field):
    target, run, path, source = _subject(tmp_path)
    calls = []

    def produce(outcome, config, **kwargs):
        calls.append("producer")
        if field == "review_hypothesis":
            outcome.review_result["hypothesis"] = "changed"
        else:
            setattr(outcome, field, 9 if field == "line" else "changed")
        return _confirmed()

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    report = backlog_drain.drain(run, target, 1.0)
    assert calls == ["producer"] and report.witnessed == 0 and report.attempted == 1
    assert report.rows[0]["reason"] in {"claim-revised", "claim-scope-mismatch"}
    assert report.spent_usd == pytest.approx(0.03)
    rejection = next(c for c in _checks(run) if c["rule_id"] == "claim-scope-rejected")
    assert rejection["scope"]["file"] == "a.c"
    assert rejection["scope"]["hypothesis"] == "discarded conversion error"


def test_withdrawal_reporting_failure_never_restores_journal_authority(tmp_path, monkeypatch):
    from core.audit import check_trace

    target, run, path, source = _subject(tmp_path)
    seen = []

    def produce(*args, **kwargs):
        path.write_text(source + "\n// changed", encoding="utf-8")
        return _confirmed()

    def failed_record(*args, **kwargs):
        seen.append("record")
        raise OSError("owned recording failure")

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    monkeypatch.setattr(check_trace, "record_source_invalidation", failed_record)
    report = backlog_drain.drain(run, target, 1.0)
    assert seen == ["record"] and report.witnessed == 0 and report.attempted == 1
    assert report.rows[0]["journal"] == "not-appended"
    assert report.spent_usd == pytest.approx(0.03)
    assert not (run / "review-journal.jsonl").exists()


@pytest.mark.parametrize("return_foreign_entry", [False, True])
def test_other_journal_growth_does_not_acknowledge_this_row(tmp_path, monkeypatch, return_foreign_entry):
    from core.audit import collector

    target, run, path, source = _subject(tmp_path)
    path.write_text(source + "int g(void) { return 0; }\n", encoding="utf-8")
    append = collector.append_journal_for_outcome
    calls = []

    def other_write(**kwargs):
        from core.audit.refutation_source import capture_source_identity
        from core.audit.verification_results import VerificationScope

        calls.append(kwargs["outcome"].function)
        other = backlog_drain._RowOutcome(file="a.c", function="g", line=102,
            status="suspicious", hypothesis="owned unrelated concern", review_result={})
        foreign = dict(kwargs, outcome=other, gap={"line_start": 102, "line_end": 102})
        foreign["verification_scope"] = VerificationScope("a.c", "g", 102, other.hypothesis,
            capture_source_identity(target, "a.c"))
        acknowledgement = append(**foreign)
        return acknowledgement if return_foreign_entry else None

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", lambda *a, **kw: _confirmed())
    monkeypatch.setattr(collector, "append_journal_for_outcome", other_write)
    report = backlog_drain.drain(run, target, 1.0)
    assert calls == ["f"]
    entries = [json.loads(line) for line in (run / "review-journal.jsonl").read_text().splitlines()]
    assert [entry["function"] for entry in entries] == ["g"]
    assert report.witnessed == 0
    assert report.attempted == 1 and report.spent_usd == pytest.approx(0.03)
    assert load_json(run / backlog_drain.BACKLOG_FILENAME)["clusters"][0]["sites"]


def test_flush_failure_retains_row_after_own_append(tmp_path, monkeypatch):
    from core.coverage import journal

    target, run, path, source = _subject(tmp_path)
    flushed = []

    def failed_flush(directory, *, strict=False):
        assert strict
        flushed.append(directory)
        raise OSError("owned flush failure")

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", lambda *a, **kw: _confirmed())
    monkeypatch.setattr(journal, "flush_journal", failed_flush)
    report = backlog_drain.drain(run, target, 1.0)
    assert flushed == [run]
    assert report.witnessed == 0 and report.attempted == 1
    assert report.rows[0]["journal"] == "flush-failed"
    assert report.spent_usd == pytest.approx(0.03)
    assert load_json(run / backlog_drain.BACKLOG_FILENAME)["clusters"][0]["sites"]
    assert (run / "review-journal.jsonl").exists()  # append is distinct from flush


def test_acknowledgement_must_cover_the_selected_receipt(tmp_path, monkeypatch):
    from dataclasses import replace
    from core.audit import collector

    target, run, path, source = _subject(tmp_path)
    append = collector.append_journal_for_outcome
    seen = []

    def other_receipt(**kwargs):
        seen.append(kwargs["outcome"].function)
        other = replace(kwargs["outcome"], evidence_tool="semgrep:other-observation", body="owned other observation")
        return append(**dict(kwargs, outcome=other))

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", lambda *a, **kw: _confirmed())
    monkeypatch.setattr(collector, "append_journal_for_outcome", other_receipt)
    report = backlog_drain.drain(run, target, 1.0)
    assert seen == ["f"] and report.witnessed == 0 and report.attempted == 1
    assert report.spent_usd == pytest.approx(0.03)
    assert load_json(run / backlog_drain.BACKLOG_FILENAME)["clusters"][0]["sites"]


@pytest.mark.parametrize("phase", ["before_writer", "after_hash"])
def test_writer_does_not_freshen_a_receipt_after_late_source_edit(tmp_path, monkeypatch, phase):
    from core.audit import collector, record

    target, run, path, source = _subject(tmp_path)
    append, compute_hash = collector.append_journal_for_outcome, record._compute_hash
    seen = []

    def changed_before_write(**kwargs):
        seen.append("writer")
        path.write_text(source.replace("return n;", "return n + 0;"), encoding="utf-8")
        return append(**kwargs)

    def changed_after_hash(*args, **kwargs):
        result = compute_hash(*args, **kwargs)
        seen.append("hash")
        path.write_text(source.replace("return n;", "return n + 0;"), encoding="utf-8")
        return result

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", lambda *a, **kw: _confirmed())
    if phase == "before_writer":
        monkeypatch.setattr(collector, "append_journal_for_outcome", changed_before_write)
    else:
        monkeypatch.setattr(record, "_compute_hash", changed_after_hash)
    report = backlog_drain.drain(run, target, 1.0)
    assert seen == ["writer" if phase == "before_writer" else "hash"]
    assert report.witnessed == 0 and report.attempted == 1
    assert report.spent_usd == pytest.approx(0.03)
    assert not (run / "review-journal.jsonl").exists()
    withdrawal = next(c for c in _checks(run) if c["rule_id"] == "source-version-drift")
    assert withdrawal["result"]["data"]["details"]["phase"] == "journal_admission"


def test_mutating_writer_cannot_rewrite_its_expected_acknowledgement(tmp_path, monkeypatch):
    from core.audit import collector

    target, run, path, source = _subject(tmp_path)
    append = collector.append_journal_for_outcome
    seen = []

    def changed_payload(**kwargs):
        seen.append("writer")
        kwargs["outcome"].body = "owned rewritten body"
        return append(**kwargs)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", lambda *a, **kw: _confirmed())
    monkeypatch.setattr(collector, "append_journal_for_outcome", changed_payload)
    report = backlog_drain.drain(run, target, 1.0)
    assert seen == ["writer"] and report.witnessed == 0 and report.attempted == 1
    assert load_json(run / backlog_drain.BACKLOG_FILENAME)["clusters"][0]["sites"]


def test_missing_journal_at_flush_cannot_retire_pending_row(tmp_path, monkeypatch):
    from core.audit import collector

    target, run, path, source = _subject(tmp_path)
    append = collector.append_journal_for_outcome
    def append_then_lose_path(**kwargs):
        entry = append(**kwargs)
        assert entry is not None
        (run / "review-journal.jsonl").unlink()
        return entry
    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", lambda *a, **kw: _confirmed())
    monkeypatch.setattr(collector, "append_journal_for_outcome", append_then_lose_path)
    report = backlog_drain.drain(run, target, 1.0)
    assert report.witnessed == 0
    assert load_json(run / backlog_drain.BACKLOG_FILENAME)["clusters"][0]["sites"]
