"""Tests for the Tier 0-aware synth-results analyzer."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from core.dataflow import trust_corpus_report as r


def _make_db(path: Path, rows: list) -> None:
    """Materialise a synth_results table matching :mod:`cvefix_bridge`'s schema.
    ``rows`` is a list of ``(fix_hash, cwe, cve_id, repo_language,
    finding_id, status, backend, barrier_query, detail)`` tuples."""
    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE synth_results ("
        "fix_hash TEXT, cwe TEXT, cve_id TEXT, repo_language TEXT, "
        "finding_id TEXT, status TEXT, backend TEXT, barrier_query TEXT, "
        "detail TEXT, ts REAL, PRIMARY KEY (fix_hash, cwe))"
    )
    for row in rows:
        con.execute(
            "INSERT INTO synth_results VALUES (?,?,?,?,?,?,?,?,?,?)",
            (*row, time.time()),
        )
    con.commit()
    con.close()


def _row(fix, cwe, cve, lang, status, backend, detail="", bq=None, fid=None):
    return (fix, cwe, cve, lang, fid or f"{cve}:{cwe}", status, backend, bq, detail)


def test_analyze_empty_db_returns_zero_counts(tmp_path: Path):
    db = tmp_path / "empty.db"
    _make_db(db, [])
    rep = r.analyze(db)
    assert rep.processed == 0
    assert rep.sound == 0
    assert rep.suppression_rate is None
    assert rep.tier0_share_of_sound is None


def test_analyze_missing_db_returns_zero_counts(tmp_path: Path):
    """If the bridge hasn't created the DB yet, analyze must still return
    a zero-counts report (not raise) — analyzer is safe to run any time."""
    rep = r.analyze(tmp_path / "does-not-exist.db")
    assert rep.processed == 0


def test_analyze_mixed_outcomes(tmp_path: Path):
    db = tmp_path / "m.db"
    _make_db(db, [
        # Two Tier 0 SOUND (smt backend) — pathtrav cases
        _row("f1", "CWE-22", "CVE-1", "Python", "sound", "smt", "UNSAT", "smt:..."),
        _row("f2", "CWE-22", "CVE-2", "Python", "sound", "smt", "UNSAT", "smt:..."),
        # One Tier 2 SOUND (codeql backend) — sqli case
        _row("f3", "CWE-89", "CVE-3", "Java", "sound", "codeql", "", "QL..."),
        # Two not_sound — different failure modes
        _row("f4", "CWE-79", "CVE-4", "JavaScript", "not_sound", "codeql",
             "suppress_fp_failed(after=1)"),
        _row("f5", "CWE-79", "CVE-5", "JavaScript", "not_sound", "codeql",
             "preserve_tp_failed(before=0)"),
        # One no_barrier
        _row("f6", "CWE-78", "CVE-6", "Ruby", "no_barrier", "codeql", "compile err"),
        # Pipeline errors — excluded from rate
        _row("f7", "CWE-22", "CVE-7", "Python", "build_fail", ""),
        _row("f8", "CWE-22", "CVE-8", "TypeScript", "fetch_fail", ""),
    ])
    rep = r.analyze(db)

    # Headline
    assert rep.processed == 6                # 3 sound + 2 not_sound + 1 no_barrier
    assert rep.sound == 3
    assert rep.not_sound == 2
    assert rep.no_barrier == 1
    assert rep.suppression_rate == 3 / 5     # 3 sound / (3 + 2)
    assert dict(rep.pipeline_errors) == {"build_fail": 1, "fetch_fail": 1}

    # Backend split — 2 smt, 1 codeql among sound
    assert rep.sound_by_backend["smt"] == 2
    assert rep.sound_by_backend["codeql"] == 1
    assert rep.tier0_share_of_sound == 2 / 3

    # Failure-mode distribution
    assert rep.not_sound_modes["suppress_fp_failed"] == 1
    assert rep.not_sound_modes["preserve_tp_failed"] == 1

    # Per-CWE
    assert rep.by_cwe["CWE-22"]["sound"]["smt"] == 2
    assert rep.by_cwe["CWE-89"]["sound"]["codeql"] == 1
    assert sum(rep.by_cwe["CWE-79"]["not_sound"].values()) == 2

    # Per-language
    assert rep.by_language["Python"]["sound"]["smt"] == 2
    assert rep.by_language["Java"]["sound"]["codeql"] == 1


def test_attempts_saved_uses_default_max_attempts(tmp_path: Path):
    db = tmp_path / "s.db"
    _make_db(db, [
        _row(f"f{i}", "CWE-22", f"CVE-{i}", "Python", "sound", "smt")
        for i in range(5)
    ])
    rep = r.analyze(db)
    # 5 Tier 0 SOUNDs * 3 attempts default = 15
    assert rep.tier0_attempts_saved() == 15
    # Configurable
    assert rep.tier0_attempts_saved(max_attempts=2) == 10


def test_render_text_handles_empty_report():
    """Renderer must not crash when nothing has been processed yet —
    analyzer is meant to be run while the bridge is still warming up."""
    rep = r.CorpusReport()
    text = r.render_text(rep)
    assert "Trust-witness corpus report" in text
    assert "no verdicts yet" in text
    assert "no rows yet" in text


def test_render_text_includes_headline_numbers(tmp_path: Path):
    db = tmp_path / "h.db"
    _make_db(db, [
        _row("f1", "CWE-22", "CVE-1", "Python", "sound", "smt"),
        _row("f2", "CWE-22", "CVE-2", "Python", "sound", "codeql"),
        _row("f3", "CWE-22", "CVE-3", "Python", "not_sound", "codeql",
             "suppress_fp_failed(after=1)"),
    ])
    rep = r.analyze(db)
    text = r.render_text(rep)
    # Suppression rate 2/3 = 66.7%
    assert "66.7%" in text
    # Backend split shows 1 smt and 1 codeql out of 2 sound
    assert "smt" in text and "codeql" in text
    # Per-CWE block names CWE-22
    assert "CWE-22" in text


def test_classify_not_sound_mode():
    assert r._classify_not_sound_mode("suppress_fp_failed(after=1)") == "suppress_fp_failed"
    assert r._classify_not_sound_mode("preserve_tp_failed(before=0)") == "preserve_tp_failed"
    assert r._classify_not_sound_mode(
        "suppress_fp_failed(after=1); preserve_tp_failed(before=0)"
    ) == "both"
    assert r._classify_not_sound_mode("") == "other"
    assert r._classify_not_sound_mode("unrelated") == "other"


def test_unknown_status_routed_to_pipeline_errors(tmp_path: Path):
    """A status not in the bridge's enum (e.g. a future addition we don't
    yet recognise) must NOT silently inflate the suppression rate — route
    to pipeline_errors so it surfaces and the rate stays honest."""
    db = tmp_path / "u.db"
    _make_db(db, [
        _row("f1", "CWE-22", "CVE-1", "Python", "totally_new_status", "x"),
    ])
    rep = r.analyze(db)
    assert rep.processed == 0
    assert rep.pipeline_errors["totally_new_status"] == 1
