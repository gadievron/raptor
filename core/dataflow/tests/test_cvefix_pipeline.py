"""Test the CVE-fix → CodeQL → corpus orchestrator with a stub runner.

Proves the ``analyze`` → generator → ``write_corpus`` wiring end-to-end
without a real CodeQL CLI: the injected runner writes canned SARIF to the
``--output=`` path the orchestrator asked ``analyze`` to produce.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from core.dataflow.cvefix_pipeline import generate_corpus_for_pair


def _loc(uri: str, line: int, snippet: str, msg: str) -> dict:
    return {"location": {"physicalLocation": {
        "artifactLocation": {"uri": uri},
        "region": {"startLine": line, "startColumn": 5, "snippet": {"text": snippet}}},
        "message": {"text": msg}}}


def _sarif(sink_snippet: str, sink_line: int) -> dict:
    return {"runs": [{"results": [{
        "ruleId": "java/sql-injection", "message": {"text": "tainted SQL"},
        "codeFlows": [{"threadFlows": [{"locations": [
            _loc("Foo.java", 10, 'request.getParameter("id")', "source"),
            _loc("Foo.java", sink_line, sink_snippet, "sink"),
        ]}]}]}]}]}


def _stub_codeql_runner(sarif_by_db: dict):
    """A subprocess.run stand-in: writes the db's canned SARIF to the
    ``--output=`` path encoded in the codeql command, then 'succeeds'."""
    def run(cmd, **kwargs):
        db = cmd[3]  # codeql database analyze <db> ...
        out = next(a.split("=", 1)[1] for a in cmd if a.startswith("--output="))
        Path(out).write_text(json.dumps(sarif_by_db[db]))
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


def test_pipeline_drives_codeql_then_labels(tmp_path: Path):
    before_db = tmp_path / "before_db"
    after_db = tmp_path / "after_db"
    runner = _stub_codeql_runner({
        str(before_db): _sarif("stmt.execute(sql)", 20),                   # vulnerable
        str(after_db): _sarif("stmt.execute(Sanitizer.clean(sql))", 22),   # fixed; still flagged
    })

    pairs = generate_corpus_for_pair(
        before_db, after_db, ["java/sql-injection"],
        cve_id="CVE-2021-9999", cwe="CWE-89", labeled_at="2026-05-25",
        out_dir=tmp_path / "out", fix_touched_files={"Foo.java"},
        runner=runner,
    )

    by_verdict = {gt.verdict: (f, gt) for f, gt in pairs}
    assert set(by_verdict) == {"true_positive", "false_positive"}
    assert by_verdict["false_positive"][1].fp_category == "missing_sanitizer_model"
    # SARIF + corpus written under out_dir.
    assert (tmp_path / "out" / "sarif" / "before.sarif").exists()
    assert (tmp_path / "out" / "sarif" / "after.sarif").exists()
    assert len(list((tmp_path / "out" / "corpus").glob("*.label.json"))) == 2


def test_pipeline_localizes_to_fix_touched_files(tmp_path: Path):
    before_db = tmp_path / "b"
    after_db = tmp_path / "a"
    # after-fix SARIF flags two paths: the CVE one (Foo.java) + an unrelated one.
    after = _sarif("stmt.execute(Sanitizer.clean(sql))", 22)
    after["runs"][0]["results"].append({
        "ruleId": "java/sql-injection", "message": {"text": "other"},
        "codeFlows": [{"threadFlows": [{"locations": [
            _loc("Other.java", 3, "src", "source"),
            _loc("Other.java", 9, "sink", "sink")]}]}]})
    runner = _stub_codeql_runner({
        str(before_db): {"runs": [{"results": []}]},
        str(after_db): after,
    })

    pairs = generate_corpus_for_pair(
        before_db, after_db, ["java/sql-injection"],
        cve_id="CVE-X", cwe="CWE-89", labeled_at="2026-05-25",
        out_dir=tmp_path / "out", fix_touched_files={"Foo.java"},
        runner=runner, write=False,
    )
    assert len(pairs) == 1
    assert pairs[0][0].sink.file_path == "Foo.java"


def test_main_cli_parses_and_dispatches(tmp_path: Path, monkeypatch):
    """main() arg-parsing + dispatch, with analyze stubbed to write canned
    SARIF — exercises the scripts/trust-corpus entry point without CodeQL."""
    from core.dataflow import cvefix_pipeline

    before_db = tmp_path / "bdb"
    after_db = tmp_path / "adb"
    sarif_by_db = {
        str(before_db): _sarif("stmt.execute(sql)", 20),
        str(after_db): _sarif("stmt.execute(Sanitizer.clean(sql))", 22),
    }

    def _stub_analyze(db_path, queries, output_path, **kwargs):
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(sarif_by_db[str(db_path)]))
        return SimpleNamespace(sarif_path=output_path)

    monkeypatch.setattr(cvefix_pipeline, "analyze", _stub_analyze)

    rc = cvefix_pipeline.main([
        str(before_db), str(after_db), "--query", "java/sql-injection",
        "--cve", "CVE-2021-9999", "--cwe", "CWE-89",
        "--out", str(tmp_path / "out"), "--fix-touched-file", "Foo.java",
        "--labeled-at", "2026-05-25",
    ])
    assert rc == 0
    assert len(list((tmp_path / "out" / "corpus").glob("*.label.json"))) == 2
