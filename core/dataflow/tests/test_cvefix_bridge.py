"""Tests for the harvest->synthesize bridge (CodeQL + LLM stubbed)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from core.dataflow import cvefix_bridge, cvefix_walk
from core.dataflow.barrier_synth import SynthResult
from core.dataflow.cvefix_loader import CveFixPair


def _pair(cwe="CWE-89", lang="Python", fix="f1"):
    return CveFixPair("CVE-X", cwe, "https://github.com/o/a", lang, fix, "p1")


def test_norm_uri_strips_scheme_and_leading_slash():
    assert cvefix_bridge._norm_uri("src/a.py") == "src/a.py"
    assert cvefix_bridge._norm_uri("file:///abs/a.py") == "abs/a.py"
    assert cvefix_bridge._norm_uri("file:src/a.py") == "src/a.py"


def test_extract_proposal_reads_source_and_returns_target_uri(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cvefix_bridge, "_git_diff", lambda *a, **k: "")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\nx = req()\nos.system(x)\nsafe()\n")
    sarif = tmp_path / "a.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"locations": [
        {"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                              "region": {"startLine": 3}}}]}]}]}))
    out = cvefix_bridge._extract_proposal(sarif, repo, _pair(cwe="CWE-78"))
    assert out is not None
    proposal, target_uri, target_line = out
    assert target_uri == "app.py" and target_line == 3
    assert proposal.sink_class == "cmdi" and proposal.language == "python"
    assert proposal.sink_snippet == "os.system(x)"
    assert proposal.finding_id == "CVE-X:CWE-78:app.py:3"


def test_extract_proposal_includes_fix_diff(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cvefix_bridge, "_git_diff", lambda *a, **k: "+ if safe(x): ...")
    monkeypatch.setattr(cvefix_bridge, "_git_diff_other_files", lambda *a, **k: "")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("os.system(x)\n")
    sarif = tmp_path / "a.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"locations": [
        {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}]}]}))
    proposal, _, _ = cvefix_bridge._extract_proposal(sarif, repo, _pair(cwe="CWE-78"))
    assert "fix diff" in proposal.source_context and "+ if safe(x)" in proposal.source_context


def test_extract_proposal_includes_other_fix_files(monkeypatch, tmp_path: Path):
    """Regression: cross-file fixes (validator in helper, sink in
    middleware) need the helper's diff in the proposer context — without
    it the LLM has no validator source to model and hallucinates.
    Pin the integration: ``_git_diff_other_files`` output reaches the
    proposal's source_context with the framing the prompt expects."""
    monkeypatch.setattr(cvefix_bridge, "_git_diff", lambda *a, **k: "")
    monkeypatch.setattr(
        cvefix_bridge, "_git_diff_other_files",
        lambda *a, **k: ("# file: server/helpers/dns.ts\n"
                         "+ async function isResolvingToUnicastOnly(h) { ... }"),
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "mock-object-storage.ts").write_text("fetch(url)\n")
    sarif = tmp_path / "a.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"locations": [{"physicalLocation":
        {"artifactLocation": {"uri": "mock-object-storage.ts"},
         "region": {"startLine": 1}}}]}]}]}))
    proposal, _, _ = cvefix_bridge._extract_proposal(
        sarif, repo, _pair(cwe="CWE-918", lang="TypeScript"))
    assert "other fix-touched files" in proposal.source_context
    assert "isResolvingToUnicastOnly" in proposal.source_context
    assert "server/helpers/dns.ts" in proposal.source_context


# ---------------------------------------------------------------------------
# Test-path heuristic + cross-file diff assembly
# ---------------------------------------------------------------------------

def test_is_test_path_recognises_common_conventions():
    """Every flagged pattern must catch real test-file shapes from each
    language we walk; non-test files must NOT match."""
    # Test paths (these MUST match):
    for p in [
        "server/tests/api/check-params/video-imports.ts",
        "src/test/java/com/example/FooTest.java",
        "src/test/java/com/example/TestFoo.java",
        "src/test/java/com/example/FooTests.java",
        "internal/server/server_test.go",
        "tests/test_app.py",
        "spec/models/user_spec.rb",
        "src/__tests__/helper.test.tsx",
        "app/foo.spec.ts",
        "components/Header.test.jsx",
        "lib/__tests__/helper.test.js",
    ]:
        assert cvefix_bridge._is_test_path(p), f"should be test: {p}"
    # Non-test paths (these MUST NOT match — false positives lose the validator):
    for p in [
        "server/helpers/dns.ts",
        "server/middlewares/validators/videos/video-imports.ts",
        "src/main/java/com/example/Foo.java",
        "internal/server/server.go",
        "src/foo.py",
        "lib/user.rb",
        "components/Header.tsx",
        # Edge: a file literally named ``test.go`` (not ``foo_test.go``) is
        # NOT a Go test file by convention — pin that we don't false-pos.
        "cmd/test.go",
    ]:
        assert not cvefix_bridge._is_test_path(p), f"should NOT be test: {p}"


def test_git_diff_other_files_excludes_sink_and_tests(monkeypatch, tmp_path: Path):
    """``_git_diff_other_files`` must skip the sink URI and any test paths;
    the remaining files' diffs are concatenated with file-header lines."""
    monkeypatch.setattr(
        cvefix_bridge, "_git_touched_files",
        lambda *a, **k: ["server/helpers/dns.ts",
                          "server/middlewares/x.ts",
                          "server/tests/check-x.ts",         # test, must skip
                          "mock-object-storage.ts"],         # sink, must skip
    )
    seen_files: list = []

    def fake_diff(repo, parent, fix, uri, *, cap=200, timeout=60):
        seen_files.append(uri)
        return f"+ change in {uri}"

    monkeypatch.setattr(cvefix_bridge, "_git_diff", fake_diff)
    out = cvefix_bridge._git_diff_other_files(
        tmp_path, "p", "f", "mock-object-storage.ts")
    # sink-file and test-file diffs must NOT have been requested:
    assert "mock-object-storage.ts" not in seen_files
    assert all("/tests/" not in p for p in seen_files)
    # remaining files appear with file-header annotation:
    assert "# file: server/helpers/dns.ts" in out
    assert "# file: server/middlewares/x.ts" in out
    # per-file order preserved (deterministic for reproducibility):
    assert out.index("dns.ts") < out.index("x.ts")


def test_git_diff_other_files_respects_total_cap(monkeypatch, tmp_path: Path):
    """Total-cap protects the LLM context budget on fixes touching many
    files.  Past the cap, the harvester stops adding new files."""
    monkeypatch.setattr(
        cvefix_bridge, "_git_touched_files",
        lambda *a, **k: [f"f{i}.py" for i in range(20)],
    )
    monkeypatch.setattr(
        cvefix_bridge, "_git_diff",
        lambda *a, **k: "\n".join([f"+ line {j}" for j in range(50)]),
    )
    out = cvefix_bridge._git_diff_other_files(
        tmp_path, "p", "f", "sink.py", total_cap=80, per_file_cap=50)
    # Verify total cap is approximately respected (within 1 chunk worth of
    # overshoot due to header lines).  Stricter: at least one file dropped.
    n_files_included = out.count("# file:")
    assert n_files_included < 20, "total_cap not enforced"
    # Truncation marker appears when a per-file or total cap is hit:
    assert "truncated" in out or n_files_included < 20


def test_git_diff_other_files_empty_when_only_sink_touched(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        cvefix_bridge, "_git_touched_files",
        lambda *a, **k: ["mock-object-storage.ts"],
    )
    out = cvefix_bridge._git_diff_other_files(
        tmp_path, "p", "f", "mock-object-storage.ts")
    assert out == ""


def test_git_touched_files_returns_empty_on_subprocess_fail(monkeypatch, tmp_path: Path):
    """Failure isolation: if `git diff --name-only` errors, callers
    silently fall back to sink-file-only context (the original behaviour),
    not abort the synth."""
    def fake_run(*a, **k):
        raise OSError("simulated git failure")
    monkeypatch.setattr(cvefix_bridge.subprocess, "run", fake_run)
    assert cvefix_bridge._git_touched_files(tmp_path, "p", "f") == []


def test_format_path_renders_codeflow_source_to_sink():
    def step(uri, line, msg):
        return {"location": {"physicalLocation": {"artifactLocation": {"uri": uri},
                "region": {"startLine": line}}, "message": {"text": msg}}}
    result = {"codeFlows": [{"threadFlows": [{"locations": [
        step("app.py", 6, "request"), step("app.py", 17, "host"),
        step("app.py", 20, "os.system")]}]}]}
    out = cvefix_bridge._format_path(result)
    assert "tainted dataflow path" in out
    assert "app.py:6" in out and "request" in out          # source
    assert "app.py:17" in out and "host" in out            # the value to protect
    assert "app.py:20" in out                              # sink
    assert cvefix_bridge._format_path({}) == ""            # no codeFlows -> empty


def test_extract_proposal_none_when_no_location(tmp_path: Path):
    sarif = tmp_path / "a.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": []}]}))
    assert cvefix_bridge._extract_proposal(sarif, tmp_path, _pair()) is None


def test_synthesize_one_build_mode_from_status(monkeypatch, tmp_path: Path):
    seen = {}
    monkeypatch.setattr(cvefix_bridge, "_TIER0_AVAILABLE", False)
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)

    def fake_build(src, commit, db, lang, codeql_bin, timeout, build_mode=None):
        seen["mode"] = build_mode
        return True

    monkeypatch.setattr(cvefix_walk, "_build_db", fake_build)
    monkeypatch.setattr(cvefix_bridge, "_run_query", lambda *a, **k: True)
    prop = cvefix_bridge.BarrierProposal("sqli", "fid", "exec(x)", "ctx", "java")
    monkeypatch.setattr(cvefix_bridge, "_extract_proposal", lambda *a, **k: (prop, "a.java", 1))
    monkeypatch.setattr(cvefix_bridge, "run_synthesis_loop",
                        lambda *a, **k: SynthResult(query_ql="q", after_count=0, before_count=1))
    jv = _pair(lang="Java", fix="fj")
    cvefix_bridge.synthesize_one(jv, work_dir=tmp_path / "w1", proposer=lambda *a: "", status="ok")
    assert seen["mode"] == "none"                      # buildless-found Java
    cvefix_bridge.synthesize_one(jv, work_dir=tmp_path / "w2", proposer=lambda *a: "", status="ok_built")
    assert seen["mode"] == "autobuild"                 # autobuild-found Java -> rebuild same way
    cvefix_bridge.synthesize_one(_pair(lang="Python"), work_dir=tmp_path / "w3",
                                 proposer=lambda *a: "", status="ok")
    assert seen["mode"] is None                        # source lang


def test_synthesize_one_happy_path_returns_sound_query(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cvefix_bridge, "_TIER0_AVAILABLE", False)
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)
    monkeypatch.setattr(cvefix_walk, "_build_db", lambda *a, **k: True)
    monkeypatch.setattr(cvefix_bridge, "_run_query", lambda *a, **k: True)
    prop = cvefix_bridge.BarrierProposal("sqli", "CVE-X:CWE-89:a.py:3", "exec(x)", "ctx", "python")
    monkeypatch.setattr(cvefix_bridge, "_extract_proposal", lambda *a, **k: (prop, "a.py", 3))
    monkeypatch.setattr(cvefix_bridge, "run_synthesis_loop",
                        lambda *a, **k: SynthResult(query_ql="SOUND_QL", after_count=0, before_count=1))
    status, fid, backend, sq, detail = cvefix_bridge.synthesize_one(
        _pair(), work_dir=tmp_path / "w", proposer=lambda *a: "")
    assert status == "sound" and fid == "CVE-X:CWE-89:a.py:3"
    assert backend == "codeql" and sq == "SOUND_QL"


def test_synthesize_one_fetch_fail(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: False)
    assert cvefix_bridge.synthesize_one(_pair(), work_dir=tmp_path / "w",
                                        proposer=lambda *a: "") == ("fetch_fail", None, "", None, "")


def _results_db(path: Path):
    con = sqlite3.connect(str(path))
    con.execute(cvefix_walk._SCHEMA)

    def ins(fix, cwe, after):
        con.execute("INSERT INTO walk_results VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (fix, "CVE-" + fix, cwe, "Python", "https://github.com/o/a",
                     fix + "p", "ok", 1, after, 0.0))
    ins("f1", "CWE-89", 1)   # candidate -> sound
    ins("f2", "CWE-79", 2)   # candidate -> not_sound
    ins("f3", "CWE-78", 1)   # candidate -> build_fail (pipeline error)
    ins("f4", "CWE-22", 0)   # after==0 -> NOT a candidate
    con.commit()
    con.close()


def test_synthesize_from_results_aggregates_persists_resumes(monkeypatch, tmp_path: Path):
    results, synth = tmp_path / "r.db", tmp_path / "s.db"
    _results_db(results)
    outcomes = {"f1": ("sound", "f1:id", "smt", "smt:charset:[a-z]+@x:1", "tier0 unsat"),
                "f2": ("not_sound", "f2:id", "codeql", "QL2", "suppress_fp_failed(after=2)"),
                "f3": ("build_fail", None, "", None, "")}
    calls = []

    def fake(pair, **kw):
        calls.append(pair.fix_hash)
        return outcomes[pair.fix_hash]

    monkeypatch.setattr(cvefix_bridge, "synthesize_one", fake)
    report = cvefix_bridge.synthesize_from_results(
        results, synth_db=synth, work_dir=tmp_path / "w", proposer=lambda *a: "", log=lambda *a: None)
    assert sorted(calls) == ["f1", "f2", "f3"]                 # f4 excluded (after==0)
    assert report.total == 2 and report.sound == 1 and report.not_sound == 1
    assert report.suppression_rate == 0.5                      # f3 excluded from rate
    with sqlite3.connect(str(synth)) as con:
        # barrier query persisted for sound AND not_sound; reason persisted too;
        # backend column distinguishes Tier 0 (smt) from Tier 2 (codeql)
        assert con.execute("SELECT barrier_query FROM synth_results WHERE fix_hash='f1'").fetchone()[0] == "smt:charset:[a-z]+@x:1"
        assert con.execute("SELECT backend FROM synth_results WHERE fix_hash='f1'").fetchone()[0] == "smt"
        assert con.execute("SELECT barrier_query FROM synth_results WHERE fix_hash='f2'").fetchone()[0] == "QL2"
        assert con.execute("SELECT backend FROM synth_results WHERE fix_hash='f2'").fetchone()[0] == "codeql"
        assert con.execute("SELECT detail FROM synth_results WHERE fix_hash='f2'").fetchone()[0] == "suppress_fp_failed(after=2)"

    # resume: re-run reprocesses nothing
    calls.clear()
    cvefix_bridge.synthesize_from_results(
        results, synth_db=synth, work_dir=tmp_path / "w", proposer=lambda *a: "", log=lambda *a: None)
    assert calls == []


def test_synthesize_from_results_crash_isolation(monkeypatch, tmp_path: Path):
    results, synth = tmp_path / "r.db", tmp_path / "s.db"
    _results_db(results)

    def boom(pair, **kw):
        if pair.fix_hash == "f2":
            raise RuntimeError("codeql exploded")
        return ("sound", pair.fix_hash + ":id", "codeql", "QL", "")

    monkeypatch.setattr(cvefix_bridge, "synthesize_one", boom)
    report = cvefix_bridge.synthesize_from_results(
        results, synth_db=synth, work_dir=tmp_path / "w", proposer=lambda *a: "", log=lambda *a: None)
    # f2 crashed -> recorded as error (excluded), f1+f3 still synthesized
    assert report.sound == 2
    with sqlite3.connect(str(synth)) as con:
        assert con.execute("SELECT status FROM synth_results WHERE fix_hash='f2'").fetchone()[0] == "error"
        assert con.execute("SELECT backend FROM synth_results WHERE fix_hash='f2'").fetchone()[0] == ""


def test_synthesize_from_results_newest_first_order(monkeypatch, tmp_path: Path):
    results, synth = tmp_path / "r.db", tmp_path / "s.db"
    _results_db(results)
    calls = []
    monkeypatch.setattr(cvefix_bridge, "synthesize_one",
                        lambda pair, **kw: calls.append(pair.cve_id) or ("not_sound", "id", "codeql", None, ""))
    cvefix_bridge.synthesize_from_results(
        results, synth_db=synth, work_dir=tmp_path / "w", proposer=lambda *a: "",
        newest_first=True, log=lambda *a: None)
    assert calls == ["CVE-f3", "CVE-f2", "CVE-f1"]             # cve_id DESC (f4 excluded: after==0)


def _tier0_setup(monkeypatch, *, tier0_result):
    """Stub the around-Tier-0 bridge plumbing.  Each test specifies what
    try_tier0 returns and the after/before DB builds are intercepted so we
    can assert which were called."""
    from core.dataflow import smt_barrier
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)
    builds: list = []

    def fake_build(src, commit, db, lang, codeql_bin, timeout, build_mode=None):
        builds.append(commit)
        return True

    monkeypatch.setattr(cvefix_walk, "_build_db", fake_build)
    monkeypatch.setattr(cvefix_bridge, "_run_query", lambda *a, **k: True)
    prop = cvefix_bridge.BarrierProposal(
        "pathtrav", "CVE-X:CWE-22:app.py:3", "open(x)", "ctx", "python")
    monkeypatch.setattr(cvefix_bridge, "_extract_proposal",
                        lambda *a, **k: (prop, "app.py", 3))
    monkeypatch.setattr(cvefix_bridge, "_git_diff",
                        lambda *a, **k: "+ if not re.match(r\"^[A-Za-z0-9]+$\", x): pass")
    monkeypatch.setattr(cvefix_bridge, "try_tier0",
                        lambda *a, **k: tier0_result)
    # Tier 2: pretend the run_synthesis_loop produces a sound CodeQL guard.
    monkeypatch.setattr(cvefix_bridge, "run_synthesis_loop",
                        lambda *a, **k: SynthResult(
                            query_ql="TIER2_QL", after_count=0, before_count=1))
    return builds, smt_barrier


def test_synthesize_one_tier0_short_circuits_sound(monkeypatch, tmp_path: Path):
    """Tier 0 SOUND -> backend=smt, artifact in barrier_query, no before-DB
    build (the whole point of the free first-pass)."""
    from core.dataflow.smt_barrier import (Tier0Result, Tier0Status,
                                            ValidatorSpec)
    spec = ValidatorSpec("charset", "x", "A-Za-z0-9", "if not re.match(...)", 0)
    t0 = Tier0Result(
        Tier0Status.SOUND, "UNSAT: no string in [A-Za-z0-9]+ can contain '/'",
        spec=spec, artifact="smt:charset:[A-Za-z0-9]+@app.py:3",
        extras={"validator_line": 3, "var_name": "x"})
    builds, _ = _tier0_setup(monkeypatch, tier0_result=t0)
    pair = _pair(cwe="CWE-22")
    status, fid, backend, bq, detail = cvefix_bridge.synthesize_one(
        pair, work_dir=tmp_path / "w", proposer=lambda *a: "RAISES_IF_CALLED")
    assert status == "sound"
    assert backend == "smt"
    assert bq == "smt:charset:[A-Za-z0-9]+@app.py:3"
    assert "UNSAT" in detail
    assert builds == [pair.fix_hash]            # only after-DB; no before-DB


def test_synthesize_one_tier0_not_applicable_falls_through(monkeypatch, tmp_path: Path):
    from core.dataflow.smt_barrier import Tier0Result, Tier0Status
    t0 = Tier0Result(Tier0Status.NOT_APPLICABLE,
                     "no recognised charset/regex validator in fix diff")
    builds, _ = _tier0_setup(monkeypatch, tier0_result=t0)
    pair = _pair(cwe="CWE-22")
    status, fid, backend, bq, detail = cvefix_bridge.synthesize_one(
        pair, work_dir=tmp_path / "w", proposer=lambda *a: "")
    assert status == "sound" and backend == "codeql" and bq == "TIER2_QL"
    # Tier 0 fell through -> before-DB WAS built
    assert builds == [pair.fix_hash, pair.parent_hash]


def test_synthesize_one_tier0_declined_falls_through(monkeypatch, tmp_path: Path):
    from core.dataflow.smt_barrier import (Tier0Result, Tier0Status,
                                            ValidatorSpec)
    spec = ValidatorSpec("charset", "x", "A-Za-z0-9_./", "if not...", 0)
    t0 = Tier0Result(
        Tier0Status.DECLINED,
        "SAT: input '/' passes [A-Za-z0-9_./]+ yet still carries pathtrav danger",
        spec=spec, counterexample="/")
    builds, _ = _tier0_setup(monkeypatch, tier0_result=t0)
    pair = _pair(cwe="CWE-22")
    status, _fid, backend, bq, _detail = cvefix_bridge.synthesize_one(
        pair, work_dir=tmp_path / "w", proposer=lambda *a: "")
    assert status == "sound" and backend == "codeql" and bq == "TIER2_QL"
    assert builds == [pair.fix_hash, pair.parent_hash]


def test_synthesize_one_tier0_unavailable_falls_through(monkeypatch, tmp_path: Path):
    """When _TIER0_AVAILABLE is False (substrate missing / import failed),
    Tier 0 is skipped entirely and Tier 2 runs unchanged."""
    monkeypatch.setattr(cvefix_bridge, "_TIER0_AVAILABLE", False)
    # Use the same setup but the tier0_result is irrelevant since the gate
    # short-circuits before try_tier0 is consulted.
    builds, _ = _tier0_setup(monkeypatch, tier0_result=None)
    pair = _pair(cwe="CWE-22")
    status, _fid, backend, bq, _detail = cvefix_bridge.synthesize_one(
        pair, work_dir=tmp_path / "w", proposer=lambda *a: "")
    assert status == "sound" and backend == "codeql" and bq == "TIER2_QL"
    assert builds == [pair.fix_hash, pair.parent_hash]


def test_synthesize_one_tier0_skipped_when_no_diff(monkeypatch, tmp_path: Path):
    """No fix diff retrievable -> Tier 0 is not attempted at all (avoids
    calling try_tier0 with empty diff which would NOT_APPLICABLE anyway,
    saving a no-op call)."""
    from core.dataflow.smt_barrier import Tier0Status
    builds, _ = _tier0_setup(
        monkeypatch,
        tier0_result=type("R", (), {"status": Tier0Status.SOUND,
                                     "artifact": "should not be used",
                                     "reasoning": "should not be used"})())
    monkeypatch.setattr(cvefix_bridge, "_git_diff", lambda *a, **k: "")
    pair = _pair(cwe="CWE-22")
    status, _fid, backend, bq, _detail = cvefix_bridge.synthesize_one(
        pair, work_dir=tmp_path / "w", proposer=lambda *a: "")
    assert status == "sound" and backend == "codeql" and bq == "TIER2_QL"
    assert builds == [pair.fix_hash, pair.parent_hash]


def test_max_refine_attempts_threads_through_to_run_synthesis_loop(monkeypatch, tmp_path: Path):
    """The bridge's ``--max-refine-attempts`` CLI flag plumbs all the way
    down to ``run_synthesis_loop``; default 0 preserves the pre-existing
    no-refinement behaviour."""
    monkeypatch.setattr(cvefix_bridge, "_TIER0_AVAILABLE", False)
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)
    monkeypatch.setattr(cvefix_walk, "_build_db", lambda *a, **k: True)
    monkeypatch.setattr(cvefix_bridge, "_run_query", lambda *a, **k: True)
    prop = cvefix_bridge.BarrierProposal("sqli", "fid", "x", "ctx", "python")
    monkeypatch.setattr(cvefix_bridge, "_extract_proposal",
                        lambda *a, **k: (prop, "a.py", 3))
    seen: dict = {}

    def fake_loop(*args, **kwargs):
        seen["max_refine_attempts"] = kwargs.get("max_refine_attempts")
        return SynthResult(query_ql="QL", after_count=0, before_count=1)

    monkeypatch.setattr(cvefix_bridge, "run_synthesis_loop", fake_loop)

    cvefix_bridge.synthesize_one(_pair(), work_dir=tmp_path / "w0",
                                 proposer=lambda *a: "")
    assert seen["max_refine_attempts"] == 0                # default

    cvefix_bridge.synthesize_one(_pair(), work_dir=tmp_path / "w2",
                                 proposer=lambda *a: "", max_refine_attempts=2)
    assert seen["max_refine_attempts"] == 2


def test_run_synthesis_loop_diag_captures_last_error(tmp_path: Path):
    from core.dataflow.barrier_synth import BarrierProposal, run_synthesis_loop
    prop = BarrierProposal("sqli", "fid", "x", "ctx", "python")
    diag: dict = {}
    # proposer emits QL without the required predicate -> assembly ValueError every attempt
    res = run_synthesis_loop(prop, tmp_path / "a", tmp_path / "b",
                             proposer=lambda p, e: "predicate nope() { any() }",
                             work_dir=tmp_path / "s", max_attempts=2, diag=diag)
    assert res is None
    assert "proposedGuard" in diag["last_error"] and diag["attempts"] == 2
