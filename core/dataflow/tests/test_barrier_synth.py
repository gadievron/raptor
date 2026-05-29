"""Tests for the sound-tier barrier synthesis loop (stubbed proposer + runner)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow.barrier_synth import (
    BarrierProposal,
    CorpusSynthItem,
    assemble_barrier_query,
    make_llm_proposer,
    render_corpus_report,
    run_synthesis_loop,
    synthesize_over_corpus,
)

_GUARD = (
    "predicate proposedGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {\n"
    '  exists(DataFlow::CallCfgNode c |\n'
    '    c.getFunction().asExpr().(Name).getId() = "host_is_allowed" and\n'
    "    g = c.asCfgNode() and node = c.getArg(0).asCfgNode() and branch = true) }"
)


def _proposer(_proposal, _prior_error=None) -> str:
    return _GUARD


def _stub_runner(counts_by_db: dict):
    """codeql stand-in: writes a SARIF with N results for the queried db."""
    def run(cmd, **kwargs):
        db = cmd[3]  # codeql database analyze <db> ...
        out = next(a.split("=", 1)[1] for a in cmd if a.startswith("--output="))
        n = counts_by_db[db]
        results = [{"ruleId": "x", "message": {"text": "m"}} for _ in range(n)]
        Path(out).write_text(json.dumps({"runs": [{"results": results}]}))
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


def _proposal() -> BarrierProposal:
    return BarrierProposal(sink_class="cmdi", finding_id="F1",
                           sink_snippet="os.system(...)", source_context="...")


# --- assembly (pure) ---

def test_assemble_wires_guard_and_stock_source_sink():
    q = assemble_barrier_query(_GUARD, sink_class="cmdi", query_id="raptor/x")
    assert "CommandInjection::Source" in q
    assert "CommandInjection::Sink" in q
    assert "BarrierGuard<proposedGuard/3>" in q
    assert "proposedGuard" in q


def test_assemble_supports_python_xss():
    q = assemble_barrier_query(_GUARD, sink_class="xss", query_id="raptor/xss")
    assert "ReflectedXSSCustomizations" in q      # the customizations module import
    assert "ReflectedXss::Source" in q
    assert "ReflectedXss::Sink" in q
    assert "BarrierGuard<proposedGuard/3>" in q


_JS_GUARD = (
    "class ProposedGuard extends TaintTracking::SanitizerGuardNode {\n"
    "  ProposedGuard() { this = this }\n"
    "  override predicate sanitizes(boolean outcome, Expr e) { none() }\n"
    "}"
)


def test_assemble_javascript_uses_legacy_config_and_guard_class():
    q = assemble_barrier_query(_JS_GUARD, sink_class="xss", query_id="raptor/js",
                               language="javascript")
    assert "import javascript" in q
    assert "ReflectedXssCustomizations::ReflectedXss" in q
    assert "extends TaintTracking::Configuration" in q
    assert "isSanitizerGuard" in q and "g instanceof ProposedGuard" in q
    assert "cfg.hasFlow(source, sink)" in q


def test_assemble_javascript_requires_proposedguard_class():
    with pytest.raises(ValueError):
        assemble_barrier_query("predicate proposedGuard() { any() }",
                               sink_class="xss", query_id="x", language="javascript")


_RB_GUARD = (
    "predicate proposedGuard(CfgNodes::AstCfgNode g, CfgNode node, boolean branch) "
    "{ none() }"
)


def test_assemble_ruby_mirrors_python_configsig_with_ruby_imports():
    q = assemble_barrier_query(_RB_GUARD, sink_class="sqli", query_id="raptor/rb",
                               language="ruby")
    assert "import codeql.ruby.DataFlow" in q
    assert "SqlInjectionCustomizations::SqlInjection" in q
    assert "implements DataFlow::ConfigSig" in q                 # python-style, not legacy
    assert "BarrierGuard<proposedGuard/3>" in q
    assert "Flow::flow(source, sink)" in q


def test_assemble_ruby_xss_uses_xss_module():
    q = assemble_barrier_query(_RB_GUARD, sink_class="xss", query_id="raptor/rbx",
                               language="ruby")
    assert "codeql.ruby.security.XSS::ReflectedXss" in q


_JAVA_GUARD = "predicate proposedGuard(Guard g, Expr e, boolean branch) { none() }"


def test_assemble_java_configsig_remoteflowsource_per_cwe_sink():
    q = assemble_barrier_query(_JAVA_GUARD, sink_class="sqli", query_id="raptor/jv",
                               language="java")
    assert "import java" in q
    assert "n instanceof RemoteFlowSource" in q           # uniform source
    assert "n instanceof QueryInjectionSink" in q          # per-CWE sink
    assert "BarrierGuard<proposedGuard/3>" in q
    assert "Flow::flow(source, sink)" in q


def test_assemble_java_path_uses_sinknode_predicate():
    q = assemble_barrier_query(_JAVA_GUARD, sink_class="pathtrav", query_id="raptor/jvp",
                               language="java")
    assert 'sinkNode(n, "path-injection")' in q            # not an instanceof sink
    assert "semmle.code.java.dataflow.ExternalFlow" in q


def test_assemble_rejects_unknown_language():
    with pytest.raises(ValueError):
        assemble_barrier_query(_GUARD, sink_class="cmdi", query_id="x", language="go")


def test_assemble_rejects_unknown_sink_class():
    with pytest.raises(ValueError):
        assemble_barrier_query(_GUARD, sink_class="nosuch", query_id="x")


def test_assemble_rejects_proposal_without_guard():
    with pytest.raises(ValueError):
        assemble_barrier_query("predicate other() { any() }", sink_class="cmdi", query_id="x")


# --- the loop (stubbed proposer + runner) ---

def test_loop_sound_when_fp_suppressed_and_tp_preserved(tmp_path: Path):
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 0, str(before_db): 1})
    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=_proposer, work_dir=tmp_path / "work", runner=runner,
    )
    assert res.after_count == 0 and res.before_count == 1
    assert res.suppressed_fp and res.preserved_tp and res.is_sound
    assert "BarrierGuard<proposedGuard/3>" in res.query_ql


def test_loop_rejects_overbroad_barrier_that_kills_the_tp(tmp_path: Path):
    # Barrier suppresses BOTH dbs -> it also killed the real TP -> unsound.
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 0, str(before_db): 0})
    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=_proposer, work_dir=tmp_path / "work", runner=runner,
    )
    assert res.suppressed_fp        # killed the FP
    assert not res.preserved_tp     # but also killed the TP
    assert not res.is_sound         # -> rejected by the soundness check


def test_loop_rejects_barrier_that_does_not_suppress(tmp_path: Path):
    # Barrier changes nothing -> FP still flagged -> not useful.
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 1, str(before_db): 1})
    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=_proposer, work_dir=tmp_path / "work", runner=runner,
    )
    assert not res.suppressed_fp
    assert not res.is_sound


# --- LLM proposer + retry ---

def test_llm_proposer_strips_markdown_fence():
    captured = {}

    def complete(system_prompt, user_prompt):
        captured["sys"] = system_prompt
        captured["user"] = user_prompt
        return f"```ql\n{_GUARD}\n```"

    proposer = make_llm_proposer(complete)
    out = proposer(_proposal(), None)
    assert out.strip().startswith("predicate proposedGuard")
    assert "```" not in out
    # the proposal context reaches the prompt
    assert "os.system(...)" in captured["user"]


def test_llm_proposer_passes_prior_error_on_retry():
    seen = []

    def complete(system_prompt, user_prompt):
        seen.append(user_prompt)
        return _GUARD

    proposer = make_llm_proposer(complete)
    proposer(_proposal(), "ValueError: proposer must define a `proposedGuard` predicate")
    assert "PREVIOUS attempt failed" in seen[0]
    assert "proposedGuard" in seen[0]


def test_loop_retries_on_bad_proposal_then_succeeds(tmp_path: Path):
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 0, str(before_db): 1})
    calls = {"n": 0}

    def flaky_proposer(_proposal, prior_error):
        calls["n"] += 1
        # First attempt: garbage (assembly rejects -> ValueError -> retry).
        if prior_error is None:
            return "this is not a predicate"
        return _GUARD  # corrected on retry

    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=flaky_proposer, work_dir=tmp_path / "work", runner=runner,
        max_attempts=2,
    )
    assert calls["n"] == 2
    assert res is not None and res.is_sound


def test_loop_returns_none_when_proposer_never_compiles(tmp_path: Path):
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 0, str(before_db): 1})
    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=lambda p, e: "garbage, no predicate here",
        work_dir=tmp_path / "work", runner=runner, max_attempts=3,
    )
    assert res is None


# --- CLI (stubbed LLM + CodeQL) ---

def test_main_cli_synthesizes_and_emits_sound_query(tmp_path: Path, monkeypatch, capsys):
    from core.dataflow import barrier_synth

    before_db, after_db = tmp_path / "bdb", tmp_path / "adb"
    src = tmp_path / "app.py"
    src.write_text("def host_is_allowed(h):\n    return h in ('localhost',)\n", encoding="utf-8")

    # stub the LLM proposer
    monkeypatch.setattr(barrier_synth, "default_completer", lambda: (lambda s, u: _GUARD))
    # stub CodeQL: post-fix suppressed (0), pre-fix preserved (1)
    counts = {str(after_db): 0, str(before_db): 1}

    def stub_analyze(db_path, queries, output_path, **kwargs):
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        n = counts[str(db_path)]
        Path(output_path).write_text(json.dumps({"runs": [{"results": [{} for _ in range(n)]}]}))
        return SimpleNamespace(sarif_path=output_path)

    monkeypatch.setattr(barrier_synth, "analyze", stub_analyze)

    rc = barrier_synth.main([
        str(before_db), str(after_db), "--sink-class", "cmdi",
        "--finding-id", "F1", "--sink", "os.system(host)",
        "--source-file", str(src), "--work-dir", str(tmp_path / "w"),
    ])
    assert rc == 0  # sound
    assert "proposedGuard" in capsys.readouterr().out  # synthesized query to stdout


# --- corpus aggregate ---

def test_synthesize_over_corpus_aggregates_outcomes(tmp_path: Path):
    a1, b1 = tmp_path / "a1", tmp_path / "b1"   # sound: after 0 / before 1
    a2, b2 = tmp_path / "a2", tmp_path / "b2"   # not_sound: after 0 / before 0 (killed TP)
    a3, b3 = tmp_path / "a3", tmp_path / "b3"   # no_barrier: proposer emits garbage
    runner = _stub_runner({str(a1): 0, str(b1): 1, str(a2): 0, str(b2): 0})

    def proposer(proposal, _prior):
        return "no predicate here" if proposal.finding_id == "F-nobar" else _GUARD

    items = [
        CorpusSynthItem(BarrierProposal("cmdi", "F-sound", "s", "c"), a1, b1),
        CorpusSynthItem(BarrierProposal("cmdi", "F-killtp", "s", "c"), a2, b2),
        CorpusSynthItem(BarrierProposal("cmdi", "F-nobar", "s", "c"), a3, b3),
    ]
    rep = synthesize_over_corpus(items, proposer=proposer, work_dir=tmp_path / "w",
                                 runner=runner, max_attempts=1)
    assert rep.total == 3
    assert (rep.sound, rep.not_sound, rep.no_barrier) == (1, 1, 1)
    assert rep.suppression_rate == 1 / 3
    assert dict(rep.per_finding) == {
        "F-sound": "sound", "F-killtp": "not_sound", "F-nobar": "no_barrier",
    }
    assert "sound barrier:   1" in render_corpus_report(rep)
