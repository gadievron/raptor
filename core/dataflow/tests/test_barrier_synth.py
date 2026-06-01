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
    assert "import codeql.ruby.AST" in q                         # AST types (MethodCall) resolve in guards
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


# CWE-94 / CWE-918 sink-class extensions (2026-05-31): matches the bridge's
# `_CWE_SINK` keys.  Each per-language assembler must accept both new
# classes without raising — verified by template substitution alone, the
# actual CodeQL compile is exercised end-to-end in the corpus run.

def test_assemble_python_codeinjection_uses_codeinjection_module():
    q = assemble_barrier_query(_GUARD, sink_class="codeinjection", query_id="raptor/pyci")
    assert "CodeInjectionCustomizations" in q
    assert "CodeInjection::Source" in q and "CodeInjection::Sink" in q


def test_assemble_python_ssrf_uses_ssrf_module():
    q = assemble_barrier_query(_GUARD, sink_class="ssrf", query_id="raptor/pyssrf")
    assert "ServerSideRequestForgeryCustomizations" in q
    assert "ServerSideRequestForgery::Source" in q and "ServerSideRequestForgery::Sink" in q


def test_assemble_javascript_ssrf_uses_request_forgery_module():
    """JS pack names the SSRF module ``RequestForgery`` (no "ServerSide"
    prefix) — regression-pin since the Python/Ruby naming is different."""
    q = assemble_barrier_query(_JS_GUARD, sink_class="ssrf",
                               query_id="raptor/jsssrf", language="javascript")
    assert "RequestForgeryCustomizations::RequestForgery" in q
    assert "Source" in q and "Sink" in q


def test_assemble_javascript_codeinjection_uses_codeinjection_module():
    q = assemble_barrier_query(_JS_GUARD, sink_class="codeinjection",
                               query_id="raptor/jsci", language="javascript")
    assert "CodeInjectionCustomizations::CodeInjection" in q


def test_assemble_ruby_ssrf_and_codeinjection():
    q1 = assemble_barrier_query(_RB_GUARD, sink_class="ssrf",
                                query_id="raptor/rbssrf", language="ruby")
    assert "ServerSideRequestForgeryCustomizations::ServerSideRequestForgery" in q1
    q2 = assemble_barrier_query(_RB_GUARD, sink_class="codeinjection",
                                query_id="raptor/rbci", language="ruby")
    assert "CodeInjectionCustomizations::CodeInjection" in q2


def test_assemble_java_ssrf_uses_request_forgery_sink():
    q = assemble_barrier_query(_JAVA_GUARD, sink_class="ssrf",
                               query_id="raptor/jvssrf", language="java")
    assert "n instanceof RequestForgerySink" in q
    assert "semmle.code.java.security.RequestForgery" in q


def test_assemble_java_codeinjection_still_rejected():
    """Java has no generic CodeInjectionSink (only framework-specific
    SpEL/MVEL/Groovy queries); matches cvefix_walk's Java CWE-94 omission.
    Pin the rejection so adding java/codeinjection later is intentional."""
    with pytest.raises(ValueError):
        assemble_barrier_query(_JAVA_GUARD, sink_class="codeinjection",
                               query_id="raptor/jvci", language="java")


# Go: new ConfigSig API like Python/Ruby, guard sig matches Java's (Expr e).
_GO_GUARD = (
    "predicate proposedGuard(DataFlow::Node g, Expr e, boolean branch) "
    "{ none() }"
)


def test_assemble_go_uses_configsig_and_go_imports():
    q = assemble_barrier_query(_GO_GUARD, sink_class="sqli",
                               query_id="raptor/go-sqli", language="go")
    assert "import go" in q
    assert "import semmle.go.dataflow.DataFlow" in q
    assert "SqlInjectionCustomizations::SqlInjection" in q
    assert "implements DataFlow::ConfigSig" in q
    assert "BarrierGuard<proposedGuard/3>" in q
    assert "Flow::flow(source, sink)" in q
    # Stamp identifies Go in the @name + select message:
    assert "[go]" in q


def test_assemble_go_each_sink_class_uses_canonical_module():
    """Pin the customization module name per sink class — a typo in the
    import path would silently fail at adjudication, not at synth-time."""
    expected = {
        "cmdi":     "CommandInjectionCustomizations::CommandInjection",
        "sqli":     "SqlInjectionCustomizations::SqlInjection",
        "pathtrav": "TaintedPathCustomizations::TaintedPath",
        "xss":      "ReflectedXssCustomizations::ReflectedXss",
        "ssrf":     "RequestForgeryCustomizations::RequestForgery",
    }
    for sink_class, expect in expected.items():
        q = assemble_barrier_query(_GO_GUARD, sink_class=sink_class,
                                   query_id=f"raptor/go-{sink_class}",
                                   language="go")
        assert expect in q, f"{sink_class}: expected {expect!r} in query"


def test_assemble_go_codeinjection_rejected():
    """Go's pack has no generic CodeInjection.qll — matches cvefix_walk's
    Go CWE-94 omission convention.  Pin the rejection so adding it later
    is an intentional substrate change."""
    with pytest.raises(ValueError, match="unknown sink_class 'codeinjection'"):
        assemble_barrier_query(_GO_GUARD, sink_class="codeinjection",
                               query_id="raptor/go-ci", language="go")


def test_assemble_go_requires_proposed_guard_predicate():
    """Same shape guarantee as the other ConfigSig-style languages:
    the proposer must define a `proposedGuard` symbol."""
    with pytest.raises(ValueError, match="proposedGuard"):
        assemble_barrier_query("predicate other() { none() }",
                               sink_class="sqli", query_id="raptor/go-sqli",
                               language="go")


def test_go_system_prompt_is_wired():
    """Go must be registered in `_SYSTEM_PROMPTS` so `_build_prompt`
    picks the Go template instead of falling back to the Python one
    (which would feed the LLM Python-typed `ControlFlowNode` examples)."""
    from core.dataflow.barrier_synth import _SYSTEM_PROMPTS
    assert "go" in _SYSTEM_PROMPTS
    # Specific Go phrasing pinned:
    assert "DataFlow::CallNode" in _SYSTEM_PROMPTS["go"]
    assert "(DataFlow::Node g, Expr e, boolean branch)" in _SYSTEM_PROMPTS["go"]


def test_count_sarif_results_scopes_to_uri_and_line(tmp_path):
    import json
    from core.dataflow.barrier_synth import _count_sarif_results
    sarif = tmp_path / "s.sarif"

    def loc(uri, line):
        return {"locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                    "region": {"startLine": line}}}]}
    sarif.write_text(json.dumps({"runs": [{"results": [
        loc("a.py", 10), loc("a.py", 20), loc("b.py", 5)]}]}))
    assert _count_sarif_results(sarif) == 3                   # unscoped: all findings
    assert _count_sarif_results(sarif, "a.py") == 2           # file-scoped (preserve check)
    assert _count_sarif_results(sarif, "a.py", 10) == 1       # line-scoped (suppress check): only a.py:10
    assert _count_sarif_results(sarif, "a.py", 99) == 0       # no finding at that line
    assert _count_sarif_results(sarif, "c.py") == 0           # file with no findings


def test_model_completer_pinned_config_bypasses_auto_resolution(monkeypatch):
    """``model_completer("claude-opus-4-8")`` builds an LLMClient whose
    config is targeted at the inferred provider only — primary_model is
    the pinned model and fallback_models is empty, so the thinking-model
    auto-resolution path (which would log misleading gemini lines when
    Anthropic is the actual caller intent) never fires."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    from core.dataflow.barrier_synth import model_completer
    from core.llm.client import LLMClient

    seen: dict = {}
    real_init = LLMClient.__init__

    def trace_init(self, *args, **kwargs):
        seen["pinned_model"] = kwargs.get("pinned_model")
        real_init(self, *args, **kwargs)
        seen["primary"] = self.config.primary_model
        seen["fallbacks"] = self.config.fallback_models

    monkeypatch.setattr(LLMClient, "__init__", trace_init)
    _ = model_completer("claude-opus-4-8")
    assert seen["pinned_model"] == "claude-opus-4-8"
    assert seen["primary"].provider == "anthropic"
    assert seen["primary"].model_name == "claude-opus-4-8"
    assert seen["primary"].role == "code"
    assert seen["fallbacks"] == []                # no auto-resolved chain


def test_pinned_llm_config_provider_inference():
    """Provider inference from the bare model name."""
    from core.llm.client import _pinned_llm_config

    for name, expected_provider, expected_model in [
        ("claude-opus-4-8",        "anthropic", "claude-opus-4-8"),
        ("claude-sonnet-4-6",      "anthropic", "claude-sonnet-4-6"),
        ("gemini-2.5-pro",         "gemini",    "gemini-2.5-pro"),
        ("gpt-4o-mini",            "openai",    "gpt-4o-mini"),
        ("anthropic/claude-opus",  "anthropic", "claude-opus"),
        ("openai/gpt-5",           "openai",    "gpt-5"),
    ]:
        cfg = _pinned_llm_config(name)
        assert cfg.primary_model.provider == expected_provider, name
        assert cfg.primary_model.model_name == expected_model, name
        assert cfg.fallback_models == []


def test_assemble_rejects_unknown_language():
    """Unknown language must raise — pin the rejection so adding a new
    language is an intentional substrate change.  ``csharp`` is the
    current canonical "not yet wired" placeholder (Go was the placeholder
    until 2026-05-31 when Go support landed)."""
    with pytest.raises(ValueError, match="unknown language 'csharp'"):
        assemble_barrier_query(_GUARD, sink_class="cmdi", query_id="x", language="csharp")


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


# --- soundness-refinement loop (RefineContext + max_refine_attempts) ---

def test_default_refine_zero_returns_first_not_sound(tmp_path: Path):
    """Baseline preserved: with the default ``max_refine_attempts=0``, the
    loop returns the first compilable result, sound or not — no extra
    proposer calls on not_sound."""
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 1, str(before_db): 1})  # not_sound
    calls = {"n": 0}

    def proposer(_p, _e):
        calls["n"] += 1
        return _GUARD

    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=proposer, work_dir=tmp_path / "w", runner=runner,
    )
    assert res is not None and not res.is_sound
    assert calls["n"] == 1                          # exactly one call, no refine


def test_refine_loop_calls_proposer_with_refine_context(tmp_path: Path):
    """When ``max_refine_attempts > 0`` and the first cycle is not_sound,
    the proposer is called again with a populated ``refine_context``
    carrying the prior verdict + the prior QL."""
    from core.dataflow.barrier_synth import RefineContext

    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    # Both cycles return the same not_sound counts so the loop runs to budget.
    runner = _stub_runner({str(after_db): 1, str(before_db): 1})
    seen_contexts: list = []

    def proposer(_p, _e, refine_context=None):
        seen_contexts.append(refine_context)
        return _GUARD

    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=proposer, work_dir=tmp_path / "w", runner=runner,
        max_refine_attempts=2,
    )
    assert res is not None and not res.is_sound
    # 1 initial + 2 refines = 3 proposer calls.
    assert len(seen_contexts) == 3
    assert seen_contexts[0] is None                 # initial call has no context
    # First refinement carries verdict from initial cycle.
    rc1 = seen_contexts[1]
    assert isinstance(rc1, RefineContext)
    assert rc1.refine_attempt == 1
    assert rc1.after_count == 1 and rc1.before_count == 1
    assert rc1.failure_mode == "suppress_fp_failed"
    assert "BarrierGuard" in rc1.prior_query_ql     # prior QL passed through
    # Second refinement is attempt 2.
    assert seen_contexts[2].refine_attempt == 2


def test_refine_loop_returns_sound_on_successful_refinement(tmp_path: Path):
    """If the proposer's refined attempt produces a sound result, the loop
    returns it WITHOUT consuming the remaining refine budget."""
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    cycle = {"n": 0}

    def runner(cmd, **_):
        # First cycle: not_sound (after=1, before=1).
        # Second cycle: sound (after=0, before=1).
        for arg in cmd:
            arg_s = str(arg)
            if str(after_db) in arg_s:
                return 0 if cycle["after_done"] else 1
            if str(before_db) in arg_s:
                return 1
        return 0

    # Simpler: explicit stub-runner that flips after the first after-DB read.
    state = {"after_returned": False}

    def stub(cmd, **_):
        from core.dataflow.barrier_synth import CodeQLRunError      # noqa: F401
        # The runner returns 0 (success) when an `--output` arg matches one of
        # our DBs.  We construct SARIF with the count we want for the current
        # cycle by writing a file at the SARIF path.
        for i, arg in enumerate(cmd):
            arg_s = str(arg)
            if arg_s.startswith("--output="):
                out = arg_s[len("--output="):]
                # First call against after_db -> count 1 (not_sound first cycle).
                # Second call against after_db -> count 0 (sound second cycle).
                # before_db calls always return count 1.
                target = next(
                    (str(p) for p in (after_db, before_db) if str(p) in str(cmd)),
                    None,
                )
                if target == str(after_db):
                    n = 0 if state["after_returned"] else 1
                    state["after_returned"] = True
                else:
                    n = 1
                Path(out).write_text(
                    '{"runs":[{"results":[%s]}]}' % (
                        ",".join(['{"locations":[]}'] * n)
                    )
                )
                return 0
        return 0

    def proposer(_p, _e, refine_context=None):
        cycle["n"] += 1
        return _GUARD

    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=proposer, work_dir=tmp_path / "w", runner=stub,
        max_refine_attempts=3,
    )
    assert res is not None and res.is_sound
    # 1 initial + 1 successful refine = 2 calls; budget (3) not exhausted.
    assert cycle["n"] == 2


def test_refine_diag_records_refine_attempts(tmp_path: Path):
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 1, str(before_db): 1})
    diag: dict = {}

    def proposer(_p, _e, refine_context=None):
        return _GUARD

    run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=proposer, work_dir=tmp_path / "w", runner=runner,
        max_refine_attempts=2, diag=diag,
    )
    assert diag["refine_attempts"] == 2


def test_synthresult_failure_mode_classification():
    from core.dataflow.barrier_synth import SynthResult
    assert SynthResult("ql", 0, 1).failure_mode == "ok"
    assert SynthResult("ql", 1, 1).failure_mode == "suppress_fp_failed"
    assert SynthResult("ql", 0, 0).failure_mode == "preserve_tp_failed"
    assert SynthResult("ql", 1, 0).failure_mode == "both"


def test_build_prompt_includes_sink_class_hint_for_known_class():
    """The sink-class hint must be appended to the user prompt for every
    sink_class the proposer can adjudicate.  Without it the LLM gets only
    the language template + generic shape examples, mis-matching the
    actual validator shape (the dominant failure mode in v3 + fresh
    corpus measurements)."""
    from core.dataflow.barrier_synth import (
        BarrierProposal, _build_prompt, _SINK_CLASS_HINTS,
    )
    for sink_class in _SINK_CLASS_HINTS:
        prop = BarrierProposal(
            sink_class=sink_class, finding_id="F", sink_snippet="x",
            source_context="ctx", language="python",
        )
        prompt = _build_prompt(prop, prior_error=None)
        assert "Canonical validator shapes for this sink class:" in prompt, sink_class
        # A distinctive token from each hint must appear:
        token = {
            "pathtrav": "safe_join",
            "cmdi": "shlex.quote",
            "sqli": "PreparedStatement",
            "xss": "DOMPurify.sanitize",
            "ssrf": "isResolvingToUnicastOnly",
            "codeinjection": "vm.runInNewContext",
        }[sink_class]
        assert token in prompt, f"{sink_class}: missing distinctive idiom {token}"


def test_build_prompt_omits_hint_for_unknown_sink_class():
    """Unknown sink_class (e.g. a not-yet-modelled CWE) -> no hint block;
    the rest of the prompt is unchanged so the call doesn't error."""
    from core.dataflow.barrier_synth import BarrierProposal, _build_prompt
    prop = BarrierProposal(
        sink_class="xxe", finding_id="F", sink_snippet="x",
        source_context="ctx", language="python",
    )
    prompt = _build_prompt(prop, prior_error=None)
    assert "Canonical validator shapes for this sink class:" not in prompt
    # But the rest must still be intact:
    assert "sink class: xxe" in prompt
    assert "ctx" in prompt


def test_summarise_surviving_finding_extracts_codeflow(tmp_path):
    """Counterexample-driven refinement: the SARIF surviving-finding
    summariser must extract source -> sink path info so the prompt can
    feed a concrete flow back to the proposer."""
    import json
    from core.dataflow.barrier_synth import _summarise_surviving_finding
    sarif = tmp_path / "after.sarif"

    def step(uri, line, msg):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line}}, "message": {"text": msg}}}

    sarif.write_text(json.dumps({"runs": [{"results": [
        {"locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "src/api.py"},
             "region": {"startLine": 127}}}],
         "message": {"text": "This URL is constructed from user input."},
         "codeFlows": [{"threadFlows": [{"locations": [
             step("src/api.py", 42, "request.url"),
             step("src/api.py", 90, "host"),
             step("src/api.py", 127, "fetch(url)")]}]}]},
    ]}]}))
    summary = _summarise_surviving_finding(
        sarif, target_uri="src/api.py", target_line=127)
    assert "surviving flow" in summary
    assert "api.py:42" in summary and "request.url" in summary  # source
    assert "api.py:90" in summary and "host" in summary         # intermediate
    assert "api.py:127" in summary                              # sink


def test_summarise_surviving_finding_returns_empty_on_no_match(tmp_path):
    """Off-target (different uri/line) -> empty.  Conservative: a wrong
    summary would mislead the proposer; an empty one falls back to the
    generic nudge."""
    import json
    from core.dataflow.barrier_synth import _summarise_surviving_finding
    sarif = tmp_path / "a.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [
        {"locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "elsewhere.py"},
             "region": {"startLine": 5}}}], "message": {"text": "m"}}]}]}))
    assert _summarise_surviving_finding(sarif, target_uri="missing.py") == ""
    # Unreadable file:
    assert _summarise_surviving_finding(tmp_path / "nope.sarif") == ""


def test_build_prompt_surfaces_counterexample_when_present():
    """When the RefineContext carries a surviving-finding summary, the
    user prompt must include it in the refinement block — that's the
    counterexample the LLM uses to target the real validator."""
    from core.dataflow.barrier_synth import RefineContext, _build_prompt
    rc = RefineContext(
        prior_query_ql="predicate proposedGuard() { any() }",
        after_count=1, before_count=1,
        failure_mode="suppress_fp_failed", refine_attempt=1,
        surviving_finding_summary=(
            "surviving flow: api.py:42 request.url -> api.py:127 fetch(url)"),
    )
    prompt = _build_prompt(_proposal(), prior_error=None, refine_context=rc)
    assert "Concrete counterexample" in prompt
    assert "api.py:42 request.url -> api.py:127 fetch(url)" in prompt


def test_build_prompt_surfaces_refine_context():
    """The skeleton prompt for refinement includes the verdict text, the
    prior QL, and a failure-mode-specific nudge."""
    from core.dataflow.barrier_synth import RefineContext, _build_prompt
    rc = RefineContext(
        prior_query_ql="predicate proposedGuard() { any() }",
        after_count=1, before_count=1,
        failure_mode="suppress_fp_failed", refine_attempt=1,
    )
    prompt = _build_prompt(_proposal(), prior_error=None, refine_context=rc)
    assert "REFINEMENT (attempt 1)" in prompt
    assert "after=1 before=1" in prompt
    assert "suppress_fp_failed" in prompt
    assert "predicate proposedGuard()" in prompt
    assert "DIDN'T suppress" in prompt              # the suppress-mode nudge


def test_make_llm_proposer_forwards_refine_context():
    """``make_llm_proposer``'s proposer must accept and forward refine_context
    into the prompt, so refinement flows end-to-end through the LLM wrapper."""
    from core.dataflow.barrier_synth import RefineContext
    seen: dict = {}

    def complete(system_prompt, user_prompt):
        seen["user"] = user_prompt
        return _GUARD

    proposer = make_llm_proposer(complete)
    rc = RefineContext(
        prior_query_ql="predicate proposedGuard() {}",
        after_count=1, before_count=1,
        failure_mode="suppress_fp_failed", refine_attempt=1,
    )
    proposer(_proposal(), None, refine_context=rc)
    assert "REFINEMENT" in seen["user"]
    assert "predicate proposedGuard()" in seen["user"]


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
