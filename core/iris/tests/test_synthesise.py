"""Tests for core.iris.synthesise — LLM-driven spec synthesis."""

import json

from core.evidence import EvidenceTier
from core.iris.assumptions import (
    AssumptionCategory,
    BypassFinding,
    SafetyAssumption,
)
from core.iris.specs import CandidateFunction, TaintSpec
from core.iris.synthesise import (
    _build_assumption_prompt,
    _build_user_prompt,
    _Batch,
    _call_llm,
    _heuristic_fallback,
    _parse_assumption_response,
    _read_candidate_source,
    synthesise_assumptions,
    synthesise_specs,
    synthesise_specs_heuristic,
)


def _cand(fn="check_input", file="src/auth.py", **kw):
    return CandidateFunction(function=fn, file=file, **kw)


class TestHeuristicFallback:
    def test_sanitiser_name(self):
        specs = _heuristic_fallback([_cand(fn="sanitize_html")])
        assert len(specs) == 1
        assert specs[0].role == "sanitiser"
        assert specs[0].source == "heuristic"

    def test_source_name(self):
        specs = _heuristic_fallback([_cand(fn="read_input")])
        assert specs[0].role == "source"

    def test_sink_name(self):
        specs = _heuristic_fallback([_cand(fn="execute_query")])
        assert specs[0].role == "sink"

    def test_propagator_default(self):
        specs = _heuristic_fallback([_cand(fn="transform_data")])
        assert specs[0].role == "propagator"

    def test_confidence_with_security_name(self):
        specs = _heuristic_fallback([
            _cand(fn="validate_token", has_security_name=True),
        ])
        assert specs[0].confidence == 0.6

    def test_confidence_without_security_name(self):
        specs = _heuristic_fallback([
            _cand(fn="process_data", has_security_name=False),
        ])
        assert specs[0].confidence == 0.4

    def test_empty_candidates(self):
        assert _heuristic_fallback([]) == []


class TestSynthesiseSpecsHeuristic:
    def test_alias_for_fallback(self):
        cands = [_cand(fn="sanitize_html"), _cand(fn="eval_code")]
        specs = synthesise_specs_heuristic(cands)
        assert len(specs) == 2
        roles = {s.role for s in specs}
        assert "sanitiser" in roles
        assert "sink" in roles


class TestSynthesiseSpecs:
    def test_with_mock_llm(self):
        response = json.dumps([{
            "function": "check_input",
            "file": "src/auth.py",
            "role": "sanitiser",
            "taint_classes": ["xss"],
            "params_affected": [0],
            "return_tainted": False,
            "confidence": 0.9,
        }])

        def mock_llm(system, user):
            return response

        cands = [_cand()]
        specs = synthesise_specs(cands, mock_llm)
        assert len(specs) == 1
        assert specs[0].role == "sanitiser"
        assert specs[0].source == "llm"
        assert specs[0].evidence_tier == EvidenceTier.HEURISTIC

    def test_llm_failure_falls_back(self):
        def failing_llm(system, user):
            raise RuntimeError("API error")

        cands = [_cand(fn="sanitize_html")]
        specs = synthesise_specs(cands, failing_llm)
        assert len(specs) == 1
        assert specs[0].source == "heuristic"

    def test_empty_candidates(self):
        specs = synthesise_specs([], lambda s, u: "[]")
        assert specs == []

    def test_batching(self):
        calls = []

        def counting_llm(system, user):
            calls.append(user)
            return "[]"

        cands = [_cand(fn=f"fn_{i}") for i in range(25)]
        synthesise_specs(cands, counting_llm, max_batch=10)
        assert len(calls) == 3  # 10 + 10 + 5

    def test_source_from_candidate(self):
        response = json.dumps([{
            "function": "check",
            "file": "a.py",
            "role": "sanitiser",
            "confidence": 0.8,
        }])

        prompts = []

        def capturing_llm(system, user):
            prompts.append(user)
            return response

        cands = [_cand(fn="check", file="a.py", source="def check(x): pass")]
        synthesise_specs(cands, capturing_llm)
        assert "def check(x): pass" in prompts[0]

    def test_prior_specs_in_prompt(self):
        prompts = []

        def capturing_llm(system, user):
            prompts.append(user)
            return "[]"

        prior = [TaintSpec(
            function="known_sink", file="b.py", role="sink",
            taint_classes=["sql"],
        )]
        synthesise_specs([_cand()], capturing_llm, prior_specs=prior)
        assert "known_sink" in prompts[0]
        assert "sql" in prompts[0]

    def test_feedback_in_prompt(self):
        prompts = []

        def capturing_llm(system, user):
            prompts.append(user)
            return "[]"

        feedback = {
            "confirmed_keys": ["a:b:sink"],
            "refuted_keys": ["c:d:source", "e:f:sanitiser"],
        }
        synthesise_specs([_cand()], capturing_llm, feedback=feedback)
        assert "1 specs confirmed" in prompts[0]
        assert "2 specs produced only false positives" in prompts[0]


class TestCallLlm:
    def test_chat_interface(self):
        class ChatClient:
            def chat(self, *, system, user):
                return f"chat:{system}:{user}"

        result = _call_llm(ChatClient(), "sys", "usr")
        assert result == "chat:sys:usr"

    def test_complete_interface(self):
        class CompleteClient:
            def complete(self, prompt):
                return f"complete:{prompt}"

        result = _call_llm(CompleteClient(), "sys", "usr")
        assert result == "complete:sys\n\nusr"

    def test_callable_interface(self):
        result = _call_llm(lambda s, u: f"fn:{s}:{u}", "sys", "usr")
        assert result == "fn:sys:usr"

    def test_unsupported_raises(self):
        import pytest
        with pytest.raises(TypeError, match="unsupported LLM client type"):
            _call_llm(42, "sys", "usr")


class TestReadCandidateSource:
    def test_reads_from_disk(self, tmp_path):
        src = tmp_path / "auth.py"
        src.write_text("def check(x):\n    return True\n", encoding="utf-8")
        cand = _cand(fn="check", file="auth.py", source="")
        result = _read_candidate_source(cand, tmp_path, max_lines=100)
        assert "def check(x):" in result

    def test_truncation(self, tmp_path):
        src = tmp_path / "big.py"
        src.write_text("\n".join(f"line {i}" for i in range(500)), encoding="utf-8")
        cand = _cand(fn="f", file="big.py", source="")
        result = _read_candidate_source(cand, tmp_path, max_lines=10)
        assert result.count("\n") == 9  # 10 lines = 9 newlines

    def test_file_not_found(self, tmp_path):
        cand = _cand(fn="f", file="missing.py", source="")
        result = _read_candidate_source(cand, tmp_path, max_lines=100)
        assert "file not found" in result

    def test_path_traversal_blocked(self, tmp_path):
        cand = _cand(fn="f", file="../../../etc/passwd", source="")
        result = _read_candidate_source(cand, tmp_path, max_lines=100)
        assert "path outside target" in result

    def test_candidate_source_field_preferred(self, tmp_path):
        src = tmp_path / "auth.py"
        src.write_text("disk version\n", encoding="utf-8")
        cand = _cand(fn="check", file="auth.py", source="inline version")
        result = _read_candidate_source(cand, tmp_path, max_lines=100)
        assert result == "inline version"

    def test_no_target_path(self):
        cand = _cand(fn="f", file="a.py", source="")
        result = _read_candidate_source(cand, None, max_lines=100)
        assert "source unavailable" in result


class TestBuildUserPrompt:
    def test_basic_prompt(self):
        batch = _Batch(
            candidates=[_cand(fn="check", reason="name matches: check")],
            sources=["def check(x):\n    pass"],
        )
        prompt = _build_user_prompt(batch, prior_specs=(), feedback=None)
        assert "check" in prompt
        assert "def check(x)" in prompt
        assert "name matches: check" in prompt

    def test_with_prior_specs(self):
        batch = _Batch(candidates=[_cand()], sources=["# src"])
        prior = [TaintSpec(
            function="eval_cmd", file="x.py", role="sink",
            taint_classes=["cmd"],
        )]
        prompt = _build_user_prompt(batch, prior_specs=prior, feedback=None)
        assert "eval_cmd" in prompt
        assert "Already-known" in prompt

    def test_cwe_gaps_in_feedback(self):
        batch = _Batch(candidates=[_cand()], sources=["# src"])
        feedback = {
            "confirmed_keys": ["a:b:sink"],
            "cwe_gaps": ["CWE-78", "CWE-89"],
        }
        prompt = _build_user_prompt(batch, prior_specs=(), feedback=feedback)
        assert "CWE-78" in prompt
        assert "CWE-89" in prompt
        assert "Low-quality" in prompt


# ── Assumption synthesis ─────────────────────────────────────────────


def _spec(fn="exec_cmd", file="src/db.py", role="sink", **kw):
    return TaintSpec(function=fn, file=file, role=role, **kw)


def _bypass(target="exec_cmd", via="do_work"):
    return BypassFinding(
        assumption=SafetyAssumption(
            target=target,
            file="src/db.py",
            assumption=f"{target} needs guard",
            category=AssumptionCategory.ORDERING,
            enforced_by=["guard"],
        ),
        caller_file="src/handler.c",
        caller_function="bad_caller",
        missing_enforcer="guard",
        via_intermediate=via,
    )


class TestParseAssumptionResponse:
    def test_valid_json(self):
        resp = json.dumps([{
            "target": "exec_cmd",
            "file": "db.py",
            "assumption": "must sanitise input first",
            "category": "sanitisation",
            "enforced_by": ["sanitize_input"],
            "confidence": 0.8,
        }])
        result = _parse_assumption_response(resp)
        assert len(result) == 1
        assert result[0].target == "exec_cmd"
        assert result[0].category == AssumptionCategory.SANITISATION
        assert result[0].source == "llm"
        assert result[0].evidence_tier.value == "heuristic"

    def test_unknown_category_defaults(self):
        resp = json.dumps([{
            "target": "f",
            "file": "x.c",
            "assumption": "test",
            "category": "bogus_category",
        }])
        result = _parse_assumption_response(resp)
        assert result[0].category == AssumptionCategory.SANITISATION

    def test_missing_required_fields(self):
        resp = json.dumps([
            {"target": "f"},
            {"assumption": "no target"},
            {"target": "ok", "assumption": "has both"},
        ])
        result = _parse_assumption_response(resp)
        assert len(result) == 1
        assert result[0].target == "ok"

    def test_non_list_wrapped(self):
        resp = json.dumps({
            "target": "f",
            "file": "x.c",
            "assumption": "test",
        })
        result = _parse_assumption_response(resp)
        assert len(result) == 1

    def test_invalid_json_returns_empty(self):
        result = _parse_assumption_response("not json at all {{{")
        assert result == []

    def test_non_dict_items_skipped(self):
        resp = json.dumps([
            "a string",
            42,
            {"target": "f", "file": "x.c", "assumption": "ok"},
        ])
        result = _parse_assumption_response(resp)
        assert len(result) == 1


class TestBuildAssumptionPrompt:
    def test_basic_prompt(self):
        batch = _Batch(
            candidates=[_cand(fn="exec_cmd", reason="taint role: sink")],
            sources=["void exec_cmd(char *q) { system(q); }"],
        )
        prompt = _build_assumption_prompt(batch)
        assert "exec_cmd" in prompt
        assert "system(q)" in prompt
        assert "taint role: sink" in prompt

    def test_bypass_findings_included(self):
        batch = _Batch(
            candidates=[_cand(fn="exec_cmd")],
            sources=["# src"],
        )
        bf = _bypass(target="exec_cmd", via="do_work")
        prompt = _build_assumption_prompt(batch, bypass_findings=[bf])
        assert "bypass" in prompt.lower()
        assert "do_work" in prompt

    def test_bypass_findings_capped(self):
        batch = _Batch(candidates=[_cand()], sources=["# src"])
        bfs = [_bypass(target=f"t{i}", via=f"v{i}") for i in range(30)]
        prompt = _build_assumption_prompt(batch, bypass_findings=bfs)
        assert prompt.count("bad_caller") <= 20


class TestSynthesiseAssumptions:
    def test_only_sinks_and_sanitisers(self):
        calls = []

        def mock_llm(system, user):
            calls.append(user)
            return "[]"

        specs = [
            _spec(fn="exec_cmd", role="sink"),
            _spec(fn="sanitize", role="sanitiser"),
            _spec(fn="read_input", role="source"),
            _spec(fn="wrap", role="propagator"),
        ]
        synthesise_assumptions(specs, mock_llm)
        assert len(calls) == 1
        assert "exec_cmd" in calls[0]
        assert "sanitize" in calls[0]
        assert "read_input" not in calls[0]

    def test_empty_specs(self):
        result = synthesise_assumptions([], lambda s, u: "[]")
        assert result == []

    def test_no_sinks(self):
        specs = [_spec(fn="read_input", role="source")]
        result = synthesise_assumptions(specs, lambda s, u: "[]")
        assert result == []

    def test_llm_failure_returns_empty(self):
        def failing_llm(system, user):
            raise RuntimeError("API error")

        specs = [_spec(fn="exec_cmd", role="sink")]
        result = synthesise_assumptions(specs, failing_llm)
        assert result == []

    def test_with_bypass_findings(self):
        prompts = []

        def mock_llm(system, user):
            prompts.append(user)
            return json.dumps([{
                "target": "exec_cmd",
                "file": "src/db.py",
                "assumption": "must validate first",
                "category": "validation",
                "enforced_by": ["validate_input"],
            }])

        specs = [_spec(fn="exec_cmd", role="sink")]
        bf = _bypass(target="exec_cmd", via="do_work")
        result = synthesise_assumptions(specs, mock_llm, bypass_findings=[bf])
        assert len(result) == 1
        assert "bypass" in prompts[0].lower()
