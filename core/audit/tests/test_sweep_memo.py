"""Per-run sweep memo: _run_tool_chain step-level memoization.

Covers the SweepMemo substrate (keying, eviction, error handling,
mutation isolation, thread safety) and the orchestrator wiring: memo
hits skip the runner while keeping the branch bookkeeping, content
changes miss, and non-memoizable step classes always re-run.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

import core.audit.orchestrator as orch
from core.audit.orchestrator import _run_tool_chain
from core.audit.sweep import SweepResult
from core.audit.sweep_memo import (
    MAX_MEMO_ENTRIES,
    MEMOIZABLE_STEP_TYPES,
    SweepMemo,
    hash_file,
    hash_text,
)


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path):
        self.target_path = target
        self.out_dir = None
        self.codeql_db_path = None
        self.project_sinks = None
        self.sweep_memo = SweepMemo()


def _semgrep_result(outcome: str = "confirmed") -> SweepResult:
    return SweepResult(
        tool="semgrep", file_path="src/a.c", function_name="f",
        outcome=outcome, rule_id="rules/r.yaml",
        matches=[{"line": 4}] if outcome == "confirmed" else [],
    )


def _write_target(tmp_path: Path, content: str = "int f(void){}\n") -> None:
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "a.c").write_text(content)


def _write_rule(tmp_path: Path) -> Path:
    rule = tmp_path / "rules" / "r.yaml"
    rule.parent.mkdir(exist_ok=True)
    rule.write_text("rules: []\n")
    return rule


class TestSweepMemoSubstrate:
    def test_make_key_none_on_unhashable_part(self):
        assert SweepMemo.make_key("semgrep", {"rule": None}) is None

    def test_make_key_order_independent(self):
        a = SweepMemo.make_key("smt", {"x": "1", "y": "2"})
        b = SweepMemo.make_key("smt", {"y": "2", "x": "1"})
        assert a == b

    def test_hash_file_none_on_missing(self, tmp_path):
        assert hash_file(tmp_path / "absent") is None
        assert hash_file(None) is None

    def test_hash_file_tracks_content(self, tmp_path):
        p = tmp_path / "x"
        p.write_text("one")
        h1 = hash_file(p)
        p.write_text("two")
        assert hash_file(p) != h1

    def test_get_or_run_caches(self):
        memo = SweepMemo()
        key = SweepMemo.make_key("smt", {"k": "v"})
        calls = []
        result = _semgrep_result()

        def runner():
            calls.append(1)
            return result

        assert memo.get_or_run(key, runner).outcome == "confirmed"
        assert memo.get_or_run(key, runner).outcome == "confirmed"
        assert len(calls) == 1

    def test_none_key_never_caches(self):
        memo = SweepMemo()
        calls = []

        def runner():
            calls.append(1)
            return _semgrep_result()

        memo.get_or_run(None, runner)
        memo.get_or_run(None, runner)
        assert len(calls) == 2

    def test_error_outcomes_not_cached(self):
        memo = SweepMemo()
        key = SweepMemo.make_key("semgrep", {"k": "v"})
        calls = []

        def runner():
            calls.append(1)
            return _semgrep_result("error")

        memo.get_or_run(key, runner)
        memo.get_or_run(key, runner)
        assert len(calls) == 2

    def test_hit_returns_isolated_copy(self):
        memo = SweepMemo()
        key = SweepMemo.make_key("semgrep", {"k": "v"})
        original = _semgrep_result()
        memo.get_or_run(key, lambda: original)

        first = memo.get_or_run(key, lambda: None)
        first.matches.append({"line": 99})
        original.matches.append({"line": 100})

        second = memo.get_or_run(key, lambda: None)
        assert second.matches == [{"line": 4}]

    def test_eviction_bounds_size(self):
        memo = SweepMemo(max_entries=3)
        for i in range(10):
            key = SweepMemo.make_key("smt", {"i": str(i)})
            memo.get_or_run(key, _semgrep_result)
        assert len(memo._entries) == 3

    def test_default_cap_value_is_pinned(self):
        """Value pin (churn-prone-limits doctrine): the cap-binding
        assertions elsewhere follow the constant, so mutating the
        constant would move both sides and stay green — only an
        explicit value pin makes a cap change a deliberate,
        test-visible act. Both directions of the trade: raising it
        holds more cached SweepResults (matches, raw details) in
        memory for the whole run; lowering it evicts exactly the
        entries the late phases (critique, promotion re-checks) would
        have hit, turning them back into subprocess spawns.
        """
        assert MAX_MEMO_ENTRIES == 1024
        assert SweepMemo()._max_entries == MAX_MEMO_ENTRIES

    def test_eviction_boundary_is_exact(self):
        """Two-direction cap binding: AT the cap nothing is evicted
        (every entry still hits); ONE past the cap evicts exactly the
        least-recently-used entry and nothing else."""
        memo = SweepMemo(max_entries=3)
        keys = [SweepMemo.make_key("smt", {"i": str(i)}) for i in range(4)]
        for k in keys[:3]:
            memo.get_or_run(k, _semgrep_result)

        calls: list[int] = []

        def runner():
            calls.append(1)
            return _semgrep_result()

        # At the cap: all three entries retained.
        for k in keys[:3]:
            memo.get_or_run(k, runner)
        assert calls == []
        # One past the cap: keys[0] (LRU) evicted, keys[1:] retained.
        memo.get_or_run(keys[3], runner)
        assert len(calls) == 1
        for k in keys[1:]:
            memo.get_or_run(k, runner)
        assert len(calls) == 1
        memo.get_or_run(keys[0], runner)
        assert len(calls) == 2

    def test_control_error_results_never_stored(self):
        """A result whose negative-control leg errored is uncapped
        only for its own dispatch — pinning it would replay the
        uncapped verdict without ever re-running the control."""
        memo = SweepMemo()
        key = SweepMemo.make_key("semgrep", {"k": "v"})
        flagged = _semgrep_result()
        flagged.details = {"negative_control_error": True}
        calls: list[int] = []

        def runner():
            calls.append(1)
            return flagged

        memo.get_or_run(key, runner)
        memo.get_or_run(key, runner)
        assert len(calls) == 2

    def test_thread_safety_smoke(self):
        memo = SweepMemo(max_entries=32)
        errors: list[BaseException] = []

        def worker(seed: int) -> None:
            try:
                for i in range(200):
                    key = SweepMemo.make_key(
                        "smt", {"i": str((seed + i) % 40)},
                    )
                    res = memo.get_or_run(key, _semgrep_result)
                    assert res.outcome == "confirmed"
            except BaseException as exc:  # noqa: BLE001 — surfaced below
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(s,)) for s in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert len(memo._entries) <= 32
        assert memo.hits + memo.misses > 0


class TestToolChainMemoWiring:
    def _chain(self, rule: Path) -> list[dict[str, Any]]:
        return [{"type": "semgrep", "config": {"rule": str(rule)}}]

    def _run(self, cfg: _Cfg, chain: list[dict[str, Any]]) -> list[str]:
        return _run_tool_chain(
            chain,
            config=cfg,
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis="missing bounds check on `len`",
            line_start=1,
        )

    def test_memo_hit_skips_runner(self, tmp_path, monkeypatch):
        _write_target(tmp_path)
        rule = _write_rule(tmp_path)
        cfg = _Cfg(tmp_path)
        calls = []

        def stub(**kw):
            calls.append(kw)
            return _semgrep_result()

        monkeypatch.setattr(orch, "run_semgrep_sweep", stub)
        first = self._run(cfg, self._chain(rule))
        second = self._run(cfg, self._chain(rule))
        assert len(calls) == 1
        assert first == second == ["semgrep:rules/r.yaml"]

    def test_memo_miss_on_target_content_change(
        self, tmp_path, monkeypatch,
    ):
        _write_target(tmp_path)
        rule = _write_rule(tmp_path)
        cfg = _Cfg(tmp_path)
        calls = []

        def stub(**kw):
            calls.append(kw)
            return _semgrep_result()

        monkeypatch.setattr(orch, "run_semgrep_sweep", stub)
        self._run(cfg, self._chain(rule))
        _write_target(tmp_path, "int f(void){ return 1; }\n")
        self._run(cfg, self._chain(rule))
        assert len(calls) == 2

    def test_memo_miss_on_rule_content_change(self, tmp_path, monkeypatch):
        _write_target(tmp_path)
        rule = _write_rule(tmp_path)
        cfg = _Cfg(tmp_path)
        calls = []

        def stub(**kw):
            calls.append(kw)
            return _semgrep_result()

        monkeypatch.setattr(orch, "run_semgrep_sweep", stub)
        self._run(cfg, self._chain(rule))
        rule.write_text("rules: [changed]\n")
        self._run(cfg, self._chain(rule))
        assert len(calls) == 2

    def test_unreadable_rule_runs_unmemoized(self, tmp_path, monkeypatch):
        _write_target(tmp_path)
        cfg = _Cfg(tmp_path)
        missing = tmp_path / "rules" / "gone.yaml"
        calls = []

        def stub(**kw):
            calls.append(kw)
            return _semgrep_result()

        monkeypatch.setattr(orch, "run_semgrep_sweep", stub)
        self._run(cfg, self._chain(missing))
        self._run(cfg, self._chain(missing))
        assert len(calls) == 2

    def test_config_without_memo_runs_every_time(
        self, tmp_path, monkeypatch,
    ):
        _write_target(tmp_path)
        rule = _write_rule(tmp_path)
        cfg = _Cfg(tmp_path)
        del cfg.sweep_memo
        calls = []

        def stub(**kw):
            calls.append(kw)
            return _semgrep_result()

        monkeypatch.setattr(orch, "run_semgrep_sweep", stub)
        self._run(cfg, self._chain(rule))
        self._run(cfg, self._chain(rule))
        assert len(calls) == 2

    def test_smt_step_memoized(self, tmp_path, monkeypatch):
        cfg = _Cfg(tmp_path)
        calls = []

        def stub(**kw):
            calls.append(kw)
            return SweepResult(
                tool="smt", file_path="src/a.c", function_name="f",
                outcome="confirmed", rule_id="smt:check-oob",
            )

        monkeypatch.setattr(orch, "run_smt_verb_direct", stub)
        chain = [{"type": "smt", "config": {"verb": "check-oob"}}]
        for _ in range(2):
            confirmed = _run_tool_chain(
                chain,
                config=cfg,
                file_path="src/a.c",
                function_name="f",
                source="int f(void){}",
                hypothesis="oob write via `len`",
                line_start=1,
            )
            assert confirmed == ["smt:check-oob"]
        assert len(calls) == 1

    def test_vocab_rendered_coccinelle_memoized_on_rendered_bytes(
        self, tmp_path, monkeypatch,
    ):
        """A vocab-bearing dispatch renders the rule ONCE up front and
        keys the memo on the rendered content — the second dispatch
        with the same vocabulary is a hit, not a re-render + re-run."""
        _write_target(tmp_path)
        rule = tmp_path / "rules" / "uaf.cocci"
        rule.parent.mkdir(exist_ok=True)
        rule.write_text("@@ @@\n")  # markerless: render() returns None
        cfg = _Cfg(tmp_path)
        calls = []

        def stub(**kw):
            calls.append(kw)
            return SweepResult(
                tool="coccinelle", file_path="src/a.c",
                function_name="f", outcome="confirmed",
                rule_id=str(rule), matches=[{"line": 3}],
            )

        monkeypatch.setattr(orch, "run_coccinelle_file_sweep", stub)
        chain = [{"type": "coccinelle", "config": {"rule": str(rule)}}]
        vocab = object()  # markerless rule: vocab splices nothing
        for _ in range(2):
            confirmed = _run_tool_chain(
                chain,
                config=cfg,
                file_path="src/a.c",
                function_name="f",
                source="",
                hypothesis="use after free of `p`",
                line_start=1,
                domain_vocab=vocab,
            )
            assert confirmed == ["coccinelle:uaf"]
        assert len(calls) == 1

    def test_coccinelle_memo_is_file_scoped_across_functions(
        self, tmp_path, monkeypatch,
    ):
        """The memo key carries no function/line dimension: a second
        function in the same file replays the file sweep instead of
        spawning a second spatch."""
        _write_target(tmp_path)
        rule = tmp_path / "rules" / "uaf.cocci"
        rule.parent.mkdir(exist_ok=True)
        rule.write_text("@@ @@\n")
        cfg = _Cfg(tmp_path)
        calls = []

        def stub(**kw):
            calls.append(kw)
            return SweepResult(
                tool="coccinelle", file_path="src/a.c",
                function_name="", outcome="confirmed",
                rule_id=str(rule), matches=[{"line": 3}],
            )

        monkeypatch.setattr(orch, "run_coccinelle_file_sweep", stub)
        chain = [{"type": "coccinelle", "config": {"rule": str(rule)}}]
        for fn, line in (("f", 1), ("g", 100)):
            _run_tool_chain(
                chain,
                config=cfg,
                file_path="src/a.c",
                function_name=fn,
                source="",
                hypothesis="use after free of `p`",
                line_start=line,
            )
        assert len(calls) == 1

    def test_stateful_channel_never_memoized(self, tmp_path, monkeypatch):
        assert "smt_invariant" not in MEMOIZABLE_STEP_TYPES
        cfg = _Cfg(tmp_path)
        calls = []

        class _InvRes:
            outcome = "violable"
            invariant = "a <= b"
            reason = "model found"

            def to_dict(self):
                return {"outcome": self.outcome}

        import core.audit.invariant_smt as inv_mod
        monkeypatch.setattr(
            inv_mod, "check_invariant_preservation",
            lambda *a, **kw: (calls.append(1), _InvRes())[1],
        )
        chain = [
            {"type": "smt_invariant", "config": {"invariant": "a <= b"}},
        ]
        for _ in range(2):
            confirmed = _run_tool_chain(
                chain,
                config=cfg,
                file_path="src/a.c",
                function_name="f",
                source="int f(void){}",
                hypothesis="invariant a <= b broken",
                line_start=1,
            )
            assert confirmed == ["smt:invariant-preservation"]
        assert len(calls) == 2

    def test_hypothesis_change_is_a_miss_for_smt(
        self, tmp_path, monkeypatch,
    ):
        cfg = _Cfg(tmp_path)
        calls = []

        def stub(**kw):
            calls.append(kw)
            return SweepResult(
                tool="smt", file_path="src/a.c", function_name="f",
                outcome="confirmed", rule_id="smt:check-oob",
            )

        monkeypatch.setattr(orch, "run_smt_verb_direct", stub)
        chain = [{"type": "smt", "config": {"verb": "check-oob"}}]
        for hyp in ("oob write via `len`", "oob write via `count`"):
            _run_tool_chain(
                chain,
                config=cfg,
                file_path="src/a.c",
                function_name="f",
                source="int f(void){}",
                hypothesis=hyp,
                line_start=1,
            )
        assert len(calls) == 2


class TestControlErrorNotPinned:
    """Transient negative-control failure through the REAL semgrep
    sweep: the first dispatch stays uncapped (a broken control must
    not fabricate inconclusive), the memo refuses to pin it, and the
    second dispatch re-runs the control and caps."""

    KEYWORD = "use after free"
    HYP = "use after free of `p` in f"

    def _fake_runner(self, monkeypatch):
        """Own only the runner lookups of this sweep and its control helper."""
        import builtins
        from types import SimpleNamespace

        from core.audit import sweep as sweep_mod
        from core.testing.module_views import module_function_view
        from packages.semgrep.models import SemgrepFinding, SemgrepResult

        control_calls: list[int] = []
        results: list[SweepResult] = []

        def run_rule(target, config, **kw):
            if "negative_controls" in str(target):
                control_calls.append(1)
                if len(control_calls) == 1:
                    return SemgrepResult(
                        config=str(config), target=str(target),
                        errors=["semgrep crashed"], returncode=2,
                    )
                return SemgrepResult(
                    config=str(config), target=str(target),
                    findings=[SemgrepFinding(
                        file=str(target), line=3, rule_id="memo-control",
                    )],
                    files_examined=[str(target)],
                )
            return SemgrepResult(
                config=str(config), target=str(target),
                findings=[SemgrepFinding(
                    file="src/a.c", line=1, rule_id="memo-control",
                )],
                files_examined=[str(target)],
            )

        runner = SimpleNamespace(run_rule=run_rule, is_available=lambda: True)

        def import_local(name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and name == "packages.semgrep.runner":
                return runner
            return builtins.__import__(name, globals, locals, fromlist, level)

        sweep_view = module_function_view(
            sweep_mod, bindings={"_negative_control_cache": {}},
            import_hook=import_local,
        )

        def run_sweep(**kwargs):
            result = sweep_view.run_semgrep_sweep(**kwargs)
            results.append(result)
            return result

        monkeypatch.setattr(orch, "run_semgrep_sweep", run_sweep)
        return control_calls, results

    def test_second_dispatch_reruns_control_and_caps(
        self, tmp_path, monkeypatch,
    ):
        source = "void f(char *p) { free(p); }\n"
        _write_target(tmp_path, source)
        rule = _write_rule(tmp_path)
        rule.write_text(
            "rules:\n- id: memo-control\n  languages: [c]\n"
            "  message: pointer use\n  severity: WARNING\n  pattern: free($P)\n"
        )
        cfg = _Cfg(tmp_path)
        control_calls, results = self._fake_runner(monkeypatch)
        chain = [{
            "type": "semgrep",
            "config": {"rule": str(rule), "keyword": self.KEYWORD},
        }]

        def run():
            return _run_tool_chain(
                chain,
                config=cfg,
                file_path="src/a.c",
                function_name="f",
                source=source,
                hypothesis=self.HYP,
                line_start=1,
            )

        first = run()
        assert first == [f"semgrep:{rule}"]  # uncapped this dispatch
        assert len(control_calls) == 1
        assert len(results) == 1
        assert results[0].outcome == "confirmed"
        assert results[0].errors == []
        assert results[0].details["negative_control_error"] is True
        assert results[0].matches[0]["rule_id"] == "memo-control"
        # The memo must NOT have pinned the uncapped result: the
        # second dispatch re-runs the sweep, the control succeeds and
        # fires, and the presence-detector cap lands.
        second = run()
        assert len(control_calls) == 2
        assert second == []
        assert len(results) == 2  # the transient result was not memo-pinned
        assert results[1].outcome == "inconclusive"
        assert results[1].errors == []
        assert not results[1].details.get("negative_control_error")
        assert results[1].details["reason"] == (
            "presence detector: rule for 'use after free' also "
            "matches the guarded negative-control fixture"
        )


def test_memoizable_set_excludes_stateful_classes():
    stateful = {
        "consistency", "fail_open", "api_boundary", "ptr_lifecycle",
        "lock_region", "resource_bounds", "release_order",
        "protocol_state", "joern", "joern_guard", "joern_flow",
        "smt_invariant", "coccinelle_flow", "integer_truncation",
        "proto_length", "struct_field",
    }
    assert not (MEMOIZABLE_STEP_TYPES & stateful)


def test_hash_text_stable():
    assert hash_text("abc") == hash_text("abc")
    assert hash_text("abc") != hash_text("abd")



def test_distinct_hypotheses_keep_their_native_smt_query_binding(tmp_path, monkeypatch):
    import hashlib

    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    from core.audit import sweep

    source = "unsigned Read(unsigned Value,unsigned Step){if(Value>0 && Step>0) return Value+Step; return 0;}"
    hypothesis = "integer overflow in `Value + Step`"
    distinct = "addition overflow in `Value + Step`"
    config = orch.OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path / "out", integer_abi="ilp32",
    )
    (tmp_path / "unit.c").write_text(source)
    native_results, returned_results = [], []

    def native_worker(**request):
        assert request.pop("include_callers") is False
        result = sweep._run_smt_verb_inner(**request)
        native_results.append(result)
        return result

    real_get_or_run = config.sweep_memo.get_or_run

    def observe(key, runner):
        result = real_get_or_run(key, runner)
        returned_results.append(result)
        return result

    monkeypatch.setattr(orch, "run_smt_verb_direct", native_worker)
    monkeypatch.setattr(config.sweep_memo, "get_or_run", observe)
    chain = [{"type": "smt", "config": {"verb": "check-overflow"}}]
    for claim in (hypothesis, distinct, hypothesis):
        result = _run_tool_chain(
            chain, config=config, file_path="unit.c", function_name="Read",
            source=source, hypothesis=claim, line_start=1,
        )
        assert result == ["smt:check-overflow"]
        packet = returned_results[-1]
        assert packet.details["witness_validated"] is True
        expected = hashlib.sha256(claim.encode("utf-8", "surrogatepass")).hexdigest()
        assert packet.details["source_scope"]["hypothesis_sha256"] == expected
    assert len(native_results) == 2  # only the unchanged query reuses a receipt

    # Distinct unsupported prose/surrogate queries keep their own bindings;
    # neither may borrow the confirmed receipt from an admitted objective.
    unsupported = (hypothesis + " during review ?", hypothesis + " during review \ud800")
    for claim in (*unsupported, unsupported[0]):
        result = _run_tool_chain(
            chain, config=config, file_path="unit.c", function_name="Read",
            source=source, hypothesis=claim, line_start=1,
        )
        assert result == []
        packet = returned_results[-1]
        assert packet.outcome == "inconclusive"
        assert packet.details.get("witness_validated") is not True
        assert packet.details["arithmetic_expression_status"] == "unavailable"
        expected = hashlib.sha256(claim.encode("utf-8", "surrogatepass")).hexdigest()
        assert packet.details["source_scope"]["hypothesis_sha256"] == expected
    assert len(native_results) == 4



@pytest.mark.parametrize("text", ["owned ascii", "\u00e9", "\U0001f642"])
def test_text_hash_keeps_existing_valid_utf8_digests(text):
    import hashlib

    assert hash_text(text) == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_text_hash_preserves_surrogate_and_replacement_identities():
    texts = ["?", "\ufffd", "\ud800", "\udfff", "\ud800\udfff", "\U000103ff"]
    assert len({hash_text(text) for text in texts}) == len(texts)


def test_transient_smt_worker_failure_is_retried(tmp_path, monkeypatch):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    from core.audit import subproc_json, sweep

    source = "unsigned Read(unsigned Value,unsigned Step){if(Value>0 && Step>0) return Value+Step; return 0;}"
    (tmp_path / "unit.c").write_text(source)
    config = orch.OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path / "out", integer_abi="ilp32",
    )
    calls = []

    def transport(entry, request, **options):
        assert entry == "core.audit.sweep:_run_smt_verb_inner_json"
        calls.append(request)
        if len(calls) == 1:
            return None  # the production transport's crash/timeout sentinel
        return sweep._run_smt_verb_inner_json(request)

    monkeypatch.setattr(subproc_json, "run_json_child", transport)
    chain = [{"type": "smt", "config": {"verb": "check-overflow"}}]

    def run():
        return orch._run_tool_chain(
            chain, config=config, file_path="unit.c", function_name="Read",
            source=source, hypothesis="integer overflow in `Value + Step`", line_start=1,
        )

    assert run() == []
    assert len(calls) == 1
    assert run() == ["smt:check-overflow"]
    assert len(calls) == 2
    assert run() == ["smt:check-overflow"]
    assert len(calls) == 2  # a successful retry remains memoised
