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

    def test_vocab_rendered_coccinelle_not_memoized(
        self, tmp_path, monkeypatch,
    ):
        """A DomainVocabulary re-renders the rule per run state, so the
        SOURCE rule's hash is not the effective rule identity — the
        sweep must run unmemoized."""
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
        vocab = object()  # opaque run-state input — must disable the memo
        for _ in range(2):
            _run_tool_chain(
                chain,
                config=cfg,
                file_path="src/a.c",
                function_name="f",
                source="",
                hypothesis="use after free of `p`",
                line_start=1,
                domain_vocab=vocab,
            )
        assert len(calls) == 2

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

    @pytest.fixture(autouse=True)
    def _clear_control_cache(self):
        from core.audit.sweep import _negative_control_cache
        _negative_control_cache.clear()
        yield
        _negative_control_cache.clear()

    def _fake_runner(self, monkeypatch):
        """Fake packages.semgrep.runner: the target scan always finds
        a match (control fixture silently skipped when it rides
        along); the SEPARATE control leg fails transiently on its
        first run and FIRES on its second."""
        import sys
        import types

        control_calls: list[int] = []

        class _Res:
            def __init__(self, findings, errors=None, returncode=0,
                         files_examined=None):
                self.findings = findings
                self.errors = errors or []
                self.returncode = returncode
                self.files_failed: list = []
                self.files_examined = files_examined or []

        def run_rule(target, config, **kw):
            if "negative_controls" in str(target):
                control_calls.append(1)
                if len(control_calls) == 1:
                    return _Res([], errors=["semgrep crashed"],
                                returncode=2)
                return _Res([{"file": str(target),
                              "start": {"line": 3}}])
            return _Res(
                [{"file": "src/a.c", "start": {"line": 1}}],
                files_examined=[str(target)],
            )

        fake = types.ModuleType("packages.semgrep.runner")
        fake.run_rule = run_rule
        fake.is_available = lambda: True
        monkeypatch.setitem(sys.modules, "packages.semgrep.runner", fake)
        return control_calls

    def test_second_dispatch_reruns_control_and_caps(
        self, tmp_path, monkeypatch,
    ):
        _write_target(tmp_path, "void f(char *p) { free(p); }\n")
        rule = _write_rule(tmp_path)
        cfg = _Cfg(tmp_path)
        control_calls = self._fake_runner(monkeypatch)
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
                source="",
                hypothesis=self.HYP,
                line_start=1,
            )

        first = run()
        assert first == [f"semgrep:{rule}"]  # uncapped this dispatch
        assert len(control_calls) == 1
        # The memo must NOT have pinned the uncapped result: the
        # second dispatch re-runs the sweep, the control succeeds and
        # fires, and the presence-detector cap lands.
        second = run()
        assert len(control_calls) == 2
        assert second == []


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
