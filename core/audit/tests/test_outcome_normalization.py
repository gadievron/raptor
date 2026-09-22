"""Outcome normalization at the tool-chain consumers.

The ``skipped`` outcome (did not look) must land in skip accounting
at every result-consuming leg — never in a refuted counter via an
elif/else fall-through — and a novel outcome string must land in
error accounting. Hermetic: every tool runner is stubbed.
"""

from __future__ import annotations

import inspect
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import core.audit.orchestrator as orch
from core.audit.orchestrator import _make_tier_counters, _run_tool_chain
from core.audit.sweep import SweepResult
from core.testing import requires_ts


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path, out_dir: Path | None = None):
        self.target_path = target
        self.out_dir = out_dir
        self.codeql_db_path = None
        self.project_sinks = None
        self.tool_chain_early_exit = True
        # No memo: every dispatch must reach the stubs.


def _write_tree(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "a.c").write_text("int f(void){ return 0; }\n")


def _sweep(tool: str, outcome: str) -> SweepResult:
    return SweepResult(
        tool=tool, file_path="src/a.c", function_name="f",
        outcome=outcome, rule_id=f"{tool}:rule",
    )


def _run(cfg, chain, *, tiers, errored, skipped):
    return _run_tool_chain(
        chain,
        config=cfg,
        file_path="src/a.c",
        function_name="f",
        source="int f(void){ return 0; }",
        hypothesis="missing bounds check on `len`",
        line_start=1,
        tier_counters=tiers,
        errored_types=errored,
        skipped_types=skipped,
    )


def _channel_stub(outcome: str) -> SimpleNamespace:
    """Structural-channel result double (api_boundary/consistency)."""
    return SimpleNamespace(
        outcome=outcome, reason="stub", rule_id="chan:rule-majority",
        corroboration=[], peer_evidence=None, fail_open_handoff=False,
        contract=None, sites=[],
        to_dict=lambda: {"outcome": outcome},
    )


# Leg specs: (tool_type, tier key, chain entry, patcher). The patcher
# monkeypatches the leg's runner to return the given outcome.
def _leg_specs(tmp_path: Path):
    rule = tmp_path / "rules" / "r.yaml"
    rule.parent.mkdir(exist_ok=True)
    rule.write_text("rules: []\n")
    cocci = tmp_path / "rules" / "check.cocci"
    cocci.write_text("@@ @@\n")

    def _patch_semgrep(mp, outcome):
        mp.setattr(orch, "run_semgrep_sweep",
                   lambda **kw: _sweep("semgrep", outcome))

    def _patch_smt(mp, outcome):
        mp.setattr(orch, "run_smt_verb_direct",
                   lambda **kw: _sweep("smt", outcome))

    def _patch_cocci(mp, outcome):
        mp.setattr(orch, "run_coccinelle_sweep",
                   lambda **kw: _sweep("coccinelle", outcome))

    def _patch_codeql(mp, outcome):
        import core.audit.sweep as sweep_mod
        mp.setattr(orch, "_codeql_db_for", lambda *a, **kw: "/db")
        mp.setattr(orch, "_codeql_query_file", lambda q: q)
        mp.setattr(sweep_mod, "run_codeql_sweep",
                   lambda **kw: _sweep("codeql", outcome))

    def _patch_compiler(mp, outcome):
        import core.audit.compiler_sweep as cs_mod
        mp.setattr(cs_mod, "run_compiler_analyzer_sweep",
                   lambda **kw: _sweep("compiler", outcome))

    def _patch_cocci_flow(mp, outcome):
        import core.audit.cocci_flow as cf_mod
        mp.setattr(cf_mod, "run_flow_cocci_sweep",
                   lambda **kw: _sweep("coccinelle_flow", outcome))

    def _patch_joern_guard(mp, outcome):
        import core.audit.joern_verify as jv_mod
        mp.setattr(jv_mod, "extract_guard_target",
                   lambda *a, **kw: ("len", "memcpy"))
        mp.setattr(jv_mod, "run_guard_dominance_check",
                   lambda **kw: _sweep("joern_guard", outcome))
        mp.setattr(orch, "_joern_dispatch_blocked", lambda c: False)
        mp.setattr(orch, "_joern_budget_timeout_s", lambda c: 60)
        mp.setattr(orch, "_record_joern_outcome", lambda *a, **kw: None)

    def _patch_api_boundary(mp, outcome):
        import core.audit.api_boundary as ab_mod
        mp.setattr(ab_mod, "run_api_boundary_check",
                   lambda *a, **kw: _channel_stub(outcome))

    def _patch_consistency(mp, outcome):
        import core.audit.consistency_verify as cv_mod
        mp.setattr(cv_mod, "run_consistency_check",
                   lambda *a, **kw: _channel_stub(outcome))

    def _patch_int_trunc(mp, outcome):
        import core.audit.sweep as sweep_mod
        mp.setattr(sweep_mod, "run_integer_truncation_sweep",
                   lambda **kw: _sweep("integer_truncation", outcome))

    return [
        ("semgrep", "semgrep",
         {"type": "semgrep", "config": {"rule": str(rule)}},
         _patch_semgrep),
        ("smt", "smt",
         {"type": "smt", "config": {"verb": "check-oob"}}, _patch_smt),
        ("coccinelle", "coccinelle",
         {"type": "coccinelle", "config": {"rule": str(cocci)}},
         _patch_cocci),
        ("codeql", "codeql",
         {"type": "codeql", "config": {"query": str(rule)}},
         _patch_codeql),
        ("compiler", "compiler",
         {"type": "compiler", "config": {"cwe": "CWE-120"}},
         _patch_compiler),
        ("coccinelle_flow", "coccinelle_flow",
         {"type": "coccinelle_flow", "config": {"template": None}},
         _patch_cocci_flow),
        ("joern_guard", "joern_guard",
         {"type": "joern_guard", "config": {"sinks": ["memcpy"]}},
         _patch_joern_guard),
        ("api_boundary", "api_boundary",
         {"type": "api_boundary", "config": {}}, _patch_api_boundary),
        ("consistency", "consistency",
         {"type": "consistency", "config": {}}, _patch_consistency),
        ("integer_truncation", None,
         {"type": "integer_truncation", "config": {}}, _patch_int_trunc),
    ]


def _run_leg(tmp_path, monkeypatch, spec, outcome):
    tool_type, tier, entry, patch = spec
    _write_tree(tmp_path)
    patch(monkeypatch, outcome)
    cfg = _Cfg(tmp_path)
    tiers = _make_tier_counters()
    errored: set = set()
    skipped: set = set()
    kwargs: dict[str, Any] = {}
    if tool_type == "joern_guard":
        kwargs["joern_server"] = object()
    _run_tool_chain(
        [entry],
        config=cfg,
        file_path="src/a.c",
        function_name="f",
        source="int f(void){ return 0; }",
        hypothesis="missing bounds check on `len`",
        line_start=1,
        tier_counters=tiers,
        errored_types=errored,
        skipped_types=skipped,
        **kwargs,
    )
    return tiers.get(tier) if tier else None, errored, skipped


class TestSkippedNeverRefuted:
    """A skipped result lands in skip accounting at every leg."""

    @pytest.mark.parametrize("idx", range(10))
    def test_skipped_outcome(self, tmp_path, monkeypatch, idx):
        spec = _leg_specs(tmp_path)[idx]
        tc, errored, skipped = _run_leg(
            tmp_path, monkeypatch, spec, "skipped",
        )
        assert spec[0] in skipped
        assert spec[0] not in errored
        if tc is not None:
            assert tc.skipped == 1
            assert tc.refuted == 0
            assert tc.errors == 0

    @pytest.mark.parametrize("idx", range(10))
    def test_novel_outcome_lands_in_error_accounting(
        self, tmp_path, monkeypatch, idx,
    ):
        spec = _leg_specs(tmp_path)[idx]
        tc, errored, skipped = _run_leg(
            tmp_path, monkeypatch, spec, "banana",
        )
        assert spec[0] in errored
        assert spec[0] not in skipped
        if tc is not None:
            assert tc.refuted == 0
            assert tc.errors == 1

    @pytest.mark.parametrize("idx", range(10))
    def test_refuted_still_counts_refuted(self, tmp_path, monkeypatch, idx):
        # The preserved direction: normalization must not eat genuine
        # refutations.
        spec = _leg_specs(tmp_path)[idx]
        tc, errored, skipped = _run_leg(
            tmp_path, monkeypatch, spec, "refuted",
        )
        assert spec[0] not in skipped
        assert spec[0] not in errored
        if tc is not None:
            assert tc.refuted == 1


class TestRefutedIncrementsAreGuarded:
    """Source-shape tripwire: every refuted tier-counter increment in
    the two dispatch surfaces sits under a branch that names the
    refuted outcome explicitly — a bare else regressing in would be
    the miscount lane this suite exists to close."""

    # Channels whose refuted increment is legitimately guarded by a
    # non-outcome condition: the joern live lane refutes on silence
    # plus a True coverage probe (no outcome object exists), the
    # invariant channel's refuted-equivalent outcome is "preserved",
    # and joern_xf refutes on a verified=False result object.
    _EXEMPT_TIERS = {"joern", "smt_invariant", "joern_xf"}

    def _bad_increments(self, source: str) -> list[str]:
        lines = source.splitlines()
        bad: list[str] = []
        for i, line in enumerate(lines):
            if '"refuted"' not in line:
                continue
            if line.strip().startswith(("if ", "elif ", "else")):
                continue  # branch header, not an increment argument
            window = "\n".join(lines[max(0, i - 2): i + 1])
            if "_increment_tier_dict" not in window:
                continue
            call = "\n".join(lines[max(0, i - 2): i + 2])
            if any(f'"{t}"' in call for t in self._EXEMPT_TIERS):
                continue
            if self._governed_by_refuted_branch(lines, i):
                continue
            bad.append(f"line {i + 1}: {line.strip()[:70]}")
        return bad

    @staticmethod
    def _governed_by_refuted_branch(lines: list[str], i: int) -> bool:
        indent = len(lines[i]) - len(lines[i].lstrip())
        j = i - 1
        while j >= 0:
            prev = lines[j]
            if prev.strip():
                p_ind = len(prev) - len(prev.lstrip())
                stripped = prev.strip()
                if p_ind < indent and stripped.startswith(
                    ("if ", "elif ", "else"),
                ):
                    # Header may wrap: include lines to the colon.
                    header = stripped
                    k = j
                    while not header.rstrip().endswith(":") and k + 1 < i:
                        k += 1
                        header += " " + lines[k].strip()
                    if '== "refuted"' in header:
                        return True
                    if stripped.startswith("elif tool_type ==") or (
                        stripped.startswith("if tool_type ==")
                    ):
                        # Reached the leg dispatch level without an
                        # outcome guard.
                        return False
                    indent = p_ind
            j -= 1
        return False

    @pytest.mark.parametrize("fn", ["_run_tool_chain", "_proactive_validate"])
    def test_no_unguarded_refuted_increment(self, fn):
        source = textwrap.dedent(inspect.getsource(getattr(orch, fn)))
        bad = self._bad_increments(source)
        assert not bad, (
            "refuted increments outside an explicit refuted branch "
            f"in {fn}: {bad}"
        )

    def test_tripwire_catches_bare_else(self):
        # The tripwire itself must flag the pre-fix shape.
        source = textwrap.dedent("""\
            if res.outcome == "confirmed":
                pass
            elif tier_counters:
                _increment_tier_dict(tier_counters, "semgrep", "refuted")
        """)
        assert self._bad_increments(source)


class TestIncrementTierAcceptsSkipped:
    def test_skipped_lands_in_skipped_counter(self):
        from core.audit.diagnostics import increment_tier

        result = SimpleNamespace(
            tier_counters={"semgrep": orch.TierCounters()},
        )
        increment_tier(result, "semgrep", "skipped")
        tc = result.tier_counters["semgrep"]
        assert tc.skipped == 1
        assert tc.inconclusive == 0
        assert tc.refuted == 0

    def test_inconclusive_unchanged(self):
        from core.audit.diagnostics import increment_tier

        result = SimpleNamespace(
            tier_counters={"semgrep": orch.TierCounters()},
        )
        increment_tier(result, "semgrep", "inconclusive")
        assert result.tier_counters["semgrep"].inconclusive == 1


class TestCallerGateSkippedExclusion:
    def _gate(self, monkeypatch, outcomes):
        import core.audit.smt_promotion_gate as gate_mod

        results = [
            SimpleNamespace(
                outcome=o, reason="r", sites=[1],
                enumeration_complete=True,
            )
            for o in outcomes
        ]
        contract = SimpleNamespace(describe=lambda: "len > 0")
        monkeypatch.setattr(
            gate_mod, "receipt_preconditions",
            lambda *a, **kw: [contract] * len(results),
        )
        it = iter(results)
        monkeypatch.setattr(
            gate_mod, "adjudicate_contract",
            lambda *a, **kw: next(it),
        )
        monkeypatch.setattr(
            gate_mod, "parse_param_names", lambda *a, **kw: ["len"],
        )
        return gate_mod._evaluate_caller_gate(
            Path("/nonexistent"), "a.c", "f", "check-oob", "m",
        )

    def test_skip_only_set_never_reads_all_refuted(self, monkeypatch):
        decision = self._gate(monkeypatch, ["skipped", "skipped"])
        assert decision.action == "hold"
        assert decision.channel_outcome == "inconclusive"

    def test_all_refuted_preserved(self, monkeypatch):
        decision = self._gate(monkeypatch, ["refuted", "refuted"])
        assert decision.channel_outcome == "refuted"

    def test_skip_beside_refuted_does_not_block_all_refuted(
        self, monkeypatch,
    ):
        # A did-not-look result adjudicates nothing: the remaining
        # genuine refutations still quantify.
        decision = self._gate(monkeypatch, ["skipped", "refuted"])
        assert decision.channel_outcome == "refuted"


class TestPrepassSkippedLanes:
    """The two refuted-drop lanes in the consistency prepass: a
    skipped verdict is neither dropped-as-refuted nor promoted."""

    _GUARD_SRC = {
        "src/pkt.c": (
            "int sum_0(pkt_t *p, int i) {\n"
            "    if (i < p->count)\n        return p->data[i];\n"
            "    return 0;\n}\n"
            "int sum_1(pkt_t *p, int i) {\n"
            "    if (i < p->count)\n        return p->data[i];\n"
            "    return 0;\n}\n"
            "int sum_2(pkt_t *p, int i) {\n"
            "    if (i < p->count)\n        return p->data[i];\n"
            "    return 0;\n}\n"
            "int sum_dev(pkt_t *p, int i) {\n"
            "    return p->data[i];\n}\n"
        ),
    }

    def _prepass(self, monkeypatch, outcome):
        import core.audit.consistency_verify as cv_mod
        from core.audit.consistency_prepass import run_consistency_prepass

        monkeypatch.setattr(
            cv_mod, "guard_presence_verdict",
            lambda *a, **kw: _channel_stub(outcome),
        )
        return run_consistency_prepass(dict(self._GUARD_SRC))

    @requires_ts("c")
    def test_guard_lane_skipped_not_promoted(self, monkeypatch):
        prepass = self._prepass(monkeypatch, "skipped")
        assert not [
            m for m in prepass["mechanical"]
            if m["detector"] in (
                "guard_presence_deviation", "insufficient_guard_smt",
            )
        ]
        dims = prepass["telemetry"]["dimensions"]
        guard_counts = dims.get("guard-presence", {})
        assert guard_counts.get("skipped", 0) >= 1
        assert guard_counts.get("refuted", 0) == 0

    @requires_ts("c")
    def test_guard_lane_refuted_still_drops(self, monkeypatch):
        prepass = self._prepass(monkeypatch, "refuted")
        assert not [
            m for m in prepass["mechanical"]
            if m["detector"] == "guard_presence_deviation"
        ]
        dims = prepass["telemetry"]["dimensions"]
        assert dims.get("guard-presence", {}).get("refuted", 0) >= 1

    def test_return_check_lane_skipped_not_confirmed(self, monkeypatch):
        import core.audit.consistency_prepass as cp_mod
        from core.audit.consistency_prepass import run_consistency_prepass

        src = {"priv.c": "".join(
            [
                f"int c{i}(void) {{\n"
                f"    if (setuid(1000) != 0) return -1;\n"
                f"    return 0;\n}}\n"
                for i in range(4)
            ]
            + ["int ack(void) {\n    (void)setuid(1000);\n"
               "    return 0;\n}\n"],
        )}
        monkeypatch.setattr(
            cp_mod, "census_verdict",
            lambda *a, **kw: _channel_stub("skipped"),
        )
        prepass = run_consistency_prepass(src)
        # Neither promoted (no finding/lead from the stub) nor
        # dropped-as-refuted (counted under its own key).
        assert prepass["telemetry"]["promotions"] == 0
        dims = prepass["telemetry"]["dimensions"]
        rc = dims.get("return-check", {})
        if rc:
            assert rc.get("refuted", 0) == 0
