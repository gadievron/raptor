"""Tests for core.iris.store — persistent spec storage."""

import logging

from core.evidence import EvidenceTier
from core.iris.assumptions import AssumptionCategory, SafetyAssumption
from core.iris.specs import TaintSpec
from core.iris.store import (
    RoundRecord,
    checklist_sha,
    evict_stale,
    load_assumptions,
    load_specs,
    load_store_metadata,
    merge_specs,
    save_specs,
)


def _make_spec(fn="check_input", file="src/auth.py", role="sanitiser", **kw):
    return TaintSpec(function=fn, file=file, role=role, **kw)


class TestChecksumSha:
    def test_deterministic(self):
        cl = {"files": [
            {"path": "a.py", "sha256": "aaa"},
            {"path": "b.py", "sha256": "bbb"},
        ]}
        assert checklist_sha(cl) == checklist_sha(cl)

    def test_order_independent(self):
        cl1 = {"files": [
            {"path": "a.py", "sha256": "aaa"},
            {"path": "b.py", "sha256": "bbb"},
        ]}
        cl2 = {"files": [
            {"path": "b.py", "sha256": "bbb"},
            {"path": "a.py", "sha256": "aaa"},
        ]}
        assert checklist_sha(cl1) == checklist_sha(cl2)

    def test_sha_change_detected(self):
        cl1 = {"files": [{"path": "a.py", "sha256": "aaa"}]}
        cl2 = {"files": [{"path": "a.py", "sha256": "bbb"}]}
        assert checklist_sha(cl1) != checklist_sha(cl2)

    def test_empty_checklist(self):
        assert checklist_sha({}) == checklist_sha({"files": []})


class TestSaveLoad:
    def test_roundtrip(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        specs = [_make_spec(), _make_spec(fn="eval_query", role="sink")]

        save_specs(run_dir, specs, cl_sha="abc123")
        loaded = load_specs(run_dir)

        assert len(loaded) == 2
        funcs = {s.function for s in loaded}
        assert "check_input" in funcs
        assert "eval_query" in funcs

    def test_empty_store(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert load_specs(run_dir) == []

    def test_metadata_preserved(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        specs = [_make_spec()]

        save_specs(
            run_dir, specs, cl_sha="xyz", round_num=2,
            history=[{"round": 0, "n_specs": 5, "n_confirmed": 3}],
        )
        meta = load_store_metadata(run_dir)

        assert meta["checklist_sha"] == "xyz"
        assert meta["round"] == 2
        assert len(meta["history"]) == 1

    def test_atomic_overwrite(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)

        save_specs(run_dir, [_make_spec(fn="first")])
        save_specs(run_dir, [_make_spec(fn="second")])

        loaded = load_specs(run_dir)
        assert len(loaded) == 1
        assert loaded[0].function == "second"

    def test_source_field_roundtrip(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        specs = [_make_spec(source="llm")]

        save_specs(run_dir, specs)
        loaded = load_specs(run_dir)

        assert loaded[0].source == "llm"


class TestMergeSpecs:
    def test_no_conflict(self):
        a = [_make_spec(fn="a")]
        b = [_make_spec(fn="b")]
        merged = merge_specs(a, b)
        assert len(merged) == 2

    def test_higher_tier_wins(self):
        old = [_make_spec(evidence_tier=EvidenceTier.HEURISTIC)]
        new = [_make_spec(evidence_tier=EvidenceTier.XREF_BACKED)]
        merged = merge_specs(old, new)
        assert len(merged) == 1
        assert merged[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_equal_tier_new_wins(self):
        old = [_make_spec(confidence=0.3)]
        new = [_make_spec(confidence=0.9)]
        merged = merge_specs(old, new)
        assert len(merged) == 1
        assert merged[0].confidence == 0.9

    def test_different_roles_kept(self):
        a = [_make_spec(role="sink")]
        b = [_make_spec(role="sanitiser")]
        merged = merge_specs(a, b)
        assert len(merged) == 2

    def test_old_higher_tier_wins(self):
        """Old XREF_BACKED must survive over new HEURISTIC (old-wins)."""
        old = [_make_spec(
            evidence_tier=EvidenceTier.XREF_BACKED, source="operator_confirmed",
        )]
        new = [_make_spec(
            evidence_tier=EvidenceTier.HEURISTIC, source="llm",
        )]
        merged = merge_specs(old, new)
        assert len(merged) == 1
        assert merged[0].evidence_tier == EvidenceTier.XREF_BACKED
        assert merged[0].source == "operator_confirmed"

    def test_empty_inputs(self):
        assert merge_specs([], []) == []
        specs = [_make_spec()]
        assert merge_specs(specs, []) == specs
        assert merge_specs([], specs) == specs


class TestEvictStale:
    def test_keeps_current_files(self):
        specs = [_make_spec(file="a.py"), _make_spec(fn="b", file="b.py")]
        result = evict_stale(specs, {"a.py", "b.py"})
        assert len(result) == 2

    def test_evicts_missing_files(self):
        specs = [_make_spec(file="a.py"), _make_spec(fn="b", file="gone.py")]
        result = evict_stale(specs, {"a.py"})
        assert len(result) == 1
        assert result[0].file == "a.py"

    def test_keeps_confirmed_despite_missing(self):
        specs = [_make_spec(
            file="gone.py", evidence_tier=EvidenceTier.XREF_BACKED,
        )]
        result = evict_stale(specs, {"a.py"})
        assert len(result) == 1

    def test_evicts_heuristic_when_missing(self):
        specs = [_make_spec(
            file="gone.py", evidence_tier=EvidenceTier.HEURISTIC,
        )]
        result = evict_stale(specs, {"a.py"})
        assert len(result) == 0

    def test_empty_specs(self):
        assert evict_stale([], {"a.py"}) == []


class TestAssumptionStorage:
    def _make_assumption(self, **kw):
        return SafetyAssumption(
            target=kw.get("target", "modify_state"),
            file=kw.get("file", "src/state.c"),
            assumption="requires enforcer",
            category=AssumptionCategory.ORDERING,
            enforced_by=kw.get("enforced_by", ["acquire_lock"]),
            evidence_tier=kw.get("evidence_tier", EvidenceTier.HEURISTIC),
        )

    def test_roundtrip(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        specs = [_make_spec()]
        assumptions = [self._make_assumption(), self._make_assumption(target="exec_query")]

        save_specs(run_dir, specs, assumptions=assumptions)
        loaded = load_assumptions(run_dir)

        assert len(loaded) == 2
        targets = {a.target for a in loaded}
        assert targets == {"modify_state", "exec_query"}

    def test_empty_when_no_assumptions(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [_make_spec()])
        loaded = load_assumptions(run_dir)
        assert loaded == []

    def test_empty_when_no_store(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert load_assumptions(run_dir) == []

    def test_target_path_filter(self, tmp_path):
        from pathlib import Path
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(
            run_dir, [_make_spec()],
            assumptions=[self._make_assumption()],
            target_path=Path("/repo/a"),
        )
        assert len(load_assumptions(run_dir, target_path=Path("/repo/a"))) == 1
        assert load_assumptions(run_dir, target_path=Path("/repo/b")) == []

    def test_assumptions_in_metadata(self, tmp_path):
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [], assumptions=[self._make_assumption()])
        meta = load_store_metadata(run_dir)
        assert len(meta["assumptions"]) == 1
        assert meta["assumptions"][0]["target"] == "modify_state"


class TestTargetMismatchLogging:
    """``load_assumptions`` logs a debug skip line when the stored
    target differs from the requested one — parity with the
    ``load_specs`` sibling."""

    def _save_for_target_a(self, run_dir):
        from pathlib import Path
        save_specs(
            run_dir, [_make_spec()],
            assumptions=[SafetyAssumption(
                target="modify_state",
                file="src/state.py",
                assumption="lock must be held",
                category=AssumptionCategory.ORDERING,
                enforced_by=["acquire_lock"],
            )],
            target_path=Path("/repo/a"),
        )

    def test_load_assumptions_logs_skip_on_mismatch(self, tmp_path, caplog):
        from pathlib import Path
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        self._save_for_target_a(run_dir)

        with caplog.at_level(logging.DEBUG, logger="core.iris.store"):
            result = load_assumptions(run_dir, target_path=Path("/repo/b"))

        assert result == []
        assert any(
            "skipping assumptions for different target" in r.message
            for r in caplog.records
        )

    def test_load_assumptions_no_skip_log_on_match(self, tmp_path, caplog):
        from pathlib import Path
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        self._save_for_target_a(run_dir)

        with caplog.at_level(logging.DEBUG, logger="core.iris.store"):
            result = load_assumptions(run_dir, target_path=Path("/repo/a"))

        assert len(result) == 1
        assert not any(
            "skipping assumptions" in r.message for r in caplog.records
        )

    def test_load_specs_sibling_still_logs(self, tmp_path, caplog):
        from pathlib import Path
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        self._save_for_target_a(run_dir)

        with caplog.at_level(logging.DEBUG, logger="core.iris.store"):
            result = load_specs(run_dir, target_path=Path("/repo/b"))

        assert result == []
        assert any(
            "skipping specs for different target" in r.message
            for r in caplog.records
        )


class TestRoundRecord:
    def test_fields(self):
        r = RoundRecord(round=0, n_specs=10, n_confirmed=7, n_refuted=2)
        assert r.round == 0
        assert r.n_specs == 10


class TestLoadRefinedSpecs:
    """Run-local refined-artifact reader (refine-loop continuity)."""

    def _write_artifact(self, run_dir, specs):
        import json

        payload = json.dumps([s.to_dict() for s in specs], indent=2)
        (run_dir / "iris-taint-specs-refined.json").write_text(payload)

    def test_round_trip_preserves_tier_and_source(self, tmp_path):
        from core.iris.store import load_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        self._write_artifact(run_dir, [
            _make_spec(fn="confirmed", role="sanitiser",
                       evidence_tier=EvidenceTier.XREF_BACKED,
                       source="operator_confirmed"),
            _make_spec(fn="guessy", role="sink",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        loaded = load_refined_specs(run_dir)
        by_fn = {s.function: s for s in loaded}
        assert by_fn["confirmed"].evidence_tier == EvidenceTier.XREF_BACKED
        assert by_fn["confirmed"].source == "operator_confirmed"
        assert by_fn["guessy"].evidence_tier == EvidenceTier.HEURISTIC

    def test_missing_artifact_empty(self, tmp_path):
        from core.iris.store import load_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert load_refined_specs(run_dir) == []

    def test_malformed_artifact_empty(self, tmp_path):
        from core.iris.store import load_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        (run_dir / "iris-taint-specs-refined.json").write_text("{not json")
        assert load_refined_specs(run_dir) == []
        (run_dir / "iris-taint-specs-refined.json").write_text('{"a": 1}')
        assert load_refined_specs(run_dir) == []

    def test_unknown_tier_degrades_to_heuristic_never_up(self, tmp_path):
        import json

        from core.iris.store import load_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        (run_dir / "iris-taint-specs-refined.json").write_text(json.dumps([
            {"function": "f", "file": "a.py", "role": "sanitiser",
             "evidence_tier": "totally_made_up_tier"},
        ]))
        loaded = load_refined_specs(run_dir)
        assert loaded[0].evidence_tier == EvidenceTier.HEURISTIC


class TestPersistRefinedSpecs:
    """Caller-persist step: store merge + envelope-metadata preservation."""

    def test_merges_into_empty_store(self, tmp_path):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        dest = persist_refined_specs(run_dir, [
            _make_spec(fn="new_sani", role="sanitiser"),
        ])
        assert dest is not None
        loaded = load_specs(run_dir)
        assert [s.function for s in loaded] == ["new_sani"]

    def test_merge_keeps_higher_tier(self, tmp_path):
        """A tool-confirmed store spec survives a heuristic re-refine."""
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="sani", role="sanitiser",
                       evidence_tier=EvidenceTier.XREF_BACKED),
        ])
        persist_refined_specs(run_dir, [
            _make_spec(fn="sani", role="sanitiser",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ])
        loaded = load_specs(run_dir)
        assert loaded[0].evidence_tier == EvidenceTier.XREF_BACKED

    def test_preserves_envelope_metadata(self, tmp_path):
        from pathlib import Path

        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(
            run_dir,
            [_make_spec(fn="old_spec", role="sink")],
            cl_sha="abc123",
            round_num=2,
            history=[{"round": 0, "n_specs": 1}, {"round": 1, "n_specs": 1}],
            target_path=Path("/repo/a"),
            assumptions=[SafetyAssumption(
                target="old_spec", file="src/auth.py",
                assumption="requires check",
                category=AssumptionCategory.ORDERING,
                enforced_by=["check"],
            )],
        )
        persist_refined_specs(
            run_dir,
            [_make_spec(fn="refined_spec", role="sanitiser")],
            history=[{"round": 0, "n_specs": 2}],
        )
        meta = load_store_metadata(run_dir)
        # checklist_sha kept when caller passes none
        assert meta["checklist_sha"] == "abc123"
        # prior history preserved, new round appended
        assert len(meta["history"]) == 3
        # target path preserved
        assert meta["target_path"] == str(Path("/repo/a").resolve())
        # stored assumptions preserved
        assert len(meta["assumptions"]) == 1
        # both specs present after merge
        fns = {s.function for s in load_specs(run_dir)}
        assert fns == {"old_spec", "refined_spec"}

    def test_cross_target_guard(self, tmp_path):
        from pathlib import Path

        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [_make_spec(fn="theirs")],
                   target_path=Path("/repo/a"))
        dest = persist_refined_specs(
            run_dir, [_make_spec(fn="mine")],
            target_path=Path("/repo/b"),
        )
        assert dest is None
        assert {s.function for s in load_specs(run_dir)} == {"theirs"}

    def test_empty_refined_is_noop(self, tmp_path):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        assert persist_refined_specs(run_dir, []) is None
        assert load_specs(run_dir) == []


class TestPersistZeroSignalGate:
    """A run whose every refinement round was zero-signal (aborted:
    evaluation attempted, nothing succeeded) must leave the shared
    store exactly as it was."""

    @staticmethod
    def _aborted_round(n=0):
        return {
            "round": n, "n_specs": 3, "n_confirmed": 0, "n_refuted": 0,
            "n_errors": 3, "aborted": True,
        }

    def test_all_aborted_rounds_refuse_persist(self, tmp_path, caplog):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        store_path = save_specs(
            run_dir, [_make_spec(fn="prior", role="sink")], cl_sha="seed",
        )
        before = store_path.read_text(encoding="utf-8")

        with caplog.at_level(logging.WARNING, logger="core.iris.store"):
            dest = persist_refined_specs(
                run_dir,
                [_make_spec(fn="zero_signal_junk", role="sink")],
                history=[self._aborted_round(0), self._aborted_round(1)],
            )

        assert dest is None
        assert store_path.read_text(encoding="utf-8") == before
        assert any(
            "zero-signal" in r.message and "store" in r.message
            for r in caplog.records
        )

    def test_one_healthy_round_persists(self, tmp_path):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        dest = persist_refined_specs(
            run_dir, [_make_spec(fn="real", role="sink")],
            history=[
                {"round": 0, "n_specs": 1, "n_confirmed": 1,
                 "aborted": False},
                self._aborted_round(1),
            ],
        )
        assert dest is not None
        assert {s.function for s in load_specs(run_dir)} == {"real"}

    def test_empty_history_persists(self, tmp_path):
        """Synthesis-only runs (no refinement rounds) keep persisting."""
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        dest = persist_refined_specs(
            run_dir, [_make_spec(fn="synth_only")], history=[],
        )
        assert dest is not None

    def test_legacy_history_without_aborted_key_persists(self, tmp_path):
        """Round dicts from before the flag existed persist as before."""
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        dest = persist_refined_specs(
            run_dir, [_make_spec(fn="legacy")],
            history=[{"round": 0, "n_specs": 1, "n_confirmed": 0}],
        )
        assert dest is not None

    def test_zero_confirmations_evaluated_round_persists(self, tmp_path):
        """'Evaluated and found 0 true positives' is a legitimate
        result — only 'could not evaluate anything' is gated."""
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        dest = persist_refined_specs(
            run_dir, [_make_spec(fn="no_tp")],
            history=[{"round": 0, "n_specs": 1, "n_confirmed": 0,
                      "n_refuted": 0, "aborted": False}],
        )
        assert dest is not None


class TestRefutedDropAtMerge:
    """Refuted specs must not resurrect from the add/upgrade-only
    store merge on the next run."""

    @staticmethod
    def _history(refuted=(), confirmed=(), rnd=0):
        return [{
            "round": rnd, "n_specs": 1,
            "refuted_keys": list(refuted),
            "confirmed_keys": list(confirmed),
        }]

    @staticmethod
    def _key(spec):
        from core.iris.store import _spec_key
        return _spec_key(spec)

    def test_refuted_heuristic_store_spec_dropped(self, tmp_path):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        ghost = _make_spec(fn="hallucinated_sink", role="sink",
                           evidence_tier=EvidenceTier.HEURISTIC)
        save_specs(run_dir, [ghost])
        persist_refined_specs(
            run_dir,
            [_make_spec(fn="other", role="sanitiser")],
            history=self._history(refuted=[self._key(ghost)]),
        )
        loaded = load_specs(run_dir)
        assert "hallucinated_sink" not in {s.function for s in loaded}
        assert "other" in {s.function for s in loaded}

    def test_refuted_tool_confirmed_spec_kept(self, tmp_path):
        """>= XREF_BACKED survives one refuted round — mirrors
        refine's _demote_refuted floor."""
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        confirmed = _make_spec(fn="real_sink", role="sink",
                               evidence_tier=EvidenceTier.XREF_BACKED)
        save_specs(run_dir, [confirmed])
        persist_refined_specs(
            run_dir,
            [_make_spec(fn="other", role="sanitiser")],
            history=self._history(refuted=[self._key(confirmed)]),
        )
        loaded = load_specs(run_dir)
        assert "real_sink" in {s.function for s in loaded}

    def test_later_confirmation_clears_refutation(self, tmp_path):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        spec = _make_spec(fn="flaky", role="sink",
                          evidence_tier=EvidenceTier.HEURISTIC)
        save_specs(run_dir, [spec])
        history = (
            self._history(refuted=[self._key(spec)], rnd=0)
            + self._history(confirmed=[self._key(spec)], rnd=1)
        )
        persist_refined_specs(
            run_dir, [_make_spec(fn="other", role="sanitiser")],
            history=history,
        )
        loaded = load_specs(run_dir)
        assert "flaky" in {s.function for s in loaded}

    def test_operator_confirmed_never_dropped(self, tmp_path):
        from core.iris.store import persist_refined_specs

        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        op = _make_spec(fn="op_sink", role="sink",
                        evidence_tier=EvidenceTier.HEURISTIC,
                        source="operator_confirmed")
        save_specs(run_dir, [op])
        persist_refined_specs(
            run_dir, [_make_spec(fn="other", role="sanitiser")],
            history=self._history(refuted=[self._key(op)]),
        )
        loaded = load_specs(run_dir)
        assert "op_sink" in {s.function for s in loaded}


class TestPersistEvictsStale:
    """persist_refined_specs evicts specs whose file vanished from
    the target tree (evict_stale finally has a persistence caller)."""

    def test_vanished_file_spec_evicted(self, tmp_path):
        from core.iris.store import persist_refined_specs

        target = tmp_path / "repo"
        (target / "src").mkdir(parents=True)
        (target / "src" / "auth.py").write_text("def f(): pass\n")
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="gone", file="src/deleted.py", role="sink",
                       evidence_tier=EvidenceTier.HEURISTIC),
        ], target_path=target)
        persist_refined_specs(
            run_dir,
            [_make_spec(fn="live", file="src/auth.py", role="sanitiser")],
            target_path=target,
        )
        loaded = load_specs(run_dir)
        names = {s.function for s in loaded}
        assert "live" in names
        assert "gone" not in names

    def test_vanished_but_tool_confirmed_kept(self, tmp_path):
        from core.iris.store import persist_refined_specs

        target = tmp_path / "repo"
        (target / "src").mkdir(parents=True)
        (target / "src" / "auth.py").write_text("def f(): pass\n")
        run_dir = tmp_path / "project" / "run_001"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            _make_spec(fn="renamed", file="src/old_name.py", role="sink",
                       evidence_tier=EvidenceTier.XREF_BACKED),
        ], target_path=target)
        persist_refined_specs(
            run_dir,
            [_make_spec(fn="live", file="src/auth.py", role="sanitiser")],
            target_path=target,
        )
        loaded = load_specs(run_dir)
        assert "renamed" in {s.function for s in loaded}
