"""Coccinelle lookahead prewarm: caller-side memo pinning.

Covers the rent-to-buy trigger, chunk construction (parent-directory
cwd parity), verdict pinning parity with run_coccinelle_file_sweep's
result shape and memo key, the pin-nothing stance on failed batches,
per-run state isolation, the advisory (never-raise) contract, and the
two-direction pins on the module's caps.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import packages.coccinelle.runner as cocci_runner
from core.audit.cocci_prewarm import (
    LOOKAHEAD_CHUNKS,
    TRIGGER_DISTINCT_FILES,
    maybe_prewarm,
)
from core.audit.sweep_memo import MAX_MEMO_ENTRIES, SweepMemo, hash_file
from packages.coccinelle.models import SpatchMatch, SpatchResult
from packages.coccinelle.runner import (
    BATCH_CHUNK_FILES,
    derive_batch_timeout_s,
    derive_batch_workers,
)


class _Cfg:
    """Minimal OrchestratorConfig stand-in for the prewarm reads."""

    def __init__(self, memo: SweepMemo | None, inventory: dict) -> None:
        self.sweep_memo = memo
        self.inventory = inventory


def _tree(tmp_path: Path, rel_paths: list[str]) -> Path:
    root = tmp_path / "target"
    for rel in rel_paths:
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("void f() { malloc(4); }\n")
    return root


def _inventory(rel_paths: list[str]) -> dict:
    return {"files": [{"path": p} for p in rel_paths]}


def _leg_key(root: Path, rule_hash: str, fp: str) -> tuple | None:
    """The exact key the orchestrator's coccinelle leg constructs."""
    return SweepMemo.make_key("coccinelle", {
        "rule": rule_hash,
        "file": hash_file(root / fp),
        "path": fp,
        "defines": "",
    })


def _stub_run_rule(calls: list[dict[str, Any]], hit_names: set[str]):
    """run_rule stand-in: records the invocation, matches hit_names."""

    def run_rule(target, rule, *, file_set=None, defines=None,
                 timeout=300, allow_scripting=False, **kw):
        calls.append({
            "target": Path(target),
            "rule": str(rule),
            "file_set": list(file_set or []),
            "defines": defines,
            "timeout": timeout,
            "allow_scripting": allow_scripting,
        })
        matches = [
            SpatchMatch(file=str(f), line=5, rule="r")
            for f in (file_set or []) if f.name in hit_names
        ]
        return SpatchResult(
            rule="r", rule_path=str(rule), matches=matches,
            files_examined=[str(f) for f in (file_set or [])],
            returncode=0,
        )

    return run_rule


def _dispatch(cfg, root: Path, rule: Path, fps: list[str],
              rule_hash: str = "rh",
              exec_rule: Path | None = None) -> None:
    for fp in fps:
        maybe_prewarm(
            cfg,
            effective_target=root,
            file_path=fp,
            rule_source=str(rule),
            exec_rule=str(exec_rule if exec_rule is not None else rule),
            rule_hash=rule_hash,
        )


class TestTrigger:
    def test_below_trigger_runs_nothing(self, tmp_path, monkeypatch):
        rels = [f"src/f{i}.c" for i in range(10)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES - 1])
        assert calls == []

    def test_trigger_fires_burst(self, tmp_path, monkeypatch):
        rels = [f"src/f{i}.c" for i in range(10)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES])
        assert calls, "third distinct file must fire the burst"

    def test_repeat_dispatch_of_same_file_never_counts_twice(
        self, tmp_path, monkeypatch,
    ):
        # The leg dispatches once per FUNCTION; many functions share a
        # file. Only distinct files may advance the trigger.
        rels = [f"src/f{i}.c" for i in range(10)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg, root, rule, [rels[0]] * 10)
        assert calls == []

    def test_no_memo_or_no_hash_is_noop(self, tmp_path, monkeypatch):
        rels = [f"src/f{i}.c" for i in range(6)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("x")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))

        _dispatch(_Cfg(None, _inventory(rels)), root, rule, rels)
        for fp in rels:
            maybe_prewarm(
                _Cfg(SweepMemo(), _inventory(rels)),
                effective_target=root, file_path=fp,
                rule_source=str(rule), exec_rule=str(rule),
                rule_hash=None,
            )
        assert calls == []


class TestBatchShape:
    def test_parity_target_is_parent_dir_and_spelling_matches(
        self, tmp_path, monkeypatch,
    ):
        rels = [f"src/f{i}.c" for i in range(6)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES])
        assert len(calls) == 1
        call = calls[0]
        # cwd parity with single-file mode: run_rule gets the files'
        # parent directory as target.
        assert call["target"] == root / "src"
        # Argv spelling parity: exactly target_path / file_path, so
        # match dicts carry the same file field the serial sweep
        # would record.
        assert call["file_set"] == [root / fp for fp in rels]
        # Trust/config parity with run_coccinelle_file_sweep.
        assert call["allow_scripting"] is True
        assert call["defines"] == {}
        assert call["timeout"] == derive_batch_timeout_s(120, len(rels))
        # The exec rule (rendered tempfile in production) is what runs.
        assert call["rule"] == str(rule)

    def test_chunks_split_per_parent_directory(
        self, tmp_path, monkeypatch,
    ):
        rels = ["a/one.c", "a/two.c", "a/three.c", "b/four.c",
                "b/five.c"]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES])
        targets = sorted(str(c["target"]) for c in calls)
        assert targets == [str(root / "a"), str(root / "b")]
        for c in calls:
            parents = {f.parent for f in c["file_set"]}
            assert len(parents) == 1

    def test_missing_files_excluded_from_batch(
        self, tmp_path, monkeypatch,
    ):
        rels = ["src/a.c", "src/b.c", "src/c.c", "src/gone.c"]
        root = _tree(tmp_path, rels[:3])  # gone.c never created
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES])
        batched = {f.name for c in calls for f in c["file_set"]}
        assert "gone.c" not in batched

    def test_escaping_symlink_excluded_from_batch(
        self, tmp_path, monkeypatch,
    ):
        # Containment parity with the serial gate (safe_join, which
        # RESOLVES symlinks): an in-tree symlink pointing outside the
        # root passes every lexical check and is a regular file when
        # followed — but the serial sweep refuses it with "path
        # escapes target", so prewarm must never batch it (under a
        # degraded sandbox tier the batch would read the out-of-tree
        # content and pin a verdict the serial gate never computes).
        rels = ["src/a.c", "src/b.c", "src/c.c", "src/link.c"]
        root = _tree(tmp_path, rels[:3])
        outside = tmp_path / "outside.c"
        outside.write_text("void h() { malloc(8); }\n")
        (root / "src" / "link.c").symlink_to(outside)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        memo = SweepMemo()
        cfg = _Cfg(memo, _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES])
        assert calls, "the in-root files must still be batched"
        batched = {f.name for c in calls for f in c["file_set"]}
        assert "link.c" not in batched
        assert memo.get(_leg_key(root, "rh", "src/link.c")) is None

    def test_chunk_cap_binds_exactly_at_batch_chunk_files(
        self, tmp_path, monkeypatch,
    ):
        # _build_chunks is the ONLY enforcement point of the batch
        # size cap (run_rule accepts any file_set length), and the
        # burst's blast-radius/timeout rationale assumes no chunk
        # exceeds it: BATCH_CHUNK_FILES+1 same-directory files must
        # split exactly (cap, 1) — not ride as one oversized batch.
        rels = [f"src/f{i:03d}.c" for i in range(BATCH_CHUNK_FILES + 1)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES])
        sizes = sorted(len(c["file_set"]) for c in calls)
        assert sizes == [1, BATCH_CHUNK_FILES]


class TestPinning:
    def test_pins_leg_shaped_results_under_leg_shaped_keys(
        self, tmp_path, monkeypatch,
    ):
        rels = ["src/hit.c", "src/quiet.c", "src/also.c"]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, {"hit.c"}))
        memo = SweepMemo()
        cfg = _Cfg(memo, _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES])

        hit = memo.get(_leg_key(root, "rh", "src/hit.c"))
        assert hit is not None
        assert hit.tool == "coccinelle"
        assert hit.outcome == "confirmed"
        assert hit.function_name == ""  # file scope
        assert hit.rule_id == str(rule)
        assert hit.matches and isinstance(hit.matches[0], dict)
        assert hit.matches[0]["file"] == str(root / "src/hit.c")
        assert hit.matches[0]["line"] == 5

        quiet = memo.get(_leg_key(root, "rh", "src/quiet.c"))
        assert quiet is not None
        assert quiet.outcome == "refuted"
        assert quiet.matches == []

    def test_rule_id_is_source_rule_even_when_exec_rule_differs(
        self, tmp_path, monkeypatch,
    ):
        # In production exec_rule is the leg's rendered TEMPFILE,
        # unlinked in the leg's finally after the step — a pinned
        # rule_id naming it would poison every later memo hit. The
        # dispatch here passes an exec rule at a DIFFERENT path (same
        # content) so the source/exec routing is observable: the exec
        # rule must be what RUNS, the source rule must be what is
        # PINNED.
        rels = ["src/a.c", "src/b.c", "src/c.c"]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        rendered = tmp_path / "rendered" / "r.cocci"
        rendered.parent.mkdir()
        rendered.write_text(rule.read_text())
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        memo = SweepMemo()
        cfg = _Cfg(memo, _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES],
                  exec_rule=rendered)

        assert calls, "burst must have fired"
        for c in calls:
            assert c["rule"] == str(rendered)
        for fp in rels:
            pinned = memo.get(_leg_key(root, "rh", fp))
            assert pinned is not None
            assert pinned.rule_id == str(rule)
            assert pinned.rule_id != str(rendered)

    def test_failed_batch_pins_nothing(self, tmp_path, monkeypatch):
        rels = [f"src/f{i}.c" for i in range(5)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")

        def _boom(target, rule, *, file_set=None, **kw):
            return SpatchResult(
                rule="r", rule_path=str(rule),
                errors=["Fatal error: oom"], returncode=2,
            )

        monkeypatch.setattr(cocci_runner, "run_rule", _boom)
        memo = SweepMemo()
        cfg = _Cfg(memo, _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES])
        for fp in rels:
            assert memo.get(_leg_key(root, "rh", fp)) is None

    def test_warmed_window_not_rerun(self, tmp_path, monkeypatch):
        rels = [f"src/f{i}.c" for i in range(10)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg, root, rule, rels)  # every file dispatched
        # One dir, 10 files, one chunk: exactly one batch ever runs —
        # the pinned/warmed bookkeeping absorbs the later dispatches.
        assert len(calls) == 1

    def test_state_isolated_per_memo_instance(
        self, tmp_path, monkeypatch,
    ):
        # Two runs (two memos) never pool their trigger counts.
        # The dispatches are DISJOINT and trigger-straddling: pooled
        # state would see TRIGGER_DISTINCT_FILES distinct files and
        # fire a burst; isolated state sees TRIGGER-1 and 1 and stays
        # silent — so the assertion distinguishes shared from
        # isolated on its own, without relying on any other test's
        # state.
        rels = [f"src/f{i}.c" for i in range(6)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        calls: list[dict] = []
        monkeypatch.setattr(
            cocci_runner, "run_rule", _stub_run_rule(calls, set()))
        cfg_a = _Cfg(SweepMemo(), _inventory(rels))
        cfg_b = _Cfg(SweepMemo(), _inventory(rels))

        _dispatch(cfg_a, root, rule,
                  rels[:TRIGGER_DISTINCT_FILES - 1])
        _dispatch(cfg_b, root, rule,
                  [rels[TRIGGER_DISTINCT_FILES - 1]])
        assert calls == []


class TestAdvisoryContract:
    def test_run_rule_raising_never_escapes(self, tmp_path, monkeypatch):
        rels = [f"src/f{i}.c" for i in range(5)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")

        def _raise(*a, **kw):
            raise RuntimeError("spatch exploded")

        monkeypatch.setattr(cocci_runner, "run_rule", _raise)
        memo = SweepMemo()
        cfg = _Cfg(memo, _inventory(rels))

        _dispatch(cfg, root, rule, rels)  # must not raise
        for fp in rels:
            assert memo.get(_leg_key(root, "rh", fp)) is None

    def test_hostile_inventory_shape_never_escapes(self, tmp_path):
        root = _tree(tmp_path, ["src/a.c"])
        rule = tmp_path / "r.cocci"
        rule.write_text("x")
        cfg = _Cfg(SweepMemo(), {"files": [None, 42, {"path": 3}]})
        for i in range(5):
            maybe_prewarm(
                cfg, effective_target=root, file_path=f"src/f{i}.c",
                rule_source=str(rule), exec_rule=str(rule),
                rule_hash="rh",
            )  # must not raise


class TestCapPins:
    """Two-direction pins: each bound encodes a failure mode; moving
    one requires re-arguing the OTHER direction too."""

    def test_trigger_floor_no_single_dispatch_burst(self):
        # A rule probed against one or two files (targeted re-check)
        # must never pay for a lookahead window it won't consume.
        assert TRIGGER_DISTINCT_FILES >= 2

    def test_trigger_ceiling_engages_early_on_real_sweeps(self):
        # Too high and the serial floor persists deep into the pass
        # before batching starts paying.
        assert TRIGGER_DISTINCT_FILES <= 8

    def test_lookahead_floor_fills_the_worker_pool(self):
        # Fewer chunks per burst than the pool has lanes leaves lanes
        # idle and makes bursts (each with pool spin-up) more frequent.
        assert LOOKAHEAD_CHUNKS >= derive_batch_workers(1024)

    def test_lookahead_ceiling_stays_inside_the_shared_memo_window(self):
        # A burst pins up to LOOKAHEAD_CHUNKS x BATCH_CHUNK_FILES
        # entries into a 1024-entry LRU shared with the other sweep
        # legs; more than half the window per burst starts evicting
        # entries before the serial cursor consumes them.
        assert LOOKAHEAD_CHUNKS * BATCH_CHUNK_FILES <= MAX_MEMO_ENTRIES // 2


class TestOrchestratorLegIntegration:
    """Drive the REAL orchestrator coccinelle leg (_run_tool_chain)
    with an inventory-carrying config and prove the memoized step HITS
    prewarm's pins: after the trigger fires, later files are served
    from the batch — no further single-file spatch spawns — and the
    hook's argument routing (file-path spelling, rendered exec rule,
    rule-hash identity) is pinned by the hit itself, not by a unit
    test restating the contract."""

    _VOCAB_RULE = (
        "@r@ expression E; @@\n"
        "// @vocab: deallocators\n"
        "* \\(kfree\\|free\\)(E)\n"
    )

    class _LegCfg:
        def __init__(self, target: Path, inventory: dict) -> None:
            self.target_path = target
            self.out_dir = None
            self.codeql_db_path = None
            self.project_sinks = None
            self.sweep_memo = SweepMemo()
            self.inventory = inventory

    def test_memoized_step_hits_prewarm_pins(
        self, tmp_path, monkeypatch,
    ):
        from types import SimpleNamespace

        from core.audit.orchestrator import _run_tool_chain
        from core.audit.substrate import _reset_substrate_caches

        _reset_substrate_caches()
        rels = [f"src/f{i}.c" for i in range(4)]
        root = _tree(tmp_path, rels)
        rule = tmp_path / "rules" / "check.cocci"
        rule.parent.mkdir()
        rule.write_text(self._VOCAB_RULE)
        vocab = SimpleNamespace(deallocators=frozenset({"my_free"}))

        calls: list[dict[str, Any]] = []

        def _run_rule(target, rule_path, *, file_set=None,
                      defines=None, timeout=300,
                      allow_scripting=False, **kw):
            rule_text = Path(rule_path).read_text()
            calls.append({
                "target": Path(target),
                "rule": str(rule_path),
                "rule_text": rule_text,
                "file_set": list(file_set) if file_set else None,
            })
            files = file_set if file_set else [Path(target)]
            return SpatchResult(
                rule="r", rule_path=str(rule_path),
                matches=[
                    SpatchMatch(file=str(f), line=2, rule="r")
                    for f in files
                ],
                files_examined=[str(f) for f in files],
                returncode=0,
            )

        monkeypatch.setattr(cocci_runner, "is_available", lambda: True)
        monkeypatch.setattr(cocci_runner, "run_rule", _run_rule)
        cfg = self._LegCfg(root, _inventory(rels))

        confirmed = [
            _run_tool_chain(
                [{"type": "coccinelle", "config": {"rule": str(rule)}}],
                config=cfg,
                file_path=fp,
                function_name=f"fn{i}",
                source="",
                hypothesis="use after free of `p`",
                line_start=1,
                domain_vocab=vocab,
                skipped_types=None,
            )
            for i, fp in enumerate(rels)
        ]

        # Every dispatch got its verdict — the last two from the pins.
        assert confirmed == [["coccinelle:check"]] * 4

        single = [c for c in calls if c["file_set"] is None]
        batch = [c for c in calls if c["file_set"] is not None]
        # Pre-trigger files ran serially; from the trigger file on,
        # the memoized step must HIT the prewarm pin — a single-file
        # spawn for f2.c or f3.c means the hook's file path / rule
        # hash never matched the leg's own memo key.
        assert [Path(c["target"]).name for c in single] == \
            ["f0.c", "f1.c"]
        assert len(batch) == 1
        assert {f.name for f in batch[0]["file_set"]} == \
            {"f0.c", "f1.c", "f2.c", "f3.c"}
        # The batch ran the leg's RENDERED rule (vocabulary spliced),
        # not the source path — the hook routes exec_rule/rule_source
        # correctly on the real call site.
        assert batch[0]["rule"] != str(rule)
        assert "my_free" in batch[0]["rule_text"]


class TestLiveSpatchParity:
    """The strongest pinning guarantee: on a real spatch, a prewarmed
    memo entry is field-for-field what run_coccinelle_file_sweep
    computes for the same (rule, file) — verdict, match dicts (argv
    path spelling included), rule identity, scope."""

    def test_pinned_equals_serial_sweep(self, tmp_path):
        import pytest

        from core.audit.sweep import run_coccinelle_file_sweep
        from core.audit.sweep_memo import hash_file as _hash_file
        from packages.coccinelle.runner import is_available

        if not is_available():
            pytest.skip("spatch not installed")

        rels = ["src/hit.c", "src/quiet.c", "src/third.c"]
        root = _tree(tmp_path, rels)
        (root / "src/quiet.c").write_text("void g() { free(0); }\n")
        rule = tmp_path / "r.cocci"
        rule.write_text("@r@\nposition p;\n@@\nmalloc@p(...)\n")
        rule_hash = _hash_file(rule)
        assert rule_hash is not None
        memo = SweepMemo()
        cfg = _Cfg(memo, _inventory(rels))

        _dispatch(cfg, root, rule, rels[:TRIGGER_DISTINCT_FILES],
                  rule_hash=rule_hash)

        for fp in rels:
            pinned = memo.get(_leg_key(root, rule_hash, fp))
            assert pinned is not None, f"{fp} not pinned"
            serial = run_coccinelle_file_sweep(
                target_path=root, file_path=fp, cocci_rule=str(rule),
            )
            assert pinned.tool == serial.tool
            assert pinned.file_path == serial.file_path
            assert pinned.function_name == serial.function_name
            assert pinned.outcome == serial.outcome
            assert pinned.matches == serial.matches
            assert pinned.rule_id == serial.rule_id
            assert pinned.errors == serial.errors

        assert memo.get(
            _leg_key(root, rule_hash, "src/hit.c"),
        ).outcome == "confirmed"
        assert memo.get(
            _leg_key(root, rule_hash, "src/quiet.c"),
        ).outcome == "refuted"
