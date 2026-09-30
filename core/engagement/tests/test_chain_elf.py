"""Tests for the ELF per-artifact chain (``core.engagement.chain_elf``).

Every child invocation is intercepted at the module's single
subprocess seam (``_run_child``) with a fake that writes exactly the
completion artifacts the real tools write — the battery proves the
SEQUENCING layer (stage order, handoff paths, resume judgement,
ledger write-back, verdict schema) without spawning Ghidra, audits,
or LLMs. Both directions throughout: every gate is exercised with the
condition present AND absent.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from core.coverage.journal import ReviewJournalEntry, append_entry
from core.engagement import chain_elf
from core.engagement import ledger as ledger_mod
from core.engagement.chain_elf import (
    RC_FAILED,
    RC_NOTHING,
    RC_OK,
    RC_USAGE,
    STAGES,
    SURVIVORS_FILENAME,
    VERDICT_SCHEMA,
    StageOutcome,
    build_verdict,
    chain_dir_for,
    load_chain_state,
    resolve_policy_depth,
    run_all_pending,
    run_chain,
)
from core.engagement.ledger import (
    checklist_slot_path,
    load_ledger,
    read_artifact_checklist,
)
from core.hash import sha256_file
from core.json import load_json, save_json

ART = "sha256-aabbccdd"


# ── fixtures ─────────────────────────────────────────────────────────

def _make_target(tmp_path: Path,
                 content: bytes = b"\x7fELF-fake") -> Path:
    root = tmp_path / "install"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "app").write_bytes(content)
    return root


def _elf_row(root: Path, rel: str = "bin/app",
             **over: Any) -> dict[str, Any]:
    sha = sha256_file(root / rel)
    row: dict[str, Any] = {
        "artifact_id": ART,
        "class": "elf-linux",
        "format_tier": "full",
        "path": rel,
        "size": (root / rel).stat().st_size,
        "identity": {"kind": "sha256", "value": sha,
                     "anchor": sha[:16], "sha256": sha},
        "status": {"state": "inventoried",
                   "updated_at": "2026-01-01T00:00:00+00:00"},
    }
    row.update(over)
    return row


def _make_ledger(out: Path, root: Path,
                 rows: list[dict[str, Any]]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    save_json(out / ledger_mod.LEDGER_FILENAME, {
        "schema_version": 1,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "target_root": str(root),
        "rows": rows,
    })


def _journal_row(file: str, function: str,
                 verdict: str) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts="2026-01-01T00:00:00+00:00", run_id="test",
        file=file, function=function, verdict=verdict,
        source_hash="d" * 12)


#: Real audits journal a verdict row per reviewed function — the
#: default fake audit does the same (one clean row), so chains that
#: should attest meet the earned-coverage floor exactly as real runs
#: do. Tests pass explicit verdicts to override.
_DEFAULT_AUDIT_VERDICTS = (("binary:app", "main", "clean"),)


class FakeRunner:
    """Stands in for ``_run_child`` — writes the completion artifacts
    the real children write, per configured behavior.

    ``audit_verdicts`` are journalled by the FIRST audit run;
    ``rereview_verdicts`` by any subsequent audit run (the seed
    re-review) — letting tests place rows in exactly one journal."""

    def __init__(self, *, fail: dict[str, int] | None = None,
                 seeds: bool = False,
                 audit_verdicts: tuple[tuple[str, str, str], ...]
                 = _DEFAULT_AUDIT_VERDICTS,
                 rereview_verdicts: tuple[tuple[str, str, str], ...]
                 = (),
                 redb_bytes: int = 64) -> None:
        self.fail = fail or {}
        self.seeds = seeds
        self.audit_verdicts = list(audit_verdicts)
        self.rereview_verdicts = list(rereview_verdicts)
        self.audit_runs = 0
        self.redb_bytes = redb_bytes
        self.calls: list[list[str]] = []

    def _tool(self, cmd: list[str]) -> str:
        name = Path(cmd[1]).name
        if name == "raptor-binary":
            return f"{name} {cmd[2]}"
        return name

    def __call__(self, cmd: list[str], *, llm: bool = False,
                 timeout_s: int = 0) -> int:
        self.calls.append([str(c) for c in cmd])
        tool = self._tool(cmd)
        if tool in self.fail:
            return self.fail[tool]
        if tool == "raptor-binary investigate":
            out = Path(cmd[cmd.index("--out") + 1])
            out.mkdir(parents=True, exist_ok=True)
            save_json(out / "binary-investigation.json", {"ok": True})
        elif tool == "raptor-ghidra":
            out = Path(cmd[cmd.index("--out") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "re-database.json").write_bytes(
                b"{}".ljust(self.redb_bytes, b" "))
        elif tool == "raptor-binary-study":
            out = Path(cmd[3])
            out.mkdir(parents=True, exist_ok=True)
            save_json(out / "domain-model.json", {"concepts": []})
        elif tool == "raptor-audit":
            if cmd[2] == "resume":
                out = Path(cmd[3])
            else:
                out = Path(cmd[cmd.index("--out") + 1])
            out.mkdir(parents=True, exist_ok=True)
            save_json(out / "audit-run-config.json", {})
            self.audit_runs += 1
            rows = (self.audit_verdicts if self.audit_runs == 1
                    else self.rereview_verdicts)
            for file, function, verdict in rows:
                append_entry(out,
                             _journal_row(file, function, verdict))
            save_json(out / "audit-report.json", {"done": True})
        elif tool == "raptor-binary siblings":
            run_dir = Path(cmd[3])
            if self.seeds:
                save_json(run_dir / "sibling-hypotheses.json", {
                    "schema_version": 1,
                    "producer": "binary-siblings",
                    "seeds": [{"claim": "peer drift"}],
                })
        return 0

    def tools_called(self) -> list[str]:
        return [self._tool(c) for c in self.calls]


@pytest.fixture()
def checklist_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process checklist stage dependencies (no real redb parse)."""
    import core.audit.binary_context as bc
    import core.inventory.binary_builder as bb
    monkeypatch.setattr(bc, "load_redb", lambda p: object())
    monkeypatch.setattr(
        bb, "build_binary_checklist",
        lambda db, binary_path=None: {
            "total_items": 2,
            "files": {"binary:app": ["f1", "f2"]},
        })


def _wire(monkeypatch: pytest.MonkeyPatch,
          runner: FakeRunner) -> None:
    monkeypatch.setattr(chain_elf, "_run_child", runner)


def _setup(tmp_path: Path, **row_over: Any) -> tuple[Path, Path]:
    root = _make_target(tmp_path)
    out = tmp_path / "engagement"
    _make_ledger(out, root, [_elf_row(root, **row_over)])
    return out, root


def _status(out: Path) -> dict[str, Any]:
    doc = load_ledger(out)
    assert doc is not None
    return doc["rows"][0]["status"]


# ── Id / dir / policy plumbing ───────────────────────────────────────

class TestPlumbing:
    def test_artifact_id_regex_parity_with_ledger(self) -> None:
        # The chain's copy must never drift from the ledger's private
        # pattern (both directions: same pattern string).
        assert (chain_elf._ARTIFACT_ID_RE.pattern
                == ledger_mod._ARTIFACT_ID_RE.pattern)

    @pytest.mark.parametrize("bad", ["", "UPPER", "-lead", "a b",
                                     "../etc", "a" * 98])
    def test_chain_dir_rejects_bad_ids(self, bad: str,
                                       tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            chain_dir_for(tmp_path, bad)

    def test_chain_dir_layout(self, tmp_path: Path) -> None:
        assert (chain_dir_for(tmp_path, ART)
                == tmp_path / "chains" / ART)

    def test_policy_precedence_policy_tier_wins(self) -> None:
        row = {"policy": {"tier": "T1", "depth": "T2"},
               "status": {"depth": "T3"}}
        assert resolve_policy_depth(row) == ("T1", "policy.tier")

    def test_policy_depth_key_second(self) -> None:
        row = {"policy": {"depth": "T2"}, "status": {"depth": "T3"}}
        assert resolve_policy_depth(row) == ("T2", "policy.depth")

    def test_policy_status_depth_third(self) -> None:
        row = {"status": {"depth": "t1"}}
        assert resolve_policy_depth(row) == ("T1", "status.depth")

    def test_policy_absent_defaults_full_with_recorded_source(
            self) -> None:
        assert resolve_policy_depth({}) == ("T3", "assumed_default")

    def test_policy_garbled_falls_through_to_default(self) -> None:
        # A garbled label must NOT silently pick a shallower chain.
        row = {"policy": {"tier": "deep"}, "status": {"depth": "T9"}}
        assert resolve_policy_depth(row) == ("T3", "assumed_default")

    def test_planned_stages_per_tier(self) -> None:
        p = chain_elf._planned_stages
        assert p("T1") == ["investigate", "import"]
        assert p("T2") == ["investigate", "import", "study",
                           "checklist"]
        assert p("T3") == list(STAGES)
        assert p("garbled") == list(STAGES)  # default = full chain

    def test_stage_outcome_rejects_unknown_status(self) -> None:
        with pytest.raises(ValueError):
            StageOutcome("bogus")
        assert StageOutcome("done").status == "done"

    def test_load_chain_state_absent_is_empty(self,
                                              tmp_path: Path) -> None:
        assert load_chain_state(tmp_path / "nowhere") == {}


# ── Usage gates ──────────────────────────────────────────────────────

class TestUsageGates:
    def test_bad_artifact_id_is_usage(self, tmp_path: Path,
                                      monkeypatch: Any) -> None:
        out, _ = _setup(tmp_path)
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, "NOT/VALID") == RC_USAGE
        assert runner.calls == []

    def test_missing_ledger_is_usage(self, tmp_path: Path) -> None:
        assert run_chain(tmp_path, ART) == RC_USAGE

    def test_unknown_artifact_is_usage(self, tmp_path: Path) -> None:
        out, _ = _setup(tmp_path)
        assert run_chain(out, "sha256-ffffffff") == RC_USAGE


# ── Dispatch arms ────────────────────────────────────────────────────

class TestDispatchArms:
    def test_parked_row_never_resumed(self, tmp_path: Path,
                                      monkeypatch: Any) -> None:
        out, _ = _setup(tmp_path, status={
            "state": "parked",
            "updated_at": "2026-01-01T00:00:00+00:00"})
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_NOTHING
        assert runner.calls == []
        assert _status(out)["state"] == "parked"

    def test_t0_policy_does_not_run(self, tmp_path: Path,
                                    monkeypatch: Any) -> None:
        out, _ = _setup(tmp_path, policy={"tier": "T0"})
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_NOTHING
        assert runner.calls == []

    def test_not_built_arm_records_degradation_once(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        root = _make_target(tmp_path)
        out = tmp_path / "engagement"
        _make_ledger(out, root, [_elf_row(root, **{"class": "pe-exe"})])
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK
        state = load_chain_state(chain_dir_for(out, ART))
        assert state["not_built"] is True
        assert state["degradations"][0]["reason"] == (
            "chain_not_built:pe-exe")
        assert "chain_not_built:pe-exe" in _status(out)["detail"]
        assert _status(out)["state"] == "inventoried"
        # Second run: already recorded — nothing to do, no rewrite.
        assert run_chain(out, ART) == RC_NOTHING
        assert runner.calls == []

    def test_not_built_arm_leaves_progressed_rows_alone(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        root = _make_target(tmp_path)
        out = tmp_path / "engagement"
        over: dict[str, Any] = {
            "class": "macho",
            "status": {"state": "in_progress",
                       "updated_at": "2026-01-01T00:00:00+00:00",
                       "detail": "another lane"}}
        _make_ledger(out, root, [_elf_row(root, **over)])
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        st = _status(out)
        assert st["state"] == "in_progress"
        assert st["detail"] == "another lane"


# ── Content gates (fail closed) ──────────────────────────────────────

class TestContentGates:
    def test_missing_binary_fails(self, tmp_path: Path,
                                  monkeypatch: Any) -> None:
        out, root = _setup(tmp_path)
        (root / "bin" / "app").unlink()
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_FAILED
        assert runner.calls == []
        assert _status(out)["state"] == "failed"

    def test_path_escape_fails(self, tmp_path: Path,
                               monkeypatch: Any) -> None:
        out, root = _setup(tmp_path, path="../outside")
        (tmp_path / "outside").write_bytes(b"\x7fELF-outside")
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_FAILED
        assert runner.calls == []

    def test_hash_mismatch_inherits_nothing(self, tmp_path: Path,
                                            monkeypatch: Any) -> None:
        out, root = _setup(tmp_path)
        (root / "bin" / "app").write_bytes(b"\x7fELF-swapped!")
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_FAILED
        assert runner.calls == []
        st = _status(out)
        assert st["state"] == "failed"
        assert "hash mismatch" in st["detail"]

    def test_missing_target_root_refuses_never_cwd(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        # A ledger without target_root and no --target-root must be a
        # NAMED refusal — never a quiet Path("").resolve() fallback
        # that makes the process CWD the containment root. Sit the
        # CWD where the fallback WOULD find the binary: the refusal
        # must fire anyway.
        out, root = _setup(tmp_path)
        doc = load_json(out / ledger_mod.LEDGER_FILENAME)
        del doc["target_root"]
        save_json(out / ledger_mod.LEDGER_FILENAME, doc)
        monkeypatch.chdir(root)
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_FAILED
        assert runner.calls == []
        st = _status(out)
        assert st["state"] == "failed"
        assert "no containment root" in st["detail"]

    def test_swapped_content_never_inherits_chain_state(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        # The stale-inherit scenario: the chain completes (attesting)
        # on bytes A; the binary is swapped to bytes B and the ledger
        # REBUILT — a build-id-anchored artifact_id survives such a
        # rebuild (build-ids are attacker-forgeable), and the row's
        # identity.sha256 now matches the swapped bytes, so the
        # ledger-identity gate alone passes. The chain-state gate
        # must refuse: NO settled-stage inheritance, NO carried
        # attesting verdict, and the re-run starts from scratch.
        out, root = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        cd = chain_dir_for(out, ART)
        assert load_chain_state(cd)["verdict"]["attesting"] is True
        # The swap + ledger rebuild (same artifact_id, new sha256).
        (root / "bin" / "app").write_bytes(b"\x7fELF-SWAPPED-B")
        _make_ledger(out, root, [_elf_row(root)])
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_chain(out, ART) == RC_FAILED  # refuse-and-reset
        assert rerun.calls == []  # and NOTHING inherited or attested
        st = _status(out)
        assert st["state"] == "failed"
        assert "content changed" in st["detail"]
        # The stale state is archived aside, named; the live chain
        # dir carries no verdict any more.
        assert load_chain_state(cd).get("verdict") is None
        stale = [p for p in (out / "chains").iterdir()
                 if p.name.startswith(f"{ART}.stale-")]
        assert len(stale) == 1
        assert load_chain_state(stale[0])["verdict"]["attesting"] \
            is True  # the OLD verdict lives only in the archive
        # Resumable: the next run rebuilds the chain from scratch
        # against the new bytes — every stage re-runs.
        fresh = FakeRunner()
        _wire(monkeypatch, fresh)
        assert run_chain(out, ART) == RC_OK
        assert "raptor-binary investigate" in fresh.tools_called()
        state = load_chain_state(cd)
        assert state["binary_sha256"] == sha256_file(
            root / "bin" / "app")
        assert _status(out)["state"] == "verdicted"

    def test_ledger_identity_drift_refused_even_with_prior_state(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        # The other direction: disk bytes still match the CHAIN STATE
        # but the LEDGER's recorded identity drifted (hand edit /
        # partial rebuild). The ledger-identity gate must refuse even
        # though prior chain state exists — prior state never waives
        # the ledger gate.
        out, root = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        doc = load_json(out / ledger_mod.LEDGER_FILENAME)
        doc["rows"][0]["identity"]["sha256"] = "f" * 64
        save_json(out / ledger_mod.LEDGER_FILENAME, doc)
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_chain(out, ART) == RC_FAILED
        assert rerun.calls == []
        assert "hash mismatch" in _status(out)["detail"]


# ── Full chain: sequencing, handoffs, idempotence, resume ───────────

class TestFullChain:
    def test_happy_path_full_chain(self, tmp_path: Path,
                                   monkeypatch: Any,
                                   checklist_stub: None) -> None:
        out, root = _setup(tmp_path)
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK
        # Tool order = the design's chain order (checklist and
        # validate are in-process; seed_rereview skips without seeds).
        assert runner.tools_called() == [
            "raptor-binary investigate", "raptor-ghidra",
            "raptor-binary-study", "raptor-audit",
            "raptor-binary siblings"]
        cd = chain_dir_for(out, ART)
        # Handoffs: redb at the chain ROOT; checklist in BOTH the
        # ledger slot and the audit run dir; survivors artifact.
        assert (cd / "re-database.json").is_file()
        assert checklist_slot_path(out, ART).is_file()
        assert read_artifact_checklist(out, ART) is not None
        assert load_json(cd / "audit" / "checklist.json") is not None
        assert (cd / SURVIVORS_FILENAME).is_file()
        # Verdict: attesting (no findings, full tier, no degradations).
        state = load_chain_state(cd)
        v = state["verdict"]
        assert v["schema"] == VERDICT_SCHEMA
        assert v["policy_depth"] == "T3"
        assert v["policy_source"] == "assumed_default"
        assert v["reached_depth"] == "T3"
        assert v["degradation_reasons"] == []
        assert v["format_capability_tier"] == "full"
        assert v["attesting"] is True
        assert "full ELF-chain capability" in v["wording"]
        st = _status(out)
        assert st["state"] == "verdicted"
        assert st["depth"] == "T3"
        assert "attesting=yes" in st["detail"]

    def test_rerun_is_idempotent_nothing_to_do(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_chain(out, ART) == RC_NOTHING
        assert rerun.calls == []  # zero child spawns on a complete chain

    def test_rerun_keeps_terminal_ledger_status(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        # The cron-drift scenario: a verdicted chain with a STANDING
        # skip (no sibling seeds) re-evaluates the skip on every
        # re-run, which transiently marks the row in_progress. The
        # LEDGER ROW must end each nothing-to-do re-run back at its
        # terminal status — not drift to in_progress forever.
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner(seeds=False))
        assert run_chain(out, ART) == RC_OK
        st = _status(out)
        assert st["state"] == "verdicted"
        assert "attesting=yes" in st["detail"]
        for _ in range(2):  # second AND third runs stay idempotent
            rerun = FakeRunner()
            _wire(monkeypatch, rerun)
            assert run_chain(out, ART) == RC_NOTHING
            assert rerun.calls == []
            st = _status(out)
            assert st["state"] == "verdicted"
            assert "attesting=yes" in st["detail"]

    def test_t1_stops_after_import_non_attesting(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        out, _ = _setup(tmp_path, policy={"tier": "T1"})
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK
        assert runner.tools_called() == [
            "raptor-binary investigate", "raptor-ghidra"]
        state = load_chain_state(chain_dir_for(out, ART))
        v = state["verdict"]
        assert v["policy_depth"] == "T1"
        assert v["reached_depth"] == "T1"
        assert v["attesting"] is False  # no audit ran — never attests
        assert "non-attesting" in v["wording"]
        assert _status(out)["state"] == "analysed"  # not verdicted

    def test_resume_at_failed_stage(self, tmp_path: Path,
                                    monkeypatch: Any,
                                    checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        broken = FakeRunner(fail={"raptor-binary-study": 7})
        _wire(monkeypatch, broken)
        assert run_chain(out, ART) == RC_FAILED
        st = _status(out)
        assert st["state"] == "failed"
        assert "stage=study" in st["detail"]
        # Re-run resumes AT study — investigate/import not re-spawned.
        fixed = FakeRunner()
        _wire(monkeypatch, fixed)
        assert run_chain(out, ART) == RC_OK
        assert fixed.tools_called()[0] == "raptor-binary-study"
        assert _status(out)["state"] == "verdicted"

    def test_done_stage_with_missing_artifact_reruns(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        cd = chain_dir_for(out, ART)
        (cd / "study" / "domain-model.json").unlink()
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_chain(out, ART) == RC_OK
        # Recorded "done" alone is not completion — the stage's own
        # artifact must exist; study re-ran, earlier stages did not.
        assert "raptor-binary-study" in rerun.tools_called()
        assert "raptor-ghidra" not in rerun.tools_called()

    def test_zero_exit_without_artifact_is_failure(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        # A child that exits 0 but writes nothing must not count as
        # done (exit codes are not completion evidence).
        out, _ = _setup(tmp_path, policy={"tier": "T1"})

        class NoArtifact(FakeRunner):
            def __call__(self, cmd: list[str], *, llm: bool = False,
                         timeout_s: int = 0) -> int:
                self.calls.append([str(c) for c in cmd])
                return 0

        _wire(monkeypatch, NoArtifact())
        assert run_chain(out, ART) == RC_FAILED
        state = load_chain_state(chain_dir_for(out, ART))
        assert state["stages"]["investigate"]["status"] == "failed"


# ── Mechanical-only (the one non-sticky degradation) ─────────────────

class TestMechanicalOnly:
    def test_skips_llm_stages_and_stamps_rerun_without(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART, mechanical_only=True) == RC_OK
        assert runner.tools_called() == [
            "raptor-binary investigate", "raptor-ghidra",
            "raptor-binary siblings"]
        state = load_chain_state(chain_dir_for(out, ART))
        for stage in ("study", "audit", "seed_rereview"):
            rec = state["stages"][stage]
            assert rec["status"] == "degraded"
            assert rec["rerun_without"] == "mechanical_only"
        assert _status(out)["state"] == "analysed"  # audit not done
        assert state["verdict"]["attesting"] is False

    def test_sticky_under_same_flag(self, tmp_path: Path,
                                    monkeypatch: Any,
                                    checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART, mechanical_only=True) == RC_OK
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_chain(out, ART, mechanical_only=True) == RC_NOTHING
        assert rerun.calls == []

    def test_flag_dropped_reopens_exactly_llm_stages(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART, mechanical_only=True) == RC_OK
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_chain(out, ART) == RC_OK
        assert rerun.tools_called() == [
            "raptor-binary-study", "raptor-audit"]
        assert _status(out)["state"] == "verdicted"

    def test_other_degradations_stay_sticky(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        cd = chain_dir_for(out, ART)
        state = load_chain_state(cd)
        state["stages"]["study"] = {"status": "degraded",
                                    "reason": "no_re_database",
                                    "at": "2026-01-01T00:00:00+00:00"}
        state.pop("verdict")
        save_json(cd / "chain-state.json", state)
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        run_chain(out, ART)
        # No rerun_without → sticky: study is NOT re-attempted.
        assert "raptor-binary-study" not in rerun.tools_called()
        v = load_chain_state(cd)["verdict"]
        assert {"stage": "study", "reason": "no_re_database"} \
            in v["degradation_reasons"]
        assert v["attesting"] is False
        assert v["reached_depth"] == "T1"  # degraded study caps depth


# ── RE-database cap (record degradation, never abort) ───────────────

class TestRedbCap:
    def _cap(self, monkeypatch: Any, cap: int) -> None:
        import core.json.utils as ju
        monkeypatch.setattr(ju, "RE_DATABASE_MAX_BYTES", cap)

    def test_over_cap_degrades_and_continues(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        self._cap(monkeypatch, 100)
        out, _ = _setup(tmp_path)
        runner = FakeRunner(redb_bytes=150)
        _wire(monkeypatch, runner)
        rc = run_chain(out, ART)
        assert rc == RC_OK  # never aborts
        state = load_chain_state(chain_dir_for(out, ART))
        assert state["stages"]["import"]["status"] == "done"
        assert state["stages"]["import"]["extra_degradations"] == [
            "re_database_over_cap"]
        assert state["stages"]["study"]["status"] == "degraded"
        # Study never spawned against an over-budget export.
        assert "raptor-binary-study" not in runner.tools_called()
        reasons = [d["reason"]
                   for d in state["verdict"]["degradation_reasons"]]
        assert reasons.count("re_database_over_cap") == 2
        assert state["verdict"]["attesting"] is False

    def test_near_cap_warns_but_study_runs(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        self._cap(monkeypatch, 100)
        out, _ = _setup(tmp_path)
        runner = FakeRunner(redb_bytes=95)  # ≥90% of cap, under cap
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK
        state = load_chain_state(chain_dir_for(out, ART))
        assert state["stages"]["import"]["extra_degradations"] == [
            "re_database_near_cap"]
        assert "raptor-binary-study" in runner.tools_called()
        assert state["stages"]["study"]["status"] == "done"

    def test_under_cap_no_extras(self, tmp_path: Path,
                                 monkeypatch: Any,
                                 checklist_stub: None) -> None:
        self._cap(monkeypatch, 100)
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner(redb_bytes=50))
        assert run_chain(out, ART) == RC_OK
        state = load_chain_state(chain_dir_for(out, ART))
        assert "extra_degradations" not in state["stages"]["import"]
        assert state["verdict"]["attesting"] is True


# ── Checklist stage degradations ─────────────────────────────────────

class TestChecklistStage:
    def test_unloadable_redb_degrades_without_slot_write(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        import core.audit.binary_context as bc

        def boom(path: Path) -> Any:
            raise ValueError("budget exceeded")

        monkeypatch.setattr(bc, "load_redb", boom)
        out, _ = _setup(tmp_path, policy={"tier": "T2"})
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        state = load_chain_state(chain_dir_for(out, ART))
        assert state["stages"]["checklist"]["status"] == "degraded"
        assert state["stages"]["checklist"]["reason"] == (
            "re_database_unloadable")
        assert not checklist_slot_path(out, ART).is_file()

    def test_empty_checklist_degrades(self, tmp_path: Path,
                                      monkeypatch: Any) -> None:
        import core.audit.binary_context as bc
        import core.inventory.binary_builder as bb
        monkeypatch.setattr(bc, "load_redb", lambda p: object())
        monkeypatch.setattr(
            bb, "build_binary_checklist",
            lambda db, binary_path=None: {"total_items": 0,
                                          "files": {}})
        out, _ = _setup(tmp_path, policy={"tier": "T2"})
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        state = load_chain_state(chain_dir_for(out, ART))
        assert state["stages"]["checklist"]["reason"] == (
            "empty_binary_checklist")

    def test_stage_writes_frame_verified_checklists(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        # Both handoffs — the audit-dir copy and the ledger slot —
        # must carry a frame that VERIFIES in place: the audit stage
        # reads its copy with the frame-authenticating accessor, and
        # an unstamped in-era document is demoted to legacy tier with
        # a per-artifact warning.
        import core.audit.binary_context as bc
        import core.inventory.binary_builder as bb
        from core.inventory import checklist_frame_mac as cm
        from core.inventory import read_checklist

        monkeypatch.setattr(bc, "load_redb", lambda p: object())
        monkeypatch.setattr(
            bb, "build_binary_checklist",
            lambda db, binary_path=None: {
                "total_items": 2,
                "files": [{"path": "binary:app", "items": []}],
            })
        out, _ = _setup(tmp_path, policy={"tier": "T2"})
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK

        audit_dir = chain_dir_for(out, ART) / "audit"
        raw = load_json(audit_dir / "checklist.json")
        assert cm.frame_provenance(
            raw, cm.frame_binding(audit_dir), cm.FORM_SINGLE,
        ) == cm.FRAME_VERIFIED
        # The audit stage's accessor reads it back at full authority.
        assert read_checklist(audit_dir)["total_items"] == 2

        slot = checklist_slot_path(out, ART)
        raw_slot = load_json(slot)
        assert cm.frame_provenance(
            raw_slot, cm.frame_binding(slot), cm.FORM_SINGLE,
        ) == cm.FRAME_VERIFIED
        assert read_artifact_checklist(out, ART)["total_items"] == 2

    def test_sharded_audit_copy_recognised_done(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        # An over-budget checklist lands at the audit dir in the
        # inventory writer's sharded layout — no checklist.json single
        # file — and the stage completion predicate must still see the
        # stage as done: a raw is_file check would re-run it forever.
        import core.audit.binary_context as bc
        import core.inventory as inv
        import core.inventory.binary_builder as bb
        from core.inventory import read_checklist

        monkeypatch.setattr(inv, "_MAX_CHECKLIST_BYTES", 256)
        monkeypatch.setattr(inv, "_CHECKLIST_SHARD_TARGET_BYTES", 400)
        monkeypatch.setattr(bc, "load_redb", lambda p: object())
        monkeypatch.setattr(
            bb, "build_binary_checklist",
            lambda db, binary_path=None: {
                "total_items": 8,
                "files": [
                    {"path": f"binary:app{i}", "sloc": 10, "items": [{
                        "name": f"fn{i}", "kind": "function",
                        "line_start": 1, "line_end": 5,
                    }]}
                    for i in range(8)
                ],
            })
        out, _ = _setup(tmp_path, policy={"tier": "T2"})
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK

        audit_dir = chain_dir_for(out, ART) / "audit"
        assert not (audit_dir / "checklist.json").is_file()
        assert read_checklist(audit_dir)["total_items"] == 8
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_chain(out, ART) == RC_NOTHING
        assert rerun.calls == []

    def test_tampered_slot_rebuilt_on_rerun(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        # A tampered slot reads as absent (the frame gate refuses it);
        # the stage-completion predicate must agree with the reader —
        # a raw existence check would keep the chain "done" over a
        # slot no consumer can read, and the refusal log's advertised
        # remedy (re-run the stage) would never fire.
        import core.audit.binary_context as bc
        import core.inventory.binary_builder as bb
        monkeypatch.setattr(bc, "load_redb", lambda p: object())
        monkeypatch.setattr(
            bb, "build_binary_checklist",
            lambda db, binary_path=None: {
                "total_items": 2,
                "files": [{"path": "binary:app", "items": []}],
            })
        out, _ = _setup(tmp_path, policy={"tier": "T2"})
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK
        slot = checklist_slot_path(out, ART)
        doc = load_json(slot)
        doc["total_items"] = 9999
        save_json(slot, doc)
        assert read_artifact_checklist(out, ART) is None
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_OK  # re-ran, not nothing-to-do
        assert read_artifact_checklist(out, ART)["total_items"] == 2

    def test_overbudget_checklist_is_contained_stage_failure(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        # The chain's checklist carries ONE binary:<stem> files entry,
        # which the sharded writer cannot split — once that entry
        # exceeds the hard per-shard reader budget the chokepoint
        # raises instead of sharding. That must surface as a named
        # per-row stage failure (resumable, ledger row failed), never
        # an uncaught abort of the whole sweep.
        import core.audit.binary_context as bc
        import core.inventory as inv
        import core.inventory.binary_builder as bb
        monkeypatch.setattr(inv, "_MAX_CHECKLIST_BYTES", 256)
        monkeypatch.setattr(inv, "_MAX_CHECKLIST_SHARD_BYTES", 256)
        monkeypatch.setattr(inv, "_CHECKLIST_SHARD_TARGET_BYTES", 400)
        monkeypatch.setattr(bc, "load_redb", lambda p: object())
        monkeypatch.setattr(
            bb, "build_binary_checklist",
            lambda db, binary_path=None: {
                "total_items": 40,
                "files": [{"path": "binary:app", "items": [
                    {"name": f"fn{i}", "kind": "function",
                     "line_start": 1, "line_end": 5}
                    for i in range(40)
                ]}],
            })
        out, _ = _setup(tmp_path, policy={"tier": "T2"})
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_FAILED  # contained, not raised
        state = load_chain_state(chain_dir_for(out, ART))
        rec = state["stages"]["checklist"]
        assert rec["status"] == "failed"
        assert "ChecklistBudgetExceededError" in rec["reason"]


# ── Seeds → re-review; siblings enrichment failure ──────────────────

class TestSeedsAndSiblings:
    def test_seeds_drive_second_audit(self, tmp_path: Path,
                                      monkeypatch: Any,
                                      checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        runner = FakeRunner(seeds=True)
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK
        audits = [c for c in runner.calls
                  if Path(c[1]).name == "raptor-audit"]
        assert len(audits) == 2
        rereview = audits[1]
        assert "--seed-rereview" in rereview
        assert "--hypothesis-seeds" in rereview
        seeds_arg = rereview[rereview.index("--hypothesis-seeds") + 1]
        assert seeds_arg.endswith("sibling-hypotheses.json")
        assert "--prior-journal" in rereview
        state = load_chain_state(chain_dir_for(out, ART))
        assert state["stages"]["seed_rereview"]["status"] == "done"

    def test_no_seeds_skips_rereview_without_latching(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        runner = FakeRunner(seeds=False)
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK
        state = load_chain_state(chain_dir_for(out, ART))
        rec = state["stages"]["seed_rereview"]
        assert rec["status"] == "skipped"
        assert rec["reason"] == "no_hypothesis_seeds"
        # A condition-judged skip never blocks attestation…
        assert state["verdict"]["attesting"] is True

    def test_skip_reevaluated_when_seeds_appear_later(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        # First run: no seeds → re-review skipped. Seeds then appear
        # (a later siblings pass) — the recorded skip must NOT latch:
        # the re-run picks the stage up and runs the re-review.
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner(seeds=False))
        assert run_chain(out, ART) == RC_OK
        cd = chain_dir_for(out, ART)
        save_json(cd / "investigate" / "sibling-hypotheses.json", {
            "schema_version": 1,
            "producer": "binary-siblings",
            "seeds": [{"claim": "peer drift"}],
        })
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_chain(out, ART) == RC_OK
        assert rerun.tools_called() == ["raptor-audit"]
        state = load_chain_state(cd)
        assert state["stages"]["seed_rereview"]["status"] == "done"

    def test_siblings_failure_degrades_not_fatal(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        runner = FakeRunner(fail={"raptor-binary siblings": 3})
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK  # chain completes
        state = load_chain_state(chain_dir_for(out, ART))
        rec = state["stages"]["siblings"]
        assert rec["status"] == "degraded"
        assert rec["reason"] == "siblings rc=3"
        assert state["verdict"]["attesting"] is False


# ── Audit command construction ───────────────────────────────────────

class TestAuditCmd:
    def _ctx(self, tmp_path: Path, **kw: Any) -> Any:
        return chain_elf.ChainContext(
            output_dir=tmp_path, chain_dir=tmp_path / "chains" / ART,
            artifact_id=ART, binary=tmp_path / "app",
            policy_depth="T3", policy_source="assumed_default", **kw)

    def test_fresh_run_when_no_config(self, tmp_path: Path) -> None:
        ctx = self._ctx(tmp_path)
        cmd = chain_elf._audit_cmd(ctx, tmp_path / "audit", [])
        assert cmd[2] == "run"
        assert "--no-validate" in cmd
        assert "--out" in cmd

    def test_resume_when_config_without_report(
            self, tmp_path: Path) -> None:
        run = tmp_path / "audit"
        run.mkdir()
        save_json(run / "audit-run-config.json", {})
        cmd = chain_elf._audit_cmd(self._ctx(tmp_path), run, [])
        assert cmd[2:] == ["resume", str(run)]

    def test_completed_run_gets_fresh_not_resume(
            self, tmp_path: Path) -> None:
        run = tmp_path / "audit"
        run.mkdir()
        save_json(run / "audit-run-config.json", {})
        save_json(run / "audit-report.json", {})
        cmd = chain_elf._audit_cmd(self._ctx(tmp_path), run, [])
        assert cmd[2] == "run"

    def test_model_and_budget_forwarded(self, tmp_path: Path) -> None:
        ctx = self._ctx(tmp_path, model="m-test", max_cost=12.5)
        cmd = chain_elf._audit_cmd(ctx, tmp_path / "audit", [])
        assert cmd[cmd.index("--model") + 1] == "m-test"
        assert cmd[cmd.index("--max-cost") + 1] == "12.5"

    def test_study_forwards_model_and_budget(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path, policy={"tier": "T2"})
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_chain(out, ART, model="m-test",
                         max_cost=3.0) == RC_OK
        study = next(c for c in runner.calls
                     if Path(c[1]).name == "raptor-binary-study")
        assert study[study.index("--model") + 1] == "m-test"
        assert study[study.index("--max-cost") + 1] == "3.0"


# ── Findings → survivors artifact ────────────────────────────────────

class TestSurvivors:
    def test_findings_produce_survivors_and_pending_wording(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        runner = FakeRunner(audit_verdicts=(
            ("app.c", "parse_hdr", "finding"),
            ("app.c", "read_len", "suspicious"),
            ("app.c", "main", "clean"),
        ))
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK
        cd = chain_dir_for(out, ART)
        payload = load_json(cd / SURVIVORS_FILENAME)
        assert payload["survivors"] == [
            {"file": "app.c", "function": "parse_hdr",
             "run": "audit"}]
        assert payload["degradation"] == (
            "validate_decomp_adapter_missing")
        assert payload["counts"] == {"finding": 1, "suspicious": 1,
                                     "clean": 1}
        assert payload["derived_from_target"] == [
            "survivors.file", "survivors.function"]
        assert payload["provenance"]["generator"] == "engage-chain"
        assert payload["provenance"]["untrusted"] is True
        v = load_chain_state(cd)["verdict"]
        assert v["attesting"] is False
        assert "1 finding-grade" in v["wording"]
        assert "validation pending" in v["wording"]
        st = _status(out)
        assert st["state"] == "verdicted"
        assert "findings=1" in st["detail"]

    def test_no_findings_survivors_still_written_clean(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        out, _ = _setup(tmp_path)
        _wire(monkeypatch, FakeRunner(audit_verdicts=(
            ("app.c", "main", "clean"),)))
        assert run_chain(out, ART) == RC_OK
        payload = load_json(
            chain_dir_for(out, ART) / SURVIVORS_FILENAME)
        assert payload["survivors"] == []
        assert payload["degradation"] is None

    def test_rereview_only_finding_counted_and_surviving(
            self, tmp_path: Path, monkeypatch: Any,
            checklist_stub: None) -> None:
        # A finding-grade row that exists ONLY in the seed re-review
        # run must appear in BOTH read paths: the verdict's
        # journal_verdicts counts AND the survivors payload (tagged
        # with its run) — the re-review journal is coverage evidence,
        # not an optional extra.
        out, _ = _setup(tmp_path)
        runner = FakeRunner(
            seeds=True,
            audit_verdicts=(("binary:app", "main", "clean"),),
            rereview_verdicts=(
                ("binary:app", "parse_hdr", "finding"),))
        _wire(monkeypatch, runner)
        assert run_chain(out, ART) == RC_OK
        cd = chain_dir_for(out, ART)
        v = load_chain_state(cd)["verdict"]
        assert v["journal_verdicts"] == {"clean": 1, "finding": 1}
        assert v["attesting"] is False
        payload = load_json(cd / SURVIVORS_FILENAME)
        assert payload["survivors"] == [
            {"file": "binary:app", "function": "parse_hdr",
             "run": "seed_rereview"}]
        assert payload["counts"] == {"clean": 1, "finding": 1}

    def test_rereview_only_rows_direct_reads(self,
                                             tmp_path: Path) -> None:
        # White-box on the two readers themselves: rows in the
        # re-review dir alone reach _journal_counts AND the
        # _stage_validate survivor sweep.
        ctx = chain_elf.ChainContext(
            output_dir=tmp_path, chain_dir=tmp_path / "chains" / ART,
            artifact_id=ART, binary=tmp_path / "app",
            policy_depth="T3", policy_source="policy.tier")
        ctx.rereview_dir.mkdir(parents=True, exist_ok=True)
        append_entry(ctx.rereview_dir,
                     _journal_row("binary:app", "gets_len", "finding"))
        counts, complete = chain_elf._journal_counts(ctx)
        assert counts == {"finding": 1}
        assert complete is True
        outcome = chain_elf._stage_validate(ctx)
        assert outcome.status == "degraded"
        payload = load_json(ctx.chain_dir / SURVIVORS_FILENAME)
        assert payload["survivors"] == [
            {"file": "binary:app", "function": "gets_len",
             "run": "seed_rereview"}]


# ── Verdict schema (M8) ──────────────────────────────────────────────

class TestVerdict:
    def _ctx(self, tmp_path: Path, depth: str = "T3") -> Any:
        return chain_elf.ChainContext(
            output_dir=tmp_path, chain_dir=tmp_path / "chains" / ART,
            artifact_id=ART, binary=tmp_path / "app",
            policy_depth=depth, policy_source="policy.tier")

    def _done_state(self, stages: list[str]) -> dict[str, Any]:
        return {"stages": {s: {"status": "done"} for s in stages}}

    def _earn(self, ctx: Any) -> None:
        """Meet the earned-coverage floor (one clean journal row) so
        each white-box test blocks attestation on EXACTLY the conjunct
        under test."""
        ctx.audit_dir.mkdir(parents=True, exist_ok=True)
        append_entry(ctx.audit_dir,
                     _journal_row("binary:app", "main", "clean"))

    def test_sub_full_tier_never_attests(self,
                                         tmp_path: Path) -> None:
        # Zero findings + full chain done, but the artifact's format
        # capability is near_full → NON-attesting by tier alone.
        ctx = self._ctx(tmp_path)
        self._earn(ctx)
        state = self._done_state(list(STAGES))
        row = {"format_tier": "near_full"}
        v = build_verdict(ctx, state, row)
        assert v["attesting"] is False
        assert "non-attesting" in v["wording"]
        assert "T3/near_full" in v["wording"]
        # Same state at full tier DOES attest (the other direction).
        v2 = build_verdict(ctx, state, {"format_tier": "full"})
        assert v2["attesting"] is True
        assert v2["journal_floor"] is None

    def test_reached_depth_capped_by_policy(self,
                                            tmp_path: Path) -> None:
        ctx = self._ctx(tmp_path, depth="T2")
        self._earn(ctx)
        state = self._done_state(list(STAGES))
        v = build_verdict(ctx, state, {"format_tier": "full"})
        assert v["reached_depth"] == "T2"  # never above policy
        assert v["attesting"] is False  # audit outside a T2 plan

    def test_degradation_blocks_attestation_even_at_full_depth(
            self, tmp_path: Path) -> None:
        # Every planned stage done AND reached == policy AND full
        # tier — but a recorded degradation (an extra on a done
        # stage) must still block attestation.
        ctx = self._ctx(tmp_path)
        self._earn(ctx)
        state = self._done_state(list(STAGES))
        state["stages"]["import"]["extra_degradations"] = [
            "re_database_near_cap"]
        v = build_verdict(ctx, state, {"format_tier": "full"})
        assert v["reached_depth"] == "T3"  # depth is still earned
        assert v["degradation_reasons"] == [
            {"stage": "import", "reason": "re_database_near_cap"}]
        assert v["attesting"] is False

    def test_finding_rows_alone_block_attestation(
            self, tmp_path: Path) -> None:
        # White-box: in a full run the survivors handoff also records
        # a validate degradation, so the finding veto must hold on
        # its own — a finding-grade journal row with an otherwise
        # perfect chain never attests.
        ctx = self._ctx(tmp_path)
        ctx.audit_dir.mkdir(parents=True, exist_ok=True)
        append_entry(ctx.audit_dir,
                     _journal_row("app.c", "parse_hdr", "finding"))
        state = self._done_state(list(STAGES))
        v = build_verdict(ctx, state, {"format_tier": "full"})
        assert v["journal_verdicts"] == {"finding": 1}
        assert v["attesting"] is False

    def test_short_reached_depth_alone_blocks_attestation(
            self, tmp_path: Path) -> None:
        # White-box: the runner never reaches the verdict with an
        # unsettled planned stage, but build_verdict's contract is
        # standalone — a missing stage record (reached < policy) must
        # block attestation even when the audit itself is done.
        ctx = self._ctx(tmp_path)
        self._earn(ctx)
        state = self._done_state(
            [s for s in STAGES if s != "checklist"])
        v = build_verdict(ctx, state, {"format_tier": "full"})
        assert v["reached_depth"] == "T1"
        assert v["attesting"] is False

    def test_empty_journal_blocks_attestation(self,
                                              tmp_path: Path) -> None:
        # Earned-coverage floor: every stage done, full tier, zero
        # degradations — but ZERO journal verdict rows. "No findings"
        # backed by no evidence must not attest, with the floor
        # reason recorded.
        state = self._done_state(list(STAGES))
        v = build_verdict(self._ctx(tmp_path), state,
                          {"format_tier": "full"})
        assert v["attesting"] is False
        assert v["journal_floor"] == "journal_no_verdict_rows"
        assert "earned-coverage floor not met" in v["wording"]
        assert "journal_no_verdict_rows" in v["wording"]

    def test_garbled_journal_blocks_attestation(
            self, tmp_path: Path) -> None:
        # A journal of only corrupt lines loads as zero rows (loud
        # stderr warning) — the floor must catch it, not attest on it.
        ctx = self._ctx(tmp_path)
        ctx.audit_dir.mkdir(parents=True, exist_ok=True)
        (ctx.audit_dir / "review-journal.jsonl").write_text(
            "{not json\ngarbage line\n", encoding="utf-8")
        state = self._done_state(list(STAGES))
        v = build_verdict(ctx, state, {"format_tier": "full"})
        assert v["journal_verdicts"] == {}
        assert v["attesting"] is False
        assert v["journal_floor"] == "journal_no_verdict_rows"

    def test_incomplete_journal_load_blocks_attestation(
            self, tmp_path: Path, monkeypatch: Any) -> None:
        # A bounded PARTIAL load (rows LOST) must veto attestation
        # even when the partial view carries verdict rows — a partial
        # view must never read as full earned coverage.
        import core.coverage.journal as journal_mod

        def partial(out_dir: Path, *, fresh: bool = False) -> Any:
            return journal_mod.JournalLoad(
                entries=[_journal_row("binary:app", "main", "clean")],
                complete=False, reason="read budget exceeded")

        monkeypatch.setattr(journal_mod, "load_entries_checked",
                            partial)
        ctx = self._ctx(tmp_path)
        ctx.audit_dir.mkdir(parents=True, exist_ok=True)
        state = self._done_state(list(STAGES))
        v = build_verdict(ctx, state, {"format_tier": "full"})
        assert v["journal_verdicts"] == {"clean": 1}
        assert v["attesting"] is False
        assert v["journal_floor"] == "journal_load_incomplete"

    def test_fixed_schema_fields_present(self, tmp_path: Path) -> None:
        v = build_verdict(self._ctx(tmp_path), {"stages": {}},
                          {"format_tier": "full"})
        for key in ("schema", "artifact_id", "policy_depth",
                    "policy_source", "reached_depth",
                    "degradation_reasons", "format_capability_tier",
                    "journal_verdicts", "journal_floor", "attesting",
                    "wording", "at"):
            assert key in v
        assert v["schema"] == VERDICT_SCHEMA
        assert v["reached_depth"] == "T0"


# ── The subprocess seam ──────────────────────────────────────────────

class TestRunChild:
    def test_env_selection_llm_vs_mechanical(
            self, monkeypatch: Any) -> None:
        picked: list[str] = []

        class FakeCfg:
            @staticmethod
            def get_safe_env() -> dict[str, str]:
                picked.append("safe")
                return dict(os.environ)

            @staticmethod
            def get_llm_env() -> dict[str, str]:
                picked.append("llm")
                return dict(os.environ)

        monkeypatch.setattr(chain_elf, "RaptorConfig", FakeCfg)
        assert chain_elf._run_child(["true"]) == 0
        assert chain_elf._run_child(["true"], llm=True) == 0
        assert picked == ["safe", "llm"]

    def test_echoed_command_is_escaped(self, monkeypatch: Any,
                                       capsys: Any) -> None:
        # A hostile path embedded in argv must not reach the terminal
        # as raw control bytes.
        assert chain_elf._run_child(
            ["true", "--x=\x1b[2Jhostile"]) == 0
        err = capsys.readouterr().err
        assert "\x1b" not in err
        assert "hostile" in err

    def test_stage_failure_reason_is_escaped_in_say(
            self, tmp_path: Path, monkeypatch: Any,
            capsys: Any) -> None:
        out, _ = _setup(tmp_path, policy={"tier": "T1"})
        monkeypatch.setitem(
            chain_elf._STAGE_FUNCS, "investigate",
            lambda ctx: StageOutcome("failed", "rc=\x1b[31mboom"))
        _wire(monkeypatch, FakeRunner())
        assert run_chain(out, ART) == RC_FAILED
        err = capsys.readouterr().err
        assert "\x1b" not in err
        assert "boom" in err


# ── all-pending sweep ────────────────────────────────────────────────

class TestAllPending:
    def _three_row_ledger(self, tmp_path: Path) -> Path:
        root = _make_target(tmp_path)
        (root / "bin" / "tool").write_bytes(b"\x7fELF-tool")
        out = tmp_path / "engagement"
        elf = _elf_row(root, policy={"tier": "T1"})
        pe = _elf_row(root, rel="bin/tool", **{
            "artifact_id": "sha256-11223344", "class": "pe-exe"})
        parked = _elf_row(root, rel="bin/tool", **{
            "artifact_id": "sha256-99887766",
            "status": {"state": "parked",
                       "updated_at": "2026-01-01T00:00:00+00:00"}})
        _make_ledger(out, root, [elf, pe, parked])
        return out

    def test_sweep_advances_then_idles(self, tmp_path: Path,
                                       monkeypatch: Any) -> None:
        out = self._three_row_ledger(tmp_path)
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        # First sweep: ELF chain advances, pe-exe records not-built,
        # parked no-ops → RC_OK.
        assert run_all_pending(out) == RC_OK
        assert runner.tools_called() == [
            "raptor-binary investigate", "raptor-ghidra"]
        # Second sweep: everything settled → RC_NOTHING, zero spawns.
        rerun = FakeRunner()
        _wire(monkeypatch, rerun)
        assert run_all_pending(out) == RC_NOTHING
        assert rerun.calls == []

    def test_sweep_reports_failure(self, tmp_path: Path,
                                   monkeypatch: Any) -> None:
        out = self._three_row_ledger(tmp_path)
        _wire(monkeypatch,
              FakeRunner(fail={"raptor-binary investigate": 9}))
        assert run_all_pending(out) == RC_FAILED

    def test_sweep_missing_ledger_is_usage(self,
                                           tmp_path: Path) -> None:
        assert run_all_pending(tmp_path) == RC_USAGE

    def test_hostile_artifact_id_row_fails_named_sweep_continues(
            self, tmp_path: Path, monkeypatch: Any,
            capsys: pytest.CaptureFixture[str]) -> None:
        # A garbled/hostile id in the hand-editable ledger is a NAMED
        # per-row failure: the sweep keeps running the rows after it,
        # the summary still prints, the overall rc reports the
        # failure, and the hostile bytes reach the terminal only in
        # escaped form.
        root = _make_target(tmp_path)
        out = tmp_path / "engagement"
        hostile = _elf_row(root, artifact_id="\x1b]0;pwn\x07../etc")
        good = _elf_row(root, policy={"tier": "T1"})
        _make_ledger(out, root, [hostile, good])
        runner = FakeRunner()
        _wire(monkeypatch, runner)
        assert run_all_pending(out) == RC_FAILED
        # The good row after the hostile one still ran its chain.
        assert runner.tools_called() == [
            "raptor-binary investigate", "raptor-ghidra"]
        err = capsys.readouterr().err
        assert "invalid artifact id in ledger row" in err
        assert "all-pending summary: advanced=1 failed=1" in err
        assert "\x1b" not in err and "\x07" not in err
