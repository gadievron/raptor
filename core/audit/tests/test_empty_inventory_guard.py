"""Startup refusal for empty inventories.

A checklist with ZERO reviewable items must refuse at orchestrator
startup (``terminated_by="empty_inventory"``, CLI exit nonzero,
lifecycle failed) instead of running an empty review loop to a clean
"complete, 0 findings" conclusion — a silent no-op indistinguishable
from a genuine clean bill of health. The OTHER zero-gaps case —
items exist and coverage already accounts for all of them — is
legitimate and must keep completing exactly as before.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    _reviewable_item_count,
    run_orchestrator,
)

_SCRIPT = Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit"


def _write_out_dir(tmp_path: Path, checklist: dict) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (out / "checklist.json").write_text(json.dumps(checklist))
    return target, out


def _clean_review(ctx, config):
    return ReviewOutcome(
        file=ctx["file"], function=ctx["function"],
        status="clean", body="reviewed", model="test-model",
    )


class TestReviewableItemCount:
    def test_counts_items_across_files(self):
        checklist = {"files": [
            {"path": "a.c", "items": [{"name": "f1"}, {"name": "f2"}]},
            {"path": "b.c", "items": [{"name": "g1"}]},
        ]}
        assert _reviewable_item_count(checklist) == 3

    def test_legacy_functions_key(self):
        checklist = {"files": [
            {"path": "a.c", "functions": [{"name": "f1"}]},
        ]}
        assert _reviewable_item_count(checklist) == 1

    def test_stale_total_items_field_ignored(self):
        # total_items is builder-stamped and can lie on inherited or
        # hand-edited checklists — the count comes from files[].items.
        checklist = {"total_items": 99, "files": []}
        assert _reviewable_item_count(checklist) == 0

    def test_non_dict_entries_tolerated(self):
        checklist = {"files": ["junk", {"path": "a.c", "items": [
            "junk", {"name": "f1"},
        ]}]}
        assert _reviewable_item_count(checklist) == 1

    def test_never_dispatched_kinds_excluded_by_default(self):
        # The review loop never dispatches these under the default
        # kind set (see gaps._resolve_reviewable_kinds) — a checklist
        # of only extraction artifacts is still an empty inventory.
        checklist = {"files": [{"path": "a.c", "items": [
            {"name": "d1", "kind": "declaration"},
            {"name": "M1", "kind": "constant_macro"},
        ]}]}
        assert _reviewable_item_count(checklist) == 0

    def test_positive_include_kinds_opts_kinds_back_in(self):
        # A positive --include-kinds entry naming an artifact kind
        # makes the loop dispatch it — the count must follow.
        checklist = {"files": [{"path": "a.c", "items": [
            {"name": "d1", "kind": "declaration"},
            {"name": "M1", "kind": "constant_macro"},
        ]}]}
        assert _reviewable_item_count(
            checklist, {"declaration"}) == 1

    def test_interstitial_counted_while_lane_enabled(self):
        # Deliberate over-count: the per-item script-handler content
        # gate is not replicated here, so interstitials count as long
        # as their lane is on (fail-open toward proceeding).
        checklist = {"files": [{"path": "a.php", "items": [
            {"name": "interstitial_1", "kind": "interstitial"},
        ]}]}
        assert _reviewable_item_count(checklist) == 1
        assert _reviewable_item_count(checklist, {"none"}) == 0


@pytest.mark.slow
class TestEmptyInventoryRefusal:
    def test_empty_files_list_refuses(self, tmp_path: Path):
        target, out = _write_out_dir(tmp_path, {
            "target_path": str(tmp_path / "target"),
            "files": [],
        })
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        result = run_orchestrator(config, _clean_review)
        assert result.terminated_by == "empty_inventory"
        assert result.reviewed == 0
        assert result.findings == 0

    def test_zero_item_file_entries_refuse(self, tmp_path: Path):
        # File entries exist but hold no items — still an empty
        # inventory (the observed shape when the builder ran against
        # the wrong target kind).
        target, out = _write_out_dir(tmp_path, {
            "target_path": str(tmp_path / "target"),
            "files": [
                {"path": "a.c", "items": []},
                {"path": "b.c", "items": []},
            ],
        })
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        result = run_orchestrator(config, _clean_review)
        assert result.terminated_by == "empty_inventory"
        assert result.reviewed == 0

    def test_refusal_names_checklist_and_target(self, tmp_path: Path, caplog):
        target, out = _write_out_dir(tmp_path, {
            "target_path": str(tmp_path / "target"),
            "files": [],
        })
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        with caplog.at_level("ERROR", logger="core.audit.orchestrator"):
            run_orchestrator(config, _clean_review)
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "empty inventory" in text
        assert str(out / "checklist.json") in text
        assert str(tmp_path / "target") in text

    def test_artifact_kind_only_checklist_refuses(self, tmp_path: Path):
        # Items exist but every one is an extraction-artifact kind the
        # default review loop never dispatches — still a silent no-op
        # shape, still refused.
        target, out = _write_out_dir(tmp_path, {
            "target_path": str(tmp_path / "target"),
            "files": [{"path": "a.c", "items": [
                {"name": "d1", "kind": "declaration",
                 "line_start": 1, "line_end": 1},
                {"name": "M1", "kind": "constant_macro",
                 "line_start": 2, "line_end": 2},
            ]}],
        })
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        result = run_orchestrator(config, _clean_review)
        assert result.terminated_by == "empty_inventory"

    def test_macro_recovery_can_rescue_an_empty_inventory(
        self, tmp_path: Path, monkeypatch,
    ):
        # ORDERING PIN: the guard fires AFTER macro recovery, which
        # can only ADD items — a generator-macro-only file set the
        # recovery rescues must proceed to a normal review, not be
        # refused at startup. A guard moved before the recovery fails
        # this test.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "gen.c").write_text(
            "DEFINE_HANDLER(gen_fn)\n"
            "int body_marker;\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        (out / "checklist.json").write_text(json.dumps({
            "target_path": str(target),
            "files": [],
        }))

        import core.audit.preprocessor_view as ppv

        def _fake_augment(checklist, target_path, **kwargs):
            checklist.setdefault("files", []).append({
                "path": "src/gen.c",
                "items": [{
                    "name": "gen_fn", "line_start": 1, "line_end": 2,
                    "macro_defined": True,
                }],
            })
            return 1

        monkeypatch.setattr(
            ppv, "augment_checklist_with_macro_functions", _fake_augment,
        )
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        result = run_orchestrator(config, _clean_review)
        assert result.terminated_by == "complete"
        assert result.reviewed == 1

    def test_missing_checklist_reason_unchanged(self, tmp_path: Path):
        # The pre-existing missing-file lane keeps its own stop reason;
        # empty_inventory is only the file-exists-but-describes-nothing
        # case.
        target = tmp_path / "target"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
        )
        result = run_orchestrator(config, _clean_review)
        assert result.terminated_by == "no_checklist"


@pytest.mark.slow
class TestFullCoverageZeroGapsStillCompletes:
    def test_second_run_over_reviewed_inventory_completes(
        self, tmp_path: Path,
    ):
        # Items exist; coverage (run 1's review journal) accounts for
        # all of them, so run 2 legitimately computes ZERO gaps. That
        # run must keep presenting as today: terminated_by="complete"
        # (exit 0 at the CLI), nothing re-reviewed — the guard fires on
        # empty INVENTORIES, never on full coverage.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "auth.c").write_text(
            "int check_pw(char *pw, int len) {\n"
            "  char buf[256];\n"
            "  memcpy(buf, pw, len);\n"
            "  return buf[0];\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        (out / "checklist.json").write_text(json.dumps({
            "target_path": str(target),
            "files": [{"path": "src/auth.c", "items": [
                {"name": "check_pw", "line_start": 1, "line_end": 5},
            ]}],
        }))

        first = run_orchestrator(
            OrchestratorConfig(target_path=target, out_dir=out,
                               resume=False),
            _clean_review,
        )
        assert first.terminated_by == "complete"
        assert first.reviewed == 1

        second = run_orchestrator(
            OrchestratorConfig(target_path=target, out_dir=out,
                               resume=False),
            _clean_review,
        )
        assert second.terminated_by == "complete"
        assert second.reviewed == 0


@pytest.fixture(scope="module")
def audit_cli():
    """Import the raptor-audit script as a module (trust marker set)."""
    import os

    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        spec = importlib.util.spec_from_loader(
            "raptor_audit_cli_empty_inv",
            importlib.machinery.SourceFileLoader(
                "raptor_audit_cli_empty_inv", str(_SCRIPT),
            ),
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["raptor_audit_cli_empty_inv"] = mod
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.modules.pop("raptor_audit_cli_empty_inv", None)
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


class TestCliRefusalPresentation:
    def test_empty_inventory_is_not_a_completed_stop(self, audit_cli):
        assert "empty_inventory" not in audit_cli._COMPLETED_STOP_REASONS
        assert audit_cli._exit_code_for("empty_inventory") == 1

    def test_finalize_fails_lifecycle_and_skips_summary(
        self, audit_cli, tmp_path: Path, monkeypatch, capsys,
    ):
        # The refusal must NOT print the "Audit complete" line or stamp
        # the run completed — that is the exact silent-no-op shape the
        # guard exists to kill.
        failed: list[tuple[Path, str]] = []
        monkeypatch.setattr(
            audit_cli, "_lifecycle_fail",
            lambda out_dir, reason: failed.append((out_dir, reason)),
        )

        import core.audit.report as report_mod

        def _no_report(*a, **k):  # pragma: no cover - assertion path
            raise AssertionError(
                "generate_report must not run for an empty-inventory "
                "refusal")

        monkeypatch.setattr(report_mod, "generate_report", _no_report)

        class _Result:
            terminated_by = "empty_inventory"

        rc = audit_cli._finalize_run(tmp_path, _Result(), "")
        captured = capsys.readouterr()
        assert rc == 1
        assert failed and failed[0][0] == tmp_path
        assert "Audit complete" not in captured.out
        assert "Audit refused" in captured.err
