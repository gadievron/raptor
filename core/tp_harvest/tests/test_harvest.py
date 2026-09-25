"""Tests for core.tp_harvest.harvest and the CLI (hermetic, synthetic)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.json import load_json
from core.tp_harvest.cli import main as cli_main
from core.tp_harvest.harvest import (
    backlog_path,
    harvest_run,
    load_manifest,
    load_record,
    manifest_path,
    record_path,
)

from .conftest import make_finding


class TestHarvestRun:
    def test_harvests_confirmed_only_with_enumerated_skips(
            self, run_dir: Path):
        summary = harvest_run(run_dir)
        assert summary["findings_total"] == 3
        assert len(summary["harvested"]) == 1
        assert summary["skipped"] == {
            "status_negative": 1,
            "status_unverified": 1,
        }

    def test_emits_record_candidate_and_backlog(self, run_dir: Path):
        summary = harvest_run(run_dir)
        hid = summary["harvested"][0]
        rec = load_record(run_dir, hid)
        assert rec is not None
        assert rec.harvest_id == hid
        assert rec.status == "exploitable"
        manifest = load_manifest(run_dir)
        entry = manifest["entries"][hid]
        assert entry["action"] == "harvested"
        assert entry["backlog"] is True
        assert entry["label"] is None
        assert (run_dir / entry["record"]).is_file()
        assert entry["candidate"] and (run_dir / entry["candidate"]).is_file()
        backlog = backlog_path(run_dir).read_text(encoding="utf-8")
        assert hid in backlog

    def test_rerun_is_a_noop(self, run_dir: Path):
        first = harvest_run(run_dir)
        record_file = record_path(run_dir, first["harvested"][0])
        before = record_file.read_bytes()
        backlog_before = backlog_path(run_dir).read_bytes()

        second = harvest_run(run_dir)
        assert second["harvested"] == []
        assert second["skipped"]["already_harvested"] == 1
        assert record_file.read_bytes() == before
        # No duplicate backlog pointers on re-run.
        assert backlog_path(run_dir).read_bytes() == backlog_before

    def test_new_finding_after_first_pass_is_picked_up(self, run_dir: Path):
        harvest_run(run_dir)
        data = load_json(run_dir / "findings.json", strict=True)
        data["findings"].append(make_finding(
            id="FIND-9", function="main", line=11, status="confirmed",
            final_status="confirmed"))
        (run_dir / "findings.json").write_text(json.dumps(data),
                                               encoding="utf-8")
        summary = harvest_run(run_dir)
        assert len(summary["harvested"]) == 1
        assert summary["skipped"]["already_harvested"] == 1

    def test_skipped_entries_are_reclassified_on_status_change(
            self, run_dir: Path):
        harvest_run(run_dir)
        data = load_json(run_dir / "findings.json", strict=True)
        for f in data["findings"]:
            if f["id"] == "FIND-3":  # was confirmed_unverified
                f["final_status"] = "exploitable"
                f["status"] = "exploitable"
        (run_dir / "findings.json").write_text(json.dumps(data),
                                               encoding="utf-8")
        summary = harvest_run(run_dir)
        assert len(summary["harvested"]) == 1

    def test_duplicate_rows_in_one_pass_skip(self, run_dir: Path):
        data = load_json(run_dir / "findings.json", strict=True)
        data["findings"].append(make_finding())  # identical identity
        (run_dir / "findings.json").write_text(json.dumps(data),
                                               encoding="utf-8")
        summary = harvest_run(run_dir)
        assert summary["skipped"]["duplicate_in_run"] == 1

    def test_empty_run_dir_is_graceful(self, tmp_path: Path):
        empty = tmp_path / "empty-run"
        empty.mkdir()
        summary = harvest_run(empty)
        assert summary["harvested"] == []
        assert summary["findings_total"] == 0
        assert any("nothing to harvest" in n for n in summary["notes"])
        # Manifest still written: the pass is auditable even when empty.
        assert manifest_path(empty).is_file()

    def test_no_candidates_flag(self, run_dir: Path):
        summary = harvest_run(run_dir, with_candidates=False)
        hid = summary["harvested"][0]
        entry = load_manifest(run_dir)["entries"][hid]
        assert entry["candidate"] is None


class TestStructureGate:
    """M-class: a hostile run dir pre-plants symlinks under
    tp-harvest/ to re-route harvest writes (candidate aimed at
    engine/semgrep/rules/ = auto-enable; backlog aimed at a host file
    = arbitrary append). Any symlink in the tree refuses."""

    def _plant(self, run_dir: Path, rel: str, victim: Path) -> None:
        p = run_dir / "tp-harvest" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.symlink_to(victim)

    def test_planted_candidate_symlink_refused(
            self, run_dir: Path, tmp_path: Path):
        from core.tp_harvest.harvest import HostileRunDirError
        from core.tp_harvest.records import harvest_identity
        hid = harvest_identity(make_finding())
        victim = tmp_path / "engine-victim.yaml"
        self._plant(run_dir, f"candidates/{hid}.candidate.yaml", victim)
        with pytest.raises(HostileRunDirError):
            harvest_run(run_dir)
        assert not victim.exists()

    def test_planted_backlog_symlink_refused(
            self, run_dir: Path, tmp_path: Path):
        from core.tp_harvest.harvest import HostileRunDirError
        victim = tmp_path / "victim.txt"
        victim.write_text("pre\n", encoding="utf-8")
        self._plant(run_dir, "disclosure-backlog.jsonl", victim)
        with pytest.raises(HostileRunDirError):
            harvest_run(run_dir)
        assert victim.read_text(encoding="utf-8") == "pre\n"

    def test_symlinked_subdir_refused(self, run_dir: Path, tmp_path: Path):
        # A dir-level symlink re-roots every "safe" final-component
        # write — per-file O_NOFOLLOW / atomic rename cannot see it.
        from core.tp_harvest.harvest import HostileRunDirError
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        self._plant(run_dir, "candidates", elsewhere)
        with pytest.raises(HostileRunDirError):
            harvest_run(run_dir)

    def test_symlinked_harvest_root_refused(
            self, run_dir: Path, tmp_path: Path):
        from core.tp_harvest.harvest import HostileRunDirError
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (run_dir / "tp-harvest").symlink_to(elsewhere)
        with pytest.raises(HostileRunDirError):
            harvest_run(run_dir)

    def test_cli_surfaces_refuse_too(self, run_dir: Path, tmp_path: Path,
                                     capsys):
        self._plant(run_dir, "disclosure-backlog.jsonl",
                    tmp_path / "victim")
        for argv in ([str(run_dir)], [str(run_dir), "--status"]):
            assert cli_main(argv) == 1
            assert "refusing run dir" in capsys.readouterr().err

    def test_clean_tree_passes(self, run_dir: Path):
        # Direction guard: the gate must not refuse legitimate output.
        first = harvest_run(run_dir)
        assert first["harvested"]
        second = harvest_run(run_dir)  # gate re-walks the real tree
        assert second["skipped"]["already_harvested"] == 1


class TestContainment:
    """M-class: finding paths are attacker-influenced — reads must be
    confined to the target tree (skip by name, never silent)."""

    def _hostile_run(self, tmp_path: Path, target_tree: Path,
                     file_value: str) -> Path:
        run = tmp_path / "hostile-run"
        run.mkdir()
        (run / ".raptor-run.json").write_text(json.dumps({
            "version": 2, "command": "validate", "status": "completed",
            "target_path": str(target_tree)}), encoding="utf-8")
        (run / "findings.json").write_text(json.dumps(
            [make_finding(file=file_value, line=1)]), encoding="utf-8")
        return run

    def test_traversal_and_absolute_paths_skip(
            self, tmp_path: Path, target_tree: Path):
        secret = tmp_path / "secret.c"
        secret.write_text("leak_me(token, region)\n", encoding="utf-8")
        for hostile in ("../secret.c", str(secret)):
            run = self._hostile_run(tmp_path, target_tree, hostile)
            summary = harvest_run(run)
            assert summary["harvested"] == [], hostile
            assert summary["skipped"] == {"path_escapes_target": 1}
            # Nothing emitted: no record, no candidate, no pointer.
            tph = run / "tp-harvest"
            assert not list(tph.glob("records/*"))
            assert not list(tph.glob("candidates/*.yaml"))
            assert not backlog_path(run).exists()
            import shutil
            shutil.rmtree(run)

    def test_in_target_absolute_path_still_harvests(
            self, tmp_path: Path, target_tree: Path):
        run = self._hostile_run(
            tmp_path, target_tree, str(target_tree / "src" / "copy.c"))
        # line=1 is the #include — candidate underivable, but the
        # finding itself harvests (confine admits in-target absolutes).
        summary = harvest_run(run)
        assert len(summary["harvested"]) == 1


class TestRobustness:
    """S-class: one malformed row skips by name; the pass continues."""

    def test_malformed_rows_do_not_abort_the_pass(
            self, run_dir: Path):
        data = load_json(run_dir / "findings.json", strict=True)
        data["findings"] = [
            "not-a-dict-row",
            make_finding(id="F-badline", line="not-a-number"),
            make_finding(id="F-dictstatus", line=7,
                         status={"a": "b"}, final_status=None),
            *data["findings"],
        ]
        (run_dir / "findings.json").write_text(json.dumps(data),
                                               encoding="utf-8")
        summary = harvest_run(run_dir)
        # The good confirmed finding still harvests; hostile rows all
        # land on enumerated skips.
        assert len(summary["harvested"]) == 1
        assert summary["skipped"]["finding_malformed"] == 1
        assert summary["skipped"]["missing_location"] == 1
        assert summary["skipped"]["status_not_confirmed"] == 1

    def test_projection_crash_skips_row_and_continues(
            self, run_dir: Path, monkeypatch):
        # The per-finding except is the containment boundary for row
        # shapes the coercion net doesn't know yet: a crash on ONE row
        # must skip it by name, not abort the pass. (JSON-shaped input
        # cannot currently reach it — the coercions above catch the
        # known shapes — so it is pinned with an injected crash.)
        import core.tp_harvest.harvest as harvest_module
        data = load_json(run_dir / "findings.json", strict=True)
        data["findings"].insert(0, make_finding(
            id="F-boom", function="main", line=11, status="confirmed",
            final_status="confirmed"))
        (run_dir / "findings.json").write_text(json.dumps(data),
                                               encoding="utf-8")
        real = harvest_module.build_record

        def exploding(finding, **kwargs):
            if finding.get("id") == "F-boom":
                raise RuntimeError("future-shape crash")
            return real(finding, **kwargs)

        monkeypatch.setattr(harvest_module, "build_record", exploding)
        summary = harvest_run(run_dir)
        assert summary["skipped"]["finding_malformed"] == 1
        assert len(summary["harvested"]) == 1  # the good row survived

    def test_deleted_record_reharvest_does_not_duplicate_backlog(
            self, run_dir: Path):
        first = harvest_run(run_dir)
        hid = first["harvested"][0]
        record_path(run_dir, hid).unlink()
        second = harvest_run(run_dir)
        assert second["harvested"] == [hid]  # re-emitted
        rows = [json.loads(ln) for ln in backlog_path(run_dir)
                .read_text(encoding="utf-8").splitlines()]
        assert len([r for r in rows if r["harvest_id"] == hid]) == 1

    def test_tampered_record_marked_not_silent(self, run_dir: Path,
                                               capsys):
        first = harvest_run(run_dir)
        hid = first["harvested"][0]
        rec_file = record_path(run_dir, hid)
        rec_file.write_text(rec_file.read_text(encoding="utf-8")
                            .replace("exploitable", "clean"),
                            encoding="utf-8")
        second = harvest_run(run_dir)
        assert second["skipped"]["already_harvested"] == 1
        assert any("tampered" in n for n in second["notes"])
        entry = load_manifest(run_dir)["entries"][hid]
        assert entry["record_tampered"] is True
        cli_main([str(run_dir), "--status"])
        assert "[record tampered]" in capsys.readouterr().out


class TestOracleVerifiedFlag:
    def test_flag_propagates_to_manifest_and_status(
            self, run_dir: Path, capsys):
        (run_dir / "verified-outcomes.jsonl").write_text(
            json.dumps({
                "finding_id": "FIND-1", "oracle": "sandbox",
                "status": "verified", "reproducible": True,
                "evidence": {"bytes_hash": "ab" * 16},
            }) + "\n", encoding="utf-8")
        summary = harvest_run(run_dir)
        hid = summary["harvested"][0]
        entry = load_manifest(run_dir)["entries"][hid]
        assert entry["oracle_verified"] is True
        rec = load_record(run_dir, hid)
        assert rec.oracle_verified is True
        cli_main([str(run_dir), "--status"])
        assert "[oracle-verified]" in capsys.readouterr().out

    def test_status_boolean_only_confirmation_stays_false(
            self, run_dir: Path):
        summary = harvest_run(run_dir)
        entry = load_manifest(run_dir)["entries"][summary["harvested"][0]]
        assert entry["oracle_verified"] is False


class TestStatusSanitisation:
    """M-class: --status renders attacker-influencible manifest values
    (imported run dirs ship their own manifest) — no raw escapes."""

    def test_hostile_status_never_reaches_terminal_raw(
            self, run_dir: Path, capsys):
        data = load_json(run_dir / "findings.json", strict=True)
        data["findings"] = [make_finding(
            status="ruled_out\x1b]0;PWNED\x07\x1b[2J",
            final_status=None, is_true_positive=None)]
        del data["findings"][0]["is_true_positive"]
        (run_dir / "findings.json").write_text(json.dumps(data),
                                               encoding="utf-8")
        harvest_run(run_dir)
        cli_main([str(run_dir), "--status"])
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "\x07" not in out

    def test_attacker_authored_manifest_rendered_inert(
            self, tmp_path: Path, capsys):
        run = tmp_path / "imported-run"
        (run / "tp-harvest").mkdir(parents=True)
        (run / "tp-harvest" / "harvest-manifest.json").write_text(
            json.dumps({"schema_version": 1, "run_dir": str(run),
                        "entries": {"\x1b[31mEVIL\x1b[0m": {
                            "action": "harvested\x1b]0;x\x07",
                            "status": "ok\x1b[2J"}}}),
            encoding="utf-8")
        assert cli_main([str(run), "--status"]) == 0
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "invalid id" in out
        assert "(unknown)" in out


class TestDirtyPinGate:
    def _label_argv(self, run_dir: Path, hid: str, base: Path) -> list:
        return [str(run_dir), "--label", hid,
                "--provenance", "own-target",
                "--bug-class", "trap", "--rationale", "x",
                "--repo", "up/stream", "--labels-base", str(base)]

    def test_unknowable_dirtiness_refuses(self, run_dir: Path,
                                          tmp_path: Path, capsys,
                                          monkeypatch):
        import core.tp_harvest.labels as labels_mod
        hid = harvest_run(run_dir)["harvested"][0]
        capsys.readouterr()
        # dirty=None: the probes could not tell. Unknowable != clean.
        monkeypatch.setattr(
            labels_mod, "derive_target_pin",
            lambda _t: {"commit": "c" * 40, "dirty": None})
        assert cli_main(self._label_argv(run_dir, hid,
                                         tmp_path / "labels")) == 1
        assert "unknowable" in capsys.readouterr().err

    def test_proven_clean_tree_auto_pins(self, run_dir: Path,
                                         tmp_path: Path, capsys,
                                         monkeypatch):
        import core.tp_harvest.labels as labels_mod
        hid = harvest_run(run_dir)["harvested"][0]
        monkeypatch.setattr(
            labels_mod, "derive_target_pin",
            lambda _t: {"commit": "c" * 40, "dirty": False})
        assert cli_main(self._label_argv(run_dir, hid,
                                         tmp_path / "labels")) == 0
        assert "label written" in capsys.readouterr().out


class TestCli:
    def test_harvest_then_status(self, run_dir: Path, capsys):
        assert cli_main([str(run_dir)]) == 0
        out = capsys.readouterr().out
        assert "newly harvested: 1" in out
        assert "status_negative: 1" in out

        assert cli_main([str(run_dir), "--status"]) == 0
        out = capsys.readouterr().out
        assert "harvested" in out
        assert "on disclosure backlog" in out
        assert "backlog pointers: 1" in out

    def test_json_summary(self, run_dir: Path, capsys):
        assert cli_main([str(run_dir), "--json"]) == 0
        summary = json.loads(capsys.readouterr().out)
        assert summary["findings_total"] == 3

    def test_label_flip_end_to_end(self, run_dir: Path, tmp_path: Path,
                                   capsys):
        cli_main([str(run_dir)])
        hid = load_json(manifest_path(run_dir), strict=True)
        hid = next(k for k, v in hid["entries"].items()
                   if v["action"] == "harvested")
        base = tmp_path / "labels"
        rc = cli_main([
            str(run_dir), "--label", hid,
            "--provenance", "public",
            "--bug-class", "trap",
            "--rationale", "overflow at pinned span",
            "--repo", "https://example.invalid/up.git",
            "--sha", "0" * 40,
            "--fix-commit", "1" * 40,
            "--labels-base", str(base),
        ])
        out = capsys.readouterr()
        assert rc == 0, out.err
        assert "label written" in out.out
        entry = load_json(manifest_path(run_dir),
                          strict=True)["entries"][hid]
        assert entry["label"] and Path(entry["label"]).is_file()

    def test_label_without_provenance_refuses(self, run_dir: Path, capsys):
        cli_main([str(run_dir)])
        capsys.readouterr()
        hid = next(k for k, v in load_manifest(run_dir)["entries"].items()
                   if v["action"] == "harvested")
        rc = cli_main([
            str(run_dir), "--label", hid,
            "--bug-class", "trap", "--rationale", "x",
            "--repo", "r",
        ])
        assert rc == 2
        assert "--provenance" in capsys.readouterr().err

    def test_label_id_charset_validated_before_path_use(
            self, run_dir: Path, capsys):
        cli_main([str(run_dir)])
        capsys.readouterr()
        rc = cli_main([
            str(run_dir), "--label", "../../../etc/passwd",
            "--provenance", "own-target",
            "--bug-class", "trap", "--rationale", "x", "--repo", "r",
            "--sha", "0" * 40,
        ])
        assert rc == 2
        assert "invalid harvest id" in capsys.readouterr().err

    def test_label_unknown_id_errors(self, run_dir: Path, capsys):
        cli_main([str(run_dir)])
        capsys.readouterr()
        rc = cli_main([
            str(run_dir), "--label", "f" * 32,
            "--provenance", "own-target",
            "--bug-class", "trap", "--rationale", "x", "--repo", "r",
            "--sha", "0" * 40,
        ])
        assert rc == 1
        assert "run the harvest first" in capsys.readouterr().err

    def test_missing_dir_errors(self, tmp_path: Path, capsys):
        rc = cli_main([str(tmp_path / "nope")])
        assert rc == 1
        assert "not a directory" in capsys.readouterr().err
