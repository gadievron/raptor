"""`raptor-audit run` never seeds a run from another target's checklist.

A pre-existing run-local checklist (a reused --out dir, or a project
symlink minted before the lifecycle-level target-match gate) whose
recorded ``target_path`` mismatches the run's resolved target is
discarded loudly and rebuilt for the actual target. A matching
checklist keeps today's inheritance byte-for-byte.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest


def _load_cli():
    import os

    cli_path = str(
        Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit",
    )
    loader = SourceFileLoader(
        "raptor_audit_cli_target_match", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_target_match", loader)
    mod = importlib.util.module_from_spec(spec)
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"  # script trust gate (see header)
    try:
        loader.exec_module(mod)
    finally:
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior
    return mod


class TestMismatchedChecklistTargetHelper:
    def _write(self, tmp_path: Path, **fields) -> Path:
        p = tmp_path / "checklist.json"
        p.write_text(json.dumps(fields))
        return p

    def test_different_tree_is_a_mismatch(self, tmp_path: Path):
        mod = _load_cli()
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        p = self._write(tmp_path, target_path=str(a), files=[])
        assert mod._mismatched_checklist_target(p, b) == str(a)

    def test_file_inside_recorded_tree_is_still_a_mismatch(
        self, tmp_path: Path,
    ):
        # The inventory describes the tree's items, not the file's.
        mod = _load_cli()
        a = tmp_path / "a"
        a.mkdir()
        inner = a / "main.c"
        inner.write_text("int main(void) { return 0; }\n")
        p = self._write(tmp_path, target_path=str(a), files=[])
        assert mod._mismatched_checklist_target(p, inner) == str(a)

    def test_same_target_matches(self, tmp_path: Path):
        mod = _load_cli()
        a = tmp_path / "a"
        a.mkdir()
        p = self._write(tmp_path, target_path=str(a), files=[])
        assert mod._mismatched_checklist_target(p, a) is None

    def test_symlinked_spelling_of_same_target_matches(
        self, tmp_path: Path,
    ):
        # resolve() equality: two spellings of one tree never trigger
        # a spurious rebuild.
        mod = _load_cli()
        a = tmp_path / "a"
        a.mkdir()
        alias = tmp_path / "alias"
        alias.symlink_to(a)
        p = self._write(tmp_path, target_path=str(alias), files=[])
        assert mod._mismatched_checklist_target(p, a) is None

    def test_missing_recorded_target_fails_open(self, tmp_path: Path):
        mod = _load_cli()
        p = self._write(tmp_path, files=[])
        assert mod._mismatched_checklist_target(
            p, tmp_path / "b") is None

    def test_relative_recorded_target_fails_open(self, tmp_path: Path):
        mod = _load_cli()
        p = self._write(tmp_path, target_path="src/tree", files=[])
        assert mod._mismatched_checklist_target(
            p, tmp_path / "b") is None

    def test_unparseable_checklist_fails_open(self, tmp_path: Path):
        # Corrupt files keep their existing downstream failure modes;
        # the gate only acts on a positive mismatch.
        mod = _load_cli()
        p = tmp_path / "checklist.json"
        p.write_text("{not json")
        assert mod._mismatched_checklist_target(
            p, tmp_path / "b") is None

    def test_resolve_runtimeerror_fails_open(
        self, tmp_path: Path, monkeypatch,
    ):
        # Python 3.10-3.12 raise RuntimeError from Path.resolve() on
        # symlink loops (this host resolves loops quietly, so the
        # error is injected). A planted loop must fail OPEN — no
        # discard, no traceback out of cmd_run — matching the gate's
        # positive-mismatch-only contract.
        mod = _load_cli()
        sentinel = "/loop-sentinel-recorded"
        p = self._write(tmp_path, target_path=sentinel, files=[])
        real_resolve = Path.resolve

        def _looping_resolve(self, *a, **k):
            if str(self) == sentinel:
                raise RuntimeError(
                    f"Symlink loop from {sentinel!r}")
            return real_resolve(self, *a, **k)

        monkeypatch.setattr(Path, "resolve", _looping_resolve)
        assert mod._mismatched_checklist_target(
            p, tmp_path / "b") is None


class _SentinelStop(Exception):
    """Raised by the stubbed binary-oracle step to end cmd_run right
    after the checklist gate + build decision under test."""


def _run_cmd_run(tmp_path, monkeypatch, out_dir, target):
    """Drive cmd_run with lifecycle stubbed to OUTPUT_DIR=out_dir and
    the checklist build stubbed to fail fast; returns (rc, calls)."""
    mod = _load_cli()
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append([str(c) for c in cmd])
        if "raptor-run-lifecycle" in str(cmd[0]):
            return SimpleNamespace(
                returncode=0, stdout=f"OUTPUT_DIR={out_dir}\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="stub stop")

    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_lifecycle_fail", lambda *a, **k: None)

    # End the match-path deterministically right after the checklist
    # section: the next target-derived step is the binary oracle.
    import core.analysis.binary_oracle_cli as bo_cli

    def _stop(*a, **k):
        raise _SentinelStop

    monkeypatch.setattr(bo_cli, "apply_to_config", _stop)

    args = SimpleNamespace(target=str(target), out=str(out_dir))
    return mod, calls, args


@pytest.mark.slow
class TestCmdRunChecklistGate:
    def test_mismatch_discards_and_rebuilds(
        self, tmp_path: Path, monkeypatch, capsys,
    ):
        target_a = tmp_path / "target-a"
        target_b = tmp_path / "target-b"
        target_a.mkdir()
        target_b.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "checklist.json").write_text(json.dumps(
            {"target_path": str(target_a), "files": []}))

        mod, calls, args = _run_cmd_run(
            tmp_path, monkeypatch, out_dir, target_b)
        rc = mod.cmd_run(args)
        assert rc == 1  # stopped at the stubbed checklist BUILD

        # The stale real file was set aside (evidence, not deleted)
        # and the rebuild path was taken.
        assert not (out_dir / "checklist.json").exists()
        asides = list(out_dir.glob("checklist.json.mismatched-target-*"))
        assert len(asides) == 1
        assert any(
            "raptor-build-checklist" in c[0] for c in calls
        ), "mismatch must route into the rebuild path"
        err = capsys.readouterr().err
        assert "checklist target mismatch" in err
        assert str(target_a) in err
        assert str(target_b.resolve()) in err

    def test_mismatched_symlink_dropped_project_copy_kept(
        self, tmp_path: Path, monkeypatch,
    ):
        target_a = tmp_path / "target-a"
        target_b = tmp_path / "target-b"
        target_a.mkdir()
        target_b.mkdir()
        proj = tmp_path / "proj"
        run = proj / "run"
        run.mkdir(parents=True)
        proj_cl = proj / "checklist.json"
        proj_cl.write_text(json.dumps(
            {"target_path": str(target_a), "files": []}))
        (run / "checklist.json").symlink_to("../checklist.json")

        mod, calls, args = _run_cmd_run(
            tmp_path, monkeypatch, run, target_b)
        rc = mod.cmd_run(args)
        assert rc == 1  # stubbed rebuild fails fast

        assert not (run / "checklist.json").exists()
        # Only the LINK is dropped — target A's project checklist
        # stays intact for its own runs.
        assert proj_cl.exists()
        assert json.loads(proj_cl.read_text())["target_path"] == str(
            target_a)

    def test_second_mismatch_preserves_first_set_aside(
        self, tmp_path: Path, monkeypatch,
    ):
        # "Evidence, never deleted" must survive a SECOND mismatch in
        # the same out dir: the set-aside name is timestamp+counter
        # unique, so replace() can never land on an earlier one.
        target_a = tmp_path / "target-a"
        target_b = tmp_path / "target-b"
        target_a.mkdir()
        target_b.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        for round_no in (1, 2):
            (out_dir / "checklist.json").write_text(json.dumps(
                {"target_path": str(target_a), "files": [],
                 "round": round_no}))
            mod, calls, args = _run_cmd_run(
                tmp_path, monkeypatch, out_dir, target_b)
            assert mod.cmd_run(args) == 1  # stubbed rebuild fails fast
        asides = sorted(
            out_dir.glob("checklist.json.mismatched-target-*"))
        assert len(asides) == 2, asides
        rounds = {json.loads(p.read_text())["round"] for p in asides}
        assert rounds == {1, 2}

    def _write_sharded(self, monkeypatch, out_dir: Path,
                       target: Path) -> None:
        """A run-local SHARDED checklist recording *target*."""
        import core.inventory as inv
        from core.inventory import save_checklist
        monkeypatch.setattr(inv, "_MAX_CHECKLIST_BYTES", 64)
        try:
            save_checklist(out_dir, {
                "target_path": str(target),
                "files": [{"path": "a.c", "items": [], "sloc": 1}],
            })
        finally:
            monkeypatch.undo()
        assert (out_dir / "checklist" / "index.json").is_file()

    def test_sharded_mismatch_discards_and_rebuilds(
        self, tmp_path: Path, monkeypatch, capsys,
    ):
        # The gate must see the SHARDED form too: a single-file probe
        # here plus the form-aware rebuild probe silently audited
        # target B against target A's sharded inventory.
        target_a = tmp_path / "target-a"
        target_b = tmp_path / "target-b"
        target_a.mkdir()
        target_b.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_sharded(monkeypatch, out_dir, target_a)

        mod, calls, args = _run_cmd_run(
            tmp_path, monkeypatch, out_dir, target_b)
        rc = mod.cmd_run(args)
        assert rc == 1  # stopped at the stubbed checklist BUILD

        # The stale sharded layout was set aside (evidence, never
        # deleted) and the rebuild path was taken.
        assert not (out_dir / "checklist" / "index.json").exists()
        asides = list(out_dir.glob("checklist.mismatched-target-*"))
        assert len(asides) == 1
        assert (asides[0] / "index.json").is_file()
        assert any(
            "raptor-build-checklist" in c[0] for c in calls
        ), "sharded mismatch must route into the rebuild path"
        err = capsys.readouterr().err
        assert "checklist target mismatch" in err

    def test_sharded_match_kept_no_rebuild(
        self, tmp_path: Path, monkeypatch,
    ):
        target_a = tmp_path / "target-a"
        target_a.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        self._write_sharded(monkeypatch, out_dir, target_a)

        mod, calls, args = _run_cmd_run(
            tmp_path, monkeypatch, out_dir, target_a)
        with pytest.raises(_SentinelStop):
            mod.cmd_run(args)

        assert (out_dir / "checklist" / "index.json").is_file()
        assert not any(
            "raptor-build-checklist" in c[0] for c in calls
        ), "a matching sharded checklist must be inherited, not rebuilt"

    def test_matching_checklist_kept_no_rebuild(
        self, tmp_path: Path, monkeypatch,
    ):
        target_a = tmp_path / "target-a"
        target_a.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        before = json.dumps({"target_path": str(target_a), "files": []})
        (out_dir / "checklist.json").write_text(before)

        mod, calls, args = _run_cmd_run(
            tmp_path, monkeypatch, out_dir, target_a)
        with pytest.raises(_SentinelStop):
            mod.cmd_run(args)

        assert (out_dir / "checklist.json").read_text() == before
        assert not any(
            "raptor-build-checklist" in c[0] for c in calls
        ), "a matching checklist must keep today's inheritance"
