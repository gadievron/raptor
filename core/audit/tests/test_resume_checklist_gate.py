"""`raptor-audit resume` never re-inherits another target's checklist.

Live-hit production shape: a binary run's segment-1 inventory was
replaced at segment-2 resume by the project slot's then-current
checklist — built for a SIBLING target — because the resume prep
re-read the slot through the run-dir symlink with no target-match
gate; the resumed segment reviewed 1,000+ of the other binary's
items until killed. The launch path has the gate
(``_mismatched_checklist_target``, pinned by
test_checklist_target_mismatch.py); these tests pin the RESUME side:

* run-local wins — a run-local inventory is the run's own segment-1
  artifact; an inherited symlink beside it is dropped (loud skip
  note), never followed, and neither the run-local inventory nor the
  project-level file is modified;
* no-run-local (legacy) resumes inherit WITH the gate — a matching
  slot keeps the historical inheritance, a mismatched slot refuses
  the resume loudly with the rebuild remedy.
"""

from __future__ import annotations

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

_CLI_MOD = None


def _load_cli():
    global _CLI_MOD
    if _CLI_MOD is not None:
        return _CLI_MOD
    cli_path = str(
        Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit",
    )
    loader = SourceFileLoader("raptor_audit_cli_resume_gate", cli_path)
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_resume_gate", loader)
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
    _CLI_MOD = mod
    return mod


def _checklist_doc(target: Path, tag: str) -> dict:
    return {
        "target_path": str(target),
        "target_kind": "source",
        "files": [{
            "path": f"{tag}.c",
            "items": [{"function": f"{tag}_fn", "line_start": 1,
                       "line_end": 2}],
        }],
        "total_files": 1,
        "total_items": 1,
    }


@pytest.fixture()
def shape(tmp_path: Path):
    """Project dir with a slot checklist for target B; run dir with a
    symlink to the slot; targets A and B exist on disk."""
    target_a = tmp_path / "target-a"
    target_a.mkdir()
    target_b = tmp_path / "target-b"
    target_b.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    (project / "checklist.json").write_text(
        json.dumps(_checklist_doc(target_b, "other")))
    run_dir = project / "audit-run"
    run_dir.mkdir()
    (run_dir / "checklist.json").symlink_to("../checklist.json")
    return SimpleNamespace(
        target_a=target_a, target_b=target_b,
        project=project, run_dir=run_dir,
    )


class TestResumeChecklistGate:
    def test_runlocal_inventory_wins_over_inherited_symlink(
            self, shape, monkeypatch, capsys):
        mod = _load_cli()
        # The production shape: the run holds its OWN inventory for
        # target A (run-local sharded form — the only on-disk form
        # that can coexist with an inherited checklist.json symlink),
        # while the shared slot now holds target B's.
        import core.inventory as inv
        with monkeypatch.context() as m:
            m.setattr(inv, "_MAX_CHECKLIST_BYTES", 16)  # force sharding
            (shape.run_dir / "checklist.json").unlink()
            inv.save_checklist(
                shape.run_dir, _checklist_doc(shape.target_a, "own"))
        assert (shape.run_dir / "checklist" / "index.json").is_file()
        (shape.run_dir / "checklist.json").symlink_to("../checklist.json")

        # BASE defect: the accessors resolve the symlink BEFORE the
        # sharded probe, so the resume re-read serves target B's slot
        # content in target A's run.
        assert inv.read_checklist(shape.run_dir).get("target_path") \
            == str(shape.target_b)

        err = mod._resume_checklist_gate(shape.run_dir, shape.target_a)
        assert err is None
        # Loud skip note; the shadowing LINK is gone; the run's own
        # inventory is what the resume now reads.
        assert "run-local inventory" in capsys.readouterr().err
        assert not (shape.run_dir / "checklist.json").is_symlink()
        assert not (shape.run_dir / "checklist.json").exists()
        assert inv.read_checklist(shape.run_dir).get("target_path") \
            == str(shape.target_a)
        # No overwrite in either direction: the project-level file
        # still holds target B's inventory byte-for-byte.
        assert json.loads(
            (shape.project / "checklist.json").read_text()
        ).get("target_path") == str(shape.target_b)

    def test_mismatched_inheritance_refused_without_runlocal(
            self, shape, capsys):
        mod = _load_cli()
        err = mod._resume_checklist_gate(shape.run_dir, shape.target_a)
        # Refused with the rebuild remedy; the LINK is dropped so the
        # named rebuild lands run-local; the project-level file
        # belongs to the other target's runs and is untouched.
        assert err is not None
        assert "raptor-build-checklist" in err
        assert "checklist target mismatch at resume" in \
            capsys.readouterr().err
        assert not (shape.run_dir / "checklist.json").is_symlink()
        assert (shape.project / "checklist.json").is_file()

    def test_matching_inheritance_is_kept(self, shape):
        mod = _load_cli()
        # Legacy no-run-local resume against a slot built for THIS
        # run's target: historical inheritance preserved, gate silent.
        (shape.project / "checklist.json").write_text(
            json.dumps(_checklist_doc(shape.target_a, "own")))
        err = mod._resume_checklist_gate(shape.run_dir, shape.target_a)
        assert err is None
        assert (shape.run_dir / "checklist.json").is_symlink()

    def test_runlocal_file_needs_no_gate(self, tmp_path: Path):
        mod = _load_cli()
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        target = tmp_path / "t"
        target.mkdir()
        (run_dir / "checklist.json").write_text(
            json.dumps(_checklist_doc(target, "own")))
        assert mod._resume_checklist_gate(run_dir, target) is None
        assert (run_dir / "checklist.json").is_file()


class TestResumeGateFailsClosedOnUncomparable:
    """RESUME fails CLOSED where LAUNCH deliberately fails open.

    The launch gate keeps fail-open on uncomparable slots (a
    legitimate first run may inherit a legacy checklist that predates
    target stamping — pinned by test_checklist_target_mismatch.py).
    A RESUMED run provably had a usable inventory at segment 1, so an
    inherited slot that can no longer be provenance-checked is
    strictly anomalous: the gate refuses (before any status flip),
    drops the run-local link, and names the rebuild remedy. The
    project-level file is never modified.
    """

    def _assert_refused(self, mod, shape, capsys) -> None:
        slot_before = (shape.project / "checklist.json").read_bytes()
        err = mod._resume_checklist_gate(shape.run_dir, shape.target_a)
        assert err is not None
        assert "provenance-checked" in err
        assert "raptor-build-checklist" in err
        assert "provenance uncheckable at resume" in \
            capsys.readouterr().err
        # The run-local LINK is dropped so the named rebuild lands
        # run-local; the project-level file is untouched.
        assert not (shape.run_dir / "checklist.json").is_symlink()
        assert (shape.project / "checklist.json").read_bytes() \
            == slot_before

    def test_corrupt_slot_json_refuses(self, shape, capsys):
        mod = _load_cli()
        (shape.project / "checklist.json").write_text("{not json")
        self._assert_refused(mod, shape, capsys)

    def test_missing_target_path_refuses(self, shape, capsys):
        mod = _load_cli()
        doc = _checklist_doc(shape.target_a, "own")
        del doc["target_path"]
        (shape.project / "checklist.json").write_text(json.dumps(doc))
        self._assert_refused(mod, shape, capsys)

    def test_relative_target_path_refuses(self, shape, capsys):
        mod = _load_cli()
        doc = _checklist_doc(shape.target_a, "own")
        doc["target_path"] = "target-a"
        (shape.project / "checklist.json").write_text(json.dumps(doc))
        self._assert_refused(mod, shape, capsys)

    def test_matching_absolute_target_still_inherits(self, shape):
        # The other direction: fail-closed must not break the
        # comparable, matching inheritance.
        mod = _load_cli()
        (shape.project / "checklist.json").write_text(
            json.dumps(_checklist_doc(shape.target_a, "own")))
        assert mod._resume_checklist_gate(
            shape.run_dir, shape.target_a) is None
        assert (shape.run_dir / "checklist.json").is_symlink()

    def test_dangling_link_keeps_the_existence_probe_refusal(
            self, shape, capsys):
        # A dangling inherited link is NOT the fail-closed case: the
        # gate passes (nothing to vet, link kept) and cmd_resume's
        # existing checklist existence probe refuses with its own
        # "nothing to resume" message, exactly as before.
        mod = _load_cli()
        (shape.project / "checklist.json").unlink()
        assert mod._resume_checklist_gate(
            shape.run_dir, shape.target_a) is None
        assert (shape.run_dir / "checklist.json").is_symlink()
        assert capsys.readouterr().err == ""


class TestCmdResumeWiring:
    def test_resume_refuses_the_swapped_slot(
            self, shape, monkeypatch, capsys):
        """The exact production entry point: `raptor-audit resume` on
        a run whose inherited slot now holds another target's
        inventory refuses at the gate — before any status flip or
        review work."""
        mod = _load_cli()
        run_dir = shape.run_dir
        meta = {
            "version": 2,
            "command": "audit",
            "status": "interrupted",
            "target_path": str(shape.target_a),
            "extra": {},
        }
        (run_dir / ".raptor-run.json").write_text(json.dumps(meta))
        (run_dir / "audit-run-config.json").write_text(
            json.dumps({"target_path": str(shape.target_a)}))
        args = SimpleNamespace(out_dir=str(run_dir), reopen=False)
        rc = mod.cmd_resume(args)
        assert rc == 1
        err = capsys.readouterr().err
        assert "checklist target mismatch at resume" in err
        assert "raptor-build-checklist" in err
        # Refused BEFORE resume_run: the run is not flipped to
        # running by a resume that did no work.
        assert json.loads(
            (run_dir / ".raptor-run.json").read_text()
        )["status"] == "interrupted"
