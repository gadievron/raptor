"""A failed Ghidra close retains live owners and incomplete scratch removal."""

from unittest.mock import Mock

import pytest

from packages.ghidra import session, server


@pytest.mark.parametrize("stage", ["decompiler", "program", "project", "directory"])
def test_session_cleanup_retains_failed_owner_and_retries(tmp_path, monkeypatch, stage):
    instance = session.GhidraSession()
    work = tmp_path / "work"
    work.mkdir()
    (work / "keep").write_text("working database")
    instance._work_dir = str(work)
    decomp, program, project = Mock(), Mock(), Mock()
    consumer = object()
    instance._decomp, instance._program, instance._consumer, instance._project = (
        decomp,
        program,
        consumer,
        project,
    )
    failed = {
        "decompiler": decomp.dispose,
        "program": program.release,
        "project": project.close,
    }.get(stage)
    with monkeypatch.context() as fault:
        if failed is not None:
            failed.side_effect = OSError("busy")
        else:
            fault.setattr(session, "rmtree_hardened", lambda path: False)
        instance.close()
        assert instance._work_dir == str(work)
        assert (work / "keep").read_text() == "working database"
        if stage == "decompiler":
            assert instance._decomp is decomp
            program.release.assert_not_called()
            project.close.assert_not_called()
        elif stage == "program":
            assert instance._program is program and instance._consumer is consumer
            project.close.assert_not_called()
        elif stage == "project":
            assert instance._project is project
    if failed is not None:
        failed.side_effect = None
    instance.close()
    assert instance._work_dir is None
    assert (
        instance._project is None
        and instance._program is None
        and instance._decomp is None
    )
    assert not work.exists()


def test_open_refuses_to_forget_existing_project(tmp_path, monkeypatch):
    instance = session.GhidraSession()
    instance._project = Mock()
    monkeypatch.setattr(
        instance, "ensure_jvm", Mock(side_effect=AssertionError("must not start"))
    )
    with pytest.raises(session.GhidraSessionError, match="already owns"):
        instance.open(tmp_path / "other.gpr")
    assert instance._project is not None
    instance.close()


def test_server_failed_removal_retains_paths_but_refuses_partial_project_reuse(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(server, "pyghidra_available", lambda: True)
    instance = server.GhidraServer(tmp_path / "source.gpr")
    work = tmp_path / "work"
    work.mkdir()
    gpr = work / "p.gpr"
    gpr.write_text("header")
    instance._work_dir, instance._work_gpr = work, gpr
    with monkeypatch.context() as fault:
        fault.setattr(server, "rmtree_hardened", lambda path: False)
        instance.stop()
        assert instance._work_dir == work and instance._work_gpr == gpr
        assert instance.enriched_gpr is None
        with pytest.raises(server.GhidraServerError, match="cleanup is incomplete"):
            instance.restart()
        with pytest.raises(server.GhidraServerError, match="cleanup is incomplete"):
            instance.persist_enriched(tmp_path / "saved")
    instance.stop()
    assert instance._work_dir is None and instance._work_gpr is None
    assert not work.exists()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_persist_failure_preserves_existing_deliverable(tmp_path, monkeypatch, error):
    from packages.ghidra import project_util

    monkeypatch.setattr(server, "pyghidra_available", lambda: True)
    source = tmp_path / "source"
    source.mkdir()
    gpr = source / "p.gpr"
    gpr.write_text("new header")
    (source / "p.rep").mkdir()
    instance = server.GhidraServer(gpr)
    instance._work_gpr = gpr
    out = tmp_path / "saved"
    out.mkdir()
    (out / "p.gpr").write_text("old header")
    (out / "p.rep").mkdir()
    (out / "p.rep/keep").write_text("old database")
    failure = error("database copy failed")

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(project_util, "_copy_rep_tree", fail)
    with pytest.raises(error) as caught:
        instance.persist_enriched(out)
    assert caught.value is failure
    assert (out / "p.gpr").read_text() == "old header"
    assert (out / "p.rep/keep").read_text() == "old database"
    assert not list(out.glob(".ghidra-copy-*"))


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_open_keeps_unremoved_scratch_for_later_close(
    tmp_path, monkeypatch, error
):
    instance = session.GhidraSession()
    monkeypatch.setattr(instance, "ensure_jvm", lambda: None)
    failure = error("copy failed")

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(session, "prepare_working_copy", fail)
    with monkeypatch.context() as fault:
        fault.setattr(session, "rmtree_hardened", lambda path: False)
        with pytest.raises(error) as caught:
            instance.open(tmp_path / "source.gpr")
        assert caught.value is failure
        work = instance._work_dir
        assert work is not None
    from pathlib import Path

    assert Path(work).exists()
    instance.close()
    assert instance._work_dir is None and not Path(work).exists()


def test_persist_uses_bounded_copy_without_changing_working_project(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(server, "pyghidra_available", lambda: True)
    source = tmp_path / "source"
    source.mkdir()
    gpr = source / "p.gpr"
    gpr.write_bytes(b"header")
    (source / "p.rep").mkdir()
    (source / "p.rep/data").write_bytes(b"database")
    instance = server.GhidraServer(gpr)
    instance._work_gpr = gpr
    result = instance.persist_enriched(tmp_path / "saved")
    assert result.read_bytes() == b"header"
    assert result.with_suffix(".rep").joinpath("data").read_bytes() == b"database"
    assert gpr.read_bytes() == b"header"
    assert (source / "p.rep/data").read_bytes() == b"database"
