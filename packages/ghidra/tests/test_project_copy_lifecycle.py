"""Bounded project copying must preserve inputs and previous deliverables."""

import pytest

from packages.ghidra import project_util as util


import packages.ghidra.project_util as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def project(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    gpr = source / "p.gpr"
    gpr.write_bytes(b"head")
    rep = source / "p.rep"
    rep.mkdir()
    (rep / "data").write_bytes(b"data")
    return gpr


@pytest.mark.parametrize("quota", ["bytes", "entries"])
def test_copy_quota_failure_preserves_previous_pair(
    project, tmp_path, monkeypatch, quota
):
    out = tmp_path / "out"
    out.mkdir()
    (out / "p.gpr").write_bytes(b"old header")
    (out / "p.rep").mkdir()
    (out / "p.rep/keep").write_bytes(b"old database")
    monkeypatch.setattr(
        util,
        "MAX_REP_COPY_BYTES" if quota == "bytes" else "MAX_REP_COPY_ENTRIES",
        5 if quota == "bytes" else 1,
        raising=False,
    )
    with pytest.raises(ValueError):
        util.prepare_working_copy(project, out)
    assert (out / "p.gpr").read_bytes() == b"old header"
    assert (out / "p.rep/keep").read_bytes() == b"old database"
    assert not list(out.glob(".ghidra-copy-*"))


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_database_copy_preserves_previous_pair(
    project, tmp_path, monkeypatch, error
):
    out = tmp_path / "out"
    out.mkdir()
    (out / "p.gpr").write_bytes(b"old header")
    (out / "p.rep").mkdir()
    (out / "p.rep/keep").write_bytes(b"old database")
    failure = error("copy failed")

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(util, "_copy_rep_tree", fail)
    with pytest.raises(error) as caught:
        util.prepare_working_copy(project, out)
    assert caught.value is failure
    assert (out / "p.gpr").read_bytes() == b"old header"
    assert (out / "p.rep/keep").read_bytes() == b"old database"


@pytest.mark.parametrize("alias", [False, True])
def test_copy_never_deletes_source_when_destination_aliases_it(
    project, tmp_path, alias
):
    out = project.parent
    if alias:
        out = tmp_path / "alias"
        out.symlink_to(project.parent, target_is_directory=True)
    with pytest.raises(ValueError):
        util.prepare_working_copy(project, out)
    assert project.read_bytes() == b"head"
    assert project.with_suffix(".rep").joinpath("data").read_bytes() == b"data"


def test_existing_restricted_database_is_replaced(project, tmp_path):
    from core.testing.restricted_tree import restricted_tree

    out = tmp_path / "out"
    out.mkdir()
    with restricted_tree(out / "p.rep", 0o555):
        util.prepare_working_copy(project, out)
        assert (out / "p.rep/data").read_bytes() == b"data"
        assert not (out / "p.rep/locked").exists()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize(
    "phase",
    [
        "retire-header",
        "retire-database",
        "retire-lock",
        "publish-header",
        "publish-database",
    ],
)
def test_publication_failure_restores_old_pair_and_lock(
    project, tmp_path, monkeypatch, error, after, phase
):
    import os

    out = tmp_path / "out"
    out.mkdir()
    (out / "p.gpr").write_bytes(b"old header")
    (out / "p.rep").mkdir()
    (out / "p.rep/keep").write_bytes(b"old database")
    (out / "p.lock").write_bytes(b"old lock")
    failure = error("publication failed")
    rename = os.rename

    def fail(src, dst):
        kinds = {
            out / "p.gpr": "header",
            out / "p.rep": "database",
            out / "p.lock": "lock",
        }
        active = (
            "retire-" + kinds[src]
            if src in kinds
            else "publish-" + kinds[dst]
            if dst in kinds and src.parent.name.startswith(".ghidra-copy-")
            else None
        )
        if active == phase:
            if after:
                rename(src, dst)
            raise failure
        return rename(src, dst)

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "rename", fail)
    with pytest.raises(error) as caught:
        util.prepare_working_copy(project, out)
    assert caught.value is failure
    assert (out / "p.gpr").read_bytes() == b"old header"
    assert (out / "p.rep/keep").read_bytes() == b"old database"
    assert (out / "p.lock").read_bytes() == b"old lock"
    assert not list(out.glob(".ghidra-copy-*"))
    assert not list(out.glob(".ghidra-retired-*"))


def test_failed_rollback_keeps_previous_database_available(
    project, tmp_path, monkeypatch
):
    import os

    out = tmp_path / "out"
    out.mkdir()
    (out / "p.gpr").write_bytes(b"old header")
    (out / "p.rep").mkdir()
    (out / "p.rep/keep").write_bytes(b"old database")
    rename = os.rename

    def fail(src, dst):
        if dst == out / "p.rep":
            raise OSError("publication and restore unavailable")
        return rename(src, dst)

    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "rename", fail)
    with pytest.raises(OSError):
        util.prepare_working_copy(project, out)
    assert (out / "p.gpr").read_bytes() == b"old header"
    backups = list(out.glob(".ghidra-retired-*"))
    assert len(backups) == 1
    assert (backups[0] / "p.rep/keep").read_bytes() == b"old database"
    assert not list(out.glob(".ghidra-copy-*"))


@pytest.mark.parametrize("header", [False, True])
def test_growing_input_is_bounded_by_actual_bytes(
    project, tmp_path, monkeypatch, header
):

    path = project if header else project.with_suffix(".rep") / "data"
    monkeypatch.setattr(util, "MAX_REP_COPY_BYTES", 16)
    opener = util.open_regular_gated if header else util.open_regular_beneath

    def growing(*args, **kwargs):
        stream = opener(*args, **kwargs)

        class Source:
            changed = False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                stream.close()

            def fileno(self):
                return stream.fileno()

            def read(self, count):
                if not self.changed:
                    self.changed = True
                    with path.open("ab") as output:
                        output.write(b"x" * 100)
                return stream.read(count)

        return Source()

    monkeypatch.setattr(
        util, "open_regular_gated" if header else "open_regular_beneath", growing
    )
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="cap|ceiling"):
        util.prepare_working_copy(project, out)
    assert not (out / "p.gpr").exists()
    assert not (out / "p.rep").exists()
    assert not list(out.glob(".ghidra-copy-*"))


def test_destination_inside_source_database_is_refused(project):
    out = project.with_suffix(".rep") / "nested"
    with pytest.raises(ValueError, match="overlaps"):
        util.prepare_working_copy(project, out)
    assert project.read_bytes() == b"head"
    assert not out.exists()


def test_source_inside_previous_destination_is_not_retired(tmp_path):
    out = tmp_path / "out"
    source = out / "p.rep/input"
    source.mkdir(parents=True)
    gpr = source / "p.gpr"
    gpr.write_bytes(b"head")
    (source / "p.rep").mkdir()
    with pytest.raises(ValueError, match="overlaps"):
        util.prepare_working_copy(gpr, out)
    assert gpr.read_bytes() == b"head"


@pytest.mark.parametrize("kind", ["symlink", "dangling", "file"])
def test_invalid_destination_database_is_preserved(project, tmp_path, kind):
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep").write_text("keep")
    if kind == "file":
        (out / "p.rep").write_text("keep")
    else:
        (out / "p.rep").symlink_to(
            victim if kind == "symlink" else tmp_path / "absent",
            target_is_directory=True,
        )
    with pytest.raises(ValueError):
        util.prepare_working_copy(project, out)
    assert (victim / "keep").read_text() == "keep"
    assert (out / "p.rep").is_symlink() or (out / "p.rep").read_text() == "keep"


def test_walk_failure_does_not_publish_partial_database(project, tmp_path, monkeypatch):
    def failed(root, **kwargs):
        kwargs["onerror"](PermissionError("cannot enumerate database"))
        yield

    patch_module_attribute(monkeypatch, util, 'os', "walk", failed)
    out = tmp_path / "out"
    with pytest.raises(OSError):
        util.prepare_working_copy(project, out)
    assert not (out / "p.gpr").exists()
    assert not list(out.glob(".ghidra-copy-*"))


def test_empty_directory_farm_consumes_entry_budget(project, tmp_path, monkeypatch):
    rep = project.with_suffix(".rep")
    (rep / "data").unlink()
    for number in range(10):
        (rep / f"dir{number}").mkdir()
    monkeypatch.setattr(util, "MAX_REP_COPY_ENTRIES", 5)
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="entries"):
        util.prepare_working_copy(project, out)
    assert not (out / "p.gpr").exists()
    assert not list(out.glob(".ghidra-copy-*"))


def test_source_changed_within_budget_is_not_published(project, tmp_path, monkeypatch):
    opener = util.open_regular_gated

    def changed(*args, **kwargs):
        stream = opener(*args, **kwargs)

        class Source:
            changed = False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                stream.close()

            def fileno(self):
                return stream.fileno()

            def read(self, count):
                if not self.changed:
                    self.changed = True
                    project.write_bytes(b"new header")
                return stream.read(count)

        return Source()

    monkeypatch.setattr(util, "open_regular_gated", changed)
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="changed"):
        util.prepare_working_copy(project, out)
    assert not (out / "p.gpr").exists()


@pytest.mark.parametrize("change", ["edit", "replace-header", "replace-database"])
def test_destination_changed_during_staging_is_preserved(
    project, tmp_path, monkeypatch, change
):
    out = tmp_path / "out"
    out.mkdir()
    (out / "p.gpr").write_bytes(b"old header")
    (out / "p.rep").mkdir()
    copy = util._copy_rep_tree

    def changed(*args, **kwargs):
        copy(*args, **kwargs)
        if change == "replace-header":
            (out / "p.gpr").rename(out / "operator-saved")
        elif change == "replace-database":
            (out / "p.rep").rename(out / "operator-saved-database")
            (out / "p.rep").mkdir()
        (out / "p.gpr").write_bytes(b"operator header")
        (out / "p.rep/operator").write_bytes(b"operator database")

    monkeypatch.setattr(util, "_copy_rep_tree", changed)
    with pytest.raises(ValueError, match="changed"):
        util.prepare_working_copy(project, out)
    assert (out / "p.gpr").read_bytes() == b"operator header"
    assert (out / "p.rep/operator").read_bytes() == b"operator database"
    assert not list(out.glob(".ghidra-copy-*"))


def test_raced_source_symlink_is_not_copied(project, tmp_path, monkeypatch):
    secret = tmp_path / "keep"
    secret.write_bytes(b"keep")
    source = project.with_suffix(".rep") / "data"
    opener = util.open_regular_beneath

    def raced(*args, **kwargs):
        source.unlink()
        source.symlink_to(secret)
        return opener(*args, **kwargs)

    monkeypatch.setattr(util, "open_regular_beneath", raced)
    out = tmp_path / "out"
    with pytest.raises(OSError):
        util.prepare_working_copy(project, out)
    assert secret.read_bytes() == b"keep"
    assert not (out / "p.gpr").exists()
    assert not list(out.glob(".ghidra-copy-*"))


def test_required_project_lock_failure_does_not_copy(project, tmp_path, monkeypatch):
    from contextlib import contextmanager

    @contextmanager
    def refused(*args, **kwargs):
        assert kwargs["required"] is True
        raise OSError("lock failed")
        yield

    monkeypatch.setattr(util, "artifact_lock", refused)
    out = tmp_path / "out"
    with pytest.raises(OSError):
        util.prepare_working_copy(project, out)
    assert not (out / "p.gpr").exists()
    assert not list(out.glob(".ghidra-copy-*"))


@pytest.mark.parametrize("mask", [0o000, 0o002, 0o077])
def test_header_creation_preserves_existing_umask_policy(project, tmp_path, mask):
    import os
    import stat

    previous = os.umask(mask)
    try:
        copied = util.prepare_working_copy(project, tmp_path / "out")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(copied.stat().st_mode) == (0o644 & ~mask)


@pytest.mark.parametrize("change", ["disappear", "replace", "appear"])
def test_database_root_change_during_header_copy_is_refused(
    project, tmp_path, monkeypatch, change
):
    rep = project.with_suffix(".rep")
    if change == "appear":
        (rep / "data").unlink()
        rep.rmdir()
    copy = util._copy_stream

    def changed(stream, destination, budget, **kwargs):
        copy(stream, destination, budget, **kwargs)
        if kwargs.get("header"):
            if change != "appear":
                rep.rename(project.parent / "operator-saved-database")
            if change != "disappear":
                rep.mkdir()
                (rep / "other").write_bytes(b"new database")

    monkeypatch.setattr(util, "_copy_stream", changed)
    out = tmp_path / "out"
    with pytest.raises((OSError, ValueError)):
        util.prepare_working_copy(project, out)
    assert not (out / "p.gpr").exists()
    assert not (out / "p.rep").exists()
    assert not list(out.glob(".ghidra-copy-*"))
