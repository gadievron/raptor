"""Resume and credential staging publish only complete, owned directory trees."""

import errno
import os
from pathlib import Path

import pytest

from core.testing.restricted_tree import restricted_tree
from packages.openant import resume, scanner


@pytest.fixture
def prior(tmp_path):
    root = tmp_path / "prior"
    root.mkdir()
    (root / "checkpoint.json").write_text('{"done":true}')
    return root


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize(
    "error", [OSError, resume.OpenAntResumeError, KeyboardInterrupt]
)
def test_failed_seed_removes_only_private_partial_copy(
    prior, tmp_path, monkeypatch, existing, error
):
    dest = tmp_path / "new"
    if existing:
        dest.mkdir()

    def copy(src, target):
        (target / "partial").write_text("copied")
        raise error("copy failed")

    monkeypatch.setattr(resume, "_copy_regular_tree", copy)
    with pytest.raises(resume.OpenAntResumeError if error is OSError else error):
        resume.seed_scan_dir(prior, dest)
    assert dest.exists() is existing
    if existing:
        assert list(dest.iterdir()) == []
    assert list(tmp_path.glob("raptor-openant-seed-*")) == []
    assert (prior / "checkpoint.json").read_text() == '{"done":true}'


@pytest.mark.parametrize(
    "kind", ["empty_link", "populated_link", "dangling_link", "file"]
)
def test_seed_refuses_non_directory_and_symlink_destinations(prior, tmp_path, kind):
    real = tmp_path / "operator-data"
    real.mkdir()
    if kind == "populated_link":
        (real / "payload").write_text("keep")
    dest = tmp_path / "new"
    if kind == "file":
        dest.write_text("keep")
    else:
        dest.symlink_to(
            tmp_path / "absent" if kind == "dangling_link" else real,
            target_is_directory=True,
        )
    before = list(real.iterdir())
    with pytest.raises(resume.OpenAntResumeError):
        resume.seed_scan_dir(prior, dest)
    assert list(real.iterdir()) == before
    if kind != "file":
        assert dest.is_symlink()
    else:
        assert dest.read_text() == "keep"


@pytest.mark.parametrize("relation", ["same", "child", "ancestor"])
def test_seed_refuses_overlapping_source_and_destination(prior, tmp_path, relation):
    dest = {"same": prior, "child": prior / "new", "ancestor": tmp_path}[relation]
    with pytest.raises(resume.OpenAntResumeError):
        resume.seed_scan_dir(prior, dest)
    assert (prior / "checkpoint.json").read_text() == '{"done":true}'
    assert not (prior / "new").exists()


def test_seed_preserves_destination_created_during_copy(prior, tmp_path, monkeypatch):
    dest = tmp_path / "new"
    copy = resume._copy_regular_tree

    def replace(src, target):
        copy(src, target)
        if dest.exists():
            dest.rename(tmp_path / "old-destination")
        dest.mkdir()
        (dest / "operator-data").write_text("keep")

    monkeypatch.setattr(resume, "_copy_regular_tree", replace)
    with pytest.raises(resume.OpenAntResumeError):
        resume.seed_scan_dir(prior, dest)
    assert (dest / "operator-data").read_text() == "keep"
    assert not (dest / "checkpoint.json").exists()
    assert list(tmp_path.glob("raptor-openant-seed-*")) == []


@pytest.mark.parametrize("mode", ["rb", "wb"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_copy_stream_setup_failure_closes_every_owned_descriptor(
    prior, tmp_path, monkeypatch, mode, error
):
    directory = os.open(prior, os.O_RDONLY | os.O_DIRECTORY)
    opened = []
    original_open = os.open
    original_fdopen = os.fdopen

    def track(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def fail(fd, stream_mode, **kwargs):
        if stream_mode == mode:
            raise error("stream setup failed")
        return original_fdopen(fd, stream_mode, **kwargs)

    monkeypatch.setattr(os, "open", track)
    monkeypatch.setattr(os, "fdopen", fail)
    try:
        with pytest.raises(error):
            resume._copy_regular_file(
                "checkpoint.json", tmp_path / "copy", dir_fd=directory
            )
        for fd in opened:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
    finally:
        os.close(directory)


@pytest.fixture
def out(tmp_path, monkeypatch):
    root = tmp_path / "out"
    root.mkdir()
    monkeypatch.setattr(
        scanner, "_operator_config_path", lambda: tmp_path / "absent.json"
    )
    return root


@pytest.mark.parametrize("phase", ["mkdir", "write", "publish"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_credential_stage_leaves_no_partial_config(
    out, monkeypatch, phase, error
):
    if phase == "mkdir":
        mkdir = Path.mkdir

        def fail(path, *args, **kwargs):
            if path.name == "openant":
                raise error("mkdir failed")
            return mkdir(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", fail)
    elif phase == "write":

        def fail(path, *args, **kwargs):
            path.write_text("partial secret")
            raise error("write failed")

        monkeypatch.setattr(scanner, "write_text_atomically", fail)
    else:

        def fail(*args, **kwargs):
            raise error("publish failed")

        monkeypatch.setattr(os, "rename", fail)
    with pytest.raises(error):
        scanner._stage_llm_config(out, "sonnet")
    assert list(out.iterdir()) == []


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("action", ["scrub", "restage"])
def test_credential_cleanup_reclaims_restricted_stage(out, mode, action):
    stage = out / scanner._XDG_STAGE_DIRNAME
    with restricted_tree(stage, mode):
        if action == "scrub":
            scanner._scrub_stage(out)
            assert not stage.exists()
        else:
            scanner._stage_llm_config(out, "sonnet")
            assert (stage / "openant" / "config.json").is_file()
            assert not (stage / "payload").exists()


def test_credential_scrub_unlinks_replacement_file(out):
    stage = out / scanner._XDG_STAGE_DIRNAME
    stage.write_text("leftover config")
    scanner._scrub_stage(out)
    assert not stage.exists()


def test_config_is_private_before_it_is_published(out, monkeypatch):
    stage = out / scanner._XDG_STAGE_DIRNAME
    write = scanner.write_text_atomically

    def observe(path, *args, **kwargs):
        assert not stage.exists()
        assert path.parent.parent.stat().st_mode & 0o777 == 0o700
        return write(path, *args, **kwargs)

    monkeypatch.setattr(scanner, "write_text_atomically", observe)
    assert scanner._stage_llm_config(out, "sonnet") == stage
    assert (stage / "openant" / "config.json").stat().st_mode & 0o777 == 0o600
    assert list(out.iterdir()) == [stage]


@pytest.mark.parametrize("existing", [False, True])
def test_successful_seed_is_published_only_after_complete_copy(
    prior, tmp_path, monkeypatch, existing
):
    dest = tmp_path / "new"
    if existing:
        dest.mkdir(mode=0o750)
    copy = resume._copy_regular_tree

    def observe(src, target):
        assert target != dest
        assert dest.exists() is existing
        if existing:
            assert list(dest.iterdir()) == []
        copy(src, target)
        assert not (dest / "checkpoint.json").exists()

    monkeypatch.setattr(resume, "_copy_regular_tree", observe)
    assert resume.seed_scan_dir(prior, dest) == 1
    assert (dest / "checkpoint.json").read_bytes() == (
        prior / "checkpoint.json"
    ).read_bytes()
    if existing:
        assert dest.stat().st_mode & 0o777 == 0o750
    assert list(tmp_path.glob("raptor-openant-seed-*")) == []


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_seed_reclaims_restricted_partial_tree(
    prior, tmp_path, monkeypatch, mode, error
):
    dest = tmp_path / "new"

    def copy(src, target):
        locked = target / "locked"
        locked.mkdir()
        (locked / "payload").write_text("partial checkpoints")
        locked.chmod(mode)
        raise error("copy failed")

    monkeypatch.setattr(resume, "_copy_regular_tree", copy)
    with pytest.raises(resume.OpenAntResumeError if error is OSError else error):
        resume.seed_scan_dir(prior, dest)
    assert not dest.exists()
    assert list(tmp_path.glob("raptor-openant-seed-*")) == []


def test_failed_old_stage_cleanup_blocks_restaging_without_masking_scrub(
    out, monkeypatch
):
    stage = out / scanner._XDG_STAGE_DIRNAME
    stage.mkdir()
    payload = stage / "old-config"
    payload.write_text("retained credential")
    monkeypatch.setattr(scanner, "rmtree_hardened", lambda path: False)
    scanner._scrub_stage(out)  # runtime teardown remains best-effort
    with pytest.raises(OSError, match="previous OpenAnt config stage"):
        scanner._stage_llm_config(out, "sonnet")
    assert payload.read_text() == "retained credential"
    assert list(out.iterdir()) == [stage]
