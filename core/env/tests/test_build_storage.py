"""Real filesystem checks; only the incidental container daemon is replaced."""

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.env import build
from core.run import scratch
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def build_case(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Makefile").write_text("all:\n")
    out = tmp_path / "out"
    calls = []

    def image(**kwargs):
        calls.append(Path(kwargs["context_dir"]))
        return SimpleNamespace(ok=True)

    def export(_tag, root):
        for name in ("a", "b"):
            path = root / "src" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x7fELF" + name.encode() * 16)
            path.chmod(0o755)
        return SimpleNamespace(ok=True)

    monkeypatch.setattr("core.container.build.build_image", image)
    monkeypatch.setattr("core.container.export.export_rootfs", export)
    monkeypatch.setattr("core.container.lifecycle.remove_labeled_images", lambda *a, **k: None)
    monkeypatch.setattr("core.container.lifecycle.prune_labeled_dangling", lambda *a, **k: None)
    return repo, out, calls


@pytest.mark.parametrize("placement", ["outside", "nested", "same", "alias"])
def test_workspace_on_output_filesystem_without_recursive_copy(build_case, monkeypatch, placement):
    repo, out, calls = build_case
    if placement == "nested":
        out = repo / "outputs"
    elif placement == "same":
        out = repo
    elif placement == "alias":
        alias = repo.parent / "alias"
        alias.symlink_to(repo, target_is_directory=True)
        repo, out = alias, alias / "outputs"
    out.mkdir(exist_ok=True)
    (out / "borrowed").write_text("retain")
    (repo / ".git").mkdir()

    def image(**kwargs):
        ctx = Path(kwargs["context_dir"])
        calls.append(ctx)
        assert ctx.parent.parent.resolve() == out.resolve()
        assert str(ctx.parent) in scratch._keepalive_paths
        assert (ctx / "src" / "Makefile").is_file()
        assert not (ctx / "src" / ".git").exists()
        assert not list((ctx / "src").rglob("raptor-env-build-*"))
        return SimpleNamespace(ok=True)

    monkeypatch.setattr("core.container.build.build_image", image)
    result = build.containerized_build(repo, "make", out_dir=out)
    assert result.ok
    assert (out / "borrowed").read_text() == "retain"
    assert not calls[0].parent.exists()
    for key, path in result.artifacts.items():
        assert path.stat().st_mode & 0o777 == 0o444
        assert result.checksums[key] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, SystemExit])
def test_both_image_cleanups_attempted(build_case, monkeypatch, failure):
    repo, out, calls = build_case
    cleaned = []

    def remove(*a, **k):
        cleaned.append("tagged")
        raise failure("cleanup")

    monkeypatch.setattr("core.container.lifecycle.remove_labeled_images", remove)
    monkeypatch.setattr("core.container.lifecycle.prune_labeled_dangling", lambda *a, **k: cleaned.append("dangling"))
    if failure is OSError:
        result = build.containerized_build(repo, "make", out_dir=out)
        assert not result.ok
        assert not result.artifacts and not result.checksums
    else:
        with pytest.raises(failure, match="cleanup"):
            build.containerized_build(repo, "make", out_dir=out)
    assert cleaned == ["tagged", "dangling"]
    assert list(out.iterdir()) == []
    assert not calls[0].parent.exists()


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, SystemExit])
def test_raised_work_error_survives_cleanup_errors(build_case, monkeypatch, failure):
    repo, out, _ = build_case
    primary = failure("primary")
    cleaned = []

    def image(**kwargs):
        raise primary

    def remove(*a, **k):
        cleaned.append("tagged")
        raise RuntimeError("secondary")

    monkeypatch.setattr("core.container.build.build_image", image)
    monkeypatch.setattr("core.container.lifecycle.remove_labeled_images", remove)
    monkeypatch.setattr("core.container.lifecycle.prune_labeled_dangling", lambda *a, **k: cleaned.append("dangling"))
    if failure is OSError:
        result = build.containerized_build(repo, "make", out_dir=out)
        assert result.detail == "primary"
    else:
        with pytest.raises(failure) as caught:
            build.containerized_build(repo, "make", out_dir=out)
        assert caught.value is primary
    assert cleaned == ["tagged", "dangling"]
    assert list(out.iterdir()) == []


@pytest.mark.parametrize("phase", ["copy", "hash", "publish"])
@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, SystemExit])
def test_later_artifact_failure_rolls_back_published_files(build_case, monkeypatch, phase, failure):
    repo, out, _ = build_case
    out.mkdir()
    (out / "borrowed").write_text("retain")
    original = {"copy": build.shutil.copy2, "hash": build._sha256, "publish": build.rename_without_replace}[phase]
    count = 0

    def operation(*args, **kwargs):
        nonlocal count
        # copytree also uses copy2, but holds its original default binding.
        count += 1
        if count == 2:
            if phase == "copy":
                Path(args[1]).write_bytes(b"partial")
            raise failure("artifact")
        return original(*args, **kwargs)

    if phase == "copy":
        patch_module_attribute(monkeypatch, build, "shutil", "copy2", operation)
    else:
        monkeypatch.setattr(build, "_sha256" if phase == "hash" else "rename_without_replace", operation)
    if failure is OSError:
        result = build.containerized_build(repo, "make", out_dir=out)
        assert not result.ok
        assert not result.artifacts and not result.checksums
    else:
        with pytest.raises(failure, match="artifact"):
            build.containerized_build(repo, "make", out_dir=out)
    assert [p.name for p in out.iterdir()] == ["borrowed"]


@pytest.mark.parametrize("kind", ["file", "directory", "dangling", "symlink", "fifo"])
def test_preexisting_outputs_are_preserved(build_case, kind):
    repo, out, _ = build_case
    out.mkdir()
    occupied = out / "a"
    if kind == "directory":
        occupied.mkdir()
    elif kind == "dangling":
        occupied.symlink_to("missing")
    elif kind == "symlink":
        (out / "target").write_text("retain")
        occupied.symlink_to("target")
    elif kind == "fifo":
        os.mkfifo(occupied)
    else:
        occupied.write_text("retain")
    before = occupied.lstat()
    result = build.containerized_build(repo, "make", out_dir=out)
    assert result.ok
    assert result.artifacts["a"].name == "a.1"
    assert occupied.lstat().st_ino == before.st_ino
    if kind in ("file", "symlink"):
        assert occupied.read_text() == "retain"


def test_publication_race_preserves_contender(build_case, monkeypatch):
    repo, out, _ = build_case
    original = build.rename_without_replace
    raced = False

    def publish(src, dst):
        nonlocal raced
        if not raced:
            raced = True
            dst.write_text("contender")
        return original(src, dst)

    monkeypatch.setattr(build, "rename_without_replace", publish)
    result = build.containerized_build(repo, "make", out_dir=out)
    assert result.ok
    assert (out / "a").read_text() == "contender"
    assert result.artifacts["a"].name == "a.1"


def test_cancellation_after_native_publication_rolls_back(build_case, monkeypatch):
    repo, out, _ = build_case
    original = build.rename_without_replace

    def publish(src, dst):
        original(src, dst)
        raise KeyboardInterrupt("published")

    monkeypatch.setattr(build, "rename_without_replace", publish)
    with pytest.raises(KeyboardInterrupt, match="published"):
        build.containerized_build(repo, "make", out_dir=out)
    assert list(out.iterdir()) == []


def test_artifacts_invisible_until_complete(build_case, monkeypatch):
    repo, out, _ = build_case
    original = build._sha256

    def digest(path):
        assert path.parent.parent == out
        assert path.stat().st_mode & 0o777 == 0o444
        assert (out / "a").exists() == (path.name != "artifact-0")
        return original(path)

    monkeypatch.setattr(build, "_sha256", digest)
    assert build.containerized_build(repo, "make", out_dir=out).ok


def test_rollback_preserves_replacement_inode(build_case, monkeypatch):
    repo, out, _ = build_case
    original = build._sha256
    retained = []

    def digest(path):
        if path.name == "artifact-1":
            # Keep the original inode alive so replacement cannot reuse it.
            (out / "a").rename(path.parent / "retired")
            (out / "a").write_text("replacement")
            retained.append(out / "a")
            raise OSError("later")
        return original(path)

    monkeypatch.setattr(build, "_sha256", digest)
    result = build.containerized_build(repo, "make", out_dir=out)
    assert not result.ok
    assert retained[0].read_text() == "replacement"
    assert list(out.iterdir()) == retained


def test_publication_collisions_are_bounded(build_case, monkeypatch):
    repo, out, _ = build_case
    collisions = []

    def publish(src, dst):
        dst.write_text("contender")
        collisions.append(dst)
        raise FileExistsError(dst)

    monkeypatch.setattr(build, "rename_without_replace", publish)
    result = build.containerized_build(repo, "make", out_dir=out)
    assert not result.ok
    assert not result.artifacts and not result.checksums
    assert len(collisions) == 16
    assert set(out.iterdir()) == set(collisions)
    assert all(path.read_text() == "contender" for path in collisions)


def test_rollback_attempts_remaining_files_after_unlink_failure(build_case, monkeypatch):
    repo, out, _ = build_case
    original = Path.unlink
    attempts = []

    def unlink(path, *args, **kwargs):
        if path.parent == out:
            attempts.append(path.name)
            if path.name == "b":
                raise OSError("cannot remove b")
        return original(path, *args, **kwargs)

    def remove(*a, **k):
        raise KeyboardInterrupt("cleanup")

    class FaultPath(type(out)):
        def unlink(self, *args, **kwargs):
            return unlink(self, *args, **kwargs)

    monkeypatch.setattr(build, "Path", FaultPath)
    monkeypatch.setattr("core.container.lifecycle.remove_labeled_images", remove)
    with pytest.raises(KeyboardInterrupt, match="cleanup"):
        build.containerized_build(repo, "make", out_dir=out)
    assert attempts == ["b", "a"]
    assert [path.name for path in out.iterdir()] == ["b"]


@pytest.mark.parametrize("kind", ["file", "dangling"])
def test_invalid_output_parent_is_structured_without_building(build_case, kind):
    repo, out, calls = build_case
    if kind == "file":
        out.write_text("retain")
    else:
        out.symlink_to("missing")
    result = build.containerized_build(repo, "make", out_dir=out)
    assert not result.ok
    assert result.reason == "export_failed"
    assert calls == []
    if kind == "file":
        assert out.read_text() == "retain"
    else:
        assert out.is_symlink()
