"""Source acquisition releases failed trees and keeps failed cleanup retryable."""

import io
import tarfile
import zlib
from types import SimpleNamespace

import pytest

from cve_env.tools import source_build as sb
from core.testing.restricted_tree import restricted_tree


def archive():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name in ("repo/first", "repo/second"):
            info = tarfile.TarInfo(name)
            info.size = 16
            tar.addfile(info, io.BytesIO(b"x" * 16))
    return out.getvalue()


@pytest.fixture
def builder():
    return sb.SourceBuilder()


@pytest.mark.parametrize("owner", ["builder", "retained"])
@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_owned_checkout_cleanup_removes_restricted_trees(
    tmp_path, builder, monkeypatch, owner, mode
):
    with restricted_tree(tmp_path / "clone", mode) as tree:
        if owner == "builder":
            builder._temp_dirs.append(tree)
            builder.cleanup()
            assert builder._temp_dirs == []
        else:
            monkeypatch.setattr(sb, "_RETAINED_DIRS", [tree])
            sb._cleanup_retained_dirs()
            assert sb._RETAINED_DIRS == []
        assert not tree.exists()


@pytest.mark.parametrize("owner", ["builder", "retained"])
def test_failed_cleanup_keeps_tracking_for_retry(tmp_path, builder, monkeypatch, owner):
    tree = tmp_path / "clone"
    tree.mkdir()
    if owner == "builder":
        builder._temp_dirs.append(tree)
        cleanup = builder.cleanup
        pending = builder._temp_dirs
    else:
        monkeypatch.setattr(sb, "_RETAINED_DIRS", [tree])
        cleanup = sb._cleanup_retained_dirs
        pending = sb._RETAINED_DIRS
    with monkeypatch.context() as fault:
        fault.setattr(sb, "rmtree_hardened", lambda path: False, raising=False)
        cleanup()
    assert pending == [tree]
    assert tree.exists()
    cleanup()
    assert not tree.exists()
    assert pending == []


@pytest.mark.parametrize(
    "method, failure",
    [
        (method, failure)
        for method in ("shallow", "sha")
        for failure in ("nonzero", "timeout", "interrupt", "checkout")
        if (method, failure) != ("shallow", "checkout")
    ],
)
def test_failed_clone_is_removed_immediately(
    tmp_path, builder, monkeypatch, method, failure
):
    target = tmp_path / "clone"

    def git(*args, **kwargs):
        target.mkdir(exist_ok=True)
        (target / "partial").write_text("clone residue")
        if failure == "interrupt":
            raise KeyboardInterrupt
        return SimpleNamespace(
            returncode=1 if failure == "nonzero" else 0,
            timed_out=failure == "timeout",
            stderr="failed",
        )

    monkeypatch.setattr(builder, "_run_git", git)
    monkeypatch.setattr(builder, "_checkout", lambda *args: False)

    def run():
        if method == "shallow":
            return builder._clone_shallow("https://github.com/owner/repo", target)
        return builder._clone_at_sha("https://github.com/owner/repo", target, "a" * 40)

    if failure == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            run()
    else:
        run()
    assert not target.exists()


@pytest.mark.parametrize(
    "failure", [OSError, tarfile.ReadError, zlib.error, KeyboardInterrupt]
)
def test_failed_archive_extraction_leaves_no_partial_checkout(
    tmp_path, builder, monkeypatch, failure
):
    target = tmp_path / "clone"
    monkeypatch.setattr(sb, "_http_get_bytes", lambda *args, **kwargs: archive())
    original = tarfile.TarFile.extract

    def extract(self, member, *args, **kwargs):
        if member.name == "second":
            raise failure("extract failed")
        return original(self, member, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            builder._download_tarball("owner", "repo", "v1", target)
    else:
        assert builder._download_tarball("owner", "repo", "v1", target) is False
    assert not target.exists()
    assert list(tmp_path.glob("cve-env-archive-*")) == []


def test_archive_is_not_visible_until_extraction_finishes(
    tmp_path, builder, monkeypatch
):
    target = tmp_path / "clone"
    monkeypatch.setattr(sb, "_http_get_bytes", lambda *args, **kwargs: archive())
    original = tarfile.TarFile.extract

    def extract(self, member, *args, **kwargs):
        assert not target.exists()
        return original(self, member, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    assert builder._download_tarball("owner", "repo", "v1", target)
    assert (target / "first").read_bytes() == b"x" * 16
    assert list(tmp_path.glob("cve-env-archive-*")) == []


@pytest.mark.parametrize("method", ["shallow", "sha", "archive"])
def test_acquisition_preserves_preexisting_destination(
    tmp_path, builder, monkeypatch, method
):
    target = tmp_path / "clone"
    target.mkdir()
    (target / "operator-data").write_text("keep")
    monkeypatch.setattr(
        builder,
        "_run_git",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1, timed_out=False, stderr="failed"
        ),
    )
    monkeypatch.setattr(sb, "_http_get_bytes", lambda *args, **kwargs: archive())
    if method == "shallow":
        assert not builder._clone_shallow("https://github.com/owner/repo", target)
    elif method == "sha":
        assert (
            builder._clone_at_sha("https://github.com/owner/repo", target, "a" * 40).tag
            is None
        )
    else:
        assert not builder._download_tarball("owner", "repo", "v1", target)
    assert (target / "operator-data").read_text() == "keep"
    assert not (target / "first").exists()


@pytest.mark.parametrize("method", ["shallow", "sha"])
def test_successful_clones_transfer_the_complete_tree(
    tmp_path, builder, monkeypatch, method
):
    target = tmp_path / "clone"

    def git(*args, **kwargs):
        target.mkdir()
        (target / "payload").write_text("complete")
        return SimpleNamespace(returncode=0, timed_out=False, stderr="")

    monkeypatch.setattr(builder, "_run_git", git)
    monkeypatch.setattr(builder, "_checkout", lambda *args: True)
    if method == "shallow":
        assert builder._clone_shallow("https://github.com/owner/repo", target)
    else:
        assert (
            builder._clone_at_sha("https://github.com/owner/repo", target, "a" * 40).tag
            == "a" * 40
        )
    assert (target / "payload").read_text() == "complete"


@pytest.mark.parametrize("owner", ["builder", "retained"])
def test_one_failed_cleanup_does_not_strand_later_checkouts(
    tmp_path, builder, monkeypatch, owner
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    remove = sb.rmtree_hardened
    monkeypatch.setattr(
        sb, "rmtree_hardened", lambda path: False if path == first else remove(path)
    )
    if owner == "builder":
        builder._temp_dirs[:] = [first, second]
        builder.cleanup()
        assert builder._temp_dirs == [first]
    else:
        monkeypatch.setattr(sb, "_RETAINED_DIRS", [first, second])
        sb._cleanup_retained_dirs()
        assert sb._RETAINED_DIRS == [first]
    assert first.exists()
    assert not second.exists()


def test_cleanup_opt_out_keeps_tracking_and_tree(tmp_path):
    builder = sb.SourceBuilder(sb.SourceBuildConfig(cleanup=False))
    tree = tmp_path / "clone"
    tree.mkdir()
    builder._temp_dirs.append(tree)
    builder.cleanup()
    assert builder._temp_dirs == [tree]
    assert tree.exists()


def test_archive_fallback_refuses_to_download_over_failed_cleanup(
    tmp_path, builder, monkeypatch
):
    target = tmp_path / "clone"
    target.mkdir()
    (target / "payload").write_text("keep")
    monkeypatch.setattr(builder, "_list_tags_via_api", lambda *args: ["v1"])
    monkeypatch.setattr(sb, "rmtree_hardened", lambda path: False)
    calls = []
    monkeypatch.setattr(builder, "_download_tarball", lambda *args: calls.append(args))
    warnings = []
    assert (
        builder._archive_fallback(
            "https://github.com/owner/repo", "1", target, warnings
        )
        is None
    )
    assert calls == []
    assert (target / "payload").read_text() == "keep"
    assert warnings


def test_archive_collision_preserves_new_destination_and_removes_scratch(
    tmp_path, builder, monkeypatch
):
    target = tmp_path / "clone"
    monkeypatch.setattr(sb, "_http_get_bytes", lambda *args, **kwargs: archive())
    original = tarfile.TarFile.extract

    def extract(self, member, *args, **kwargs):
        if member.name == "second":
            target.mkdir()
            (target / "operator-data").write_text("keep")
        return original(self, member, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "extract", extract)
    assert builder._download_tarball("owner", "repo", "v1", target) is False
    assert (target / "operator-data").read_text() == "keep"
    assert list(tmp_path.glob("cve-env-archive-*")) == []


def test_preexisting_archive_destination_refuses_before_http(
    tmp_path, builder, monkeypatch
):
    target = tmp_path / "clone"
    target.mkdir()

    def forbidden(*args, **kwargs):
        raise AssertionError("unnecessary download")

    monkeypatch.setattr(sb, "_http_get_bytes", forbidden)
    assert builder._download_tarball("owner", "repo", "v1", target) is False


@pytest.mark.parametrize("foreign", [False, True])
def test_archives_without_source_files_are_not_published(
    tmp_path, builder, monkeypatch, foreign
):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        root = tarfile.TarInfo("repo")
        root.type = tarfile.DIRTYPE
        tar.addfile(root)
        if foreign:
            info = tarfile.TarInfo("other/file")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
    monkeypatch.setattr(sb, "_http_get_bytes", lambda *args, **kwargs: out.getvalue())
    target = tmp_path / "clone"
    assert builder._download_tarball("owner", "repo", "v1", target) is False
    assert not target.exists()
    assert list(tmp_path.glob("cve-env-archive-*")) == []


@pytest.mark.parametrize("caller", ["build", "fallback"])
def test_existing_non_directory_checkout_is_not_chmodded_or_deleted(
    tmp_path, monkeypatch, caller
):
    target = tmp_path / "clone"
    target.write_text("operator data")
    target.chmod(0o640)
    mode = target.stat().st_mode
    builder = sb.SourceBuilder(sb.SourceBuildConfig(work_dir=tmp_path))
    if caller == "build":
        result = builder.build(
            source_url="https://github.com/owner/repo", product="clone", version="1"
        )
        assert not result.ok
    else:
        monkeypatch.setattr(builder, "_list_tags_via_api", lambda *args: ["v1"])
        assert (
            builder._archive_fallback("https://github.com/owner/repo", "1", target, [])
            is None
        )
    assert target.read_text() == "operator data"
    assert target.stat().st_mode == mode


@pytest.mark.parametrize("owner", ["builder", "retained"])
def test_replaced_non_directory_root_is_kept_for_review_without_chmod(
    tmp_path, builder, monkeypatch, owner
):
    target = tmp_path / "clone"
    target.write_text("replacement")
    target.chmod(0o640)
    mode = target.stat().st_mode
    if owner == "builder":
        builder._temp_dirs.append(target)
        builder.cleanup()
        assert builder._temp_dirs == [target]
    else:
        monkeypatch.setattr(sb, "_RETAINED_DIRS", [target])
        sb._cleanup_retained_dirs()
        assert sb._RETAINED_DIRS == [target]
    assert target.stat().st_mode == mode
    assert target.read_text() == "replacement"
